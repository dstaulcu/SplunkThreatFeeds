function Iterate-Tree($jsonTree) {
    $result = @()

    # Go through each node in the tree
    foreach ($node in $jsonTree) {

        # For each node we need to set up its keys/properties/fields
        $nodeHash = @{}
        foreach ($property in $node.Keys) {
            # If a field is a set (either a dictionary or array - both used by the deserializer) we will need to iterate it
            if ($node[$property] -is [System.Collections.Generic.Dictionary[String, Object]] -or $node[$property] -is [Object[]]) {
                # This assignment is important as it forces single result sets to be wrapped in an array, which is required
                $inner = @()
                $inner += Iterate-Tree $node[$property]

                $nodeHash.Add($property, $inner)
            } else {
                $nodeHash.Add($property, $node[$property])
            }
        }

        # Create a custom object from the hash table so it matches the original. It must be a PSCustomObject
        # because the serializer (later) requires that and not a PSObject or HashTable.
        $result += [PSCustomObject] $nodeHash
    }

    return $result
}


function Write-SplunkLog
{
    Param
    (
        $File="$($env:temp)\logfile.txt"
        ,$Level="INFO"
        ,$Component="Default"
        ,$Message="Hello World!"
    )
    $LogTime = get-date
    $LogTimeSplunk = $LogTime.ToString("MM-dd-yyyy hh:mm:ss.fff") 
    $LogTimeSplunk += " " + $LogTime.ToString("zzz").Replace(":","")
    $content = "$($LogTimeSplunk)`t$($Level)`t$($Component) - $($Message)"
    write-host $content
    Add-Content -Path $File -Value $content
}


# define some constants
$AppDir = "C:\ThreatFeeds"
$component = "NVD.Modified"
$logfile = "$($AppDir)\Logs\$($component).LOG"
$PurgeAfterThisNumberOfDays = 7
$ziptool = "$($AppDir)\Bin\7z.exe"
$extractDir = "$($AppDir)\Extracts\$($component)"
$MonitorDir = "$($AppDir)\Monitor\$($component)"


# get the files of interest
$Downloads = Get-ChildItem -path "$($AppDir)\Downloads" -Filter "nvdcve-1.0-modified-*.json.gz"

# purge the exaction directory if it already exists
if (test-path -Path $extractDir) {
    remove-item -Path $extractDir -Force -recurse
    mkdir $extractDir
}

# extract all the downloads
foreach ($Download in $Downloads) {
    # Decompress the GZ file
    & $ziptool "x" `"$($Download.FullName)`" `"-o$($extractDir)`"    
}

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")        
$jsonserial= New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer 
$jsonserial.MaxJsonLength = 2147483644 


$Extracts = Get-ChildItem -Path $extractDir 
foreach ($extractfile in $Extracts) {
    # the downloaded file has some junk.. trim it
        $jsonFileName =  $extractfile.fullname
        $jsonContent = Get-Content $jsonFileName
        $jsonTree = $javaScriptSerializer.DeserializeObject($jsonContent)
        $jsonTree = Iterate-Tree $jsonTree
        # The -Compress option is important, and works around conversion bugs revolving around single double-quotes
        ConvertTo-Json $jsonTree -Depth 99 -Compress | Set-Content (Get-ChildItem $jsonFileName | %{ Join-Path $_.DirectoryName "$($_.BaseName)_Fixed$($_.Extension)" } )
    
        $item=0
        foreach ($cve in $jsonTree.CVE_Items.cve) {
            $item++
            $cve_id = $cve | select -ExpandProperty CVE_data_meta | select -ExpandProperty ID
            $splunk_filename = "$($MonitorDir)\$($cve_id).json"
            if (Test-Path -Path $splunk_filename) { Remove-Item -Path $splunk_filename -Force }
            $splunk_filename_content = $cve | ConvertTo-Json -Depth 99 -Compress
            write-host "Writing output to $($splunk_filename)."
            Add-Content -Path $splunk_filename -Value $splunk_filename_content
    }
}
# make sure the monitoring related folders exist
if (!(Test-Path -Path "$($AppDir)\Monitor")) { mkdir "$($AppDir)\Monitor" } 
if (!(Test-Path -Path $MonitorDir)) { mkdir $MonitorDir } 

# move the transformed data into folder monitored by Splunk
$Extracts = Get-ChildItem -Path $extractDir 
foreach ($extractfile in $Extracts) {
    Copy-Item -Path $extractfile.FullName -destination "$($MonitorDir)"
}

