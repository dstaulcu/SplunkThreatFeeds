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

function Get-Feed-NVD-Modified 
{
    param($DownloadFile)
    $url = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz"
    $WebClient = New-Object System.Net.WebClient
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $WebClient.DownloadFile($url,$DownloadFile)
}

# define some constants
$AppDir = "C:\ThreatFeeds"
$component = "NVD.Modified"
$logfile = "$($AppDir)\Logs\$($component).LOG"
$PurgeAfterThisNumberOfDays = 7

# define path to desired output file
$Package = ((get-date).ToUniversalTime())
$Package = $Package.ToString("yyyyMMdd")
$DownloadFile = "$($AppDir)\Downloads\nvdcve-1.0-modified-$($Package).json.gz"

# remove the file if it already exists
if (test-path -Path $DownloadFile) { Remove-Item -Path $DownloadFile -Force }

# invoke a download of the file
Get-Feed-NVD-Modified -DownloadFile $DownloadFile

# check to see if download failed
if (!(test-path -Path $DownloadFile)) {
    Write-SplunkLog -Level "WARN" -Component "$($component).Download" -Message "Download of `"$($DownloadFile)`" failed" -File $logfile
    exit
} else {
    Write-SplunkLog -Level "INFO" -Component "$($component).Download" -Message "Download of `"$($DownloadFile)`" succeeded" -File $logfile
}

# cleanup old files
$Downloads = Get-ChildItem -path "$($AppDir)\Downloads" -Filter "nvdcve-1.0-modified-*.json.gz"
foreach ($download in $Downloads) {
    $FileAgeDays = (New-TimeSpan -Start $download.LastWriteTime -End (get-date)).TotalDays
    if ($FileAgeDays -ge $PurgeAfterThisNumberOfDays) {
        Write-SplunkLog -Level "INFO" -Component "$($component).Grooming" -Message "Removing `"$($Download.FullName)`" because it is ge $($PurgeAfterThisNumberOfDays) days old."  -File $logfile
    } else {
        Write-SplunkLog -Level "INFO" -Component "$($component).Grooming" -Message "Keeping `"$($Download.FullName)`" because it is lt $($PurgeAfterThisNumberOfDays) days old." -File $logfile
    }
    
}


