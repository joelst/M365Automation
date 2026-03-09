# This script was borrowed and modified from https://gist.github.com/YoraiLevi/

#https://serverfault.com/questions/1018220/how-do-i-install-an-app-from-windows-store-using-powershell

#Usage:
# > Download-AppxPackage "https://www.microsoft.com/p/dynamic-theme/9nblggh1zbkw" "$ENV:USERPROFILE\Desktop"
# C:\Users\user\Desktop\55888ChristopheLavalle.DynamicTheme_1.4.30233.0_neutral_~_jdggxwd41xcr0.AppxBundle
# C:\Users\user\Desktop\55888ChristopheLavalle.DynamicTheme_1.4.30234.0_neutral_~_jdggxwd41xcr0.AppxBundle
# C:\Users\user\Desktop\Microsoft.NET.Native.Framework.1.7_1.7.27413.0_x64__8wekyb3d8bbwe.Appx
# C:\Users\user\Desktop\Microsoft.NET.Native.Runtime.1.7_1.7.27422.0_x64__8wekyb3d8bbwe.Appx
# C:\Users\user\Desktop\Microsoft.Services.Store.Engagement_10.0.19011.0_x64__8wekyb3d8bbwe.Appx
# C:\Users\user\Desktop\Microsoft.VCLibs.140.00_14.0.29231.0_x64__8wekyb3d8bbwe.Appx

function Resolve-NameConflict {
    #Accepts Path to a FILE and changes it so there are no name conflicts
    param(
        [string]$Path
    )
    $newPath = $Path
    if (Test-Path $Path) {
        $i = 0;
        $item = (Get-Item $Path)
        while (Test-Path $newPath) {
            $i += 1;
            $newPath = Join-Path "$($item.DirectoryName)" "$($item.BaseName)$($i)$($item.Extension)"
        }
    }
    return $newPath
}
[string]$Uri = "https://apps.microsoft.com/store/detail/9WZDNCRFJBMP"
[string]$Path = "C:\temp\"
$Path = (Resolve-Path $Path).Path
#Get Urls to download
$WebResponse = Invoke-WebRequest -UseBasicParsing -Method 'POST' -Uri 'https://store.rg-adguard.net/api/GetFiles' -Body "type=url&url=$Uri&ring=Retail" -ContentType 'application/x-www-form-urlencoded'
$LinksMatch = $WebResponse.Links | Where-Object { $_ -like '*.appx*' } | Where-Object { $_ -like '*_neutral_*' -or $_ -like "*_" + $env:PROCESSOR_ARCHITECTURE.Replace("AMD", "X").Replace("IA", "X") + "_*" } | Select-String -Pattern '(?<=a href=").+(?=" r)'
$DownloadLinks = $LinksMatch.matches.value 
New-Item $path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
#Download Urls
foreach ($url in $DownloadLinks) {
    $FileRequest = Invoke-WebRequest -Uri $url -UseBasicParsing #-Method Head
    $FileName = ($FileRequest.Headers['Content-Disposition'] | Select-String -Pattern  '(?<=filename=).+').matches.value
    $FilePath = Join-Path $Path $FileName 
    $FilePath = Resolve-NameConflict($FilePath)
    [System.IO.File]::WriteAllBytes($FilePath, $FileRequest.content)
    Write-Host $FilePath
    Add-AppxPackage -Path $FilePath
}

# C:\WINDOWS\system32\Microsoft.NET.Native.Framework.1.7_1.7.27413.0_x64__8wekyb3d8bbwe.Appx 
#C:\WINDOWS\system32\Microsoft.NET.Native.Framework.2.2_2.2.29512.0_x64__8wekyb3d8bbwe.Appx 
#C:\WINDOWS\system32\Microsoft.NET.Native.Runtime.1.7_1.7.27422.0_x64__8wekyb3d8bbwe.Appx 
#C:\WINDOWS\system32\Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe.Appx 
#C:\WINDOWS\system32\Microsoft.UI.Xaml.2.4_2.42007.9001.0_x64__8wekyb3d8bbwe.Appx 
#C:\WINDOWS\system32\Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe.Appx 
# C:\WINDOWS\system32\Microsoft.VCLibs.140.00.UWPDesktop_14.0.32530.0_x64__8wekyb3d8bbwe.Appx 
# C:\WINDOWS\system32\Microsoft.VCLibs.140.00_14.0.32530.0_x64__8wekyb3d8bbwe.Appx 
# C:\WINDOWS\system32\Microsoft.WindowsStore_11811.1001.2713.0_neutral_~_8wekyb3d8bbwe.AppxBundle 
#C:\WINDOWS\system32\Microsoft.WindowsStore_12107.1001.15.0_neutral_~_8wekyb3d8bbwe.AppxBundle