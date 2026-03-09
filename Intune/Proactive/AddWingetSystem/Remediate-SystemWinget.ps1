<#
Version: 1.0
Author:
- Joey Verlinden (joeyverlinden.com)
- Andrew Taylor (andrewstaylor.com)
- Florian Slazmann (scloud.work)
- Jannik Reinhard (jannikreinhard.com)
Script: remediate-app.ps1
Description: Installs app via Winget
Hint: This is a community script. There is no guarantee for this. Please check thoroughly before running.
Version 1.0: Init
Run as: System
Context: 64 Bit
#>

$appid = ""

if ([string]::IsNullOrWhiteSpace($appid)) {
    Write-Host "No appid specified; skipping winget installation." -ForegroundColor Yellow
    exit 0
}
$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
if ($ResolveWingetPath){
       $WingetPath = $ResolveWingetPath[-1].Path
       $Winget = $WingetPath + "\winget.exe"
       &$winget install --id $appid --silent --force --accept-package-agreements --accept-source-agreements --scope machine --exact | out-null
}

