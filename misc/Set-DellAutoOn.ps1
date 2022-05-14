try
{
    Set-Location "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    & winget.exe install --id Dell.CommandConfigure --silent --accept-package-agreements --accept-source-agreements
    Start-Sleep 30
}
catch {
    Write-Output " Could not use winget. Hope that Dell Command Config is already available!"
}

Invoke-Command -ScriptBlock {cmd /c "'C:\program files (x86)\Dell\Command Configure\X86_64\cctk.exe' --AutoOn=everyday --AutoOnHr=19 --AutoOnMn=35 --AcPwrRcvry=On"}
exit 0