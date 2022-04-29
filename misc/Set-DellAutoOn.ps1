cmd /c "pushd "%ProgramW6432%\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" && winget.exe install --id Dell.CommandConfigure --silent --accept-package-agreements --accept-source-agreements"
Start-Sleep 30
& "C:\program files (x86)\Dell\Command Configure\X86_64\cctk.exe" --AutoOn=everyday --AutoOnHr=19 --AutoOnMn=35 --AcPwrRcvry=On