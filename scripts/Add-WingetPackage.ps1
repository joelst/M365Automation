# Make sure the latest version of winget is installed.
#
Write-Host "$(Get-Date) Testing for winget "
while (!(Get-Command -Name winget -ErrorAction SilentlyContinue)) {
  
  Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile "C:\Windows\Temp\winget.appxbundle"
  Add-AppxPackage C:\Windows\Temp\winget.appxbundle
  Start-Sleep 5
}
