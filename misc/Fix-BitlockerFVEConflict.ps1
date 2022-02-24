# This script is to fix the Bitlocker key and password conflict issue
Remove-Item -Path "HKLM:\Software\Policies\Microsoft\FVE\*" -Recurse -Force
