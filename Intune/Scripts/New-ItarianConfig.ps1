#
# Despite many hours of trying to work through this process. It never worked reliably when running as SYSTEM
#   I decided to use a different tool since I couldn't automate deployment using a cloud-based tool.
#   There is probably a simple answer, but I don't need it anymore.
#

$script1 = 
@"
function Set-RegInfo {
    [CmdletBinding()]
    param (
        $RegistryPath,
        $Name,
        $Value,
        $Type
    )
    
# Create the key if it does not exist
    If (-NOT (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
    }  
    # Now set the value
    $null = New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $Type -Force
}

$file = "[General]

host = XXXXXXX.itsm-us1.comodo.com
port = 443
remove_third_party = false
suite = 4
token = XXXXXXXX
"

Write-Output " Removing config files."
Remove-Item -Path "C:\Program Files (x86)\COMODO\Comodo ITSM\*.ini" -Force -ErrorAction SilentlyContinue
Write-Output " Removing Itarian registration..."
Start-Process 'C:\Program Files (x86)\COMODO\Comodo ITSM\ITSMService.exe' -ArgumentList '-c 2'
Get-Process ITSMAgent -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue -Force
Start-Sleep 10
Write-Output " Stopping ITSM Service"
Stop-Service ITSMService -Force -ErrorAction SilentlyContinue
Write-Output " Writing new config file"
# Set Permissions to allow end user to run this.
$null = New-Item -Path "C:\Program Files (x86)\COMODO\Comodo ITSM\" -Force -ItemType Directory

#### $file | Out-File "C:\Program Files (x86)\COMODO\Comodo ITSM\enrollment_config.ini" -force

$file | Out-File "C:\Program Files (x86)\COMODO\Comodo ITSM\enrollment_settings.ini" -force
Start-Sleep 5

Write-Output " Updating Registry directly"
$rPath = "HKLM:\SOFTWARE\WOW6432Node\COMODO\ITSM\Communication\Service"
Set-RegInfo -RegistryPath $rPath -Name "IsUpdatesDisabled" -Value "false" -Type "String"
Set-RegInfo -RegistryPath $rPath -Name "Host" -Value "xxxxxxx.itsm-us1.comodo.com:443" -Type "String"
Set-RegInfo -RegistryPath $rPath -Name "Token" -Value "3403550ec23f77f8ebca75aaa089d819" -Type "String"
# & 'C:\Program Files (x86)\COMODO\Comodo ITSM\RmmService.exe'
Start-Service ITSMService -ErrorAction SilentlyContinue
"@
Write-host $script1

$null = New-Item -Path C:\tmp -force -Type Directory -ErrorAction SilentlyContinue
$script1 | Out-file C:\tmp\New-ItarianConfig.ps1 -force -ErrorAction SilentlyContinue

$taskName = "Fix-Itarian-Client"
$taskDesc = "Run this script to fix the itarian client"
$actionArgs = '-file "C:\tmp\New-ItarianConfig.ps1"'
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $actionArgs 
$taskTrigger = New-ScheduledTaskTrigger -AtLogon
$taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 15) -RunOnlyIfNetworkAvailable -Compatibility "Win8"
$taskPrincipal = New-ScheduledTaskPrincipal -UserID "$env:username" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Description $taskDesc -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal