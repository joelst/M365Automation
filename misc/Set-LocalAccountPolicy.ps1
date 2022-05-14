
<#
Description
Chrome allows for processes started while the browser is open to remain running once the browser has been closed. It also allows for background apps and the current browsing session to remain active after the browser has been closed. Disabling this feature will stop all processes and background applications when the browser window is closed.
Potential risk
If this setting is enabled, vulnerable or malicious plugins, apps and processes can continue running even after Chrome has closed.

M365 Defender: scid-19

#>

function Set-RegInfo {
    [CmdletBinding()]
    param (
        $Path,
        $Name,
        $Value,
        $PropertyType
    )
    
# Create the key if it does not exist
    if (-NOT (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
    }  
    # Now set the value
    $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Continue
}

#Set-RegInfo -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\" -Name BackgroundModeEnabled -Value '0' -PropertyType DWORD
#Set-RegInfo -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\" -Name BlockThirdPartyCookies -Value '1' -PropertyType DWORD
#Set-RegInfo -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name AuditLevel -Value '00000008' -PropertyType DWORD
#Set-RegInfo -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value '1' -PropertyType DWORD

Invoke-Command {net accounts /minpwlen:12 /minpwage:1 /lockoutduration:15 /lockoutthreshold:10 /lockoutwindow:15}
