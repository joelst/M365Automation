<#
    Set-DellCommandUpdateSettings.ps1

    Configures Dell Command Update client preferences via registry settings
    (e.g., setup popup behavior, advanced driver restore, BitLocker suspension,
    automation mode, and notifications).
    As-is no warranties, please test before using in production.
    Please provide suggestions and updates via GitHub.

Joel Stidley
https://github.com/joelst

#>

function Set-RegInfo {
    [CmdletBinding()]
    param (
        $RegistryPath,
        $Name,
        $Value,
        $Type
    )

    # Clean up entries
    $Type = $Type.replace("REG_", "")
    $RegistryPath = $RegistryPath.Replace("HKLM\", "HKLM:\").Replace("HKCU\", "HKCU:\").Replace("HCU\", "HCU:\")
    # Create the key if it does not exist
    If (-NOT (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
    # Now set the value
    Get-ItemProperty -Path $RegistryPath -Name $Name | Format-Table -AutoSize
    $null = New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $Type -Force
    Get-ItemProperty -Path $RegistryPath -Name $Name | Format-Table -AutoSize
}


try {


    # Set other registry keys
    # Don't show the setup popup
    Set-RegInfo -RegistryPath "HKLM:\SOFTWARE\DELL\UpdateService\Clients\CommandUpdate\Preferences\CFG" -Name "ShowSetupPopup" -Value 0 -Type "DWORD"
    # Enable Advanced Driver Restore
    Set-RegInfo -RegistryPath "HKLM:\SOFTWARE\DELL\UpdateService\Clients\CommandUpdate\Preferences\Settings\AdvancedDriverRestore" -Name "IsAdvancedDriverRestoreEnabled" -Value 1 -Type "DWORD"
    # Disable User Consent for sharing data
    Set-RegInfo -RegistryPath "HKLM:\SOFTWARE\DELL\UpdateService\Clients\CommandUpdate\Preferences\Settings\General" -Name "UserConsentDefault" -Value 0 -Type "DWORD"
    # Allow Bitlocker to be suspended for updates
    Set-RegInfo -RegistryPath "HKLM:\SOFTWARE\DELL\UpdateService\Clients\CommandUpdate\Preferences\Settings\General" -Name "SuspendBitLocker" -Value 1 -Type "DWORD"
    # Automatically download and install updates
    Set-RegInfo -RegistryPath "HKLM:\SOFTWARE\DELL\UpdateService\Clients\CommandUpdate\Preferences\Settings\Schedule" -Name "AutomationMode" -Value "ScanDownloadApplyNotify" -Type "String"
    # Disable notifications about updates
    Set-RegInfo -RegistryPath "HKLM:\SOFTWARE\DELL\UpdateService\Clients\CommandUpdate\Preferences\Settings\Schedule" -Name "DisableNotification" -Value 0 -Type "DWORD"

    Write-Output "Completed $(Get-Date)"

    exit 0
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error $errorMessage
    Write-Output "Error occurred $(Get-Date)"
    exit 1
}