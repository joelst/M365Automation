function Set-RegInfo {
    [CmdletBinding()]
    param (
        $Path,
        $Name,
        $Value,
        $PropertyType
    )
    
# Create key if it does not exist
    if (-NOT (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
    }  
    # Now set the value
    $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Continue
}

$ErrorActionPreference = "Continue"

Start-Transcript -Path "$env:TEMP\MEMBLocker-$(Get-Date -f MMddHHmm).txt"
# https://apps.microsoft.com/store/detail/microsoft-store/9WZDNCRFJBMP?hl=en-us&gl=US
# Check Bitlocker prerequisites
$TPMNotEnabled = Get-CimInstance win32_tpm -Namespace root\cimv2\security\microsofttpm | where { $_.IsEnabled_InitialValue -eq $false } -ErrorAction SilentlyContinue
$TPMEnabled = Get-CimInstance win32_tpm -Namespace root\cimv2\security\microsofttpm | where { $_.IsEnabled_InitialValue -eq $true } -ErrorAction SilentlyContinue
$WindowsVer = Get-CimInstance -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
$BitLockerDecrypted = Get-BitLockerVolume -MountPoint $env:SystemDrive | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" } -ErrorAction SilentlyContinue

# Step 1 - Check if TPM is enabled and initialize, if required
if ($WindowsVer -and !$TPMNotEnabled) {
    Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue
}

# Step 2 - Check if BitLocker volume is provisioned and partition system drive for Bitlocker if required
if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive) {
    Get-Service -Name defragsvc -ErrorAction SilentlyContinue | Set-Service -Status Running -ErrorAction SilentlyContinue
    BdeHdCfg -target $env:SystemDrive shrink -quiet
}

# Step 3 - Check Bitlocker AD Key backup registry values exist and if not, create them.
$BitLockerRegLoc = "HKLM:\SOFTWARE\Policies\Microsoft"
if ((Test-Path "$BitLockerRegLoc\FVE") -and $TPMNotEnabled) {
    Write-Output "Removing $BitLockerRegLoc\FVE key"
    Remove-Item -Path "$BitLockerRegLoc\FVE"
}
else {
    New-Item -Path "$BitLockerRegLoc" -Name 'FVE'
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD 
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodNoDiffuser' -Value '00000003' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsOs' -Value '00000006' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsFdv' -Value '00000006' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsRdv' -Value '00000003' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethod' -Value '00000003' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecovery' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSManageDRA' -Value '00000000' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryPassword' -Value '00000002' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryKey' -Value '00000002' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSHideRecoveryPage' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSAllowSecureBootForIntegrity' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSEncryptionType' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecovery' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVManageDRA' -Value '00000000' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryPassword' -Value '00000002' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryKey' -Value '00000002' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVHideRecoveryPage' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
    New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVEncryptionType' -Value '00000001' -PropertyType DWORD
}

# Step 4 - If all prerequisites are met, then enable Bitlocker
if ($WindowsVer -and $TPMEnabled -and $BitLockerReadyDrive -and $BitLockerDecrypted) {
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector
    Enable-BitLocker -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction SilentlyContinue
}

$BLVS = Get-BitLockerVolume | Where-Object { $_.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } } -ErrorAction SilentlyContinue
# Step 5 - Backup Bitlocker recovery passwords to AD
if ($BLVS) {
    ForEach ($BLV in $BLVS) {
        $Key = $BLV | Select-Object -ExpandProperty KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        ForEach ($obj in $key) { 
            Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorId $obj.KeyProtectorId -ErrorAction SilentlyContinue
            BackupToAAD-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorId $obj.KeyProtectorId -ErrorAction SilentlyContinue
        }
    }
}

Stop-Transcript