try {
    $BLinfo = Get-BitlockerVolume
    if ($BLinfo.EncryptionPercentage -eq '100') {
        $Result = (Get-BitLockerVolume -MountPoint C).KeyProtector
        $Recoverykey = $result.recoverypassword	
        Write-Output "Bitlocker recovery key $recoverykey"
        Exit 0
    }
    if ($BLinfo.EncryptionPercentage -ne '100' -and $BLinfo.EncryptionPercentage -ne '0') {
        Resume-BitLocker -MountPoint "C:"
        $BLV = Get-BitLockerVolume -MountPoint "C:" | Select-Object *
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
        Exit 1
    }
    if ($BLinfo.VolumeStatus -eq 'FullyEncrypted' -and $BLinfo.ProtectionStatus -eq 'Off') {
        Resume-BitLocker -MountPoint "C:"
        $BLV = Get-BitLockerVolume -MountPoint "C:" | Select-Object *
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
        Exit 1
    }
    if ($BLinfo.EncryptionPercentage -eq '0') {
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector
        $BLV = Get-BitLockerVolume -MountPoint "C:" | Select-Object *
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
        Exit 1
    }
}
catch {
    Write-Warning "Value Missing"
    exit 1
}

