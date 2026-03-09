[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$nonCompliantReasons = New-Object System.Collections.Generic.List[string]

try {
    $windowsClient = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Where-Object {
        $_.ProductType -eq 1 -and ($_.Version -like '6.2*' -or $_.Version -like '6.3*' -or $_.Version -like '10.0*')
    }
    if (-not $windowsClient) {
        $nonCompliantReasons.Add('Unsupported or non-client Windows edition.')
    }

    $tpmInfo = Get-CimInstance -ClassName Win32_Tpm -Namespace 'root\cimv2\security\microsofttpm' -ErrorAction SilentlyContinue
    if (-not $tpmInfo) {
        $nonCompliantReasons.Add('TPM was not detected.')
    }
    elseif (-not $tpmInfo.IsEnabled_InitialValue) {
        $nonCompliantReasons.Add('TPM is not enabled.')
    }

    $systemDriveVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if (-not $systemDriveVolume) {
        $nonCompliantReasons.Add('System drive is not BitLocker ready.')
    }
    else {
        if ($systemDriveVolume.ProtectionStatus -ne 'On') {
            $nonCompliantReasons.Add('BitLocker protection is not enabled on the system drive.')
        }

        if ($systemDriveVolume.VolumeStatus -eq 'FullyDecrypted') {
            $nonCompliantReasons.Add('System drive is fully decrypted.')
        }

        $recoveryProtector = $systemDriveVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if (-not $recoveryProtector) {
            $nonCompliantReasons.Add('Recovery password protector is missing on the system drive.')
        }
    }

    $fvePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    if (-not (Test-Path $fvePolicyPath)) {
        $nonCompliantReasons.Add('BitLocker policy registry key is missing.')
    }
}
catch {
    $nonCompliantReasons.Add("Detection failed with error: $($_.Exception.Message)")
}

if ($nonCompliantReasons.Count -gt 0) {
    $nonCompliantReasons | ForEach-Object { Write-Output "Non-compliant: $_" }
    exit 1
}

Write-Output 'Compliant: BitLocker health checks passed.'
exit 0