<#
.SYNOPSIS
Repairs Windows component store health for Intune Proactive Remediations.

.DESCRIPTION
Runs DISM RestoreHealth first and then SFC ScanNow. The script exits nonzero when
DISM fails or when SFC reports a clearly unsuccessful outcome.

.NOTES
Recommended Intune settings:
- Run this script using the logged-on credentials: No
- Run script in 64-bit PowerShell: Yes
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Output ('[Remediation] {0}' -f $Message)
}

function Invoke-NativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $outputLines = & $FilePath @Arguments 2>&1 | ForEach-Object { [string]$_ }
    $exitCode = $LASTEXITCODE

    return [pscustomobject]@{
        ExitCode = $exitCode
        Output   = ($outputLines -join [Environment]::NewLine).Trim()
    }
}

function Invoke-DismRestoreHealth {
    [CmdletBinding()]
    param()

    $arguments = @('/Online', '/Cleanup-Image', '/RestoreHealth', '/English')
    $result = Invoke-NativeCommand -FilePath 'DISM.exe' -Arguments $arguments

    if ($result.ExitCode -eq 87 -and $result.Output -match 'English') {
        Write-LogMessage 'DISM /English is not supported on this device. Retrying without /English.'
        $arguments = @('/Online', '/Cleanup-Image', '/RestoreHealth')
        $result = Invoke-NativeCommand -FilePath 'DISM.exe' -Arguments $arguments
    }

    return $result
}

function Test-SfcFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    if ($ExitCode -eq 0) {
        return $false
    }

    $knownFailurePatterns = @(
        'Windows Resource Protection could not perform the requested operation',
        'Windows Resource Protection found corrupt files but was unable to fix some of them',
        'There is a system repair pending which requires reboot to complete'
    )

    foreach ($pattern in $knownFailurePatterns) {
        if ($Output -match [regex]::Escape($pattern)) {
            return $true
        }
    }

    return $true
}

try {
    Write-LogMessage 'Running DISM RestoreHealth.'
    $dismResult = Invoke-DismRestoreHealth

    if (-not [string]::IsNullOrWhiteSpace($dismResult.Output)) {
        Write-LogMessage $dismResult.Output
    }

    if ($dismResult.ExitCode -ne 0) {
        throw ("DISM RestoreHealth failed with exit code {0}." -f $dismResult.ExitCode)
    }

    Write-LogMessage 'DISM RestoreHealth completed successfully. Running SFC ScanNow.'
    $sfcResult = Invoke-NativeCommand -FilePath 'sfc.exe' -Arguments @('/scannow')

    if (-not [string]::IsNullOrWhiteSpace($sfcResult.Output)) {
        Write-LogMessage $sfcResult.Output
    }

    if (Test-SfcFailure -Output $sfcResult.Output -ExitCode $sfcResult.ExitCode) {
        throw ("SFC ScanNow did not complete successfully. Exit code: {0}." -f $sfcResult.ExitCode)
    }

    Write-LogMessage 'Remediation completed successfully.'
    exit 0
}
catch {
    Write-LogMessage ("Remediation failed: {0}" -f $_.Exception.Message)
    exit 1
}
