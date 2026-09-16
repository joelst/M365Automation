<#
.SYNOPSIS
Detects whether Windows image repair remediation is needed for Intune Proactive Remediations.

.DESCRIPTION
Runs DISM CheckHealth and returns exit code 1 when remediation should run.
Return code 0 indicates no remediation is required.

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

    Write-Output ('[Detection] {0}' -f $Message)
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

function Invoke-DismCheckHealth {
    [CmdletBinding()]
    param()

    $arguments = @('/Online', '/Cleanup-Image', '/CheckHealth', '/English')
    $result = Invoke-NativeCommand -FilePath 'DISM.exe' -Arguments $arguments

    if ($result.ExitCode -eq 87 -and $result.Output -match 'English') {
        Write-LogMessage 'DISM /English is not supported on this device. Retrying without /English.'
        $arguments = @('/Online', '/Cleanup-Image', '/CheckHealth')
        $result = Invoke-NativeCommand -FilePath 'DISM.exe' -Arguments $arguments
    }

    return $result
}

function Test-DismRepairRequired {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output
    )

    if ($Output -match 'No component store corruption detected') {
        return $false
    }

    if ($Output -match 'The component store is repairable' -or
        $Output -match 'The component store is not repairable' -or
        $Output -match 'The component store is corrupted') {
        return $true
    }

    return $true
}

try {
    Write-LogMessage 'Running DISM CheckHealth.'
    $result = Invoke-DismCheckHealth

    if (-not [string]::IsNullOrWhiteSpace($result.Output)) {
        Write-LogMessage $result.Output
    }

    if ($result.ExitCode -ne 0) {
        Write-LogMessage ("DISM CheckHealth returned exit code {0}. Marking device as needing remediation." -f $result.ExitCode)
        exit 1
    }

    if (Test-DismRepairRequired -Output $result.Output) {
        Write-LogMessage 'DISM detected a component store issue. Remediation is required.'
        exit 1
    }

    Write-LogMessage 'No remediation required.'
    exit 0
}
catch {
    Write-LogMessage ("Detection failed: {0}" -f $_.Exception.Message)
    exit 1
}
