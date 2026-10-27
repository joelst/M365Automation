<#
.SYNOPSIS
    Intune Proactive Remediation - DETECTION script for Claude Cowork prerequisites.

.DESCRIPTION
    Checks whether:
      1) The VirtualMachinePlatform Windows optional feature is Enabled
         (EnablePending counts as non-compliant - reboot still required)
      2) HCS services Cowork depends on (vmcompute, hns) exist and are running
      3) The readiness flag from a prior remediation run is present

    Exit 0  = Compliant. Remediation script will NOT run.
    Exit 1  = Non-compliant. Remediation script WILL run automatically.

    Deploy this as the "Detection script" in an Intune Proactive Remediation,
    paired with Remediate-CoworkPrereqs.ps1. Run as SYSTEM (default).
    Run script in 64-bit PowerShell: Yes.

    Assign only to devices/users in the Claude Cowork pilot (or production)
    group - chat-only Claude does not need this remediation.
#>

$ErrorActionPreference = 'SilentlyContinue'

$flagDir   = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude'
$flagPath  = Join-Path $flagDir 'ClaudeCoworkPrereqsReady.flag'
$logFile   = Join-Path $flagDir 'ClaudeCowork-Detection.log'
$logSource = 'ClaudeCoworkMSIX'
$hcsServices = @('vmcompute', 'hns')

if (-not (Test-Path $flagDir)) {
    New-Item -Path $flagDir -ItemType Directory -Force | Out-Null
}

function Write-DetectLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $Message
    try { Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue } catch { }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($logSource)) {
            New-EventLog -LogName Application -Source $logSource
        }
        Write-EventLog -LogName Application -Source $logSource -EntryType Information -EventId 100 -Message $Message
    } catch {
        # Event log is best-effort; file log is primary
    }
    Write-Host $line
}

$reasons = @()

# 1) Virtual Machine Platform feature state
$feature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
if (-not $feature) {
    $reasons += 'VirtualMachinePlatform feature not found (unsupported SKU or query failed)'
} elseif ($feature.State -eq 'EnablePending') {
    $reasons += 'VirtualMachinePlatform is EnablePending (reboot required; use Restart not Shutdown)'
} elseif ($feature.State -ne 'Enabled') {
    $reasons += "VirtualMachinePlatform feature not enabled (state: $($feature.State))"
}

# 2) HCS services Anthropic documents for Cowork (not full Hyper-V vmms)
foreach ($svcName in $hcsServices) {
    $svc = Get-Service -Name $svcName
    if (-not $svc) {
        $reasons += "Service $svcName not present"
    } elseif ($svc.Status -ne 'Running') {
        $reasons += "Service $svcName present but not running (status: $($svc.Status))"
    }
}

# 3) Readiness flag written by a successful remediation
if (-not (Test-Path $flagPath)) {
    $reasons += 'Readiness flag not present'
}

if ($reasons.Count -eq 0) {
    Write-DetectLog -Message 'Detection PASSED: Cowork prerequisites are ready.'
    Write-Host 'Compliant: Cowork prerequisites ready'
    exit 0
} else {
    $msg = 'Detection FAILED: ' + ($reasons -join '; ')
    Write-DetectLog -Message $msg
    Write-Host $msg
    exit 1
}
