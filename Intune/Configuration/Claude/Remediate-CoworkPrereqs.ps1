<#
.SYNOPSIS
    Intune Proactive Remediation - REMEDIATION script for Claude Cowork prerequisites.

.DESCRIPTION
    Runs as SYSTEM. Enables Virtual Machine Platform and ensures the HCS services
    Cowork needs (vmcompute, hns) are running so standard users can use Cowork
    without local admin.

    Claude Desktop may already be installed for chat-only use. Enabling
    virtualization later does not require reinstalling Claude - once services
    are up and the user restarts Claude (or signs out/in), Cowork becomes
    available. Assign this remediation only to the Claude Cowork group.

    Steps:
      1) Enable VirtualMachinePlatform if disabled; treat EnablePending as
         "waiting for reboot" (do not re-enable in a loop).
      2) When Enabled, set vmcompute/hns to Automatic and start them.
      3) Write readiness flag when services are confirmed running; remove
         the flag if services are not healthy so install requirement rules
         (if used) stay honest.

    Deployment notes:
      - Schedule HOURLY during pilot; scale to daily once fleet is compliant.
      - Prefer Restart over Shutdown after feature enable (Windows Fast Startup
        can leave virtualization services uninitialized after a soft power-on).
      - Run script in 64-bit PowerShell: Yes.
#>

$ErrorActionPreference = 'Stop'

$flagDir        = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude'
$flagPath       = Join-Path $flagDir 'ClaudeCoworkPrereqsReady.flag'
$rebootFlagPath = Join-Path $flagDir 'ClaudeCoworkFeatureEnablePending.flag'
$logFile        = Join-Path $flagDir 'ClaudeCowork-Remediation.log'
$logSource      = 'ClaudeCoworkMSIX'
$hcsServices    = @('vmcompute', 'hns')

function Write-RemediateLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $Message
    try { Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue } catch { }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($logSource)) {
            New-EventLog -LogName Application -Source $logSource
        }
        Write-EventLog -LogName Application -Source $logSource -EntryType Information -EventId 200 -Message $Message
    } catch { }
    Write-Host $line
}

function Remove-ReadyFlag {
    if (Test-Path $flagPath) {
        Remove-Item -Path $flagPath -Force -ErrorAction SilentlyContinue
        Write-RemediateLog -Message 'Removed stale readiness flag (services/feature not healthy).'
    }
}

try {
    if (-not (Test-Path $flagDir)) {
        New-Item -Path $flagDir -ItemType Directory -Force | Out-Null
    }

    # Step 1: Optional feature state
    $feature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    if (-not $feature) {
        Remove-ReadyFlag
        Write-RemediateLog -Message 'VirtualMachinePlatform feature not available on this SKU.'
        Write-Host 'Remediation failed: VirtualMachinePlatform not available.'
        exit 1
    }

    switch ($feature.State) {
        'Enabled' {
            Write-RemediateLog -Message 'VirtualMachinePlatform is Enabled.'
        }
        'EnablePending' {
            # Already requested; do not call Enable again every hourly cycle
            Set-Content -Path $rebootFlagPath -Value (Get-Date).ToString('o')
            Remove-ReadyFlag
            Write-RemediateLog -Message 'VirtualMachinePlatform is EnablePending. Reboot still required (use Restart, not Shutdown).'
            Write-Host 'Feature EnablePending. Reboot required before services can start.'
            exit 0
        }
        default {
            Write-RemediateLog -Message "Enabling VirtualMachinePlatform (current state: $($feature.State)). Reboot will be required."
            Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart | Out-Null
            Set-Content -Path $rebootFlagPath -Value (Get-Date).ToString('o')
            Remove-ReadyFlag
            Write-Host 'Feature enabled. Reboot required before services can start. Exiting - will re-check next cycle.'
            # Does not force a reboot; schedule Restart via Intune restart notifications if needed.
            exit 0
        }
    }

    # Step 2: Feature Enabled - ensure HCS services exist and are running
    $servicesOk = $true
    foreach ($svcName in $hcsServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-RemediateLog -Message "Service $svcName still not present after feature enable + reboot. May need another Restart cycle."
            $servicesOk = $false
            continue
        }
        if ($svc.Status -ne 'Running') {
            try {
                Set-Service -Name $svcName -StartupType Automatic
                Start-Service -Name $svcName
                Write-RemediateLog -Message "Started service $svcName."
            } catch {
                Write-RemediateLog -Message "Failed to start $svcName - $($_.Exception.Message)"
                $servicesOk = $false
            }
        } else {
            # Ensure they stay Automatic across reboots
            try { Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
        }
    }

    if ($servicesOk) {
        Set-Content -Path $flagPath -Value (Get-Date).ToString('o')
        Remove-Item -Path $rebootFlagPath -ErrorAction SilentlyContinue
        Write-RemediateLog -Message 'Cowork prerequisites confirmed ready. Flag written.'
        Write-Host 'Remediation succeeded: Cowork prerequisites ready.'
        exit 0
    } else {
        Remove-ReadyFlag
        Write-Host 'Remediation partially applied - HCS services not yet running. Will retry next cycle (may need another Restart).'
        exit 1
    }

} catch {
    Remove-ReadyFlag
    Write-RemediateLog -Message "Remediation FAILED: $($_.Exception.Message)"
    Write-Host "Remediation failed: $($_.Exception.Message)"
    exit 1
}
