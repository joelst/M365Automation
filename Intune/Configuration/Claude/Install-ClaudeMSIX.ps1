<#
.SYNOPSIS
    Intune Win32 app INSTALL script for Claude Desktop, provisioned machine-wide.

.DESCRIPTION
    Provisions the Claude Desktop MSIX for ALL users on the device (not just
    the installing account). Runs in SYSTEM context - set Win32 "Install
    behavior: System".

    CHAT vs COWORK:
      Default (no switch): installs Claude for chat. Virtualization is NOT
      required. If Cowork prereqs are missing, the script logs a warning and
      continues - chat works; Cowork stays unavailable until the Cowork
      Proactive Remediation enables Virtual Machine Platform later (no
      reinstall needed).

      -RequireCoworkPrereqs: hard-gates install until the remediation flag
      and live HCS services are healthy. Use only on a Cowork-gated Win32
      app assignment if you want install to wait for virtualization.

    ARCHITECTURE:
      Place both packages in the Win32 source folder when packaging:
        Claude-x64.msix    (from Anthropic x64 MSIX URL)
        Claude-arm64.msix  (from Anthropic arm64 MSIX URL)
      The script picks the package matching PROCESSOR_ARCHITECTURE.
      Fallback: Claude-latest.msix is used only on AMD64 if Claude-x64.msix
      is missing (legacy package name).

    MSIX DELIVERY:
      The .msix files ship inside the Win32 .intunewin next to this script.
      IME extracts content and runs the install; nothing is downloaded at runtime.

    PRIOR INSTALLS (winget / Squirrel / user AppX):
      Detection only accepts a MACHINE-PROVISIONED package. Winget-as-SYSTEM
      alone is "not installed" so this app migrates once, then stays quiet.
      Cleanup removes Squirrel, best-effort winget, per-user AppX, then stages
      the bundled MSIX. If already provisioned, exit 0 (idempotent - no loop).

    EXIT CODES (map in Intune Return codes):
      0 = success
      1 = MSIX missing, wrong arch package, or provisioning failed  -> Retry
      2 = Cowork prereqs not ready AND -RequireCoworkPrereqs set   -> Retry
#>

[CmdletBinding()]
param(
    # When set, abort install (exit 2) if Cowork virtualization prereqs are not ready.
    # Omit for the general "Claude chat" Win32 app used during pilot.
    [switch]$RequireCoworkPrereqs,

    # Force remove + re-provision even when a provisioned package already exists.
    # Use when superseding with a new MSIX and Intune re-runs install.
    [switch]$ForceReprovision
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir    = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude'
$logFile   = Join-Path $logDir 'Install-ClaudeMSIX.log'
$prereqFlag = Join-Path $logDir 'ClaudeCoworkPrereqsReady.flag'
$hcsServices = @('vmcompute', 'hns')

if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $Message
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

function Get-ClaudeMsixPath {
    $arch = $env:PROCESSOR_ARCHITECTURE
    # Normalize: AMD64, ARM64, x86 (rare for modern managed Win11)
    switch -Regex ($arch) {
        '^(AMD64|X64)$' {
            $preferred = Join-Path $scriptDir 'Claude-x64.msix'
            $legacy    = Join-Path $scriptDir 'Claude-latest.msix'
            if (Test-Path $preferred) { return $preferred }
            if (Test-Path $legacy) {
                Write-Log "WARNING: Claude-x64.msix not found; using legacy Claude-latest.msix on AMD64."
                return $legacy
            }
            return $null
        }
        '^ARM64$' {
            $preferred = Join-Path $scriptDir 'Claude-arm64.msix'
            if (Test-Path $preferred) { return $preferred }
            return $null
        }
        default {
            Write-Log "WARNING: Unexpected PROCESSOR_ARCHITECTURE='$arch'."
            $fallback = Join-Path $scriptDir 'Claude-x64.msix'
            if (Test-Path $fallback) { return $fallback }
            return $null
        }
    }
}

function Test-CoworkPrereqsLive {
    $issues = @()

    if (-not (Test-Path $prereqFlag)) {
        $issues += "Prereq flag not found at $prereqFlag"
    }

    $feature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
    if (-not $feature) {
        $issues += 'VirtualMachinePlatform feature not found'
    } elseif ($feature.State -eq 'EnablePending') {
        $issues += 'VirtualMachinePlatform is EnablePending (reboot required)'
    } elseif ($feature.State -ne 'Enabled') {
        $issues += "VirtualMachinePlatform not enabled (state: $($feature.State))"
    }

    foreach ($svcName in $hcsServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            $issues += "Service $svcName not present"
        } elseif ($svc.Status -ne 'Running') {
            $issues += "Service $svcName present but not running (status: $($svc.Status))"
        }
    }

    return $issues
}

function Get-ClaudeProvisionedPackages {
    Get-AppxProvisionedPackage -Online | Where-Object {
        $_.DisplayName -eq 'Claude' -or
        $_.DisplayName -like '*Claude*' -or
        $_.PackageName -like 'Claude_*' -or
        $_.PackageName -like '*Anthropic*Claude*'
    }
}

function Get-ClaudeUserPackages {
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like '*Claude*' -or
        $_.Name -like '*Anthropic*' -or
        $_.PackageFullName -like '*Claude*'
    }
}

function Stop-ClaudeProcesses {
    Get-Process -Name 'Claude', 'Update' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

function Remove-SquirrelInstalls {
    Write-Log 'Checking for pre-existing per-user Squirrel installs...'
    $userProfiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $squirrelPath = Join-Path $profile.FullName 'AppData\Local\AnthropicClaude'
        if (-not (Test-Path $squirrelPath)) { continue }

        Write-Log "Found Squirrel install for profile $($profile.Name) - removing $squirrelPath"
        $updateExe = Join-Path $squirrelPath 'Update.exe'
        if (Test-Path $updateExe) {
            try {
                $p = Start-Process -FilePath $updateExe -ArgumentList '--uninstall', '-s' -Wait -PassThru -ErrorAction Stop
                Write-Log "Update.exe --uninstall exit code: $($p.ExitCode)"
            } catch {
                Write-Log "WARNING: Update.exe uninstall failed - $($_.Exception.Message)"
            }
        }
        try {
            Remove-Item -Path $squirrelPath -Recurse -Force -ErrorAction Stop
            Write-Log "Removed $squirrelPath"
        } catch {
            Write-Log "WARNING: could not fully remove $squirrelPath - $($_.Exception.Message)"
        }
    }
}

function Remove-WingetClaude {
    # Best-effort: clear winget's package registration if Anthropic.Claude was installed via winget.
    # Does not fail the install if winget is missing or the package is already gone.
    $winget = $null
    foreach ($candidate in @(
            "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe",
            "$env:LocalAppData\Microsoft\WindowsApps\winget.exe",
            'winget.exe'
        )) {
        if ($candidate -like '*`**') {
            $resolved = Get-Item $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($resolved) { $winget = $resolved.FullName; break }
        } else {
            $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($cmd) { $winget = $cmd.Source; break }
        }
    }
    # Prefer known SYSTEM-safe path under Program Files\WindowsApps
    if (-not $winget) {
        $wingetPkg = Get-ChildItem "$env:ProgramFiles\WindowsApps" -Filter 'Microsoft.DesktopAppInstaller_*' -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '_x64_' -or $_.Name -match '_arm64_' } |
            Sort-Object Name -Descending |
            Select-Object -First 1
        if ($wingetPkg) {
            $candidate = Join-Path $wingetPkg.FullName 'winget.exe'
            if (Test-Path $candidate) { $winget = $candidate }
        }
    }
    if (-not $winget -or -not (Test-Path $winget)) {
        Write-Log 'winget.exe not found - skipping winget uninstall (AppX cleanup still runs).'
        return
    }

    Write-Log "Attempting winget uninstall Anthropic.Claude via $winget"
    try {
        $args = @(
            'uninstall', '-e', '--id', 'Anthropic.Claude',
            '--silent', '--accept-source-agreements', '--disable-interactivity'
        )
        $p = Start-Process -FilePath $winget -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        Write-Log "winget uninstall exit code: $($p.ExitCode) (0/no-package both OK for migration)"
    } catch {
        Write-Log "WARNING: winget uninstall failed - $($_.Exception.Message)"
    }
}

function Remove-ClaudeUserAppx {
    Write-Log 'Removing per-user Claude AppX registrations (winget / Add-AppxPackage leftovers)...'
    $userPkgs = Get-ClaudeUserPackages
    if (-not $userPkgs) {
        Write-Log 'No per-user Claude AppX packages found.'
        return
    }
    foreach ($pkg in $userPkgs) {
        Write-Log "Removing per-user package $($pkg.PackageFullName)"
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
        } catch {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
            } catch {
                Write-Log "WARNING: could not remove $($pkg.PackageFullName) - $($_.Exception.Message)"
            }
        }
    }
}

function Remove-ClaudeProvisioned {
    $existing = Get-ClaudeProvisionedPackages
    if (-not $existing) { return }
    foreach ($pkg in $existing) {
        Write-Log "Removing existing provisioned package $($pkg.PackageName)"
        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -AllUsers | Out-Null
    }
}

try {
    # --- Step 0: Cowork prereq check (soft by default) ---
    $prereqIssues = Test-CoworkPrereqsLive
    if ($prereqIssues.Count -eq 0) {
        Write-Log 'Cowork prereq check passed: VMP enabled, vmcompute/hns running, flag present.'
    } else {
        $detail = $prereqIssues -join '; '
        if ($RequireCoworkPrereqs) {
            Write-Log "ABORT: -RequireCoworkPrereqs set and prereqs not ready - $detail"
            exit 2
        }
        Write-Log "INFO: Installing Claude for chat; Cowork not ready yet - $detail"
        Write-Log 'Cowork will become available after the Cowork Proactive Remediation completes and the device is Restarted. No reinstall of Claude is required.'
    }

    # --- Idempotent success path (prevents install/detect loops) ---
    # Detection uses the same provisioned-package check. If we already staged
    # Claude machine-wide, do not remove/re-add on every accidental re-run.
    $already = Get-ClaudeProvisionedPackages
    if ($already -and -not $ForceReprovision) {
        foreach ($pkg in $already) {
            Write-Log "ALREADY PROVISIONED: $($pkg.DisplayName) $($pkg.Version) ($($pkg.PackageName)) - nothing to do."
        }
        Write-Log 'Exit 0 (idempotent). Winget-only installs without a provisioned package would not hit this path.'
        exit 0
    }
    if ($ForceReprovision -and $already) {
        Write-Log 'ForceReprovision set - will replace existing provisioned package.'
    }

    $msixPath = Get-ClaudeMsixPath
    if (-not $msixPath -or -not (Test-Path $msixPath)) {
        $arch = $env:PROCESSOR_ARCHITECTURE
        Write-Log "ERROR: No MSIX for architecture '$arch' in $scriptDir. Expected Claude-x64.msix and/or Claude-arm64.msix."
        exit 1
    }
    Write-Log "Using package: $msixPath (PROCESSOR_ARCHITECTURE=$($env:PROCESSOR_ARCHITECTURE))"

    # --- Step 1: Stop processes and clear prior install types ---
    Stop-ClaudeProcesses
    Remove-SquirrelInstalls
    Remove-WingetClaude
    Remove-ClaudeUserAppx
    Remove-ClaudeProvisioned

    # --- Step 2: Provision machine-wide from bundled MSIX ---
    Write-Log "Provisioning $msixPath machine-wide (all users, current and future)."
    Add-AppxProvisionedPackage -Online -PackagePath $msixPath -SkipLicense -Regions All | Out-Null

    # --- Step 3: Verify (same signal as Detect-ClaudeMSIX.ps1) ---
    $installed = Get-ClaudeProvisionedPackages
    if ($installed) {
        foreach ($pkg in $installed) {
            Write-Log "SUCCESS: Claude Desktop provisioned - $($pkg.DisplayName) $($pkg.Version) ($($pkg.PackageName))"
        }
        exit 0
    } else {
        Write-Log 'ERROR: Provisioning command completed but package not found afterward.'
        exit 1
    }

} catch {
    Write-Log "FATAL: $($_.Exception.Message)"
    exit 1
}
