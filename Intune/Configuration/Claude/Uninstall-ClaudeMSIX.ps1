<#
.SYNOPSIS
    Intune Win32 app UNINSTALL script for Claude Desktop.

.DESCRIPTION
    Removes the machine-wide provisioned package, per-user AppX registrations,
    and leftover Squirrel (ClaudeSetup.exe) installs under user profiles.
    Run in SYSTEM context, paired with Install-ClaudeMSIX.ps1.
#>

$ErrorActionPreference = 'Stop'

$logDir  = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude'
$logFile = Join-Path $logDir 'Uninstall-ClaudeMSIX.log'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $Message
    Add-Content -Path $logFile -Value $line
    Write-Host $line
}

function Get-ClaudeProvisionedPackages {
    Get-AppxProvisionedPackage -Online | Where-Object {
        $_.DisplayName -eq 'Claude' -or
        $_.DisplayName -like '*Claude*' -or
        $_.PackageName -like 'Claude_*' -or
        $_.PackageName -like '*Anthropic*Claude*'
    }
}

try {
    Get-Process -Name 'Claude', 'Update' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    $pkgs = Get-ClaudeProvisionedPackages
    foreach ($pkg in $pkgs) {
        Write-Log "Removing provisioned package $($pkg.PackageName)"
        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -AllUsers | Out-Null
    }

    # Remove per-user registered instances so the app disappears without waiting for logoff
    $userPkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like '*Claude*' -or
        $_.Name -like '*Anthropic*' -or
        $_.PackageFullName -like '*Claude*'
    }
    foreach ($pkg in $userPkgs) {
        Write-Log "Removing per-user package $($pkg.PackageFullName)"
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
        } catch {
            # Fallback without -AllUsers for packages that reject it
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
            } catch {
                Write-Log "WARNING: could not remove $($pkg.PackageFullName) - $($_.Exception.Message)"
            }
        }
    }

    # Squirrel leftovers from self-service ClaudeSetup.exe
    Write-Log 'Checking for Squirrel leftovers under user profiles...'
    $userProfiles = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue
    foreach ($profile in $userProfiles) {
        $squirrelPath = Join-Path $profile.FullName 'AppData\Local\AnthropicClaude'
        if (-not (Test-Path $squirrelPath)) { continue }

        $updateExe = Join-Path $squirrelPath 'Update.exe'
        if (Test-Path $updateExe) {
            try {
                Start-Process -FilePath $updateExe -ArgumentList '--uninstall', '-s' -Wait -ErrorAction Stop | Out-Null
            } catch {
                Write-Log "WARNING: Update.exe uninstall for $($profile.Name) - $($_.Exception.Message)"
            }
        }
        try {
            Remove-Item -Path $squirrelPath -Recurse -Force -ErrorAction Stop
            Write-Log "Removed Squirrel path $squirrelPath"
        } catch {
            Write-Log "WARNING: could not remove $squirrelPath - $($_.Exception.Message)"
        }
    }

    Write-Log 'Uninstall complete.'
    exit 0
} catch {
    Write-Log "FATAL: $($_.Exception.Message)"
    exit 1
}
