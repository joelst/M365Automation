<#
.SYNOPSIS
    Intune Win32 app DETECTION script for Claude Desktop (machine-wide MSIX).

.DESCRIPTION
    Exit 0 with stdout = detected (any version machine-provisioned).
    Exit 1 = not detected.

    INTENTIONAL: does NOT treat winget-only or per-user AppX as installed.
    That forces a one-time migration to Add-AppxProvisionedPackage via the
    install script. After provisioning succeeds, this exits 0 every check-in
    so Intune does not re-run install (no detection/install loop).

    Use as a custom detection rule on the Claude Win32 app.
    Run as 32-bit process: No. Enforce script signature check: No.

    If you leave Claude auto-update enabled, users may run a newer per-user
    build than the provisioned baseline. This script still only checks the
    provisioned package so MDM reporting stays stable. Do not also run a
    winget install/upgrade app for Anthropic.Claude on the same devices.
#>

$ErrorActionPreference = 'SilentlyContinue'

$pkgs = Get-AppxProvisionedPackage -Online | Where-Object {
    $_.DisplayName -eq 'Claude' -or
    $_.DisplayName -like '*Claude*' -or
    $_.PackageName -like 'Claude_*' -or
    $_.PackageName -like '*Anthropic*Claude*'
}

if ($pkgs) {
    $summary = ($pkgs | ForEach-Object { '{0} {1}' -f $_.DisplayName, $_.Version }) -join '; '
    Write-Host "Detected (provisioned): $summary"
    exit 0
}

# Explicit non-detect for winget/user-only so operators reading IME logs understand
$userOnly = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -like '*Claude*' -or $_.PackageFullName -like '*Claude*'
}
if ($userOnly) {
    Write-Host 'Not detected: Claude AppX exists for user(s) but is not machine-provisioned (e.g. winget). Install will migrate.'
}

exit 1
