
<# 
Remediate: Remove Brother/Xerox printer companion Store apps by PFN
- Removes installed appx for all users
- Removes provisioned packages from the image
- Writes clear output and returns 0 on success, 1 if any remain
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$WhatIf
)

$ErrorActionPreference = 'Continue'

$TargetPfns = @(
    'C2258428.Brother.PrintSupportApp_m06mxaavvcjkt',
    'XeroxCorp.PrintExperience_f7egpvdyrs2a8'
)
$PfnRoots = $TargetPfns | ForEach-Object { ($_ -split '_')[0] }

function Get-InstalledByPFN {
    Get-AppxPackage -AllUsers |
        Where-Object { $TargetPfns -contains $_.PackageFamilyName }
}

function Get-ProvisionedByRoot {
    Get-AppxProvisionedPackage -Online |
        Where-Object { 
            $d = $_.DisplayName
            $PfnRoots | ForEach-Object { if ($d -match [Regex]::Escape($_)) { $true } }
        }
}

# --- Remove installed (all users) ---
$installed = Get-InstalledByPFN
if ($installed -and $installed.Count -gt 0) {
    Write-Output "Removing installed packages:"
    $installed | Select-Object Name, PackageFamilyName, Publisher, Version |
        Format-Table -AutoSize | Out-String | Write-Output

    foreach ($pkg in $installed) {
        try {
            $msg = "Remove-AppxPackage -AllUsers: $($pkg.Name) ($($pkg.PackageFullName))"
            Write-Output $msg
            if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Remove-AppxPackage -AllUsers')) {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            }
        }
        catch {
            Write-Output "[WARN] Failed to remove installed $($pkg.PackageFamilyName): $($_.Exception.Message)"
        }
    }
} else {
    Write-Output "No installed targeted PFNs found."
}

# --- Remove provisioned (online image) ---
$prov = Get-ProvisionedByRoot
if ($prov -and $prov.Count -gt 0) {
    Write-Output "Removing provisioned packages:"
    $prov | Select-Object DisplayName, PackageName, Version |
        Format-Table -AutoSize | Out-String | Write-Output

    foreach ($p in $prov) {
        try {
            $msg = "Remove-AppxProvisionedPackage -Online: $($p.DisplayName) ($($p.PackageName))"
            Write-Output $msg
            if ($PSCmdlet.ShouldProcess($p.PackageName, 'Remove-AppxProvisionedPackage -Online')) {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Output "[WARN] Failed to remove provisioned $($p.DisplayName): $($_.Exception.Message)"
        }
    }
} else {
    Write-Output "No provisioned targeted PFNs found."
}

# --- Re-check to confirm removal ---
$remainingInstalled   = Get-InstalledByPFN
$remainingProvisioned = Get-ProvisionedByRoot

if (($remainingInstalled -and $remainingInstalled.Count) -or ($remainingProvisioned -and $remainingProvisioned.Count)) {
    Write-Output "[RESULT] Some targeted PFNs remain:"
    if ($remainingInstalled) {
        $remainingInstalled | Select-Object Name, PackageFamilyName |
            Format-Table -AutoSize | Out-String | Write-Output
    }
    if ($remainingProvisioned) {
        $remainingProvisioned | Select-Object DisplayName, PackageName |
            Format-Table -AutoSize | Out-String | Write-Output
    }
    exit 1
}
else {
    Write-Output "[RESULT] Remediation succeeded. No targeted PFNs remain (installed or provisioned)."
    exit 0
}