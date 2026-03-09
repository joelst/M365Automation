
<# 
Detect: Brother/Xerox printer companion Store apps by PFN
- Exit 1 if found (trigger remediation), else Exit 0
#>

[CmdletBinding()]
param()

$TargetPfns = @(
    'C2258428.Brother.PrintSupportApp_m06mxaavvcjkt',
    'XeroxCorp.PrintExperience_f7egpvdyrs2a8'
)

function Get-InstalledByPFN {
    Get-AppxPackage -AllUsers |
        Where-Object { $TargetPfns -contains $_.PackageFamilyName }
}

function Get-ProvisionedByPFN {
    # Provisioned entries don’t expose PFN directly; match by DisplayName contains the PFN root (before the underscore)
    $roots = $TargetPfns | ForEach-Object { ($_ -split '_')[0] }
    Get-AppxProvisionedPackage -Online |
        Where-Object { 
            $d = $_.DisplayName
            $roots | ForEach-Object { if ($d -match [Regex]::Escape($_)) { $true } }
        }
}

$installed  = Get-InstalledByPFN
$provisioned = Get-ProvisionedByPFN

if (($installed -and $installed.Count -gt 0) -or ($provisioned -and $provisioned.Count -gt 0)) {
    Write-Output "Detected PFN-targeted apps:"
    if ($installed) {
        $installed | Select-Object Name, PackageFamilyName, Publisher, Version |
            Format-Table -AutoSize | Out-String | Write-Output
    }
    if ($provisioned) {
        $provisioned | Select-Object DisplayName, PackageName, Version |
            Format-Table -AutoSize | Out-String | Write-Output
    }
    exit 1
} else {
    Write-Output "No targeted PFNs detected (installed or provisioned)."
    exit 0
}
