<#
.SYNOPSIS
Removes one or more apps from the iOS app protection (MAM) policy.

.DESCRIPTION
Removing an app from the app protection policy stops MAM data-protection controls applying to
it -- the app keeps working and stays deployed, it just no longer participates in the managed
data boundary. Org data can then move into it freely from unmanaged sources, and it is no longer
subject to the PIN, save-as block or transfer restrictions.

Apps are matched by bundle id, exactly, so a partial name cannot remove the wrong app.

.PARAMETER BundleId
One or more bundle ids to remove, e.g. com.microsoft.msapps.

.PARAMETER PolicyId
iosManagedAppProtection id. Defaults to the tenant's single policy.

.EXAMPLE
.\Remove-IosAppProtectionApp.ps1 -BundleId com.microsoft.msapps -WhatIf

.EXAMPLE
.\Remove-IosAppProtectionApp.ps1 -BundleId com.microsoft.msapps -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string[]] $BundleId,

    [string] $PolicyId,

    # Exact display name, when more than one iOS app protection policy exists.
    [string] $PolicyName,

    # Apply to every iOS app protection policy. Use this to keep a production policy and its
    # PILOT clone from drifting -- removing an app from only one of them is how they diverge.
    [switch] $AllPolicies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All' -NoWelcome | Out-Null

$all = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections?`$select=id,displayName" -OutputType PSObject).value)
$targetPolicies = @()

if ($PolicyId) {
    $targetPolicies = @($all | Where-Object { $_.id -eq $PolicyId })
    if (-not $targetPolicies.Count) { throw "No iOS app protection policy with id '$PolicyId'." }
}
elseif ($PolicyName) {
    $targetPolicies = @($all | Where-Object { $_.displayName -eq $PolicyName })
    if ($targetPolicies.Count -ne 1) { throw "Expected exactly one policy named '$PolicyName', found $($targetPolicies.Count)." }
}
elseif ($AllPolicies) { $targetPolicies = $all }
elseif ($all.Count -eq 1) { $targetPolicies = $all }
else {
    $list = ($all | ForEach-Object { "    $($_.displayName)`n      id: $($_.id)" }) -join "`n"
    throw "Found $($all.Count) iOS app protection policies. Pick one with -PolicyName or -PolicyId, or pass -AllPolicies to do all of them:`n$list"
}

Write-Host "Policies in scope: $($targetPolicies.Count)"
$removedTotal = 0; $failedTotal = 0

foreach ($pol in $targetPolicies) {

$PolicyId = $pol.id
$before = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId`?`$expand=apps" -OutputType PSObject
$apps = @($before.apps)
Write-Host ""
Write-Host "=============================================================="
Write-Host "Policy: $($before.displayName)"
Write-Host "  targets $($apps.Count) app(s)"
Write-Host ""

$toRemove = @()
foreach ($b in $BundleId) {
    $hit = @($apps | Where-Object { "$($_.mobileAppIdentifier.bundleId)" -eq $b })
    if (-not $hit.Count) { Write-Warning "Bundle '$b' is not targeted by this policy; nothing to remove."; continue }
    foreach ($h in $hit) {
        Write-Host ("  REMOVE  {0}   (entry id {1})" -f $b, $h.id) -ForegroundColor Yellow
        $toRemove += $h
    }
}

if (-not $toRemove.Count) { Write-Host "  Nothing to remove from this policy."; continue }

Write-Host ""
Write-Host "Remaining after removal: $($apps.Count - $toRemove.Count) app(s)"
Write-Host ""

$removed = 0; $failed = 0
foreach ($r in $toRemove) {
    $b = "$($r.mobileAppIdentifier.bundleId)"
    if (-not $PSCmdlet.ShouldProcess("$($before.displayName)", "Remove $b from app protection")) { continue }
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId/apps/$($r.id)" | Out-Null
        $removed++
        Write-Host ("  removed {0}" -f $b) -ForegroundColor Green
    }
    catch {
        $failed++
        Write-Host ("  FAILED {0} -- {1}" -f $b, $_.Exception.Message) -ForegroundColor Red
    }
}

$removedTotal += $removed; $failedTotal += $failed

if (-not $PSCmdlet.ShouldProcess('tenant', 'verify')) { continue }

Write-Host "  verifying against a fresh read..."
$after = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId`?`$expand=apps" -OutputType PSObject
$remaining = @($after.apps)
Write-Host ("  policy now targets {0} app(s)  (was {1})" -f $remaining.Count, $apps.Count)
foreach ($b in $BundleId) {
    $still = @($remaining | Where-Object { "$($_.mobileAppIdentifier.bundleId)" -eq $b })
    Write-Host ("  {0,-42} {1}" -f $b, $(if ($still.Count) { 'STILL PRESENT' } else { 'removed' }))
}

}  # end foreach policy

Write-Host ""
if (-not $PSCmdlet.ShouldProcess('tenant', 'summary')) { Write-Host 'Dry run -- nothing was changed.'; return }
Write-Host "Removed: $removedTotal   Failed: $failedTotal   across $($targetPolicies.Count) policy/policies"
