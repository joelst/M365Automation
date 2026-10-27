<#
.SYNOPSIS
Applies a Managed apps assignment filter to the iOS app protection policy, so the policy (and
its app PIN) reaches only unmanaged / BYOD devices.

.DESCRIPTION
App protection policies target a user identity, so by default they apply to that user's enrolled
AND unenrolled devices. Scoping the assignment with a Managed apps filter in Include mode limits
it to devices matching the filter -- the supported way to run MAM for BYOD while leaving
corporate ADE devices to MDM controls.

This avoids needing IntuneMAMUPN app configuration policies purely to stop the app PIN appearing
on corporate devices, because the policy never applies to them at all.

TRADE-OFF: corporate devices also stop receiving the MAM data-protection controls (saveAsBlocked,
outbound transfer restrictions). On supervised ADE devices those are largely covered by device
restrictions, but it is a deliberate reduction -- make sure that is the intent.

The filter itself must already exist. Create it under
Tenant administration > Assignment filters > Create > Managed apps, platform iOS/iPadOS.

The rule for unmanaged / BYOD devices is:

    (app.deviceManagementType -eq "Unmanaged")

Note that Graph cannot be used to discover this. deviceManagement/assignmentFilters/
getPlatformSupportedProperties(platform='iOS') returns the MANAGED DEVICES property set --
whose deviceManagementType values are Managed, Automated Device Enrollment user-associated
devices, Automated Device Enrollment userless devices, Account Driven User Enrollment and
Device Enrollment with Company Portal and Web Enrollment. "Unmanaged" does not appear there,
and the assignmentFilterManagementType='apps' variant of that call returns 400 on beta. The
apps-scoped value set is only visible in the portal rule builder.

Verifying the rule matches the right things: compare the filter preview against
deviceAppManagement/managedAppRegistrations. Registrations with no managedDeviceId are the
unmanaged ones. A good tell is any app you deploy only to enrolled devices -- Microsoft Defender
(com.microsoft.scmx) often fits -- so if it appears in the preview the rule is matching managed
devices and is wrong.

.PARAMETER FilterName
Display name of an existing Managed apps (iOS) assignment filter.

.PARAMETER FilterType
include (default) or exclude.

.EXAMPLE
.\Set-IosAppProtectionFilter.ps1 -FilterName 'iOS unmanaged apps' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $FilterName,

    [ValidateSet('include', 'exclude')]
    [string] $FilterType = 'include'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'DeviceManagementConfiguration.Read.All', 'Group.Read.All' -NoWelcome | Out-Null

# --- resolve the filter, and insist it is the right kind -----------------------------
$filters = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/assignmentFilters" -OutputType PSObject).value)
$f = @($filters | Where-Object { $_.displayName -eq $FilterName })
if ($f.Count -ne 1) { throw "Expected exactly one assignment filter named '$FilterName', found $($f.Count)." }
$f = $f[0]

Write-Host "Filter : $($f.displayName)"
Write-Host "   id            : $($f.id)"
Write-Host "   platform      : $($f.platform)"
Write-Host "   managementType: $($f.assignmentFilterManagementType)"
Write-Host "   rule          : $($f.rule)"

if ("$($f.assignmentFilterManagementType)" -ne 'apps') {
    throw "Filter '$FilterName' is managementType '$($f.assignmentFilterManagementType)'. App protection policies require a 'Managed apps' filter; a Managed devices filter will not apply."
}
if ("$($f.platform)" -notmatch '(?i)ios') {
    throw "Filter '$FilterName' is platform '$($f.platform)', expected iOS/iPadOS."
}

# --- the app protection policy and its current assignments ---------------------------
$pol = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections?`$select=id,displayName" -OutputType PSObject).value)
if ($pol.Count -ne 1) { throw "Expected exactly one iOS app protection policy, found $($pol.Count)." }
$pol = $pol[0]

$full = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$($pol.id)?`$expand=assignments" -OutputType PSObject
$current = @($full.assignments)
Write-Host ""
Write-Host "Policy : $($full.displayName)"
foreach ($a in $current) {
    $t = "$($a.target.'@odata.type')" -replace '#microsoft.graph.|AssignmentTarget', ''
    $gid = if ($a.target.PSObject.Properties['groupId']) { " groupId=$($a.target.groupId)" } else { '' }
    $cf = if ($a.target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId'] -and $a.target.deviceAndAppManagementAssignmentFilterId) {
        " filter=$($a.target.deviceAndAppManagementAssignmentFilterType)"
    } else { ' no filter' }
    Write-Host ("   current: {0}{1}{2}" -f $t, $gid, $cf)
}
if (-not $current.Count) { throw 'The app protection policy has no assignments; nothing to filter.' }

# --- rebuild every assignment, adding the filter -------------------------------------
$rebuilt = @()
foreach ($a in $current) {
    $target = @{ '@odata.type' = "$($a.target.'@odata.type')" }
    if ($a.target.PSObject.Properties['groupId'] -and $a.target.groupId) { $target['groupId'] = $a.target.groupId }
    $target['deviceAndAppManagementAssignmentFilterId'] = $f.id
    $target['deviceAndAppManagementAssignmentFilterType'] = $FilterType
    $rebuilt += @{ target = $target }
}

Write-Host ""
Write-Host "Will set filter '$FilterName' in $FilterType mode on $($rebuilt.Count) assignment(s)."
if (-not $PSCmdlet.ShouldProcess($full.displayName, "Apply filter '$FilterName' ($FilterType)")) { Write-Host "`nDry run -- nothing was changed."; return }

Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$($pol.id)/assign" `
    -Body (@{ assignments = $rebuilt } | ConvertTo-Json -Depth 8) -ContentType 'application/json' | Out-Null
Write-Host "Applied." -ForegroundColor Green

# --- verify ---------------------------------------------------------------------------
Write-Host "`nVerifying against a fresh read..."
$after = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$($pol.id)?`$expand=assignments" -OutputType PSObject
$okCount = 0
foreach ($a in @($after.assignments)) {
    $fid = if ($a.target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId']) { "$($a.target.deviceAndAppManagementAssignmentFilterId)" } else { '' }
    $ft = if ($a.target.PSObject.Properties['deviceAndAppManagementAssignmentFilterType']) { "$($a.target.deviceAndAppManagementAssignmentFilterType)" } else { '' }
    if ($fid -eq $f.id -and $ft -eq $FilterType) { $okCount++ }
    Write-Host ("   filterId={0}  mode={1}" -f $(if ($fid) { $fid } else { '(none)' }), $(if ($ft) { $ft } else { '(none)' }))
}
Write-Host ""
if ($okCount -eq @($after.assignments).Count) { Write-Host "All $okCount assignment(s) carry the filter." -ForegroundColor Green }
else { Write-Host "Only $okCount of $(@($after.assignments).Count) assignment(s) carry the filter." -ForegroundColor Yellow }

Write-Host ""
Write-Host "NEXT: confirm in the portal that the filter previews the devices you expect before enabling the PIN." -ForegroundColor Yellow
Write-Host "      A filter that matches nothing silently applies the policy to nobody." -ForegroundColor Yellow
