<#
.SYNOPSIS
Removes assignments from iOS App Store app records that are superseded by a VPP record.

.DESCRIPTION
Where the same bundle ID exists twice in Intune -- once as an `iosVppApp` and once as an
`iosStoreApp` -- and both carry required assignments, iOS gets two competing install
directives for one bundle. The store record also cannot install at all on a supervised ADE
device, because non-VPP store apps use user-based Apple ID licensing and ADE devices have no
Apple ID signed in.

This script unassigns the store record. It deliberately does NOT delete the app object, so
the change is reversible by re-adding assignments.

Only pass bundles where the VPP record already covers the store record's REQUIRED targets.
Where the store record reaches more than the VPP record (a broader required target, or no VPP
record at all), leave it out: removing it would reduce coverage rather than clean it up.

.PARAMETER BundleId
Bundle IDs to clean up. Review each against the rule above first.

.EXAMPLE
.\Remove-DuplicateIosStoreAppAssignments.ps1 -BundleId com.microsoft.scmx -WhatIf

.EXAMPLE
.\Remove-DuplicateIosStoreAppAssignments.ps1 -BundleId com.microsoft.scmx, com.microsoft.skydrive

.NOTES
Read the plan output before confirming. Each removal is a DELETE against
/deviceAppManagement/mobileApps/{id}/assignments/{assignmentId}.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string[]] $BundleId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'Group.Read.All' -NoWelcome | Out-Null

$groupNameCache = @{}
function Get-GroupName {
    param([string] $Id)
    if (-not $groupNameCache.ContainsKey($Id)) {
        try { $groupNameCache[$Id] = (Invoke-MgGraphRequest -Method GET -Uri "$graph/groups/$Id`?`$select=displayName" -OutputType PSObject).displayName }
        catch { $groupNameCache[$Id] = "(group $Id)" }
    }
    $groupNameCache[$Id]
}

# --- gather -------------------------------------------------------------------------
$all = (Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps?`$select=id,displayName" -OutputType PSObject).value
$records = @()
foreach ($a in $all) {
    $f = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)" -OutputType PSObject
    $type = "$($f.'@odata.type')"
    if ($type -notmatch 'iosVppApp|iosStoreApp') { continue }
    $bid = if ($f.PSObject.Properties['bundleId']) { "$($f.bundleId)" } else { '' }
    if (-not $bid -or $bid -notin $BundleId) { continue }
    $records += [pscustomobject]@{
        Bundle = $bid
        Name   = $f.displayName
        Type   = ($type -replace '#microsoft.graph.', '')
        Id     = $a.id
    }
}

$plan = @()
foreach ($b in ($records.Bundle | Sort-Object -Unique)) {
    $vpp = @($records | Where-Object { $_.Bundle -eq $b -and $_.Type -eq 'iosVppApp' })
    $store = @($records | Where-Object { $_.Bundle -eq $b -and $_.Type -eq 'iosStoreApp' })

    if (-not $vpp.Count) { Write-Warning "$b -- no VPP record found; skipping so nothing is left uncovered."; continue }
    if (-not $store.Count) { Write-Host "$b -- no store record; nothing to do."; continue }

    foreach ($s in $store) {
        $asg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($s.Id)/assignments" -OutputType PSObject).value)
        foreach ($x in $asg) {
            $t = "$($x.target.'@odata.type')" -replace '#microsoft.graph.|AssignmentTarget', ''
            if ($x.target.PSObject.Properties['groupId'] -and $x.target.groupId) { $t = "group:$(Get-GroupName $x.target.groupId)" }
            $plan += [pscustomobject]@{
                Bundle = $b; App = $s.Name; AppId = $s.Id
                Intent = $x.intent; Target = $t; AssignmentId = $x.id
            }
        }
    }
}

if (-not $plan.Count) { Write-Host "`nNothing to remove."; return }

Write-Host "=== ASSIGNMENTS TO REMOVE (iosStoreApp records only) ==="
$plan | Sort-Object Bundle, Intent | Format-Table Bundle, App, Intent, Target -AutoSize | Out-String -Width 200 | Write-Host
Write-Host ("Total: {0} assignment(s) across {1} store record(s)" -f $plan.Count, (@($plan.AppId | Sort-Object -Unique)).Count)

# --- remove -------------------------------------------------------------------------
$removed = 0
$failed = 0
foreach ($p in $plan) {
    $label = "$($p.App) [$($p.Intent) -> $($p.Target)]"
    if (-not $PSCmdlet.ShouldProcess($label, 'Remove assignment')) { continue }
    try {
        Invoke-MgGraphRequest -Method DELETE -Uri "$graph/deviceAppManagement/mobileApps/$($p.AppId)/assignments/$($p.AssignmentId)" | Out-Null
        $removed++
        Write-Host ("  removed: {0}" -f $label) -ForegroundColor Green
    }
    catch {
        $failed++
        Write-Host ("  FAILED : {0} -- {1}" -f $label, $_.Exception.Message) -ForegroundColor Red
    }
}

if (-not $PSCmdlet.ShouldProcess('tenant', 'verify')) { Write-Host "`nDry run -- nothing was changed."; return }

# --- verify by fresh read -----------------------------------------------------------
Write-Host "`nVerifying against a fresh read..."
$left = 0
foreach ($appId in ($plan.AppId | Sort-Object -Unique)) {
    $asg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$appId/assignments" -OutputType PSObject).value)
    $name = ($plan | Where-Object AppId -eq $appId | Select-Object -First 1).App
    Write-Host ("  {0,-34} assignments remaining: {1}" -f $name, $asg.Count)
    $left += $asg.Count
}

Write-Host ""
Write-Host "Removed : $removed"
Write-Host "Failed  : $failed"
Write-Host "Remaining assignments on those store records: $left (expect 0)"
