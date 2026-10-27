<#
.SYNOPSIS
Repoints iOS app configuration policies that target an app record with no assignments.

.DESCRIPTION
An app configuration policy delivers settings for the app record listed in targetedMobileApps.
If that record has no assignments the app is not deployed from it, and the configuration has
nothing to attach to -- the policy looks healthy in the portal but does nothing.

This became live when duplicate iosStoreApp records were unassigned in favour of their
iosVppApp twins: any app config still pointing at the store record was silently orphaned.

For each iOS app configuration policy the script resolves every targeted app, and where a
targeted app has zero assignments but another record with the SAME bundle id does have
assignments, it repoints the policy at the deployed record.

Only targetedMobileApps is changed. Settings, assignments and everything else are untouched.

.EXAMPLE
.\Repair-IosAppConfigTargets.ps1 -WhatIf

.EXAMPLE
.\Repair-IosAppConfigTargets.ps1 -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All' -NoWelcome | Out-Null

# --- index every iOS app record: id -> bundle, type, assignment count ----------------
Write-Host 'Indexing iOS app records...'
$index = @{}
foreach ($a in (Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps?`$select=id,displayName" -OutputType PSObject).value) {
    $f = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)" -OutputType PSObject
    if ("$($f.'@odata.type')" -notmatch 'ios') { continue }
    $bid = if ($f.PSObject.Properties['bundleId']) { "$($f.bundleId)" } else { '' }
    $asg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)/assignments" -OutputType PSObject).value)
    $index[$a.id] = [pscustomobject]@{
        Id = $a.id; Name = $f.displayName; Bundle = $bid
        Type = ("$($f.'@odata.type')" -replace '#microsoft.graph.', ''); Assignments = $asg.Count
    }
}
Write-Host "  indexed $($index.Count) iOS app record(s)"

# --- examine each app configuration policy -------------------------------------------
$fixes = @()
foreach ($c in @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations" -OutputType PSObject).value)) {
    $full = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)" -OutputType PSObject
    $cfgAsg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)/assignments" -OutputType PSObject).value)

    Write-Host ''
    Write-Host ("--- {0}   (config assignments: {1})" -f $full.displayName, $cfgAsg.Count)

    $current = @($full.targetedMobileApps)
    $desired = @()
    $changed = $false

    foreach ($aid in $current) {
        if (-not $index.ContainsKey($aid)) {
            Write-Host ("    {0}  <<< app record not found; leaving as-is" -f $aid) -ForegroundColor Yellow
            $desired += $aid; continue
        }
        $app = $index[$aid]
        if ($app.Assignments -gt 0) {
            Write-Host ("    OK   {0} [{1}] assignments={2}" -f $app.Name, $app.Type, $app.Assignments)
            $desired += $aid; continue
        }

        # Targeted app is not deployed -- look for a deployed sibling on the same bundle.
        $alt = @($index.Values | Where-Object { $_.Bundle -and $_.Bundle -eq $app.Bundle -and $_.Id -ne $app.Id -and $_.Assignments -gt 0 })
        if ($alt.Count -eq 1) {
            Write-Host ("    FIX  {0} [{1}] has 0 assignments" -f $app.Name, $app.Type) -ForegroundColor Yellow
            Write-Host ("         -> repoint to {0} [{1}] assignments={2}" -f $alt[0].Name, $alt[0].Type, $alt[0].Assignments) -ForegroundColor Green
            $desired += $alt[0].Id; $changed = $true
        }
        elseif ($alt.Count -gt 1) {
            Write-Host ("    AMBIGUOUS  {0} has 0 assignments; {1} deployed records share bundle {2}. Leaving as-is." -f $app.Name, $alt.Count, $app.Bundle) -ForegroundColor Red
            $desired += $aid
        }
        else {
            Write-Host ("    ORPHAN  {0} [{1}] has 0 assignments and no deployed sibling for bundle {2}." -f $app.Name, $app.Type, $app.Bundle) -ForegroundColor Red
            $desired += $aid
        }
    }

    if ($changed) { $fixes += [pscustomobject]@{ Id = $c.id; Name = $full.displayName; Targets = $desired } }
}

if (-not $fixes.Count) { Write-Host "`nNothing to repair."; return }

Write-Host ''
foreach ($fx in $fixes) {
    if (-not $PSCmdlet.ShouldProcess($fx.Name, 'Repoint targetedMobileApps')) { continue }
    $body = @{ '@odata.type' = '#microsoft.graph.iosMobileAppConfiguration'; targetedMobileApps = @($fx.Targets) } | ConvertTo-Json -Depth 6
    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($fx.Id)" -Body $body -ContentType 'application/json' | Out-Null
        Write-Host ("  repointed {0}" -f $fx.Name) -ForegroundColor Green
    }
    catch { Write-Host ("  FAILED {0} -- {1}" -f $fx.Name, $_.Exception.Message) -ForegroundColor Red }
}

if (-not $PSCmdlet.ShouldProcess('tenant', 'verify')) { Write-Host "`nDry run -- nothing was changed."; return }

Write-Host "`nVerifying against a fresh read..."
foreach ($fx in $fixes) {
    $after = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($fx.Id)" -OutputType PSObject
    foreach ($aid in @($after.targetedMobileApps)) {
        $app = if ($index.ContainsKey($aid)) { $index[$aid] } else { $null }
        $desc = if ($app) { "$($app.Name) [$($app.Type)] assignments=$($app.Assignments)" } else { $aid }
        Write-Host ("  {0}: {1}" -f $after.displayName, $desc)
    }
}
