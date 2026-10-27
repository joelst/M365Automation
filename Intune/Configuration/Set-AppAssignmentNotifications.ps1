<#
.SYNOPSIS
Finds app assignments set to "Show all toast notifications" and changes them to hide all
toasts or show only computer-restart toasts.

.DESCRIPTION
Win32 (including Enterprise App Catalog) and WinGet / Microsoft Store apps carry an
end-user notification setting on every include assignment: `showAll`, `showReboot`, or
`hideAll`. `showAll` is the Intune default and produces a toast for every download, install
and completion, which is noise for most required deployments.

This script reads every assigned app, lists each assignment whose `settings.notifications`
is `showAll`, then changes it to the value given by -Notifications. The type is detected from
the assignment settings rather than a hardcoded app-type list, so any app type that exposes
`notifications` is covered.

PATCH on a single assignment has been seen returning 400 Bad Request for Win32 apps, so each
app is updated the way the portal does it: POST /assign with the app's complete assignment set.
Every existing assignment -- exclusions and other intents included -- is resent exactly as
read, with only `notifications` changed on the showAll ones. Restart grace periods, install
deadlines, delivery optimization, auto-update settings and assignment filters are preserved.
A fresh read afterwards confirms intent, target, filter and all non-notification settings are
unchanged.

Assignments that come from a policy set (`source = policySets`) cannot be edited directly and
are listed separately; change them in the policy set instead. An app that has ANY policy-set
assignment is skipped entirely, because /assign would resend or drop that assignment.

.PARAMETER Notifications
The new value. `showReboot` (default) hides install toasts but still warns users before a
restart. `hideAll` suppresses every toast, including restart warnings.

.PARAMETER AppId
Limit the run to specific mobileApp IDs. Useful for testing the change on one app first.

.EXAMPLE
.\Set-AppAssignmentNotifications.ps1 -WhatIf
Lists every showAll assignment and what would change, without changing anything.

.EXAMPLE
.\Set-AppAssignmentNotifications.ps1 -AppId 00000000-0000-0000-0000-000000000000

.EXAMPLE
.\Set-AppAssignmentNotifications.ps1 -Notifications hideAll -Confirm:$false

.NOTES
Each change is a POST to /deviceAppManagement/mobileApps/{id}/assign, confirmed once per app.
To revert, set the assignment back to "Show all toast notifications" in the portal.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('showReboot', 'hideAll')]
    [string] $Notifications = 'showReboot',

    [string[]] $AppId
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

function Get-TargetLabel {
    param($Target)
    $t = "$($Target.'@odata.type')" -replace '#microsoft.graph.|AssignmentTarget', ''
    if ($Target.PSObject.Properties['groupId'] -and $Target.groupId) { $t = "group:$(Get-GroupName $Target.groupId)" }
    if ($Target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId'] -and $Target.deviceAndAppManagementAssignmentFilterId) {
        $t += " (filter:$($Target.deviceAndAppManagementAssignmentFilterType))"
    }
    $t
}

function Get-ShowAllAssignments {
    param([string] $Id)
    $asg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$Id/assignments" -OutputType PSObject).value)
    # Exclusion targets have no settings; only include assignments carry notifications.
    @($asg | Where-Object {
            $_.PSObject.Properties['settings'] -and $_.settings -and
            $_.settings.PSObject.Properties['notifications'] -and $_.settings.notifications -eq 'showAll'
        })
}

# --- gather -------------------------------------------------------------------------
$apps = @()
$uri = "$graph/deviceAppManagement/mobileApps?`$select=id,displayName,isAssigned"
while ($uri) {
    $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $apps += @($page.value)
    $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
}
if ($AppId) { $apps = @($apps | Where-Object { $_.id -in $AppId }) }
$apps = @($apps | Where-Object { $_.isAssigned })
Write-Host ("Checking assignments on {0} assigned app(s)..." -f $apps.Count)

$plan = @()
$policySet = @()
foreach ($a in $apps) {
    foreach ($x in (Get-ShowAllAssignments $a.id)) {
        $row = [pscustomobject]@{
            App          = $a.displayName
            AppId        = $a.id
            Type         = ("$($x.settings.'@odata.type')" -replace '#microsoft.graph.|AssignmentSettings', '')
            Intent       = $x.intent
            Target       = Get-TargetLabel $x.target
            Assignment   = $x
            AssignmentId = $x.id
        }
        if ($x.PSObject.Properties['source'] -and $x.source -eq 'policySets') { $policySet += $row }
        else { $plan += $row }
    }
}

if ($policySet.Count) {
    Write-Host "`n=== SHOW ALL, FROM A POLICY SET (not changed -- edit the policy set) ===" -ForegroundColor Yellow
    $policySet | Sort-Object App, Intent | Format-Table App, Type, Intent, Target -AutoSize | Out-String -Width 200 | Write-Host
}

if (-not $plan.Count) { Write-Host "`nNo directly assigned apps are set to show all toast notifications."; return }

Write-Host "`n=== ASSIGNMENTS SET TO SHOW ALL TOAST NOTIFICATIONS -> $Notifications ==="
$plan | Sort-Object App, Intent | Format-Table App, Type, Intent, Target -AutoSize | Out-String -Width 200 | Write-Host
Write-Host ("Total: {0} assignment(s) across {1} app(s)" -f $plan.Count, (@($plan.AppId | Sort-Object -Unique)).Count)

# --- update -------------------------------------------------------------------------
# PATCH on a single assignment has been seen returning 400, so do what the portal does:
# POST /assign with the app's COMPLETE assignment set. /assign replaces everything, so every
# existing assignment (exclusions and untouched intents included) is resent as read, with only
# showAll -> $Notifications changed.
# The key covers everything /assign could silently drop: target, filter, and every setting
# other than notifications (restart, install deadline, auto-update, DO priority).
function Get-AssignmentKey {
    param($Assignment)
    $t = $Assignment.target
    $gid = if ($t.PSObject.Properties['groupId']) { $t.groupId } else { '' }
    $fid = if ($t.PSObject.Properties['deviceAndAppManagementAssignmentFilterId']) { $t.deviceAndAppManagementAssignmentFilterId } else { '' }
    $ftype = if ($t.PSObject.Properties['deviceAndAppManagementAssignmentFilterType']) { $t.deviceAndAppManagementAssignmentFilterType } else { '' }
    $settings = ''
    if ($Assignment.PSObject.Properties['settings'] -and $Assignment.settings) {
        $s = [ordered]@{}
        foreach ($prop in ($Assignment.settings.PSObject.Properties | Sort-Object Name)) {
            if ($prop.Name -ne 'notifications') { $s[$prop.Name] = $prop.Value }
        }
        $settings = $s | ConvertTo-Json -Depth 10 -Compress
    }
    "$($Assignment.intent)|$($t.'@odata.type')|$gid|$fid|$ftype|$settings"
}

$updated = 0
$failed = 0
$skipped = 0
$before = @{}
$failures = @()
foreach ($id in ($plan.AppId | Sort-Object -Unique)) {
    $rows = @($plan | Where-Object AppId -eq $id)
    $name = $rows[0].App
    $current = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$id/assignments" -OutputType PSObject).value)

    # /assign would resend or drop policy-set assignments -- leave those apps for manual handling.
    if (@($current | Where-Object { $_.PSObject.Properties['source'] -and $_.source -eq 'policySets' }).Count) {
        $skipped++
        Write-Host ("  SKIPPED: {0} -- also has policy-set assignments; change it in the portal" -f $name) -ForegroundColor Yellow
        continue
    }

    $label = "$name ($($rows.Count) of $($current.Count) assignment(s): $(($rows | ForEach-Object { "$($_.Intent)->$($_.Target)" }) -join ', '))"
    if (-not $PSCmdlet.ShouldProcess($label, "Set notifications showAll -> $Notifications")) { continue }

    $assignments = foreach ($x in $current) {
        $settings = $null
        if ($x.PSObject.Properties['settings'] -and $x.settings) {
            $settings = [ordered]@{}
            foreach ($prop in $x.settings.PSObject.Properties) { $settings[$prop.Name] = $prop.Value }
            if ($settings.Contains('notifications') -and $settings['notifications'] -eq 'showAll') { $settings['notifications'] = $Notifications }
        }
        [ordered]@{
            '@odata.type' = '#microsoft.graph.mobileAppAssignment'
            id            = $x.id
            intent        = $x.intent
            target        = $x.target
            settings      = $settings
        }
    }
    $body = @{ mobileAppAssignments = @($assignments) } | ConvertTo-Json -Depth 10

    # Intune throttles /assign with 429 ThrottledByDownstreamService and RetryAfter 00:00:00, so
    # the SDK's own retries fire instantly and all fail. Back off on our own schedule instead.
    $delays = 15, 30, 60, 120
    for ($attempt = 0; ; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/mobileApps/$id/assign" -Body $body -ContentType 'application/json' | Out-Null
            $before[$id] = @($current | ForEach-Object { Get-AssignmentKey $_ } | Sort-Object)
            $updated++
            Write-Host ("  updated: {0}" -f $name) -ForegroundColor Green
            break
        }
        catch {
            $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            if ($detail -match 'TooManyRequests|ThrottledByDownstreamService|ServiceUnavailable' -and $attempt -lt $delays.Count) {
                Write-Host ("  throttled: {0} -- waiting {1}s (retry {2} of {3})" -f $name, $delays[$attempt], ($attempt + 1), $delays.Count) -ForegroundColor Yellow
                Start-Sleep -Seconds $delays[$attempt]
                continue
            }
            $failed++
            $code = if ($detail -match '"code"\s*:\s*"([^"]+)"') { $Matches[1] } else { ($detail -split "`n")[0] }
            $failures += [pscustomobject]@{ App = $name; AppId = $id; Error = $code }
            Write-Host ("  FAILED : {0} -- {1}" -f $name, $detail) -ForegroundColor Red
            break
        }
    }
    Start-Sleep -Seconds 2   # pace /assign calls so a full-tenant run doesn't trip the throttle
}

if (-not $PSCmdlet.ShouldProcess('tenant', 'verify')) { Write-Host "`nDry run -- nothing was changed."; return }

# --- verify by fresh read -----------------------------------------------------------
Write-Host "`nVerifying against a fresh read..."
$left = 0
$drift = 0
foreach ($id in $before.Keys) {
    $now = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$id/assignments" -OutputType PSObject).value)
    $remaining = @(Get-ShowAllAssignments $id)
    $same = ($now.Count -eq $before[$id].Count) -and
        -not (Compare-Object $before[$id] @($now | ForEach-Object { Get-AssignmentKey $_ } | Sort-Object))
    $name = ($plan | Where-Object AppId -eq $id | Select-Object -First 1).App
    $color = if ($same -and -not $remaining.Count) { 'Gray' } else { 'Red' }
    Write-Host ("  {0,-40} assignments {1} -> {2}{3}, showAll remaining: {4}" -f $name, $before[$id].Count, $now.Count, $(if ($same) { '' } else { ' (ASSIGNMENTS DRIFTED)' }), $remaining.Count) -ForegroundColor $color
    $left += $remaining.Count
    if (-not $same) { $drift++ }
}

Write-Host ""
Write-Host "Updated : $updated app(s)"
Write-Host "Skipped : $skipped app(s) with policy-set assignments"
Write-Host "Failed  : $failed app(s)"
Write-Host "Remaining showAll assignments on updated apps: $left (expect 0)"
Write-Host "Apps whose targets, filters or other settings changed: $drift (expect 0)"

if ($failures.Count) {
    Write-Host "`n=== FAILED (re-run to retry; only remaining showAll assignments are picked up) ===" -ForegroundColor Red
    $failures | Format-Table App, AppId, Error -AutoSize | Out-String -Width 200 | Write-Host
}
