<#
.SYNOPSIS
Turns on the app PIN for the iOS App Protection (MAM) policy.

.DESCRIPTION
On an unenrolled personal device you cannot enforce a device passcode, so the app PIN is the
only access control standing in front of corporate mail and Teams data. Intune's own default
for 'PIN for access' is Require, so a policy with it set to False had it turned off
deliberately at some point.

This script sets only the PIN-related settings and leaves every other setting alone:

    pinRequired       False -> True
    minimumPinLength  4     -> 6      (configurable)
    simplePinBlocked  False -> True   (blocks 1234, 1111, abcd ...)

Touch ID / Face ID remain allowed, so the day-to-day experience is a biometric prompt rather
than typing a PIN -- the PIN is the fallback and the enrolment-free security floor.

.PARAMETER PolicyId
The iosManagedAppProtection id. Defaults to the tenant's single policy.

.PARAMETER MinimumPinLength
Minimum PIN digits. Intune default is 4; 6 is the common hardened value.

.PARAMETER AllowSimplePin
Leave simple sequences (1234, 1111) allowed. Not recommended.

.EXAMPLE
.\Set-IosAppProtectionPin.ps1 -WhatIf

.EXAMPLE
.\Set-IosAppProtectionPin.ps1 -MinimumPinLength 6
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $PolicyId,
    [ValidateRange(4, 16)]
    [int]    $MinimumPinLength = 6,
    [switch] $AllowSimplePin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All' -NoWelcome | Out-Null

if (-not $PolicyId) {
    $all = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections?`$select=id,displayName" -OutputType PSObject).value)
    if ($all.Count -ne 1) { throw "Expected exactly one iOS App Protection policy, found $($all.Count). Pass -PolicyId explicitly." }
    $PolicyId = $all[0].id
}

$before = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId" -OutputType PSObject
Write-Host "Policy: $($before.displayName)   id=$PolicyId"

# --- preflight: the app PIN must not land on company-owned devices -------------------
# 'disableAppPinIfDevicePinIsSet' suppresses the app PIN on ENROLLED devices that have a
# device lock -- but only if the managed apps can detect their enrollment state, which
# requires IntuneMAMUPN to be delivered by an app configuration policy. Without it, turning
# on pinRequired prompts for an app PIN on corporate devices too.
$disableOnEnrolled = $before.PSObject.Properties['disableAppPinIfDevicePinIsSet'] -and $before.disableAppPinIfDevicePinIsSet
Write-Host ("  disableAppPinIfDevicePinIsSet = {0}" -f $disableOnEnrolled)

# Coverage must be per app, not "any". One app's IntuneMAMUPN policy does not stop the app PIN
# appearing in every OTHER managed app on a corporate device. Apps auto-configured by Intune
# since the 2409 service release count as covered without a policy.
$AutoCovered = @(
    'com.microsoft.office.outlook', 'com.microsoft.skype.teams',
    'com.microsoft.office.word', 'com.microsoft.office.excel', 'com.microsoft.office.powerpoint'
)

$mamUpnApps = @{}
$mamUpnUnassigned = @()
foreach ($c in @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations" -OutputType PSObject).value)) {
    $full = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)" -OutputType PSObject

    # Settings may be key/value pairs OR a base64-encoded XML plist -- check both.
    $found = ("$($full | ConvertTo-Json -Depth 20 -Compress)") -match '(?i)IntuneMAMUPN'
    if (-not $found -and $full.PSObject.Properties['encodedSettingXml'] -and $full.encodedSettingXml) {
        try { $found = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($full.encodedSettingXml))) -match '(?i)IntuneMAMUPN' } catch { }
    }
    if (-not $found) { continue }

    $asg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)/assignments" -OutputType PSObject).value)
    if (-not $asg.Count) { $mamUpnUnassigned += $full.displayName; continue }
    foreach ($aid in @($full.targetedMobileApps)) { $mamUpnApps[$aid] = $true }
}
foreach ($n in $mamUpnUnassigned) { Write-Warning "'$n' carries IntuneMAMUPN but has no assignments -- it delivers nothing." }

# Which apps in this policy are deployed via Intune and still lack enrollment detection?
$appsInPolicy = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId`?`$expand=apps" -OutputType PSObject).apps |
    ForEach-Object { "$($_.mobileAppIdentifier.bundleId)" } | Where-Object { $_ })
$uncovered = @()
foreach ($a in (Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps?`$select=id,displayName" -OutputType PSObject).value) {
    $af = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)" -OutputType PSObject
    if ("$($af.'@odata.type')" -notmatch 'ios') { continue }
    $b = if ($af.PSObject.Properties['bundleId']) { "$($af.bundleId)" } else { '' }
    if (-not $b -or $b -notin $appsInPolicy -or $b -in $AutoCovered) { continue }
    if (@((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)/assignments" -OutputType PSObject).value).Count -le 0) { continue }
    if ($mamUpnApps.ContainsKey($a.id)) { continue }
    $uncovered += $af.displayName
}
$hasMamUpn = ($uncovered.Count -eq 0)
Write-Host ("  apps in policy, deployed, lacking IntuneMAMUPN = {0}" -f $uncovered.Count)
if ($uncovered.Count) { Write-Host ("     {0}" -f (($uncovered | Sort-Object) -join ', ')) -ForegroundColor DarkYellow }

# A Managed apps filter in include mode that scopes the policy to unmanaged devices is the
# other way to keep the PIN off company-owned devices -- and it makes enrollment detection
# irrelevant, because the policy never reaches an enrolled device in the first place.
$scopedToUnmanaged = $false
$policyAssignments = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId`?`$expand=assignments" -OutputType PSObject).assignments)
if ($policyAssignments.Count) {
    $filtered = @($policyAssignments | Where-Object {
            $_.target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId'] -and $_.target.deviceAndAppManagementAssignmentFilterId
        })
    if ($filtered.Count -eq $policyAssignments.Count) {
        $scopedToUnmanaged = $true
        foreach ($a in $filtered) {
            $fid = "$($a.target.deviceAndAppManagementAssignmentFilterId)"
            $mode = "$($a.target.deviceAndAppManagementAssignmentFilterType)"
            try { $flt = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/assignmentFilters/$fid" -OutputType PSObject }
            catch { $scopedToUnmanaged = $false; break }
            $isUnmanagedRule = "$($flt.rule)" -match '(?i)deviceManagementType\s+-eq\s+"?Unmanaged'
            if ("$($flt.assignmentFilterManagementType)" -ne 'apps' -or $mode -ne 'include' -or -not $isUnmanagedRule) { $scopedToUnmanaged = $false; break }
            Write-Host ("  assignment filtered by '{0}' ({1}): {2}" -f $flt.displayName, $mode, $flt.rule)
        }
    }
}
Write-Host ("  policy scoped to unmanaged devices only = {0}" -f $scopedToUnmanaged)

if (-not $disableOnEnrolled -and -not $scopedToUnmanaged) {
    throw "disableAppPinIfDevicePinIsSet is False and the policy is not filtered to unmanaged devices, so the app PIN would apply to company-owned devices."
}
if (-not $hasMamUpn -and -not $scopedToUnmanaged) {
    throw @'
No assigned app configuration policy delivers IntuneMAMUPN, so managed apps cannot detect
enrollment state. disableAppPinIfDevicePinIsSet will not take effect and enabling the PIN would
prompt on company-owned devices as well as BYOD.

Resolve either way:
  * scope this policy to unmanaged devices with a Managed apps assignment filter
    (app.deviceManagementType -eq "Unmanaged") in include mode -- see
    Set-IosAppProtectionFilter.ps1; or
  * deploy IntuneMAMUPN = {{userprincipalname}} to the managed apps -- see
    New-IosMamUpnAppConfigs.ps1
'@
}
Write-Host ""
Write-Host "Current:"
foreach ($k in 'pinRequired', 'minimumPinLength', 'simplePinBlocked', 'faceIdBlocked', 'maximumPinRetries') {
    if ($before.PSObject.Properties[$k]) { Write-Host ("  {0,-22} = {1}" -f $k, $before.$k) }
}

$desired = @{
    pinRequired      = $true
    minimumPinLength = $MinimumPinLength
    simplePinBlocked = (-not $AllowSimplePin)
}

Write-Host ""
Write-Host "Desired:"
foreach ($k in $desired.Keys | Sort-Object) {
    $cur = if ($before.PSObject.Properties[$k]) { $before.$k } else { '(unset)' }
    $mark = if ("$cur" -ne "$($desired[$k])") { '   <<< CHANGE' } else { '' }
    Write-Host ("  {0,-22} = {1}{2}" -f $k, $desired[$k], $mark)
}

$changes = @($desired.Keys | Where-Object { -not $before.PSObject.Properties[$_] -or "$($before.$_)" -ne "$($desired[$_])" })
if (-not $changes.Count) { Write-Host "`nAlready in the desired state."; return }

if (-not $PSCmdlet.ShouldProcess($before.displayName, "Set $($changes -join ', ')")) { Write-Host "`nDry run -- nothing was changed."; return }

Invoke-MgGraphRequest -Method PATCH -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId" `
    -Body ($desired | ConvertTo-Json) -ContentType 'application/json' | Out-Null
Write-Host "`nApplied." -ForegroundColor Green

$after = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$PolicyId" -OutputType PSObject
Write-Host "Verified on fresh read:"
$ok = $true
foreach ($k in $desired.Keys | Sort-Object) {
    $v = if ($after.PSObject.Properties[$k]) { $after.$k } else { '(unset)' }
    if ("$v" -ne "$($desired[$k])") { $ok = $false }
    Write-Host ("  {0,-22} = {1}" -f $k, $v)
}
if ($ok) { Write-Host "All settings confirmed." -ForegroundColor Green }
else { Write-Host "One or more settings did not take. Re-read before assuming failure." -ForegroundColor Yellow }
