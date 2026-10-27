<#
.SYNOPSIS
Aligns the Android app protection PIN requirements with iOS.

.DESCRIPTION
Android already requires an app PIN, but at 4 digits with simple sequences (1234, 1111) allowed,
while iOS pilots at 6 digits with simple sequences blocked. Leaving them different means the
change notification has to explain two standards, and the weaker one sets the real floor for
anyone using both platforms.

No assignment filter is involved, unlike iOS. This assumes Android Enterprise enrollment is
blocked and no Android devices are enrolled, so every Android device is already unmanaged and the
policy only ever reaches personal phones.

Run it against a pilot policy first. Users outside the pilot keep 4 digits until the pilot folds
into production -- raising the floor for everyone at once is a user-facing change that belongs in
the notification, not in a quiet edit.

.PARAMETER PolicyName
Exact display name of the Android app protection policy.

.PARAMETER MinimumPinLength
Defaults to 6, matching the iOS pilot.

.PARAMETER AllowSimplePin
Leave simple sequences allowed. Not recommended.

.EXAMPLE
.\Set-AndroidAppProtectionPin.ps1 -PolicyName 'Android app protection (PILOT)' -WhatIf

.EXAMPLE
# Once the pilot folds into production:
.\Set-AndroidAppProtectionPin.ps1 -PolicyName 'Android app protection' -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $PolicyName,

    [ValidateRange(4, 16)]
    [int]    $MinimumPinLength = 6,

    [switch] $AllowSimplePin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All' -NoWelcome | Out-Null

$all = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/androidManagedAppProtections?`$select=id,displayName" -OutputType PSObject).value)
$match = @($all | Where-Object { $_.displayName -eq $PolicyName })
if ($match.Count -ne 1) {
    $list = ($all | ForEach-Object { "    $($_.displayName)" }) -join "`n"
    throw "Expected exactly one Android app protection policy named '$PolicyName', found $($match.Count). Available:`n$list"
}

$id = $match[0].id
$before = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/androidManagedAppProtections/$id" -OutputType PSObject

Write-Host "Policy: $($before.displayName)   id=$id"
Write-Host ""
Write-Host "Current:"
foreach ($k in 'pinRequired', 'minimumPinLength', 'simplePinBlocked', 'pinCharacterSet', 'maximumPinRetries') {
    if ($before.PSObject.Properties[$k]) { Write-Host ("   {0,-22} = {1}" -f $k, $before.$k) }
}

if (-not $before.pinRequired) {
    throw "pinRequired is False on '$PolicyName'. This script tightens an existing PIN; it does not turn one on."
}

$desired = @{
    minimumPinLength = $MinimumPinLength
    simplePinBlocked = (-not $AllowSimplePin)
}

Write-Host ""
Write-Host "Desired:"
$changes = @()
foreach ($k in ($desired.Keys | Sort-Object)) {
    $cur = if ($before.PSObject.Properties[$k]) { "$($before.$k)" } else { '(unset)' }
    $isChange = ($cur -ne "$($desired[$k])")
    if ($isChange) { $changes += $k }
    Write-Host ("   {0,-22} = {1}{2}" -f $k, $desired[$k], $(if ($isChange) { "   <<< was $cur" } else { '   (no change)' }))
}

if (-not $changes.Count) { Write-Host "`nAlready in the desired state."; return }
if (-not $PSCmdlet.ShouldProcess($before.displayName, "Set $($changes -join ', ')")) { Write-Host "`nDry run -- nothing was changed."; return }

Invoke-MgGraphRequest -Method PATCH -Uri "$graph/deviceAppManagement/androidManagedAppProtections/$id" `
    -Body ($desired | ConvertTo-Json) -ContentType 'application/json' | Out-Null
Write-Host "`nApplied." -ForegroundColor Green

$after = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/androidManagedAppProtections/$id" -OutputType PSObject
Write-Host "Verified on fresh read:"
$ok = $true
foreach ($k in ($desired.Keys | Sort-Object)) {
    $v = if ($after.PSObject.Properties[$k]) { "$($after.$k)" } else { '(unset)' }
    if ($v -ne "$($desired[$k])") { $ok = $false }
    Write-Host ("   {0,-22} = {1}" -f $k, $v)
}
Write-Host ("   {0,-22} = {1}  (unchanged)" -f 'pinRequired', $after.pinRequired)
if ($ok) { Write-Host "All settings confirmed." -ForegroundColor Green } else { Write-Host "One or more settings did not take." -ForegroundColor Yellow }
