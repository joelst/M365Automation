<#
.SYNOPSIS
Brings the iOS Microsoft Enterprise SSO plug-in profile in line with Microsoft's recommended
additional configuration.

.DESCRIPTION
Microsoft's iOS/iPadOS guidance for the Entra ID SSO app extension recommends three
additional-configuration keys. Profiles often have browser_sso_interaction_enabled but not the
other two. This script ensures all three:

    AppPrefixAllowList               -> com.microsoft.,com.apple.
    disable_explicit_app_prompt      -> 1
    browser_sso_interaction_enabled  -> 1

AppPrefixAllowList is an opt-in list, not a filter: it lets apps that do not use MSAL reuse the
user's Entra session silently. MSAL apps, Safari and ASWebAuthenticationSession keep working
regardless, and apps outside the list keep signing in exactly as before.

Every other key already on the profile (e.g. device_registration) and every other extension
property (shared device mode, bundle ID list) is preserved -- the PATCH sends the merged object.

https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-enterprise-sso-plugin-ios

.PARAMETER ProfileName
Display name of the iosDeviceFeaturesConfiguration profile.

.PARAMETER AppPrefixAllowList
Comma-separated bundle ID prefixes. Only add third-party prefixes after testing the app --
an allow-listed app with a non-standard web view can loop at sign-in.

.EXAMPLE
.\Set-IosSsoExtensionConfig.ps1 -ProfileName 'iOS Enterprise SSO plug-in' -WhatIf

.EXAMPLE
.\Set-IosSsoExtensionConfig.ps1 -ProfileName 'iOS Enterprise SSO plug-in'
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string] $ProfileName,
    [string] $AppPrefixAllowList = 'com.microsoft.,com.apple.'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome | Out-Null

$match = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/deviceConfigurations?`$filter=displayName eq '$($ProfileName -replace "'", "''")'&`$select=id" -OutputType PSObject).value)
if ($match.Count -ne 1) { throw "Expected exactly one profile named '$ProfileName', found $($match.Count)." }
$id = $match[0].id

$before = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/deviceConfigurations/$id" -OutputType PSObject
if ("$($before.'@odata.type')" -ne '#microsoft.graph.iosDeviceFeaturesConfiguration') { throw "'$ProfileName' is $($before.'@odata.type'), not an iOS device features profile." }
$ext = $before.iosSingleSignOnExtension
if (-not $ext -or "$($ext.'@odata.type')" -ne '#microsoft.graph.iosAzureAdSingleSignOnExtension') {
    throw "'$ProfileName' does not carry a Microsoft Entra ID SSO app extension."
}
Write-Host "Profile: $($before.displayName)   id=$id"

# key -> @(odata type, value)
$desired = [ordered]@{
    AppPrefixAllowList              = @('#microsoft.graph.keyStringValuePair', $AppPrefixAllowList)
    browser_sso_interaction_enabled = @('#microsoft.graph.keyIntegerValuePair', 1)
    disable_explicit_app_prompt     = @('#microsoft.graph.keyIntegerValuePair', 1)
}

$current = [ordered]@{}
foreach ($c in @($ext.configurations)) { $current[$c.key] = $c }

Write-Host ""
Write-Host "Additional configuration:"
$changes = @()
foreach ($k in $desired.Keys) {
    $cur = if ($current.Contains($k)) { "$($current[$k].value)" } else { '(unset)' }
    $mark = ''
    if ($cur -ne "$($desired[$k][1])") { $changes += $k; $mark = '   <<< CHANGE' }
    Write-Host ("  {0,-32} = {1}{2}" -f $k, $desired[$k][1], $mark)
}
foreach ($k in $current.Keys | Where-Object { -not $desired.Contains($_) }) {
    Write-Host ("  {0,-32} = {1}   (kept)" -f $k, $current[$k].value)
}
if (-not $changes.Count) { Write-Host "`nAlready in the desired state."; return }

# Merge: keep unrelated keys in their original order, then set the desired ones.
$merged = [System.Collections.Generic.List[object]]::new()
foreach ($k in $current.Keys | Where-Object { -not $desired.Contains($_) }) {
    $merged.Add(@{ '@odata.type' = $current[$k].'@odata.type'; key = $k; value = $current[$k].value })
}
foreach ($k in $desired.Keys) {
    $merged.Add(@{ '@odata.type' = $desired[$k][0]; key = $k; value = $desired[$k][1] })
}

$body = @{
    '@odata.type'            = '#microsoft.graph.iosDeviceFeaturesConfiguration'
    iosSingleSignOnExtension = @{
        '@odata.type'             = '#microsoft.graph.iosAzureAdSingleSignOnExtension'
        enableSharedDeviceMode    = [bool] $ext.enableSharedDeviceMode
        bundleIdAccessControlList = @($ext.bundleIdAccessControlList)
        configurations            = $merged
    }
}

if (-not $PSCmdlet.ShouldProcess($before.displayName, "Set $($changes -join ', ') (assigned to All Devices)")) { Write-Host "`nDry run -- nothing was changed."; return }

Invoke-MgGraphRequest -Method PATCH -Uri "$graph/deviceManagement/deviceConfigurations/$id" `
    -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
Write-Host "`nApplied." -ForegroundColor Green

$after = (Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/deviceConfigurations/$id" -OutputType PSObject).iosSingleSignOnExtension
Write-Host "Verified on fresh read:"
$ok = $true
$afterKeys = @{}
foreach ($c in @($after.configurations)) { $afterKeys[$c.key] = "$($c.value)" }
foreach ($k in $desired.Keys) {
    $v = if ($afterKeys.ContainsKey($k)) { $afterKeys[$k] } else { '(unset)' }
    if ($v -ne "$($desired[$k][1])") { $ok = $false }
    Write-Host ("  {0,-32} = {1}" -f $k, $v)
}
foreach ($k in $current.Keys | Where-Object { -not $desired.Contains($_) }) {
    $v = if ($afterKeys.ContainsKey($k)) { $afterKeys[$k] } else { '(MISSING)' }
    if ($v -ne "$($current[$k].value)") { $ok = $false }
    Write-Host ("  {0,-32} = {1}   (kept)" -f $k, $v)
}
Write-Host ("  enableSharedDeviceMode           = {0}" -f $after.enableSharedDeviceMode)
if ($ok) { Write-Host "All settings confirmed." -ForegroundColor Green }
else { Write-Host "One or more settings did not take. Re-read before assuming failure." -ForegroundColor Yellow }
