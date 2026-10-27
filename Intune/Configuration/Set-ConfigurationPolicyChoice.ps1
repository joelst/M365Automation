<#
.SYNOPSIS
Changes a single choice setting on a settings catalog policy.

.NOTES
DOES NOT WORK on template-backed enrollment policies (technologies='enrollment', e.g. the Apple
ADE policies). Both supported-looking write routes were tried live on 2026-09-18 against
'iOS: ADE Setup Assistant modern auth' and both were rejected. The policy was left untouched by
each -- settingCount and lastModifiedDateTime were verified unchanged after both -- so this is a
hard refusal, not a partial write. Use the Intune portal for that policy type.

  1. PATCH .../configurationPolicies/{id}/settings/{settingId}
       400  "No OData route exists that match template
             ~/singleton/navigation/key/navigation/key with http verb PATCH"
       Individual settings are readable but writes to them are blocked at the API level.

  2. PUT .../configurationPolicies('{id}')  with name/description/platforms/technologies/
     roleScopeTagIds/templateReference and all 40 settings round-tripped from the paged GET
       400  ConditionNotMet  (generic DeviceConfigV2 rejection, no actionable detail)
       Most likely the settings payload shape returned by GET is not directly valid for PUT on
       a template-backed policy -- the template reference fields on each setting instance and
       value probably need reconstructing rather than echoing. Not pursued further: the blast
       radius on an enrollment policy is a broken ADE flow discovered only on a device wipe.

Untested against non-template settings catalog policies (ordinary Windows/macOS config), where
route 2 is the documented approach and may well work.

.DESCRIPTION
Settings catalog policies expose each setting as an addressable child object, so one setting can
be PATCHed without rewriting the whole collection. That matters: this policy reports
settingCount=40 while /settings returns paged results, so a naive read-modify-write of the whole
array risks silently dropping settings -- and on an ADE policy you would not find out until a
device was wiped.

Guards:
  * The setting must already exist. This never adds one.
  * The requested value must be a valid option for that setting definition.
  * Total setting count is compared before and after; a change means something was clobbered.
  * Every other setting's value is compared before and after and any drift is reported.

Changes to an ADE enrollment policy only take effect on devices that are wiped after the change.
Already-enrolled devices keep their current configuration.

.PARAMETER PolicyName
Display name of the settings catalog policy.

.PARAMETER SettingDefinitionId
e.g. ade_setupassistant_appleid

.PARAMETER Value
The option itemId to set, e.g. ade_setupassistant_appleid_0

.EXAMPLE
.\Set-ConfigurationPolicyChoice.ps1 -PolicyName 'iOS: ADE Setup Assistant modern auth' `
    -SettingDefinitionId ade_setupassistant_appleid -Value ade_setupassistant_appleid_0 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $PolicyName,
    [Parameter(Mandatory)] [string] $SettingDefinitionId,
    [Parameter(Mandatory)] [string] $Value
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome | Out-Null

function Get-AllSettings {
    param([string] $PolicyId)
    $out = @()
    $uri = "$graph/deviceManagement/configurationPolicies/$PolicyId/settings?`$top=200"
    while ($uri) {
        $r = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        $out += $r.value
        $uri = if ($r.PSObject.Properties['@odata.nextLink']) { $r.'@odata.nextLink' } else { $null }
    }
    $out
}

function Get-ValueMap {
    param($Settings)
    $m = @{}
    foreach ($s in $Settings) {
        $si = $s.settingInstance
        $v = if ($si.PSObject.Properties['choiceSettingValue'] -and $si.choiceSettingValue) { "$($si.choiceSettingValue.value)" }
        elseif ($si.PSObject.Properties['simpleSettingValue'] -and $si.simpleSettingValue) { "$($si.simpleSettingValue.value)" }
        else { '<other>' }
        $m["$($si.settingDefinitionId)"] = $v
    }
    $m
}

# --- resolve policy -------------------------------------------------------------------
$pols = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/configurationPolicies?`$select=id,name,platforms,technologies" -OutputType PSObject).value | Where-Object { $_.name -eq $PolicyName })
if ($pols.Count -ne 1) { throw "Expected exactly one policy named '$PolicyName', found $($pols.Count)." }
$pol = $pols[0]
$polFull = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/configurationPolicies/$($pol.id)" -OutputType PSObject
Write-Host "Policy : $($pol.name)"
Write-Host "   id            : $($pol.id)"
Write-Host "   platforms     : $($pol.platforms)   technologies: $($pol.technologies)"
Write-Host "   settingCount  : $($polFull.settingCount)"
Write-Host "   lastModified  : $($polFull.lastModifiedDateTime)"

# --- locate the setting ----------------------------------------------------------------
$before = Get-AllSettings $pol.id
$beforeMap = Get-ValueMap $before
Write-Host "   settings read : $($before.Count)"

$target = @($before | Where-Object { "$($_.settingInstance.settingDefinitionId)" -eq $SettingDefinitionId })
if ($target.Count -ne 1) { throw "Expected exactly one setting '$SettingDefinitionId' on this policy, found $($target.Count). This script will not add a setting that is not already configured." }
$target = $target[0]

$current = "$($target.settingInstance.choiceSettingValue.value)"
if (-not $current) { throw "'$SettingDefinitionId' is not a choice setting on this policy." }

# --- validate the requested value against the definition --------------------------------
$def = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/configurationSettings/$SettingDefinitionId" -OutputType PSObject
$valid = @($def.options | ForEach-Object { "$($_.itemId)" })
Write-Host ""
Write-Host "Setting: $($def.displayName)  ($SettingDefinitionId)"
foreach ($o in $def.options) {
    $mark = if ("$($o.itemId)" -eq $current) { '  <- current' } elseif ("$($o.itemId)" -eq $Value) { '  <- requested' } else { '' }
    Write-Host ("   {0,-14} = {1}{2}" -f $o.name, $o.itemId, $mark)
}
if ($Value -notin $valid) { throw "'$Value' is not a valid option. Valid: $($valid -join ', ')" }
if ($current -eq $Value) { Write-Host "`nAlready set to '$Value'. Nothing to do."; return }

Write-Host ""
Write-Host "Change : $current  ->  $Value   (setting object id '$($target.id)')"
Write-Host ""
Write-Host "NOTE: ADE policy changes apply only to devices wiped after the change." -ForegroundColor Yellow

if (-not $PSCmdlet.ShouldProcess($pol.name, "Set $SettingDefinitionId = $Value")) { Write-Host "`nDry run -- nothing was changed."; return }

# --- write ------------------------------------------------------------------------------
# Writes to an individual setting are blocked at the API level: PATCH on
# .../configurationPolicies/{id}/settings/{settingId} returns
#   "No OData route exists that match template ~/singleton/navigation/key/navigation/key"
# The whole policy, settings included, has to go back via PUT on the policy itself. That is
# why the read above is paged and why the verification below compares every setting -- a
# full round-trip is the only supported route, so the risk is dropping settings, not the write.
$payloadSettings = @()
foreach ($s in $before) {
    $clone = $s | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    if ("$($clone.settingInstance.settingDefinitionId)" -eq $SettingDefinitionId) {
        $clone.settingInstance.choiceSettingValue.value = $Value
    }
    $payloadSettings += $clone
}
if ($payloadSettings.Count -ne $before.Count) { throw "Built $($payloadSettings.Count) settings from $($before.Count) read. Refusing to write a short payload." }

$put = @{
    '@odata.type'     = '#microsoft.graph.deviceManagementConfigurationPolicy'
    name              = $polFull.name
    description       = $polFull.description
    platforms         = $polFull.platforms
    technologies      = $polFull.technologies
    roleScopeTagIds   = @($polFull.roleScopeTagIds)
    templateReference = $polFull.templateReference
    settings          = $payloadSettings
}
Write-Host ("Writing whole policy back: {0} setting(s), template {1}" -f $payloadSettings.Count, $polFull.templateReference.templateId)
Invoke-MgGraphRequest -Method PUT -Uri "$graph/deviceManagement/configurationPolicies('$($pol.id)')" `
    -Body ($put | ConvertTo-Json -Depth 40) -ContentType 'application/json' | Out-Null
Write-Host "PUT sent." -ForegroundColor Green

# --- verify: target changed, nothing else did, nothing lost ------------------------------
Start-Sleep -Seconds 3
$after = Get-AllSettings $pol.id
$afterMap = Get-ValueMap $after
$polAfter = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/configurationPolicies/$($pol.id)" -OutputType PSObject

Write-Host ""
Write-Host "Verifying against a fresh read..."
Write-Host ("   settingCount : {0} -> {1}  {2}" -f $polFull.settingCount, $polAfter.settingCount, $(if ($polFull.settingCount -eq $polAfter.settingCount) { 'OK' } else { '<<< SETTINGS LOST' }))
Write-Host ("   settings read: {0} -> {1}" -f $before.Count, $after.Count)

$newVal = "$($afterMap[$SettingDefinitionId])"
Write-Host ("   {0} = {1}  {2}" -f $SettingDefinitionId, $newVal, $(if ($newVal -eq $Value) { 'OK' } else { '<<< DID NOT APPLY' }))

$drift = @()
foreach ($k in $beforeMap.Keys) {
    if ($k -eq $SettingDefinitionId) { continue }
    if (-not $afterMap.ContainsKey($k)) { $drift += "$k  MISSING after"; continue }
    if ("$($beforeMap[$k])" -ne "$($afterMap[$k])") { $drift += "$k  $($beforeMap[$k]) -> $($afterMap[$k])" }
}
foreach ($k in $afterMap.Keys) { if (-not $beforeMap.ContainsKey($k)) { $drift += "$k  APPEARED after" } }

Write-Host ""
if ($drift.Count) {
    Write-Host "UNEXPECTED DRIFT in other settings:" -ForegroundColor Red
    foreach ($d in $drift) { Write-Host "   $d" -ForegroundColor Red }
}
else { Write-Host "No other setting changed." -ForegroundColor Green }
