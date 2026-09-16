<#
.SYNOPSIS
Renames Intune policies to the canonical platform prefix reported by Analyze-PolicyOverlap.ps1.

.DESCRIPTION
Reads the NonCanonicalPrefix findings from a policy-overlap-report.json and rewrites just the
leading platform token: 'Win: Chrome-configuration' becomes 'Windows: Chrome-configuration'.
Everything after the prefix -- including the separator -- is preserved exactly, so
'win1x-account-policies' becomes 'Windows-account-policies' rather than being reformatted.

By default ONLY unambiguous prefixes are changed:

    Win -> Windows      ios -> iOS      macos -> macOS

Version-bearing prefixes (Win1x, Win10, Win11) are NOT renamed by default, because the
version is information: 'Win10-BitLocker' -> 'Windows-BitLocker' discards the fact that it is
the Windows 10 variant, and could collide with a Windows 11 equivalent. Opt in per prefix
with -PrefixesToFix once you have decided where that version belongs -- usually in an
assignment filter, which is what the macOSTahoeDevices / macOSSequoiaDevices filters already
do for macOS.

Every rename is verified by reading the policy back. A policy whose current name no longer
starts with the expected prefix is skipped, so a stale report cannot rename the wrong thing.
Failures are collected and reported rather than aborting the run.

.PARAMETER ReportPath
policy-overlap-report.json to read findings from. Defaults to the newest report under
.\exports.

.PARAMETER PrefixesToFix
Which non-canonical prefixes to act on. Defaults to the unambiguous ones.
Pass e.g. -PrefixesToFix Win,ios,macos,Win10,Win11,Win1x to include the versioned ones.

.PARAMETER Category
Limit to one policy type (e.g. ConfigurationPolicies), for a cautious first pass.

.PARAMETER tenantId
Optional tenant id or domain for authentication.

.EXAMPLE
./Rename-PolicyPrefix.ps1 -WhatIf

Lists every rename it would make, grouped by type, without writing anything.

.EXAMPLE
./Rename-PolicyPrefix.ps1 -Category ConfigurationPolicies

Renames only Settings Catalog policies.

.EXAMPLE
./Rename-PolicyPrefix.ps1 -PrefixesToFix Win,ios,macos,Win10,Win11,Win1x

Includes the versioned prefixes, once you have decided that is what you want.

.NOTES
Requires DeviceManagementConfiguration.ReadWrite.All, plus DeviceManagementApps.ReadWrite.All
and DeviceManagementScripts.ReadWrite.All if app or script policies are in scope.

Settings Catalog policies carry their name in 'name'; every other type uses 'displayName'.
The script handles both.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ReportPath,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string[]]$PrefixesToFix = @('Win', 'ios', 'macos'),

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$Category,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$tenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'

# Policy type -> Graph collection, and which property carries the name. Settings Catalog is
# the odd one out: deviceManagementConfigurationPolicy has 'name', not 'displayName'.
$endpointMap = @{
  'DeviceConfigurations'         = @{ Path = 'deviceManagement/deviceConfigurations'; NameProperty = 'displayName' }
  'ConfigurationPolicies'        = @{ Path = 'deviceManagement/configurationPolicies'; NameProperty = 'name' }
  'GroupPolicyConfigurations'    = @{ Path = 'deviceManagement/groupPolicyConfigurations'; NameProperty = 'displayName' }
  'EndpointSecurityPolicies'     = @{ Path = 'deviceManagement/intents'; NameProperty = 'displayName' }
  'CompliancePolicies'           = @{ Path = 'deviceManagement/deviceCompliancePolicies'; NameProperty = 'displayName' }
  'AppProtectionPolicies'        = @{ Path = 'deviceAppManagement/managedAppPolicies'; NameProperty = 'displayName' }
  'AppConfigurationPolicies'     = @{ Path = 'deviceAppManagement/mobileAppConfigurations'; NameProperty = 'displayName' }
  'ManagedAppConfigurations'     = @{ Path = 'deviceAppManagement/targetedManagedAppConfigurations'; NameProperty = 'displayName' }
  'EnrollmentConfigurations'     = @{ Path = 'deviceManagement/deviceEnrollmentConfigurations'; NameProperty = 'displayName' }
  'WindowsDriverUpdateProfiles'  = @{ Path = 'deviceManagement/windowsDriverUpdateProfiles'; NameProperty = 'displayName' }
  'WindowsQualityUpdateProfiles' = @{ Path = 'deviceManagement/windowsQualityUpdateProfiles'; NameProperty = 'displayName' }
  'WindowsFeatureUpdateProfiles' = @{ Path = 'deviceManagement/windowsFeatureUpdateProfiles'; NameProperty = 'displayName' }
  'DeviceHealthScripts'          = @{ Path = 'deviceManagement/deviceHealthScripts'; NameProperty = 'displayName' }
  'DeviceManagementScripts'      = @{ Path = 'deviceManagement/deviceManagementScripts'; NameProperty = 'displayName' }
  'DeviceShellScripts'           = @{ Path = 'deviceManagement/deviceShellScripts'; NameProperty = 'displayName' }
}

#region Helpers

function Get-GraphProperty {
  param(
    [Parameter()][AllowNull()][object]$InputObject,
    [Parameter(Mandatory = $true)][string]$name
  )
  if ($null -eq $InputObject) { return $null }
  if ($InputObject -is [System.Collections.IDictionary]) {
    if ($InputObject.Contains($name)) { return $InputObject[$name] }
    return $null
  }
  $prop = $InputObject.PSObject.Properties[$name]
  if ($prop) { return $prop.Value }
  return $null
}

function Invoke-Graph {
  param(
    [Parameter(Mandatory = $true)][ValidateSet('GET', 'PATCH')][string]$method,
    [Parameter(Mandatory = $true)][string]$uri,
    [Parameter()][object]$body
  )
  $params = @{ Method = $method; Uri = $uri; OutputType = 'PSObject' }
  if ($null -ne $body) {
    $params.Body = ($body | ConvertTo-Json -Depth 20)
    $params.ContentType = 'application/json'
  }
  return Invoke-MgGraphRequest @params
}

function Get-RenamedName {
  <#
    Replace only the leading platform token, preserving the separator and everything after.
    'Win: Chrome-configuration' -> 'Windows: Chrome-configuration'
    'win1x-account-policies'    -> 'Windows-account-policies'
  #>
  param(
    [Parameter(Mandatory = $true)][string]$currentName,
    [Parameter(Mandatory = $true)][string]$found,
    [Parameter(Mandatory = $true)][string]$expected
  )

  # Match case-insensitively so Win / win / WIn are all caught, but emit the canonical
  # casing. The pattern is anchored, so it can only ever replace the leading token.
  $pattern = '^(\s*)' + [regex]::Escape($found) + '(?=[:\-_ ]|$)'
  if ($currentName -notmatch $pattern) { return $null }
  return [regex]::Replace($currentName, $pattern, "`$1$expected", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

#endregion

#region Load findings

if (-not $ReportPath) {
  $exportRoot = Join-Path $PSScriptRoot 'exports'
  if (-not (Test-Path -LiteralPath $exportRoot)) { throw "No -ReportPath given and no exports folder at $exportRoot." }
  $candidate = Get-ChildItem -LiteralPath $exportRoot -Recurse -File -Filter 'policy-overlap-report.json' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $candidate) { throw "No policy-overlap-report.json found under $exportRoot. Run Analyze-PolicyOverlap.ps1 first." }
  $ReportPath = $candidate.FullName
}

if ($WhatIfPreference) {
  Write-Host ''
  Write-Host '  ===============================================================' -ForegroundColor Cyan
  Write-Host '   DRY RUN (-WhatIf). Nothing will be changed.' -ForegroundColor Cyan
  Write-Host '   Read-only Graph scopes are requested; no write consent needed.' -ForegroundColor Cyan
  Write-Host '  ===============================================================' -ForegroundColor Cyan
  Write-Host ''
}

$report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
$findings = @(Get-GraphProperty -InputObject (Get-GraphProperty -InputObject $report -name 'Naming') -name 'NonCanonicalPrefix')

Write-Output "Report      : $ReportPath"
Write-Output "Generated   : $(Get-GraphProperty -InputObject $report -name 'GeneratedAtUtc')"
Write-Output "Findings    : $($findings.Count) non-canonical prefixes"
Write-Output "Fixing      : $($PrefixesToFix -join ', ')"
Write-Output ''

$inScope = @($findings | Where-Object { $_.Found -in $PrefixesToFix })
if ($Category) { $inScope = @($inScope | Where-Object { $_.Category -eq $Category }) }

$skippedPrefixes = @($findings | Where-Object { $_.Found -notin $PrefixesToFix } | Group-Object Found)
if ($skippedPrefixes.Count) {
  Write-Warning ("Not in scope (pass -PrefixesToFix to include): {0}" -f (($skippedPrefixes | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '))
  Write-Output ''
}

if (-not $inScope.Count) { Write-Output 'Nothing to rename.'; return }

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

# Only request the scopes the selected categories actually need -- and under -WhatIf ask for
# READ only. A dry run must never make you grant write access just to preview a change.
$accessLevel = if ($WhatIfPreference) { 'Read' } else { 'ReadWrite' }
$requiredScopes = @("DeviceManagementConfiguration.$accessLevel.All")
$categoriesInScope = @($inScope | ForEach-Object { $_.Category } | Sort-Object -Unique)
if ($categoriesInScope -match 'App') { $requiredScopes += "DeviceManagementApps.$accessLevel.All" }
if ($categoriesInScope -match 'Script') { $requiredScopes += "DeviceManagementScripts.$accessLevel.All" }
if ($categoriesInScope -contains 'EnrollmentConfigurations') { $requiredScopes += "DeviceManagementServiceConfig.$accessLevel.All" }

$ctx = $null
try { $ctx = Get-MgContext } catch { $ctx = $null }
$needConnect = $true
if ($null -ne $ctx -and $ctx.Scopes) {
  if (@($requiredScopes | Where-Object { $_ -notin $ctx.Scopes }).Count -eq 0) { $needConnect = $false }
}
if ($needConnect) {
  $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
  if ($tenantId) { $connectParams.TenantId = $tenantId }
  Connect-MgGraph @connectParams | Out-Null
  $ctx = Get-MgContext
}
if ($null -eq $ctx -or -not $ctx.Account -or -not $ctx.TenantId) { throw 'Not connected to Microsoft Graph.' }

Write-Output "Connected as $($ctx.Account) on tenant $($ctx.TenantId)"
Write-Output ''

#endregion

#region Plan (from live state)

# Built by reading each policy from Graph, NOT from the report. The report is a snapshot and
# goes stale the moment anything is renamed -- a plan derived from it would keep listing
# policies that have already been fixed.
$plan = @()
$skipped = @()
$failed = @()
$index = 0

foreach ($f in $inScope) {
  $index++
  Write-Progress -Id 1 -Activity 'Checking current names' -Status ("{0} of {1}" -f $index, $inScope.Count) `
    -PercentComplete ([int](($index / $inScope.Count) * 100))

  if (-not $endpointMap.ContainsKey($f.Category)) {
    $failed += [pscustomobject]@{ Name = $f.PolicyName; Category = $f.Category; Reason = 'No endpoint mapping for this policy type' }
    continue
  }

  $endpoint = $endpointMap[$f.Category]
  $uri = "$graphBase/$($endpoint.Path)/$($f.PolicyId)"

  try {
    $live = Invoke-Graph -method GET -uri $uri
  }
  catch {
    $failed += [pscustomobject]@{ Name = $f.PolicyName; Category = $f.Category; Reason = "Read failed: $($_.Exception.Message)" }
    continue
  }

  $liveName = Get-GraphProperty -InputObject $live -name $endpoint.NameProperty
  $newName = Get-RenamedName -currentName $liveName -found $f.Found -expected $f.Expected

  if (-not $newName) {
    $skipped += [pscustomobject]@{ Name = $liveName; Category = $f.Category; Reason = "No longer starts with '$($f.Found)'" }
    continue
  }
  # -ceq, not -eq: PowerShell string comparison is case-insensitive by default, which would
  # treat 'iOS-device-restrictions' and 'ios-device-restrictions' as equal and silently skip
  # every pure case correction -- the majority of the iOS and macOS renames.
  if ($newName -ceq $liveName) {
    $skipped += [pscustomobject]@{ Name = $liveName; Category = $f.Category; Reason = 'Already canonical' }
    continue
  }

  $plan += [pscustomobject]@{
    Old = $liveName; New = $newName; Category = $f.Category
    Uri = $uri; NameProperty = $endpoint.NameProperty
    OdataType = (Get-GraphProperty -InputObject $live -name '@odata.type')
  }
}

Write-Progress -Id 1 -Activity 'Checking current names' -Completed

Write-Output '--- Planned renames (current names read from Graph) ---'
if (-not $plan.Count) {
  Write-Output '  none - every policy in scope is already canonical'
}
foreach ($g in $plan | Group-Object Category | Sort-Object Name) {
  Write-Output ("  {0}" -f $g.Name)
  foreach ($p in $g.Group | Sort-Object Old) {
    Write-Output ("      {0,-52} ->  {1}" -f $p.Old, $p.New)
  }
}
if ($skipped.Count) {
  Write-Output ("  ({0} already canonical or renamed since the report was generated)" -f $skipped.Count)
}
Write-Output ''

#endregion

#region Rename

$renamed = @()
$wouldRename = @($plan)
$index = 0

foreach ($p in $plan) {
  $index++
  Write-Progress -Id 1 -Activity 'Renaming policies' -Status ("{0} of {1}: {2}" -f $index, $plan.Count, $p.Old) `
    -PercentComplete ([int](($index / $plan.Count) * 100))

  $body = @{ $p.NameProperty = $p.New }
  # Graph wants the concrete type on a PATCH to a polymorphic collection; reuse whatever the
  # policy already reports rather than guessing a subtype.
  if ($p.OdataType) { $body['@odata.type'] = $p.OdataType }

  if (-not $PSCmdlet.ShouldProcess($p.Old, "Rename to '$($p.New)'")) { continue }

  try {
    Invoke-Graph -method PATCH -uri $p.Uri -body $body | Out-Null
    $after = Invoke-Graph -method GET -uri $p.Uri
    $afterName = Get-GraphProperty -InputObject $after -name $p.NameProperty
    # -ceq for the same reason as above: a case-only rename that silently did not apply
    # would otherwise read back as equal and be reported as a success.
    if ($afterName -ceq $p.New) {
      $renamed += [pscustomobject]@{ Old = $p.Old; New = $p.New; Category = $p.Category }
    }
    else {
      $failed += [pscustomobject]@{ Name = $p.Old; Category = $p.Category; Reason = "PATCH did not take (still '$afterName')" }
    }
  }
  catch {
    $failed += [pscustomobject]@{ Name = $p.Old; Category = $p.Category; Reason = $_.Exception.Message }
  }
}

Write-Progress -Id 1 -Activity 'Renaming policies' -Completed

#endregion

#region Summary

if ($WhatIfPreference) {
  Write-Output '--- Dry run result ---'
  Write-Output ("  would rename : {0}" -f $wouldRename.Count)
  Write-Output ("  would skip   : {0}   (already canonical, or the report is stale)" -f $skipped.Count)
  Write-Output ("  unreadable   : {0}" -f $failed.Count)
  Write-Output ''
  Write-Host '  NOTHING WAS CHANGED. Re-run without -WhatIf to apply.' -ForegroundColor Cyan
  Write-Output ''
  if ($skipped.Count) {
    Write-Output '  Would skip:'
    foreach ($s in $skipped) { Write-Output ("      {0,-52} {1}" -f $s.Name, $s.Reason) }
    Write-Output ''
  }
  if ($failed.Count) {
    Write-Warning "$($failed.Count) policy/policies could not be read:"
    foreach ($x in $failed) { Write-Output ("      [{0}] {1}: {2}" -f $x.Category, $x.Name, $x.Reason) }
  }
  return
}

Write-Output '--- Result ---'
Write-Output ("  renamed : {0}" -f $renamed.Count)
Write-Output ("  skipped : {0}" -f $skipped.Count)
Write-Output ("  failed  : {0}" -f $failed.Count)
Write-Output ''

if ($renamed.Count) {
  foreach ($g in $renamed | Group-Object Category | Sort-Object Name) {
    Write-Output ("  {0}" -f $g.Name)
    foreach ($r in $g.Group) { Write-Output ("      {0,-52} ->  {1}" -f $r.Old, $r.New) }
  }
  Write-Output ''
}

if ($skipped.Count) {
  Write-Output '  Skipped:'
  foreach ($s in $skipped) { Write-Output ("      {0,-52} {1}" -f $s.Name, $s.Reason) }
  Write-Output ''
}

if ($failed.Count) {
  Write-Warning "$($failed.Count) rename(s) failed:"
  foreach ($x in $failed) { Write-Output ("      [{0}] {1}: {2}" -f $x.Category, $x.Name, $x.Reason) }
  Write-Output ''
}

Write-Output 'Next: re-run Export-DeviceConfigurations.ps1 and Analyze-PolicyOverlap.ps1 to confirm the naming section is clear.'
Write-Output 'Note: renaming changes the exported filename, so the export will clean up the old file on its next run.'

#endregion
