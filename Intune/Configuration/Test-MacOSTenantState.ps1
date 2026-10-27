<#
.SYNOPSIS
Read-only check of the macOS configuration this toolkit cares about, against LIVE Graph.

.DESCRIPTION
Answers "what is true right now" rather than "what was true when the last export ran".

An export is a snapshot, and it is stale the moment anything changes -- including changes made
by these same scripts. Reading one and reporting its contents as current state is how a tool
ends up confidently describing a tenant that no longer exists. This script exists so that any
claim about tenant state can be checked directly.

Requests READ-ONLY scopes and issues only GET requests. It cannot change anything.

Checks:
  - profiles sharing a PayloadIdentifier (the collision), and AllowUserOverrides on each
  - the DLP enforcement block (unallowedBrowserMode / pasteToBrowserMode)
  - AllowUserOverrides on any macOS profile that sets it
  - macOS shell scripts, and crucially whether they are ASSIGNED
  - macOS compliance policies and the assignment filters that scope them

.PARAMETER Identifier
PayloadIdentifier to check for collisions. Optional; omit to report every identifier that is
shared by more than one profile.

.PARAMETER TenantId
Tenant to connect to. Optional.

.EXAMPLE
.\Test-MacOSTenantState.ps1

.EXAMPLE
.\Test-MacOSTenantState.ps1 -Identifier 23FE3F82-71F0-11EF-89EE-26DE397E1932
#>

[CmdletBinding()]
param(
  [Parameter()]
  [string]$Identifier,

  [Parameter()]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'

#region Helpers

function Get-GraphProperty {
  param([Parameter()][AllowNull()][object]$InputObject, [Parameter(Mandatory)][string]$name)
  if ($null -eq $InputObject) { return $null }
  if ($InputObject -is [System.Collections.IDictionary]) {
    if ($InputObject.Contains($name)) { return $InputObject[$name] }
    return $null
  }
  $prop = $InputObject.PSObject.Properties[$name]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

function Invoke-GraphGetAll {
  # Follows @odata.nextLink. A single page silently truncating the answer is exactly the kind
  # of quiet wrongness this script exists to avoid.
  param([Parameter(Mandatory)][string]$uri)
  $out = New-Object System.Collections.Generic.List[object]
  $next = $uri
  while ($next) {
    $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
    foreach ($v in @(Get-GraphProperty -InputObject $page -name 'value')) { [void]$out.Add($v) }
    $next = "$(Get-GraphProperty -InputObject $page -name '@odata.nextLink')"
    if (-not $next) { break }
  }
  return $out
}

function ConvertFrom-Payload {
  param([Parameter()][AllowNull()][object]$payload)
  if (-not $payload) { return '' }
  try { return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$payload")) } catch { return '' }
}

function Get-TopLevelIdentifier {
  # XPath, not the XML property adapter: "$x.plist.dict" throws under StrictMode and the
  # failure reads as "nothing found" rather than as an error.
  param([Parameter(Mandatory)][string]$text)
  try {
    [xml]$x = $text
    $key = $x.SelectSingleNode("/plist/dict/key[.='PayloadIdentifier']")
    if ($null -eq $key) { return $null }
    $node = $key.NextSibling
    while ($null -ne $node -and $node.NodeType -ne [System.Xml.XmlNodeType]::Element) { $node = $node.NextSibling }
    if ($null -eq $node) { return $null }
    return $node.InnerText
  }
  catch { return $null }
}

function Get-AssignmentSummary {
  param([Parameter()][AllowNull()][object]$assignments)
  $items = @($assignments)
  if (-not $items.Count) { return 'UNASSIGNED' }
  $parts = foreach ($a in $items) {
    $t = Get-GraphProperty -InputObject $a -name 'target'
    switch ("$(Get-GraphProperty -InputObject $t -name '@odata.type')") {
      '#microsoft.graph.allDevicesAssignmentTarget'       { 'All devices' }
      '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All users' }
      '#microsoft.graph.groupAssignmentTarget'            { "group:$(Get-GraphProperty -InputObject $t -name 'groupId')" }
      '#microsoft.graph.exclusionGroupAssignmentTarget'   { "EXCLUDE:$(Get-GraphProperty -InputObject $t -name 'groupId')" }
      default                                              { "$(Get-GraphProperty -InputObject $t -name '@odata.type')" }
    }
  }
  return (@($parts) -join ' + ')
}

#endregion

#region Connect -- read-only

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

# Read scopes only. This script must never be capable of changing anything, so there is no
# -WhatIf and no write scope to request.
$requiredScopes = @(
  'DeviceManagementConfiguration.Read.All',
  'DeviceManagementScripts.Read.All'
)

$ctx = $null
try { $ctx = Get-MgContext } catch { $ctx = $null }
$needConnect = $true
if ($null -ne $ctx -and $ctx.Scopes) {
  if (@($requiredScopes | Where-Object { $_ -notin $ctx.Scopes }).Count -eq 0) { $needConnect = $false }
}
if ($needConnect) {
  $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
  if ($TenantId) { $connectParams.TenantId = $TenantId }
  Connect-MgGraph @connectParams | Out-Null
  $ctx = Get-MgContext
}
if ($null -eq $ctx -or -not $ctx.Account -or -not $ctx.TenantId) { throw 'Not connected to Microsoft Graph.' }

Write-Output "Live read of tenant $($ctx.TenantId) as $($ctx.Account)"
Write-Output "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') local"
Write-Output ''

#endregion

#region macOS custom profiles

$all = Invoke-GraphGetAll -uri "$graphBase/deviceManagement/deviceConfigurations"
$macCustom = @($all | Where-Object { "$(Get-GraphProperty -InputObject $_ -name '@odata.type')" -eq '#microsoft.graph.macOSCustomConfiguration' })

$profiles = @()
foreach ($c in $macCustom) {
  $id = "$(Get-GraphProperty -InputObject $c -name 'id')"
  $payload = Get-GraphProperty -InputObject $c -name 'payload'
  if (-not $payload) {
    $payload = Get-GraphProperty -InputObject (Invoke-MgGraphRequest -Method GET -Uri "$graphBase/deviceManagement/deviceConfigurations/$id" -OutputType PSObject) -name 'payload'
  }
  $text = ConvertFrom-Payload -payload $payload
  $auo = if ($text -match '<key>AllowUserOverrides</key>\s*<(true|false)\s*/>') { $Matches[1] } else { $null }
  $profiles += [pscustomobject]@{
    Id          = $id
    DisplayName = "$(Get-GraphProperty -InputObject $c -name 'displayName')"
    TopId       = if ($text) { Get-TopLevelIdentifier -text $text } else { $null }
    AllowUserOverrides = $auo
    HasDlpEnforce = ($text -match '<key>unallowedBrowserMode</key>\s*<string>enforce</string>') -and
                    ($text -match '<key>pasteToBrowserMode</key>\s*<string>enforce</string>')
    Text        = $text
  }
}

Write-Output "macOS custom profiles: $($profiles.Count)"
Write-Output ''

Write-Output '--- PayloadIdentifier collisions ---'
$groups = @($profiles | Where-Object { $_.TopId } | Group-Object TopId | Where-Object { $_.Count -gt 1 })
if ($Identifier) { $groups = @($groups | Where-Object { $_.Name -eq $Identifier }) }

if (-not $groups.Count) {
  Write-Output '  none'
}
foreach ($g in $groups) {
  Write-Output "  $($g.Name)  -- $($g.Count) profiles"
  foreach ($p in $g.Group) {
    $asn = Get-AssignmentSummary -assignments (Invoke-GraphGetAll -uri "$graphBase/deviceManagement/deviceConfigurations/$($p.Id)/assignments")
    Write-Output ("      {0,-56} AUO={1,-7} {2}" -f $p.DisplayName, ($p.AllowUserOverrides ?? 'n/a'), $asn)
  }
}
Write-Output ''

Write-Output '--- AllowUserOverrides across all macOS profiles that set it ---'
foreach ($p in @($profiles | Where-Object { $_.AllowUserOverrides } | Sort-Object AllowUserOverrides, DisplayName)) {
  $flag = if ($p.AllowUserOverrides -eq 'true') { '  <== users can approve extensions' } else { '' }
  Write-Output ("  {0,-8} {1}{2}" -f $p.AllowUserOverrides, $p.DisplayName, $flag)
}
Write-Output ''

Write-Output '--- Purview DLP browser enforcement (unallowedBrowserMode / pasteToBrowserMode) ---'
$withDlp = @($profiles | Where-Object { $_.HasDlpEnforce })
if ($withDlp.Count) { foreach ($p in $withDlp) { Write-Output "  enforce  $($p.DisplayName)" } }
else { Write-Output '  NOT SET on any profile -- DLP browser protection relies on an undeclared default' }
Write-Output ''

#endregion

#region Shell scripts

Write-Output '--- macOS shell scripts ---'
# $expand from the PARENT entity. Requesting the assignments child collection directly --
# deviceShellScripts/{id}/assignments -- returns 400 "No method match route template". Several
# Intune endpoints behave this way; the parent-side expand is the form that works.
$scripts = Invoke-GraphGetAll -uri "$graphBase/deviceManagement/deviceShellScripts?`$expand=assignments"
$unassigned = 0
foreach ($s in @($scripts | Sort-Object { "$(Get-GraphProperty -InputObject $_ -name 'displayName')" })) {
  $asn = Get-AssignmentSummary -assignments (Get-GraphProperty -InputObject $s -name 'assignments')
  if ($asn -eq 'UNASSIGNED') { $unassigned++ }
  Write-Output ("  {0,-62} {1,-7} {2}" -f "$(Get-GraphProperty -InputObject $s -name 'displayName')",
    "$(Get-GraphProperty -InputObject $s -name 'executionFrequency')", $asn)
}
Write-Output ''
if ($unassigned) {
  Write-Warning "$unassigned shell script(s) are UNASSIGNED and will never run. An unassigned script reports nothing, which looks identical to one that is passing."
  Write-Output ''
}

#endregion

#region Compliance

Write-Output '--- macOS compliance policies ---'
$comp = Invoke-GraphGetAll -uri "$graphBase/deviceManagement/deviceCompliancePolicies"
foreach ($c in @($comp | Where-Object { "$(Get-GraphProperty -InputObject $_ -name '@odata.type')" -match '(?i)macos' })) {
  $id = "$(Get-GraphProperty -InputObject $c -name 'id')"
  $min = "$(Get-GraphProperty -InputObject $c -name 'osMinimumVersion')"
  $asn = Get-AssignmentSummary -assignments (Invoke-GraphGetAll -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$id/assignments")
  Write-Output ("  {0,-44} osMin={1,-10} {2}" -f "$(Get-GraphProperty -InputObject $c -name 'displayName')", $(if ($min) { $min } else { '-' }), $asn)
}
Write-Output ''

Write-Output '--- assignment filters ---'
foreach ($f in @(Invoke-GraphGetAll -uri "$graphBase/deviceManagement/assignmentFilters")) {
  $plat = "$(Get-GraphProperty -InputObject $f -name 'platform')"
  if ($plat -notmatch '(?i)mac') { continue }
  Write-Output ("  {0,-30} {1}" -f "$(Get-GraphProperty -InputObject $f -name 'displayName')", "$(Get-GraphProperty -InputObject $f -name 'rule')")
}

#endregion
