<#
.SYNOPSIS
Applies a completed policy-name-proposal.csv: renames each policy, stamps its original name
into the description, and writes a rename map.

.DESCRIPTION
Reads the sheet produced by New-PolicyNameProposal.ps1 after you have filled in ProposedName,
and for each actionable row:

  1. Renames the policy ('name' for Settings Catalog, 'displayName' for everything else).
  2. APPENDS the original name to the policy description, so the provenance lives in Intune
     where whoever opens the policy at 2am will find it -- not only in a log on one machine.
  3. Records the change in rename-map-<date>.csv.

A row is acted on only when ProposedName is filled in beyond the pre-filled platform prefix
and differs from the current name. Leave a row as just 'Windows: ', or blank it, to skip.

Safety:
  - The plan is rebuilt from LIVE policy state, never assumed from the sheet, so a stale sheet
    cannot rename something twice or rename the wrong thing.
  - A row whose live name no longer matches the sheet's CurrentName is skipped and reported.
  - Proposed names are checked for collisions against every other name in the sheet before
    anything is written.
  - Comparisons are case-SENSITIVE. PowerShell's default -eq would treat 'iOS: Mail' and
    'ios: Mail' as equal and silently report a no-op as a success.
  - The description stamp is idempotent; re-running does not append it twice.
  - Under -WhatIf only READ scopes are requested, so a dry run never asks you to grant write
    access.

.PARAMETER ProposalPath
The completed CSV. Defaults to policy-name-proposal.csv in the newest export folder.

.PARAMETER RenameMapPath
Where to write the rename map. Defaults to rename-map-<date>.csv beside the proposal.

.PARAMETER SkipDescriptionStamp
Rename without touching the description.

.PARAMETER tenantId
Optional tenant id or domain for authentication.

.EXAMPLE
./Invoke-PolicyRename.ps1 -WhatIf

Shows every rename and description stamp it would make. Writes nothing, and asks only for
read access.

.EXAMPLE
./Invoke-PolicyRename.ps1

Applies the sheet.

.NOTES
Requires DeviceManagementConfiguration.ReadWrite.All, plus the Apps / Scripts / ServiceConfig
equivalents when those policy types are in the sheet.

Renaming changes the exported filename; the next export run cleans up the old file.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ProposalPath,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$RenameMapPath,

  [Parameter()]
  [switch]$SkipDescriptionStamp,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$tenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'
$stampDate = Get-Date -Format 'yyyy-MM-dd'

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

function Get-ProvenanceStamp {
  param([Parameter(Mandatory = $true)][string]$originalName)
  return "[Renamed $stampDate - previously: ""$originalName""]"
}

function Add-ProvenanceStamp {
  <#
    Append, never replace: 69 of these policies already carry a description written by a
    human. Idempotent -- a stamp naming this same original is not added twice, so re-running
    the sheet is safe.
  #>
  param(
    [Parameter()][AllowNull()][string]$existingDescription,
    [Parameter(Mandatory = $true)][string]$originalName
  )

  $stamp = Get-ProvenanceStamp -originalName $originalName
  $existing = if ($null -eq $existingDescription) { '' } else { $existingDescription }

  # .Contains, not -like: policy names contain square brackets ('[disabled] macOS: ...') and
  # -like reads those as a wildcard character class, so the stamp never matches its own text.
  # That produced both a duplicate stamp and a false "stamp did not persist" warning.
  if ($existing.Contains("previously: ""$originalName""")) { return $null }   # already stamped

  if ([string]::IsNullOrWhiteSpace($existing)) { return $stamp }
  return ($existing.TrimEnd() + "`n`n" + $stamp)
}

#endregion

#region Load the sheet

if (-not $ProposalPath) {
  $exportRoot = Join-Path $PSScriptRoot 'exports'
  if (-not (Test-Path -LiteralPath $exportRoot)) { throw "No -ProposalPath given and no exports folder at $exportRoot." }
  $candidate = Get-ChildItem -LiteralPath $exportRoot -Recurse -File -Filter 'policy-name-proposal.csv' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $candidate) { throw "No policy-name-proposal.csv found under $exportRoot. Run New-PolicyNameProposal.ps1 first." }
  $ProposalPath = $candidate.FullName
}
# [System.IO.Path]::GetDirectoryName rather than Split-Path: -LiteralPath and -Parent are in
# different Split-Path parameter sets and cannot be combined, and plain -Path would treat
# square brackets in a folder name as wildcards.
if (-not $RenameMapPath) { $RenameMapPath = Join-Path ([System.IO.Path]::GetDirectoryName($ProposalPath)) "rename-map-$stampDate.csv" }

$sheet = @(Import-Csv -LiteralPath $ProposalPath)
if (-not $sheet.Count) { throw "Proposal sheet is empty: $ProposalPath" }

foreach ($required in 'ProposedName', 'CurrentName', 'Category', 'PolicyId') {
  if ($sheet[0].PSObject.Properties[$required] -eq $null) {
    throw "Proposal sheet is missing the '$required' column. Regenerate it with New-PolicyNameProposal.ps1."
  }
}

if ($WhatIfPreference) {
  Write-Host ''
  Write-Host '  ===============================================================' -ForegroundColor Cyan
  Write-Host '   DRY RUN (-WhatIf). Nothing will be changed.' -ForegroundColor Cyan
  Write-Host '   Read-only Graph scopes are requested; no write consent needed.' -ForegroundColor Cyan
  Write-Host '  ===============================================================' -ForegroundColor Cyan
  Write-Host ''
}

Write-Output "Proposal   : $ProposalPath"
Write-Output "Rows       : $($sheet.Count)"
Write-Output "Rename map : $RenameMapPath"
Write-Output ''

#endregion

#region Select actionable rows

# A row is actionable only when the descriptive half has actually been written. The sheet
# arrives pre-filled with 'Windows: ' and similar, so anything still matching that shape is
# an untouched row, not an instruction to rename a policy to its bare platform.
$actionable = @()
$notFilled = 0

foreach ($row in $sheet) {
  $proposed = "$($row.ProposedName)".Trim()
  $current = "$($row.CurrentName)"

  if (-not $proposed) { $notFilled++; continue }
  if ($proposed -match '^[A-Za-z/]+\s*[:\-]?\s*$') { $notFilled++; continue }   # prefix only
  if ($proposed -ceq $current) { $notFilled++; continue }

  $actionable += [pscustomobject]@{
    PolicyId = "$($row.PolicyId)"; Category = "$($row.Category)"
    CurrentName = $current; ProposedName = $proposed
  }
}

Write-Output "  rows with a completed name : $($actionable.Count)"
Write-Output "  rows left untouched        : $notFilled"
Write-Output ''

if (-not $actionable.Count) {
  Write-Output 'Nothing to do. Fill in ProposedName for the policies you want renamed.'
  return
}

# Collision check across the WHOLE sheet -- the sheet is the full inventory, so this catches
# both "two rows propose the same name" and "this name already belongs to another policy".
$allNames = @{}
foreach ($row in $sheet) {
  $n = "$($row.CurrentName)"
  if ($n) { if (-not $allNames.ContainsKey($n)) { $allNames[$n] = @() }; $allNames[$n] += "$($row.PolicyId)" }
}
$collisions = @()
$proposedSeen = @{}
foreach ($a in $actionable) {
  if ($allNames.ContainsKey($a.ProposedName) -and ($allNames[$a.ProposedName] -notcontains $a.PolicyId)) {
    $collisions += "'$($a.ProposedName)' is already the name of another policy"
  }
  if ($proposedSeen.ContainsKey($a.ProposedName)) {
    $collisions += "'$($a.ProposedName)' is proposed for more than one policy"
  }
  $proposedSeen[$a.ProposedName] = $true
}
if ($collisions.Count) {
  Write-Warning 'Name collisions in the sheet -- nothing has been changed. Fix these and re-run:'
  foreach ($c in ($collisions | Sort-Object -Unique)) { Write-Output "    $c" }
  return
}

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

$accessLevel = if ($WhatIfPreference) { 'Read' } else { 'ReadWrite' }
$requiredScopes = @("DeviceManagementConfiguration.$accessLevel.All")
$cats = @($actionable | ForEach-Object { $_.Category } | Sort-Object -Unique)
if ($cats -match 'App') { $requiredScopes += "DeviceManagementApps.$accessLevel.All" }
if ($cats -match 'Script') { $requiredScopes += "DeviceManagementScripts.$accessLevel.All" }
if ($cats -contains 'EnrollmentConfigurations') { $requiredScopes += "DeviceManagementServiceConfig.$accessLevel.All" }

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

#region Plan from live state

$plan = @()
$skipped = @()
$failed = @()
$index = 0

foreach ($a in $actionable) {
  $index++
  Write-Progress -Id 1 -Activity 'Checking current names' -Status ("{0} of {1}" -f $index, $actionable.Count) `
    -PercentComplete ([int](($index / $actionable.Count) * 100))

  if (-not $endpointMap.ContainsKey($a.Category)) {
    $failed += [pscustomobject]@{ Name = $a.CurrentName; Category = $a.Category; Reason = 'No endpoint mapping for this policy type' }
    continue
  }
  $endpoint = $endpointMap[$a.Category]
  $uri = "$graphBase/$($endpoint.Path)/$($a.PolicyId)"

  try { $live = Invoke-Graph -method GET -uri $uri }
  catch {
    $failed += [pscustomobject]@{ Name = $a.CurrentName; Category = $a.Category; Reason = "Read failed: $($_.Exception.Message)" }
    continue
  }

  $liveName = "$(Get-GraphProperty -InputObject $live -name $endpoint.NameProperty)"

  if ($liveName -ceq $a.ProposedName) {
    $skipped += [pscustomobject]@{ Name = $liveName; Category = $a.Category; Reason = 'Already has the proposed name' }
    continue
  }
  # The sheet is a snapshot. If the live name has moved on, do not overwrite whatever
  # somebody else did -- report it and let a human decide.
  if ($liveName -cne $a.CurrentName) {
    $skipped += [pscustomobject]@{ Name = $liveName; Category = $a.Category
      Reason = "Live name differs from the sheet (sheet said '$($a.CurrentName)') - sheet is stale"
    }
    continue
  }

  $plan += [pscustomobject]@{
    PolicyId = $a.PolicyId; Category = $a.Category; Uri = $uri
    NameProperty = $endpoint.NameProperty
    Old = $liveName; New = $a.ProposedName
    Description = "$(Get-GraphProperty -InputObject $live -name 'description')"
    OdataType = (Get-GraphProperty -InputObject $live -name '@odata.type')
  }
}
Write-Progress -Id 1 -Activity 'Checking current names' -Completed

Write-Output '--- Planned renames (current names read from Graph) ---'
if (-not $plan.Count) { Write-Output '  none' }
foreach ($g in $plan | Group-Object Category | Sort-Object Name) {
  Write-Output ("  {0}" -f $g.Name)
  foreach ($p in $g.Group | Sort-Object Old) { Write-Output ("      {0,-46} ->  {1}" -f $p.Old, $p.New) }
}
if ($skipped.Count) { Write-Output ("  ({0} skipped - see below)" -f $skipped.Count) }
Write-Output ''

#endregion

#region Apply

$renamed = @()

$index = 0
foreach ($p in $plan) {
  $index++
  Write-Progress -Id 1 -Activity 'Renaming policies' -Status ("{0} of {1}: {2}" -f $index, $plan.Count, $p.Old) `
    -PercentComplete ([int](($index / $plan.Count) * 100))

  $body = @{ $p.NameProperty = $p.New }
  if ($p.OdataType) { $body['@odata.type'] = $p.OdataType }

  $newDescription = $null
  if (-not $SkipDescriptionStamp) {
    $newDescription = Add-ProvenanceStamp -existingDescription $p.Description -originalName $p.Old
    if ($newDescription) { $body['description'] = $newDescription }
  }

  $action = if ($newDescription) { "Rename to '$($p.New)' and stamp previous name into the description" } else { "Rename to '$($p.New)'" }
  if (-not $PSCmdlet.ShouldProcess($p.Old, $action)) { continue }

  try {
    Invoke-Graph -method PATCH -uri $p.Uri -body $body | Out-Null
    $after = Invoke-Graph -method GET -uri $p.Uri
    $afterName = "$(Get-GraphProperty -InputObject $after -name $p.NameProperty)"

    # -ceq: a case-only rename that silently did not apply would read back as equal under the
    # default comparison and be reported as a success.
    if ($afterName -cne $p.New) {
      $failed += [pscustomobject]@{ Name = $p.Old; Category = $p.Category; Reason = "PATCH did not take (still '$afterName')" }
      continue
    }

    $stamped = $false
    if (-not $SkipDescriptionStamp) {
      # Verify against LIVE state, not against whether this run wrote anything.
      # Add-ProvenanceStamp returns $null when the description already carries a stamp for
      # this same original name -- that is the idempotent path, and it is a success. Gating
      # this check on $newDescription made every re-run report that every stamp had failed to
      # persist, which is the exact opposite of what had happened.
      $afterDescription = "$(Get-GraphProperty -InputObject $after -name 'description')"
      # .Contains for the same reason as above -- bracketed names break -like.
      $stamped = $afterDescription.Contains("previously: ""$($p.Old)""")
      if (-not $stamped) { Write-Warning "Renamed '$($p.Old)' but the description stamp did not persist." }
    }

    $renamed += [pscustomobject]@{
      Timestamp = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
      PolicyId  = $p.PolicyId; Category = $p.Category
      OldName   = $p.Old; NewName = $p.New
      Stamped   = $stamped; Operator = $ctx.Account
    }
  }
  catch {
    $failed += [pscustomobject]@{ Name = $p.Old; Category = $p.Category; Reason = $_.Exception.Message }
  }
}
Write-Progress -Id 1 -Activity 'Renaming policies' -Completed

#endregion

#region Report

if ($WhatIfPreference) {
  Write-Output '--- Dry run result ---'
  Write-Output ("  would rename : {0}" -f $plan.Count)
  Write-Output ("  would skip   : {0}" -f $skipped.Count)
  Write-Output ("  unreadable   : {0}" -f $failed.Count)
  Write-Output ''
  if ($plan.Count -and -not $SkipDescriptionStamp) {
    $sample = $plan[0]
    Write-Output '  Description stamp would look like:'
    Write-Output ("      {0}" -f (Get-ProvenanceStamp -originalName $sample.Old))
    Write-Output ''
  }
  Write-Host '  NOTHING WAS CHANGED. Re-run without -WhatIf to apply.' -ForegroundColor Cyan
  Write-Output ''
  if ($skipped.Count) {
    Write-Output '  Would skip:'
    foreach ($s in $skipped) { Write-Output ("      {0,-46} {1}" -f $s.Name, $s.Reason) }
  }
  return
}

if ($renamed.Count) {
  # UTF8BOM, not UTF8. This map is the audit record of what changed, it is opened in Excel, and
# it carries the ORIGINAL names verbatim -- some of which contain a curly apostrophe. Without a
# byte-order mark Excel decodes it as the system codepage and 'don't' becomes 'donâ€™t', in the
# one file whose whole job is to say exactly what the old name was.
$renamed | Export-Csv -LiteralPath $RenameMapPath -NoTypeInformation -Encoding UTF8BOM
}

Write-Output '--- Result ---'
Write-Output ("  renamed : {0}" -f $renamed.Count)
Write-Output ("  skipped : {0}" -f $skipped.Count)
Write-Output ("  failed  : {0}" -f $failed.Count)
Write-Output ''

if ($renamed.Count) {
  Write-Output "  Rename map written to: $RenameMapPath"
  $unstamped = @($renamed | Where-Object { -not $_.Stamped })
  if ($unstamped.Count -and -not $SkipDescriptionStamp) {
    Write-Warning "$($unstamped.Count) policy/policies were renamed but their description stamp did not persist."
  }
  Write-Output ''
}

if ($skipped.Count) {
  Write-Output '  Skipped:'
  foreach ($s in $skipped) { Write-Output ("      {0,-46} {1}" -f $s.Name, $s.Reason) }
  Write-Output ''
}

if ($failed.Count) {
  Write-Warning "$($failed.Count) rename(s) failed:"
  foreach ($x in $failed) { Write-Output ("      [{0}] {1}: {2}" -f $x.Category, $x.Name, $x.Reason) }
  Write-Output ''
}

Write-Output 'Next: re-run Export-DeviceConfigurations.ps1 and Analyze-PolicyOverlap.ps1 to confirm.'

#endregion
