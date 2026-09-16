<#
Generates an overlap/conflict report for exported Intune policies.
Looks at assignments and settings to highlight when the same target receives
multiple policies that touch the same setting with different values (conflict)
or identical values (overlap/duplication).

Consumes the artefacts written by Export-DeviceConfigurations.ps1:
  export-manifest.json      what the export actually fetched, and what failed
  setting-definitions.json  Settings Catalog id -> display name / type / options
  assignment-filters.json   every filter in the tenant, including unused ones
  role-scope-tags.json      scope tag id -> name

Usage:
  pwsh ./Analyze-PolicyOverlap.ps1 -ExportRoot ./exports -TenantId <tenantGuid>
                                    -ExportDate 2026-01-29
Params are optional; the script will pick the first tenant folder and the most
recent date folder when omitted.
#>
[CmdletBinding()]
param(
  [string]$ExportRoot = (Join-Path $PSScriptRoot 'exports'),
  [string]$TenantId,
  [string]$ExportDate,
  [string[]]$ComparePolicies,
  [string]$OutputJson,
  [string]$OutputText,
  [string]$OutputMarkdown,

  # Policy families whose settings are compared. Types outside this list are
  # inventoried but not compared -- see $analyzableCategories below.
  [string[]]$AnalyzeCategories,

  # Compare every exported folder, including inventory-only types. Off by default:
  # enrollment configs, update rings and scripts have their own priority and
  # ordering semantics that setting-level overlap comparison does not model, so
  # including them manufactures findings out of scaffolding.
  [switch]$IncludeInventoryOnly,

  # Treat policies carrying different role scope tags as separate administrative
  # domains: they are reported, but demoted out of the headline conflict counts.
  [switch]$SeparateByScopeTag
)

#Set-StrictMode -Version 3
#$ErrorActionPreference = 'Stop'

# Policy families where a shared setting key genuinely means the same thing, so
# comparing values across policies is meaningful. Everything else is exported for
# inventory only. Overridden by -AnalyzeCategories / -IncludeInventoryOnly, and by
# the AnalyzedTypes list in export-manifest.json when one is present.
$defaultAnalyzableCategories = @(
  'DeviceConfigurations',
  'ConfigurationPolicies',
  'GroupPolicyConfigurations',
  'EndpointSecurityPolicies',
  'CompliancePolicies',
  'AppProtectionPolicies'
)

# Keys to always skip when flattening — metadata and Graph API scaffolding that
# carries no configurable setting value.
$metadataKeys = @(
  '@odata.context', '@odata.type', 'id', 'displayName', 'name', 'description',
  'createdDateTime', 'lastModifiedDateTime', 'version', 'roleScopeTagIds',
  'priorityMetaData', 'settingCount', 'platforms', 'technologies',
  'templateReference', 'supportsScopeTags', 'supportsDeviceScope',
  'isAssigned', 'payloadFileName', 'payloadName', 'creationSource',
  # Nested structural noise
  'settingValueTemplateReference', 'settingInstanceTemplateReference',
  'settingDefinitionId', '@odata.count',
  # Expanded Settings Catalog definitions. These are reference metadata (display
  # names, allowed options, defaults) harvested into setting-definitions.json —
  # flattening them would explode definition text into the comparison space.
  'settingDefinitions',
  # Already handled by type-aware extractors
  'settings', 'definitionValues', 'omaSettings', 'scheduledActionsForRule',
  # Template/assignment metadata present on intents
  'templateId', 'templateName', 'templateType', 'platformType',
  # Export-generated metadata (not real Intune settings)
  '_payloadHash', '_payloadTypes', '_payloadError', '_templateName',
  '_templateFamily', '_templateDisplayName', '_roleScopeTags', '_statusOverview',
  '_payloadIdentifier', '_payloadUUID', '_payloadParseError'
)

# ── Naming convention ──────────────────────────────────────────────────────────────────
# Derived from what this tenant already does, not imposed: 'macOS' is already used
# consistently, so it is canonical; Windows is split across Windows/Win/Win1x/Win10/Win11,
# with 'Windows' the plurality. Edit this table to change the house style -- the naming
# check reads it rather than hard-coding any convention.
$namingConvention = @{
  # Canonical prefix -> lower-case variants that should be renamed to it.
  CanonicalPlatforms = [ordered]@{
    'macOS'   = @('macos', 'mac os', 'mac', 'osx', 'os x')
    'Windows' = @('win', 'win1x', 'win10', 'win11', 'windows10', 'windows11', 'w10', 'w11')
    'iOS'     = @('ios')
    'iPadOS'  = @('ipados')
    'Android' = @('android')
  }
  # A retired policy should be findable by name. One marker, consistently applied.
  DisabledMarkers    = @('[disabled]', 'DISABLED', '(old)', 'deprecated', 'do not use', 'unused')
  PreferredMarker    = '[disabled]'
}

# Extractor-generated context keys. These are emitted deliberately by the custom-profile
# extractor for reporting, but they describe the profile rather than configure anything,
# so they are stripped before settings enter the comparison space.
$syntheticKeys = @('_payloadHash', '_payloadTypes', '_payloadError', '_templateName')

# Compliance settings that report device STATE rather than push a setting. A configuration
# profile cannot enforce these -- they are attestation/health results -- so the absence of a
# matching config profile is not a gap, and reporting it as one buries the real gaps.
$attestationOnlyComplianceSettings = @(
  'secureBootEnabled', 'codeIntegrityEnabled', 'systemIntegrityProtectionEnabled',
  'securityBlockJailbrokenDevices', 'deviceThreatProtectionEnabled',
  'deviceThreatProtectionRequiredSecurityLevel', 'osMinimumVersion', 'osMaximumVersion',
  'earlyLaunchAntiMalwareDriverEnabled', 'tpmRequired', 'defenderEnabled',
  'rtpEnabled', 'antivirusRequired', 'antiSpywareRequired', 'activeFirewallRequired',
  'deviceCompliancePolicyScript', 'validOperatingSystemBuildRanges'
)

# Compliance checks whose enforcement lives in another policy family under a different
# setting name. The analyzer matches settings textually, so without this map a compliance
# check for bitLockerEnabled looks unenforced even when an Endpoint Security disk
# encryption policy enforces exactly that. Values are regex fragments matched against the
# setting keys of configuration policies assigned to the same target.
$complianceEnforcementEquivalents = @{
  'bitLockerEnabled'                      = 'bitlocker|requiredeviceencryption|encryptionmethod'
  'storageRequireEncryption'              = 'bitlocker|requiredeviceencryption|encryptionmethod|filevault'
  'firewallEnabled'                       = 'firewall'
  'firewallBlockAllIncoming'              = 'firewall'
  'passwordRequired'                      = 'devicelock|password|passcode'
  'passwordBlockSimple'                   = 'devicelock|password|passcode|simple'
  'passwordMinimumLength'                 = 'minimumpasswordlength|passwordminimumlength|maxpinlength|minpinlength'
  'passwordMinutesOfInactivityBeforeLock' = 'inactivity|screenlock|maxinactivity|screentimeout'
  'passwordPreviousPasswordBlockCount'    = 'passwordhistory|previouspassword'
  'passwordRequiredToUnlockFromIdle'      = 'inactivity|screenlock|devicelock'
  'passcodeExpirationDays'                = 'passwordexpiration|passcodeexpiration'
  'passwordExpirationDays'                = 'passwordexpiration|passcodeexpiration'
}

function Write-TextFile {
  <#
    Write UTF-8 text without a BOM, via .NET rather than Set-Content/Out-File.

    Their -Encoding parameter is a portability hazard: Windows PowerShell 5.1 and
    PowerShell 7 disagree on whether 'utf8' emits a BOM, and either cmdlet can be shadowed
    by a proxy function that has no -Encoding parameter at all (failing at runtime with
    "A parameter cannot be found that matches parameter name 'Encoding'").
  #>
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Content
  )
  $text = if ($null -eq $Content) { '' } else { $Content }
  [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-PropertyValue {
  param(
    [object]$Object,
    [string]$Name
  )

  if ($null -eq $Object) { return $null }
  if ($Object -is [psobject] -and $Object.PSObject.Properties[$Name]) {
    return $Object.$Name
  }
  return $null
}

function Get-ExportPath {
  param(
    [string]$Root,
    [string]$Tenant,
    [string]$Date
  )

  if (-not (Test-Path -Path $Root)) {
    throw "Export root not found: $Root"
  }

  $tenantPath = if ($Tenant) {
    Join-Path $Root $Tenant
  }
  else {
    (Get-ChildItem -Path $Root -Directory | Select-Object -First 1).FullName
  }

  if (-not $tenantPath -or -not (Test-Path -Path $tenantPath)) {
    throw "Tenant folder not found under $Root"
  }

  $datePath = if ($Date) {
    Join-Path $tenantPath $Date
  }
  else {
    (Get-ChildItem -Path $tenantPath -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
  }

  if (-not $datePath -or -not (Test-Path -Path $datePath)) {
    throw "Export date folder not found under $tenantPath"
  }

  return $datePath
}

function Read-JsonFileIfPresent {
  param(
    [string]$Path,
    [string]$Label
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Verbose "$Label not found at $Path"
    return $null
  }

  try {
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  }
  catch {
    Write-Warning "Failed to read $Label ($Path): $($_.Exception.Message)"
    return $null
  }
}

function Get-SettingDefinitionIndex {
  <#
    setting-definitions.json is a shared dictionary keyed by settingDefinitionId. It is
    emitted once per export rather than inline per policy, because the same definition
    blob repeats for every policy touching that setting.

    Returns id -> { DisplayName, CategoryId, Description, OptionMap }, where OptionMap
    translates a raw choice value ("...bitlocker_requiredeviceencryption_1") into its
    human label ("Enabled"). Without this the report can compare values but cannot say
    what they mean.
  #>
  param([object]$Definitions)

  $index = @{}
  if ($null -eq $Definitions) { return $index }

  foreach ($prop in $Definitions.PSObject.Properties) {
    $def = $prop.Value
    if ($null -eq $def) { continue }

    $optionMap = @{}
    $options = Get-PropertyValue -Object $def -Name 'options'
    if ($options) {
      foreach ($opt in @($options)) {
        $optValue = Get-PropertyValue -Object $opt -Name 'itemId'
        $optName = Get-PropertyValue -Object $opt -Name 'displayName'
        if ($optValue -and $optName) { $optionMap["$optValue"] = $optName }
      }
    }

    $index[$prop.Name] = [pscustomobject]@{
      DisplayName = Get-PropertyValue -Object $def -Name 'displayName'
      CategoryId  = Get-PropertyValue -Object $def -Name 'categoryId'
      Description = Get-PropertyValue -Object $def -Name 'description'
      OdataType   = Get-PropertyValue -Object $def -Name '@odata.type'
      OptionMap   = $optionMap
    }
  }

  return $index
}

function Get-SettingKeyForDefinition {
  <#
    Build the comparison key for a Settings Catalog setting. The key must stay stable
    across policies (it is what groups two policies onto the same setting), so the raw
    settingDefinitionId tail remains the identity and the display name is only appended
    for readability.
  #>
  param(
    [string]$DefinitionId,
    [hashtable]$DefinitionIndex
  )

  if (-not $DefinitionId) { return $null }

  $shortId = ($DefinitionId -split '_' | Select-Object -Last 2) -join '/'

  if ($DefinitionIndex -and $DefinitionIndex.ContainsKey($DefinitionId)) {
    $name = $DefinitionIndex[$DefinitionId].DisplayName
    if ($name) { return "$shortId ($name)" }
  }

  return $shortId
}

function Resolve-ChoiceLabel {
  # Translate a raw choice value to its display label when the definition is known.
  param(
    [string]$DefinitionId,
    [object]$RawValue,
    [hashtable]$DefinitionIndex
  )

  if ($null -eq $RawValue) { return $null }
  $text = "$RawValue"

  if ($DefinitionId -and $DefinitionIndex -and $DefinitionIndex.ContainsKey($DefinitionId)) {
    $map = $DefinitionIndex[$DefinitionId].OptionMap
    if ($map -and $map.ContainsKey($text)) {
      return $map[$text]
    }
  }

  # Fall back to the tail token of the enum URI.
  return ($text -split '_')[-1]
}

function Get-ComplianceActionSummary {
  <#
    Grace period and the action taken on non-compliance. A "compliance gap" means
    something very different when the action is "mark non-compliant after 7 days"
    versus "retire the device immediately", so findings carry this as context.
  #>
  param([object]$Policy)

  $rules = Get-PropertyValue -Object $Policy -Name 'scheduledActionsForRule'
  if (-not $rules) { return $null }

  $actions = @()
  foreach ($rule in @($rules)) {
    $configs = Get-PropertyValue -Object $rule -Name 'scheduledActionConfigurations'
    foreach ($cfg in @($configs)) {
      if ($null -eq $cfg) { continue }
      $actionType = Get-PropertyValue -Object $cfg -Name 'actionType'
      if (-not $actionType) { continue }
      $actions += [pscustomobject]@{
        ActionType       = $actionType
        GracePeriodHours = Get-PropertyValue -Object $cfg -Name 'gracePeriodHours'
      }
    }
  }

  if (-not $actions.Count) { return $null }

  $summary = @($actions | ForEach-Object {
      if ($null -ne $_.GracePeriodHours -and $_.GracePeriodHours -gt 0) {
        '{0} after {1}h' -f $_.ActionType, $_.GracePeriodHours
      }
      else {
        '{0} immediately' -f $_.ActionType
      }
    }) -join '; '

  return [pscustomobject]@{
    Actions = $actions
    Summary = $summary
    # An immediate block/retire is materially more dangerous than a delayed one.
    IsImmediateBlock = [bool](@($actions | Where-Object {
          $_.ActionType -in @('block', 'retire', 'remoteLock') -and
          (($null -eq $_.GracePeriodHours) -or ($_.GracePeriodHours -le 0))
        }).Count)
  }
}

function Get-ComplianceComparison {
  <#
    Compare a configuration value against what a compliance policy requires, respecting the
    setting's direction. A straight equality test is wrong for threshold settings: a config
    pushing a 6-character passcode against a compliance minimum of 4 is STRONGER than
    required, not a violation, whereas a password expiry of 65535 days against a compliance
    maximum of 730 is weaker and genuinely fails the check.

    Returns Stronger | Equal | Weaker | Unknown.
  #>
  param(
    [string]$SettingPath,
    [object]$ComplianceValue,
    [object]$ConfigValue
  )

  $c = 0.0; $g = 0.0
  $numeric = [double]::TryParse("$ComplianceValue", [ref]$c) -and [double]::TryParse("$ConfigValue", [ref]$g)

  if (-not $numeric) {
    if ("$ComplianceValue" -eq "$ConfigValue") { return 'Equal' }
    # Booleans: config true against a compliance requirement of true is equal; anything
    # else that differs on a non-numeric setting cannot be ranked.
    return 'Unknown'
  }

  if ($c -eq $g) { return 'Equal' }

  $leaf = ($SettingPath -split '/')[-1]

  # Higher is stronger: minimum lengths, history depth, required counts.
  $higherIsStronger = $leaf -match '(?i)minimum|minlength|blockcount|history|required.*count'
  # Lower is stronger: expiry windows, idle timeouts, maximums, grace periods.
  $lowerIsStronger = $leaf -match '(?i)expiration|expiry|inactivity|timeout|maximum|maxminutes|graceperiod|before'

  if ($higherIsStronger -and -not $lowerIsStronger) {
    return $(if ($g -gt $c) { 'Stronger' } else { 'Weaker' })
  }
  if ($lowerIsStronger -and -not $higherIsStronger) {
    return $(if ($g -lt $c) { 'Stronger' } else { 'Weaker' })
  }

  return 'Unknown'
}

function Test-ComplianceEnforcedElsewhere {
  <#
    Is this compliance check enforced by a configuration policy on the same target, under a
    different setting name? Settings are matched textually, so a compliance check for
    bitLockerEnabled never lines up with a Settings Catalog key like
    bitlocker/requiredeviceencryption, and the check looks unenforced when it is not.
  #>
  param(
    [string]$SettingPath,
    [object[]]$ConfigRecords,
    [hashtable]$EquivalenceMap
  )

  $leaf = ($SettingPath -split '/')[-1]
  if (-not $EquivalenceMap.ContainsKey($leaf)) { return $null }

  $pattern = $EquivalenceMap[$leaf]
  foreach ($r in @($ConfigRecords)) {
    if ($r.SettingPath -match $pattern) {
      return [pscustomobject]@{ PolicyName = $r.PolicyName; PolicyId = $r.PolicyId; SettingPath = $r.SettingPath }
    }
  }
  return $null
}

function Get-PolicyScopeTagKey {
  # Stable key for the set of scope tags on a policy, for administrative-domain grouping.
  param([object]$Policy)

  $tags = Get-PropertyValue -Object $Policy -Name '_roleScopeTags'
  if ($tags) {
    $names = @(@($tags) | ForEach-Object {
        $n = Get-PropertyValue -Object $_ -Name 'displayName'
        if ($n) { $n } else { Get-PropertyValue -Object $_ -Name 'id' }
      } | Where-Object { $_ }) | Sort-Object -Unique
    if ($names.Count) { return ($names -join ',') }
  }

  $ids = Get-PropertyValue -Object $Policy -Name 'roleScopeTagIds'
  if ($ids) {
    return (@($ids) | Sort-Object -Unique) -join ','
  }

  return 'Default'
}

function Get-NamingFindings {
  <#
    Naming-convention pass over every exported policy.

    Deliberately kept out of the risk counts: an inconsistent name is untidy, not dangerous,
    and inflating the headline numbers with hygiene would undo the work of making those
    numbers trustworthy. The one exception is a policy whose name says it is retired while it
    is still assigned -- that is a genuine trap and is reported as a risk.

    Intune's own built-in objects are excluded. The five enrollment configurations Microsoft
    ships are all literally named "All users and all devices", which would otherwise be the
    first thing a duplicate-name check reports.
  #>
  param(
    [object[]]$Policies,          # { PolicyId, DisplayName, Category, IsAssigned }
    [hashtable]$Convention
  )

  $aliasLookup = @{}
  foreach ($canonical in $Convention.CanonicalPlatforms.Keys) {
    foreach ($alias in $Convention.CanonicalPlatforms[$canonical]) { $aliasLookup[$alias] = $canonical }
  }

  $nonCanonical = @()
  $disabledButAssigned = @()
  $markerUsage = @{}

  foreach ($p in @($Policies)) {
    $name = "$($p.DisplayName)"
    if (-not $name) { continue }
    # Intune built-ins carry a _Default* suffix on the id and are not ours to rename.
    if ("$($p.PolicyId)" -match '_Default|_WindowsRestore') { continue }

    # Leading token, ignoring any disabled marker.
    $stripped = $name
    foreach ($m in $Convention.DisabledMarkers) {
      $stripped = $stripped -replace ('^\s*' + [regex]::Escape($m) + '\s*'), ''
    }
    if ($stripped -match '^\s*([A-Za-z0-9]+)\s*[:\-_ ]') {
      $token = $Matches[1]
      $canonical = $aliasLookup[$token.ToLowerInvariant()]
      if ($canonical -and $token -cne $canonical) {
        $nonCanonical += [pscustomobject]@{
          PolicyName = $name; PolicyId = $p.PolicyId; Category = $p.Category
          Found = $token; Expected = $canonical
        }
      }
    }

    # Which retirement marker is in use, and is anything marked-but-live?
    foreach ($m in $Convention.DisabledMarkers) {
      if ($name -match ('(?i)' + [regex]::Escape($m))) {
        if (-not $markerUsage.ContainsKey($m)) { $markerUsage[$m] = 0 }
        $markerUsage[$m]++
        if ($p.IsAssigned) {
          $disabledButAssigned += [pscustomobject]@{
            PolicyName = $name; PolicyId = $p.PolicyId; Category = $p.Category; Marker = $m
          }
        }
        break
      }
    }
  }

  $duplicates = @()
  foreach ($g in @($Policies | Where-Object { $_.DisplayName -and ("$($_.PolicyId)" -notmatch '_Default|_WindowsRestore') } | Group-Object DisplayName)) {
    if ($g.Count -lt 2) { continue }
    $duplicates += [pscustomobject]@{
      DisplayName = $g.Name
      Count       = $g.Count
      Policies    = @($g.Group | Select-Object PolicyId, Category)
    }
  }

  return [pscustomobject]@{
    NonCanonicalPrefix  = $nonCanonical
    DuplicateNames      = $duplicates
    DisabledButAssigned = $disabledButAssigned
    MarkersInUse        = @($markerUsage.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        [pscustomobject]@{ Marker = $_.Key; Count = $_.Value }
      })
  }
}

function Get-ProfileIdentity {
  <#
    Profile-level identity for a custom configuration profile.

    macOS keys an installed profile by its top-level PayloadIdentifier: two profiles sharing
    one REPLACE each other on the device rather than merging, which no amount of
    setting-value comparison can detect. Newer exports promote this to _payloadIdentifier;
    older ones only have the base64 payload, so fall back to parsing it.
  #>
  param([object]$Policy)

  $identifier = Get-PropertyValue -Object $Policy -Name '_payloadIdentifier'
  $uuid = Get-PropertyValue -Object $Policy -Name '_payloadUUID'
  $types = Get-PropertyValue -Object $Policy -Name '_payloadTypes'

  if (-not $identifier) {
    $payload = Get-PropertyValue -Object $Policy -Name 'payload'
    if ($payload) {
      try {
        $xml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$payload"))
        $identifier = [regex]::Match($xml, '<key>PayloadIdentifier</key>\s*<string>([^<]+)</string>').Groups[1].Value
        $uuid = [regex]::Match($xml, '<key>PayloadUUID</key>\s*<string>([^<]+)</string>').Groups[1].Value
      }
      catch {
        # A malformed payload simply has no identity to report.
        $identifier = $null
      }
    }
  }

  if (-not $identifier) { return $null }

  return [pscustomobject]@{
    PayloadIdentifier = $identifier
    PayloadUUID       = $uuid
    PayloadTypes      = @($types)
  }
}

function Get-AssignmentTargetLabel {
  # Short human label for where a policy is assigned, used in profile-level findings.
  param([object[]]$Assignments)

  $labels = @(@($Assignments) | ForEach-Object {
      if ($null -eq $_) { return }
      if (Get-PropertyValue -Object $_ -Name 'allDevices') { 'All devices' }
      elseif (Get-PropertyValue -Object $_ -Name 'allLicensedUsers') { 'All licensed users' }
      elseif (Get-PropertyValue -Object $_ -Name 'groupName') {
        $prefix = if (Get-PropertyValue -Object $_ -Name 'isExclusion') { 'EXCLUDE:' } else { '' }
        "$prefix$(Get-PropertyValue -Object $_ -Name 'groupName')"
      }
      else { Get-PropertyValue -Object $_ -Name 'targetType' }
    } | Where-Object { $_ }) | Sort-Object -Unique

  if (-not $labels.Count) { return 'UNASSIGNED' }
  # Comma-separated, not pipe: this string lands in Markdown table cells, where a pipe
  # would be read as a column break.
  return ($labels -join ', ')
}

function Get-BlastRadius {
  <#
    Aggregate reach of a policy, so a conflict hitting 3 devices and one hitting 3,000
    do not read identically. Group member counts come from -includeGroupMemberCounts and
    status overviews from -includeStatusSummaries; both are optional, so this returns
    $null rather than a misleading zero when the data was not collected.
  #>
  param(
    [object]$Policy,
    [object[]]$Assignments
  )

  $deviceCount = $null
  $overview = Get-PropertyValue -Object $Policy -Name '_statusOverview'
  if ($overview) {
    $deviceOverview = Get-PropertyValue -Object $overview -Name 'deviceStatusOverview'
    if ($deviceOverview) {
      $total = 0
      $sawAny = $false
      foreach ($field in @('successCount', 'errorCount', 'failedCount', 'conflictCount', 'pendingCount')) {
        $v = Get-PropertyValue -Object $deviceOverview -Name $field
        if ($null -ne $v) { $total += [int]$v; $sawAny = $true }
      }
      if ($sawAny) { $deviceCount = $total }
    }
  }

  $memberCount = $null
  $isBroad = $false
  foreach ($a in @($Assignments)) {
    if ($null -eq $a) { continue }
    if ((Get-PropertyValue -Object $a -Name 'allDevices') -or (Get-PropertyValue -Object $a -Name 'allLicensedUsers')) {
      $isBroad = $true
    }
    $mc = Get-PropertyValue -Object $a -Name 'groupMemberCount'
    if ($null -ne $mc) {
      if ($null -eq $memberCount) { $memberCount = 0 }
      $memberCount += [int]$mc
    }
  }

  if ($null -eq $deviceCount -and $null -eq $memberCount -and -not $isBroad) {
    return $null
  }

  return [pscustomobject]@{
    DeployedDeviceCount = $deviceCount
    GroupMemberCount    = $memberCount
    TargetsAllDevices   = $isBroad
  }
}

function ConvertTo-FlattenedSettings {
  param(
    [object]$InputObject,
    [string]$Prefix = ''
  )

  $result = @{}

  if ($null -eq $InputObject) {
    return $result
  }

  # Arrays: emit indexed children.
  if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
    $index = 0
    foreach ($item in $InputObject) {
      $childPrefix = if ($Prefix) { "$Prefix[$index]" } else { "[$index]" }
      $result += ConvertTo-FlattenedSettings -InputObject $item -Prefix $childPrefix
      $index++
    }
    return $result
  }

  # Objects / dictionaries.
  if ($InputObject -is [System.Collections.IDictionary]) {
    foreach ($key in $InputObject.Keys) {
      if ($metadataKeys -contains $key) { continue }
      $value = $InputObject[$key]
      $childPrefix = if ($Prefix) { "$Prefix.$key" } else { "$key" }
      $result += ConvertTo-FlattenedSettings -InputObject $value -Prefix $childPrefix
    }
    return $result
  }

  # PSCustomObject exposes properties; handle them like dictionary.
  if ($InputObject -is [pscustomobject]) {
    foreach ($prop in $InputObject.PSObject.Properties) {
      if ($metadataKeys -contains $prop.Name) { continue }
      $childPrefix = if ($Prefix) { "$Prefix.$($prop.Name)" } else { $prop.Name }
      $result += ConvertTo-FlattenedSettings -InputObject $prop.Value -Prefix $childPrefix
    }
    return $result
  }

  # Scalar value: leaf node.
  $result[$Prefix] = $InputObject
  return $result
}

function Get-SettingInstanceLeaves {
  # Recursively extract value(s) from a settingInstance / choiceSettingValue / groupSettingCollectionValue tree.
  param(
    [object]$Instance,
    [string]$Prefix,
    [hashtable]$DefinitionIndex = @{}
  )

  $result = @{}
  if ($null -eq $Instance) { return $result }

  # Simple value
  $simpleVal = Get-PropertyValue -Object $Instance -Name 'simpleSettingValue'
  if ($simpleVal) {
    $v = Get-PropertyValue -Object $simpleVal -Name 'value'
    $result[$Prefix] = $v
    return $result
  }

  # Choice value
  $choiceVal = Get-PropertyValue -Object $Instance -Name 'choiceSettingValue'
  if ($choiceVal) {
    $v = Get-PropertyValue -Object $choiceVal -Name 'value'
    if ($v) {
      # Prefer the definition's option label ("Enabled") over the raw enum tail ("1").
      $instanceDefId = Get-PropertyValue -Object $Instance -Name 'settingDefinitionId'
      $result[$Prefix] = Resolve-ChoiceLabel -DefinitionId $instanceDefId -RawValue $v -DefinitionIndex $DefinitionIndex
    }
    # Recurse into children of the choice
    $children = Get-PropertyValue -Object $choiceVal -Name 'children'
    if ($children) {
      foreach ($child in @($children)) {
        $childId = Get-PropertyValue -Object $child -Name 'settingDefinitionId'
        $childKey = if ($childId) { Get-SettingKeyForDefinition -DefinitionId $childId -DefinitionIndex $DefinitionIndex } else { $Prefix }
        $result += Get-SettingInstanceLeaves -Instance $child -Prefix $childKey -DefinitionIndex $DefinitionIndex
      }
    }
    return $result
  }

  # Collection of simple values
  $collectionVal = Get-PropertyValue -Object $Instance -Name 'simpleSettingCollectionValue'
  if ($collectionVal) {
    $vals = @($collectionVal | ForEach-Object { Get-PropertyValue -Object $_ -Name 'value' })
    $result[$Prefix] = ($vals -join '; ')
    return $result
  }

  # Group collection — recurse each child
  $groupVal = Get-PropertyValue -Object $Instance -Name 'groupSettingCollectionValue'
  if ($groupVal) {
    $gi = 0
    foreach ($groupItem in @($groupVal)) {
      $children = @(Get-PropertyValue -Object $groupItem -Name 'children')

      # Identify the collection member by its own name rather than its position. Firewall
      # rules are the common case: keying on [0]/[1] compares the first rule of one policy
      # against the unrelated first rule of another and reports a conflict, and reordering
      # a rule list would silently change every key.
      $memberName = $null
      foreach ($child in $children) {
        $cid = Get-PropertyValue -Object $child -Name 'settingDefinitionId'
        if ($cid -and $cid -match '(?i)(_name|_displayname|_id)$') {
          $simple = Get-PropertyValue -Object $child -Name 'simpleSettingValue'
          if ($simple) {
            $nameVal = Get-PropertyValue -Object $simple -Name 'value'
            if ($nameVal) { $memberName = "$nameVal"; break }
          }
        }
      }

      $memberKey = if ($memberName) { "{$memberName}" } else { "[$gi]" }

      foreach ($child in $children) {
        $childId = Get-PropertyValue -Object $child -Name 'settingDefinitionId'
        $childKey = if ($childId) { "$Prefix/$memberKey." + (Get-SettingKeyForDefinition -DefinitionId $childId -DefinitionIndex $DefinitionIndex) } else { "$Prefix/$memberKey" }
        $result += Get-SettingInstanceLeaves -Instance $child -Prefix $childKey -DefinitionIndex $DefinitionIndex
      }
      $gi++
    }
    return $result
  }

  # Direct value property (Endpoint Security intents)
  $directValue = Get-PropertyValue -Object $Instance -Name 'value'
  if ($null -ne $directValue) {
    $result[$Prefix] = $directValue
    return $result
  }

  return $result
}

function ConvertFrom-PlistNode {
  <#
    Convert a plist XML node into ordered hashtables / arrays / scalars.

    A flat regex scan cannot read a plist correctly: entries inside a TCC payload are
    serialised alphabetically, so CodeRequirement comes before the Identifier it belongs
    to, and any "the last Identifier seen scopes what follows" heuristic attributes each
    requirement to the wrong app. Parsing the document structurally removes that guesswork.
  #>
  param([System.Xml.XmlNode]$Node)

  switch ($Node.Name) {
    'dict' {
      $h = [ordered]@{}
      $children = @($Node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
      for ($i = 0; $i -lt $children.Count; $i++) {
        if ($children[$i].Name -ne 'key') { continue }
        if ($i + 1 -ge $children.Count) { break }
        $h[$children[$i].InnerText] = ConvertFrom-PlistNode -Node $children[$i + 1]
        $i++
      }
      return $h
    }
    'array' {
      return @($Node.ChildNodes |
          Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element } |
          ForEach-Object { ConvertFrom-PlistNode -Node $_ })
    }
    # Canonicalise booleans to 0/1 so <true/> and <integer>1</integer> compare equal.
    'true' { return '1' }
    'false' { return '0' }
    'data' {
      # Base64 blobs are certificates, keys and provisioning payloads. Never surface the
      # contents; emit a short digest so identical blobs still compare equal.
      $raw = ($Node.InnerText -replace '\s', '')
      if (-not $raw) { return '<data:empty>' }
      $digest = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))
      ).Replace('-', '').Substring(0, 12).ToLower()
      return "<data:sha256:$digest>"
    }
    default { return $Node.InnerText }
  }
}

function ConvertTo-PlistSettings {
  <#
    Flatten a parsed plist into comparable settingPath -> value pairs, qualifying each key
    with the payload and the app entry that contains it, so "Identifier" inside a Defender
    TCC entry is a different setting from "Identifier" inside a OneDrive one.
  #>
  param(
    [object]$Node,
    [string]$Prefix,
    [hashtable]$Result
  )

  if ($null -eq $Node) { return $Result }

  # Plist boilerplate that describes the profile rather than configuring anything.
  $plistMetaKeys = @('PayloadUUID', 'PayloadType', 'PayloadVersion', 'PayloadIdentifier',
    'PayloadDisplayName', 'PayloadDescription', 'PayloadOrganization', 'PayloadEnabled',
    'PayloadRemovalDisallowed', 'PayloadScope')

  if ($Node -is [System.Collections.IDictionary]) {
    # A dict that names a payload or an app entry contributes that name to the path.
    $scope = $Prefix
    foreach ($idKey in @('PayloadType', 'Identifier', 'BundleIdentifier', 'RuleValue')) {
      if ($Node.Contains($idKey) -and $Node[$idKey] -is [string] -and $Node[$idKey]) {
        $scope = if ($scope) { "$scope/$($Node[$idKey])" } else { "$($Node[$idKey])" }
        break
      }
    }

    foreach ($key in @($Node.Keys)) {
      if ($plistMetaKeys -contains $key) { continue }
      ConvertTo-PlistSettings -Node $Node[$key] -Prefix "$scope/$key" -Result $Result | Out-Null
    }
    return $Result
  }

  if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
    $index = 0
    foreach ($item in $Node) {
      # Prefer the member's own identity over its position, so reordering a list does not
      # change every key and unrelated members do not line up by index.
      $memberKey = "[$index]"
      if ($item -is [System.Collections.IDictionary]) {
        foreach ($idKey in @('PayloadType', 'Identifier', 'BundleIdentifier', 'RuleValue')) {
          if ($item.Contains($idKey) -and $item[$idKey] -is [string] -and $item[$idKey]) { $memberKey = ''; break }
        }
      }
      $childPrefix = if ($memberKey) { "$Prefix$memberKey" } else { $Prefix }
      ConvertTo-PlistSettings -Node $item -Prefix $childPrefix -Result $Result | Out-Null
      $index++
    }
    return $Result
  }

  if ($Prefix) { $Result[$Prefix] = $Node }
  return $Result
}

function ConvertTo-ReadableSettings {
  # Produce a hashtable of human-readable settingKey -> value for a policy,
  # dispatching by category (profile type folder name).
  param(
    [object]$Policy,
    [string]$Category,
    [hashtable]$DefinitionIndex = @{}
  )

  $result = @{}

  switch ($Category) {
    'ConfigurationPolicies' {
      # Settings Catalog: key on settingDefinitionId (stable identity), annotated with
      # the definition's display name when setting-definitions.json is available.
      $settings = Get-PropertyValue -Object $Policy -Name 'settings'
      if (-not $settings) { return $result }
      foreach ($s in @($settings)) {
        $inst = Get-PropertyValue -Object $s -Name 'settingInstance'
        if (-not $inst) { continue }
        $defId = Get-PropertyValue -Object $inst -Name 'settingDefinitionId'
        $key = if ($defId) {
          Get-SettingKeyForDefinition -DefinitionId $defId -DefinitionIndex $DefinitionIndex
        }
        else { "setting_$($result.Count)" }
        $leaves = Get-SettingInstanceLeaves -Instance $inst -Prefix $key -DefinitionIndex $DefinitionIndex
        foreach ($leaf in $leaves.GetEnumerator()) {
          $result[$leaf.Key] = $leaf.Value
        }
      }
    }

    'AppProtectionPolicies' {
      # MAM policies keep their settings as top-level properties (data transfer, PIN,
      # wipe thresholds), the same shape as compliance policies.
      $mamSkip = $metadataKeys + @(
        'assignments', 'deployedAppCount', 'apps', 'deploymentSummary',
        'exemptAppPackages', 'exemptedAppProtocols', 'isAssigned'
      )
      $defaultValues = @($null, $false, 0, '', 'notConfigured', 'deviceDefault', 'unavailable')
      if ($Policy -is [psobject]) {
        foreach ($prop in $Policy.PSObject.Properties) {
          if ($mamSkip -contains $prop.Name) { continue }
          $val = $prop.Value
          if ($val -in $defaultValues) { continue }
          if ($val -is [string] -or $val -is [ValueType]) {
            $result[$prop.Name] = $val
          }
        }
      }
    }

    'GroupPolicyConfigurations' {
      # Administrative Templates: use definition displayName / categoryPath.
      $dvs = Get-PropertyValue -Object $Policy -Name 'definitionValues'
      if (-not $dvs) { return $result }
      foreach ($dv in @($dvs)) {
        $def = Get-PropertyValue -Object $dv -Name 'definition'
        $defName = if ($def) { Get-PropertyValue -Object $def -Name 'displayName' } else { $null }
        $catPath = if ($def) { Get-PropertyValue -Object $def -Name 'categoryPath' } else { $null }
        $enabled = Get-PropertyValue -Object $dv -Name 'enabled'

        $keyBase = if ($catPath -and $defName) {
          "$catPath/$defName"
        }
        elseif ($defName) { $defName }
        else { "admx_$(Get-PropertyValue -Object $dv -Name 'id')" }

        $result["$keyBase (enabled)"] = $enabled

        $pvs = Get-PropertyValue -Object $dv -Name 'presentationValues'
        if ($pvs) {
          foreach ($pv in @($pvs)) {
            $pres = Get-PropertyValue -Object $pv -Name 'presentation'
            $presLabel = if ($pres) { Get-PropertyValue -Object $pres -Name 'label' } else { $null }
            if (-not $presLabel) { $presLabel = Get-PropertyValue -Object $pv -Name 'id' }
            $pvValue = Get-PropertyValue -Object $pv -Name 'value'
            if ($null -eq $pvValue) { $pvValue = Get-PropertyValue -Object $pv -Name 'values' }

            $pvKey = "$keyBase/$presLabel"
            $result[$pvKey] = $pvValue
          }
        }
      }
    }

    'EndpointSecurityPolicies' {
      # Intents: settings array with definitionId + value/valueJson.
      $settings = Get-PropertyValue -Object $Policy -Name 'settings'
      if (-not $settings) { return $result }
      foreach ($s in @($settings)) {
        $defId = Get-PropertyValue -Object $s -Name 'definitionId'
        $displayName = Get-PropertyValue -Object $s -Name 'displayName'
        $key = if ($displayName) { $displayName }
        elseif ($defId) { ($defId -split '_' | Select-Object -Last 2) -join '/' }
        else { "intent_setting_$($result.Count)" }

        $val = Get-PropertyValue -Object $s -Name 'valueJson'
        if ($null -eq $val) { $val = Get-PropertyValue -Object $s -Name 'value' }
        $result[$key] = $val
      }

      # Also capture the template name as a pseudo-setting for context.
      $tmpl = Get-PropertyValue -Object $Policy -Name 'templateName'
      if ($tmpl) { $result['_templateName'] = $tmpl }
    }

    'DeviceConfigurations' {
      $odataType = Get-PropertyValue -Object $Policy -Name '@odata.type'

      if ($odataType -match 'CustomConfiguration') {
        # macOS/iOS/Windows custom profiles: settings are in a base64-encoded payload
        # (mobileconfig plist or OMA-URI). Extract PayloadType identifiers and key
        # settings from the plist XML so we have something meaningful to compare.
        $payloadB64 = Get-PropertyValue -Object $Policy -Name 'payload'
        $oma = Get-PropertyValue -Object $Policy -Name 'omaSettings'
        if ($oma) {
          # Windows custom config with OMA-URI settings
          foreach ($o in @($oma)) {
            $omaUri = Get-PropertyValue -Object $o -Name 'omaUri'
            $omaDisplayName = Get-PropertyValue -Object $o -Name 'displayName'
            $key = if ($omaUri) { $omaUri } elseif ($omaDisplayName) { $omaDisplayName } else { "oma_$($result.Count)" }
            $val = Get-PropertyValue -Object $o -Name 'value'
            $result[$key] = $val
          }
        }
        elseif ($payloadB64) {
          # macOS/iOS custom config with base64-encoded plist payload.
          # Extract PayloadType values from the XML to identify what it configures.
          try {
            $payloadXml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadB64))
            # Extract all PayloadType values (tells us what the profile configures)
            $payloadTypes = [regex]::Matches($payloadXml, '<key>PayloadType</key>\s*<string>([^<]+)</string>') |
              ForEach-Object { $_.Groups[1].Value } |
              Where-Object { $_ -ne 'Configuration' } |
              Select-Object -Unique
            if ($payloadTypes) {
              # Descriptive metadata, not a setting. Two profiles configuring different
              # payload types are not in conflict -- they are simply different profiles --
              # so this is kept out of the comparison space (see $syntheticKeys).
              $result['_payloadTypes'] = ($payloadTypes -join '; ')
            }
            # Extract a stable fingerprint for comparison (SHA256 of decoded plist)
            $hash = [System.BitConverter]::ToString(
              [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($payloadXml)
              )
            ).Replace('-', '').Substring(0, 16).ToLower()
            $result['_payloadHash'] = $hash

            # Parse the plist structurally so each key is qualified by the payload and app
            # entry that actually contains it. (Plist boilerplate keys are filtered inside
            # ConvertTo-PlistSettings, not here.)
            try {
              $plistDoc = [xml]$payloadXml
              $rootDict = $plistDoc.SelectSingleNode('/plist/dict')
              if ($null -ne $rootDict) {
                $parsed = ConvertFrom-PlistNode -Node $rootDict
                $flat = @{}
                ConvertTo-PlistSettings -Node $parsed -Prefix '' -Result $flat | Out-Null
                foreach ($entry in $flat.GetEnumerator()) {
                  $result[$entry.Key] = $entry.Value
                }
              }
            }
            catch {
              # A malformed or non-XML payload still leaves the hash and payload types.
              $result['_payloadParseError'] = $_.Exception.Message
            }
          }
          catch {
            $result['_payloadError'] = $_.Exception.Message
          }
        }
      }
      else {
        # Non-custom typed profiles (BitLocker, Wi-Fi, endpoint protection, general, etc.)
        # Extract only the typed setting properties, skipping nested sub-resources.
        # Also skip default/not-configured values.
        $typedSkip = $metadataKeys + @(
          'assignments', 'deviceStatuses', 'userStatuses',
          'deviceStatusOverview', 'userStatusOverview',
          'deviceSettingStateSummaries',
          'payload', 'payloadFileName'
        )
        $defaultValues = @($null, $false, 0, '', 'notConfigured', 'deviceDefault', 'unavailable')
        if ($Policy -is [psobject]) {
          foreach ($prop in $Policy.PSObject.Properties) {
            if ($typedSkip -contains $prop.Name) { continue }
            $val = $prop.Value
            if ($val -in $defaultValues) { continue }
            if ($val -is [string] -or $val -is [ValueType]) {
              $result[$prop.Name] = $val
            }
            elseif ($val -is [System.Collections.IEnumerable]) {
              $items = @($val)
              $allScalar = $true
              foreach ($item in $items) {
                if ($null -ne $item -and -not ($item -is [string]) -and -not ($item -is [ValueType])) {
                  $allScalar = $false; break
                }
              }
              if ($allScalar) {
                $result[$prop.Name] = ($items -join '; ')
              }
              else {
                $result[$prop.Name] = ($val | ConvertTo-Json -Compress -Depth 5)
              }
            }
            elseif ($val -is [psobject]) {
              foreach ($sub in $val.PSObject.Properties) {
                if ($metadataKeys -contains $sub.Name) { continue }
                $result["$($prop.Name)/$($sub.Name)"] = $sub.Value
              }
            }
          }
        }
      }
    }

    'CompliancePolicies' {
      # Compliance: extract top-level setting properties; skip status/action sub-resources.
      # Also skip default/not-configured values — null, false, 0, etc. mean the admin
      # never configured that compliance check.
      $complianceSkip = $metadataKeys + @(
        'assignments', 'scheduledActionsForRule', 'deviceStatuses',
        'userStatuses', 'deviceStatusOverview', 'userStatusOverview',
        'deviceSettingStateSummaries', 'validOperatingSystemBuildRanges'
      )
      $defaultValues = @($null, $false, 0, '', 'notConfigured', 'deviceDefault', 'unavailable')
      if ($Policy -is [psobject]) {
        foreach ($prop in $Policy.PSObject.Properties) {
          if ($complianceSkip -contains $prop.Name) { continue }
          $val = $prop.Value
          # Skip default/not-configured values.
          if ($val -in $defaultValues) { continue }
          if ($val -is [string] -or $val -is [ValueType]) {
            $result[$prop.Name] = $val
          }
          elseif ($val -is [System.Collections.IEnumerable]) {
            $items = @($val)
            $allScalar = $true
            foreach ($item in $items) {
              if ($null -ne $item -and -not ($item -is [string]) -and -not ($item -is [ValueType])) {
                $allScalar = $false; break
              }
            }
            if ($allScalar) {
              $result[$prop.Name] = ($items -join '; ')
            }
            else {
              $result[$prop.Name] = ($val | ConvertTo-Json -Compress -Depth 5)
            }
          }
        }
      }
    }

    default {
      $result = ConvertTo-FlattenedSettings -InputObject $Policy
    }
  }

  return $result
}

function ConvertTo-NormalizedValue {
  param([object]$Value)
  if ($null -eq $Value) { return 'null' }
  if ($Value -is [string]) {
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $decoded = Try-DecodeBase64String -Value $Value
    if ($decoded.Decoded) {
      return $decoded.Value
    }
    return $Value
  }
  if ($Value -is [ValueType]) { return $Value.ToString() }
  return (ConvertTo-Json -InputObject $Value -Compress -Depth 10)
}

function Try-DecodeBase64String {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  $trimmed = $Value.Trim()
  if ([string]::IsNullOrEmpty($trimmed)) {
    return [pscustomobject]@{ Decoded = $false; Value = $Value }
  }
  if ($trimmed.Length -lt 32) {
    return [pscustomobject]@{ Decoded = $false; Value = $Value }
  }

  if ($trimmed.Length % 4 -ne 0) {
    return [pscustomobject]@{ Decoded = $false; Value = $Value }
  }

  if ($trimmed -notmatch '^[A-Za-z0-9+/=]+$') {
    return [pscustomobject]@{ Decoded = $false; Value = $Value }
  }

  try {
    $bytes = [System.Convert]::FromBase64String($trimmed)
    if ($bytes.Length -lt 4) {
      return [pscustomobject]@{ Decoded = $false; Value = $Value }
    }

    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ([string]::IsNullOrWhiteSpace($text)) {
      return [pscustomobject]@{ Decoded = $false; Value = $Value }
    }

    $sample = $text.Substring(0, [Math]::Min(100, $text.Length))
    $looksTextual = ($sample -match '<\?xml') -or ($sample -match '<plist') -or ($sample -match '\{') -or ($sample -match '\[') -or ($sample -match '[A-Za-z]')
    if (-not $looksTextual) {
      return [pscustomobject]@{ Decoded = $false; Value = $Value }
    }

    return [pscustomobject]@{ Decoded = $true; Value = $text }
  }
  catch {
    return [pscustomobject]@{ Decoded = $false; Value = $Value }
  }
}

function Format-MarkdownValue {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [object]$Value
  )

  if ($null -eq $Value) { return 'null' }

  $text = $Value.ToString()
  if ([string]::IsNullOrEmpty($text)) { return '' }

  # Truncate very long values — show a preview + SHA256 hash for comparison.
  if ($text.Length -gt 200) {
    $hash = [System.BitConverter]::ToString(
      [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($text)
      )
    ).Replace('-', '').Substring(0, 12).ToLower()
    $preview = ($text.Substring(0, 80) -replace "`r`n\|`n", ' ' -replace '\|', '/').Trim()
    return "$preview... (sha256:$hash)"
  }

  # Short simple values.
  if ($text -notmatch "`r`n|`n" -and $text.Length -le 120) {
    $escaped = $text -replace '\|', '\|'
    return $escaped
  }

  $safe = $text -replace '```', '``\u200B`'
  $codeBlock = @"
```text
$safe
```
"@
  return $codeBlock
}

function Format-TargetReach {
  <#
    One-line reach descriptor for a target. Returns an empty string when neither member
    counts nor deployment status were collected -- silence is correct there, because
    printing "0 devices" for uncollected data would be worse than printing nothing.
  #>
  param([pscustomobject]$Target)

  $parts = @()
  if ($null -ne $Target.GroupMemberCount) {
    $parts += ('{0:N0} group members' -f $Target.GroupMemberCount)
  }
  if ($null -ne $Target.MaxDeviceCount) {
    $parts += ('{0:N0} devices reporting' -f $Target.MaxDeviceCount)
  }
  if ($Target.TargetKey -match 'AllDevices|AllLicensedUsers') {
    $parts += 'tenant-wide target'
  }

  if (-not $parts.Count) { return '' }
  return (' — reach: ' + ($parts -join ', '))
}

function Get-AssignmentTargetKey {
  param([pscustomobject]$Assignment)

  $baseKey = switch ($Assignment.targetType) {
    '#microsoft.graph.allDevicesAssignmentTarget' { 'AllDevices' }
    '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'AllLicensedUsers' }
    '#microsoft.graph.groupAssignmentTarget' { "Group:$($Assignment.groupId)" }
    '#microsoft.graph.exclusionGroupAssignmentTarget' { "GroupExclusion:$($Assignment.groupId)" }
    '#microsoft.graph.configurationManagerCollectionAssignmentTarget' { "CMCollection:$($Assignment.collectionId)" }
    '#microsoft.graph.userSecurityGroupTarget' { "UserGroup:$($Assignment.groupId)" }
    default {
      if ($Assignment.groupId) { "Group:$($Assignment.groupId)" }
      elseif ($Assignment.userId) { "User:$($Assignment.userId)" }
      else { $Assignment.targetType }
    }
  }

  if ($Assignment.filterId) {
    return "$baseKey| Filter:$($Assignment.filterId)"
  }

  return $baseKey
}

function Get-PolicyPlatformKey {
  param(
    [pscustomobject]$Policy
  )

  $platforms = Get-PropertyValue -Object $Policy -Name 'platforms'
  if ($platforms) {
    $list = @(@($platforms) | ForEach-Object { $_.ToString().ToLowerInvariant() })
    if ($list.Count) {
      return ($list | Sort-Object -Unique) -join ','
    }
  }

  $odataType = (Get-PropertyValue -Object $Policy -Name '@odata.type')
  if ($odataType) {
    $ot = $odataType.ToLowerInvariant()
    if ($ot -match 'android') { return 'android' }
    if ($ot -match 'ios|iphone|ipad') { return 'ios' }
    if ($ot -match 'macos') { return 'macos' }
    if ($ot -match 'windows') { return 'windows' }
  }

  # Endpoint Security intents: infer platform from templateName if available
  $templateName = Get-PropertyValue -Object $Policy -Name 'templateName'
  if ($templateName) {
    $tn = $templateName.ToLowerInvariant()
    if ($tn -match 'windows|endpoint detection|antivirus|firewall|bitlocker|disk encryption|attack surface') { return 'windows' }
    if ($tn -match 'macos') { return 'macos' }
    if ($tn -match 'linux') { return 'linux' }
  }

  return 'unknown'
}

function Read-Assignments {
  param([System.IO.FileInfo]$PolicyFile)

  $assignFile = Join-Path $PolicyFile.DirectoryName "$($PolicyFile.BaseName).assignments.json"
  if (-not (Test-Path -LiteralPath $assignFile)) {
    return @()
  }

  $content = Get-Content -LiteralPath $assignFile -Raw | ConvertFrom-Json
  if ($null -eq $content) { return @() }
  if ($content -isnot [System.Collections.IEnumerable]) { return @($content) }
  return $content
}

$exportPath = Get-ExportPath -Root $ExportRoot -Tenant $TenantId -Date $ExportDate
if (-not $OutputJson) { $OutputJson = Join-Path $exportPath 'policy-overlap-report.json' }
if (-not $OutputText) { $OutputText = Join-Path $exportPath 'policy-overlap-report.txt' }
if (-not $OutputMarkdown) { $OutputMarkdown = Join-Path $exportPath 'policy-overlap-report.md' }

Write-Host "Analyzing export at: $exportPath" -ForegroundColor Cyan

# ── Reference data written by Export-DeviceConfigurations.ps1 ──
$manifest = Read-JsonFileIfPresent -Path (Join-Path $exportPath 'export-manifest.json') -Label 'export manifest'
$definitionIndex = Get-SettingDefinitionIndex -Definitions (Read-JsonFileIfPresent -Path (Join-Path $exportPath 'setting-definitions.json') -Label 'setting definitions')
$filterCatalog = Read-JsonFileIfPresent -Path (Join-Path $exportPath 'assignment-filters.json') -Label 'assignment filter catalog'

if ($definitionIndex.Count) {
  Write-Host "  Loaded $($definitionIndex.Count) Settings Catalog definitions." -ForegroundColor DarkGray
}
else {
  Write-Warning 'No setting-definitions.json found. Settings Catalog findings will show raw setting ids instead of display names. Re-run the export to generate it.'
}

# Index manifest entries by policy id so a missing setting can be reported as
# "the fetch failed" rather than silently as "this policy has no settings".
$manifestByPolicy = @{}
if ($manifest) {
  foreach ($entry in @(Get-PropertyValue -Object $manifest -Name 'Policies')) {
    # NB: not $pid -- that is a read-only PowerShell automatic variable (process id).
    $manifestPolicyId = Get-PropertyValue -Object $entry -Name 'PolicyId'
    if ($manifestPolicyId) { $manifestByPolicy["$manifestPolicyId"] = $entry }
  }
}

# ── Decide which folders take part in setting-level comparison ──
# The export marks each type as analyzable or inventory-only; honour that when a
# manifest is present, otherwise fall back to the built-in list.
$analyzableCategories = if ($AnalyzeCategories) {
  @($AnalyzeCategories)
}
elseif ($manifest -and (Get-PropertyValue -Object $manifest -Name 'AnalyzedTypes')) {
  @(Get-PropertyValue -Object $manifest -Name 'AnalyzedTypes')
}
else {
  $defaultAnalyzableCategories
}

if ($IncludeInventoryOnly) {
  Write-Warning 'Comparing inventory-only policy types. Enrollment configurations, update rings and scripts have their own priority semantics, so expect low-signal findings.'
}

# Root-level artefacts are reference data, not policies. Without this they would fall
# through to the generic flattener and manufacture findings out of export scaffolding.
$nonPolicyFiles = @(
  'export-manifest.json',
  'setting-definitions.json',
  'assignment-filters.json',
  'role-scope-tags.json',
  'consolidated-config-profiles.json',
  'policy-overlap-report.json'
)

$allJsonFiles = @(Get-ChildItem -Path $exportPath -Recurse -File -Filter '*.json' |
    Where-Object {
      -not $_.Name.EndsWith('.assignments.json', 'OrdinalIgnoreCase') -and
      $_.Name -notin $nonPolicyFiles -and
      $_.DirectoryName -ne $exportPath
    })

# Defensive de-duplication: an export written before stale-file cleanup existed can hold two
# files for one policy id -- the current name and a previous one. Reading both makes a policy
# appear twice and collide with itself. Keep only the most recently written file per id.
$deduped = @()
$byPolicyId = @{}
foreach ($f in $allJsonFiles) {
  if ($f.BaseName -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') {
    $fileId = $Matches[1]
    if (-not $byPolicyId.ContainsKey($fileId)) { $byPolicyId[$fileId] = @() }
    $byPolicyId[$fileId] += $f
  }
  else {
    $deduped += $f
  }
}
$staleSkipped = @()
foreach ($entry in $byPolicyId.GetEnumerator()) {
  $ordered = @($entry.Value | Sort-Object LastWriteTime -Descending)
  $deduped += $ordered[0]
  if ($ordered.Count -gt 1) {
    foreach ($old in $ordered[1..($ordered.Count - 1)]) {
      $staleSkipped += [pscustomobject]@{ PolicyId = $entry.Key; File = $old.Name; Written = $old.LastWriteTime }
    }
  }
}
if ($staleSkipped.Count) {
  Write-Warning ("Ignored {0} stale export file(s) -- a policy was renamed and an older copy remains on disk. Re-run the export to clean them up." -f $staleSkipped.Count)
  foreach ($s in $staleSkipped) { Write-Verbose "  stale: $($s.File)" }
}
$allJsonFiles = @($deduped)

$policyFiles = @()
$inventoryOnly = @()
foreach ($f in $allJsonFiles) {
  $cat = Split-Path -Path $f.DirectoryName -Leaf
  if ($IncludeInventoryOnly -or ($cat -in $analyzableCategories)) {
    $policyFiles += $f
  }
  else {
    $inventoryOnly += [pscustomobject]@{ Category = $cat; File = $f.FullName; Name = $f.BaseName }
  }
}

if ($inventoryOnly.Count) {
  $invCats = (@($inventoryOnly | ForEach-Object { $_.Category }) | Sort-Object -Unique) -join ', '
  Write-Host "  Inventoried but not compared: $($inventoryOnly.Count) policies across $invCats" -ForegroundColor DarkGray
}

$records = @()
$missingSettings = @()
$policyContext = @{}

Write-Host "  Reading $(@($policyFiles).Count) policies..." -ForegroundColor DarkGray
$fileIndex = 0

foreach ($file in $policyFiles) {
  $fileIndex++
  if ($fileIndex % 25 -eq 0) { Write-Host "    $fileIndex / $(@($policyFiles).Count)" -ForegroundColor DarkGray }
  $category = Split-Path -Path $file.DirectoryName -Leaf
  $raw = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
  if (-not $raw) { continue }

  # Normalize arrays by taking the first element (exports should be single objects).
  if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string]) -and $raw -isnot [pscustomobject]) {
    $raw = $raw | Select-Object -First 1
  }

  $displayName = Get-PropertyValue -Object $raw -Name 'displayName'
  if (-not $displayName) { $displayName = Get-PropertyValue -Object $raw -Name 'name' }
  if (-not $displayName) { $displayName = $file.BaseName }

  $platformKey = Get-PolicyPlatformKey -Policy $raw
  $policyId = Get-PropertyValue -Object $raw -Name 'id'

  $settings = ConvertTo-ReadableSettings -Policy $raw -Category $category -DefinitionIndex $definitionIndex

  # Synthetic keys the extractor adds for context are not Intune settings and must not be
  # compared: two profiles always have different payload hashes and usually different
  # payload types, which previously surfaced as a "conflict" between unrelated profiles.
  # The hash is still useful, but only for spotting byte-identical duplicates.
  $payloadHash = $null
  $payloadTypes = $null
  foreach ($synthetic in @($syntheticKeys)) {
    if ($settings.ContainsKey($synthetic)) {
      if ($synthetic -eq '_payloadHash') { $payloadHash = $settings[$synthetic] }
      if ($synthetic -eq '_payloadTypes') { $payloadTypes = $settings[$synthetic] }
      [void]$settings.Remove($synthetic)
    }
  }

  $assignmentsRaw = @(Read-Assignments -PolicyFile $file)

  # Per-policy context that findings are annotated with, rather than compared.
  $scopeTagKey = Get-PolicyScopeTagKey -Policy $raw
  $templateFamily = Get-PropertyValue -Object $raw -Name '_templateFamily'
  $complianceActions = if ($category -eq 'CompliancePolicies') { Get-ComplianceActionSummary -Policy $raw } else { $null }
  $blastRadius = Get-BlastRadius -Policy $raw -Assignments $assignmentsRaw

  if ($policyId) {
    $policyContext["$policyId"] = [pscustomobject]@{
      PolicyName        = $displayName
      Category          = $category
      ScopeTagKey       = $scopeTagKey
      TemplateFamily    = $templateFamily
      ComplianceActions = $complianceActions
      BlastRadius       = $blastRadius
      PayloadHash       = $payloadHash
      PayloadTypes      = $payloadTypes
      SettingKeys       = @($settings.Keys)
      Identity          = Get-ProfileIdentity -Policy $raw
      TargetLabel       = Get-AssignmentTargetLabel -Assignments $assignmentsRaw
      IsAssigned        = ([bool]@($assignmentsRaw).Count)
    }
  }

  if (-not $settings.Count) {
    # Distinguish "this policy genuinely has no settings" from "the sub-resource fetch
    # failed during export" -- otherwise an absence in the data reads as a fact.
    $fetchStatus = 'no settings emitted'
    $manifestEntry = if ($policyId -and $manifestByPolicy.ContainsKey("$policyId")) { $manifestByPolicy["$policyId"] } else { $null }
    if ($manifestEntry) {
      $subResources = Get-PropertyValue -Object $manifestEntry -Name 'SubResources'
      if ($subResources) {
        $failures = @()
        foreach ($sp in $subResources.PSObject.Properties) {
          if ("$($sp.Value)" -like 'failed:*') { $failures += "$($sp.Name): $($sp.Value)" }
        }
        if ($failures.Count) { $fetchStatus = "export failure -- $($failures -join '; ')" }
        elseif ($subResources.PSObject.Properties.Count) { $fetchStatus = 'sub-resources fetched successfully; policy has no comparable settings' }
      }
    }
    elseif ($manifest) {
      $fetchStatus = 'not present in export manifest (exported by an older script version?)'
    }

    $missingSettings += [pscustomobject]@{
      PolicyName           = $displayName
      PolicyId             = $policyId
      Category             = $category
      File                 = $file.FullName
      SettingCountReported = Get-PropertyValue -Object $raw -Name 'settingCount'
      Reason               = $fetchStatus
    }
  }

  $assignments = $assignmentsRaw
  if (-not $assignments.Count) {
    # Treat as unassigned so we still surface duplicates by policy name.
    $assignments = @([pscustomobject]@{
        targetType = '(Unassigned)'
        filterId   = $null
        groupId    = $null
        userId     = $null
      })
  }

  foreach ($assignment in $assignments) {
    $targetKey = Get-AssignmentTargetKey -Assignment $assignment
    $targetDisplay = if (Get-PropertyValue -Object $assignment -Name 'groupName') {
      Get-PropertyValue -Object $assignment -Name 'groupName'
    }
    elseif (Get-PropertyValue -Object $assignment -Name 'userDisplayName') {
      Get-PropertyValue -Object $assignment -Name 'userDisplayName'
    }
    elseif (Get-PropertyValue -Object $assignment -Name 'allDevices') {
      'All devices'
    }
    elseif (Get-PropertyValue -Object $assignment -Name 'allLicensedUsers') {
      'All licensed users'
    }
    else {
      $targetKey
    }

    # An exclusion target removes a policy from devices rather than applying it, so it
    # cannot conflict with an include target for the same setting. Record it for context
    # but keep it out of the comparison space.
    $isExclusion = [bool](Get-PropertyValue -Object $assignment -Name 'isExclusion')
    if (-not $isExclusion) {
      $isExclusion = ((Get-PropertyValue -Object $assignment -Name 'targetType') -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
    }

    foreach ($setting in $settings.GetEnumerator()) {
      $records += [pscustomobject]@{
        PolicyName          = $displayName
        PolicyId            = $policyId
        Category            = $category
        TargetKey           = $targetKey
        Target              = $targetDisplay
        PlatformKey         = $platformKey
        SettingPath         = $setting.Key
        SettingValue        = ConvertTo-NormalizedValue -Value $setting.Value
        SourceFile          = $file.FullName
        AssignmentId        = Get-PropertyValue -Object $assignment -Name 'assignmentId'
        FilterId            = Get-PropertyValue -Object $assignment -Name 'filterId'
        FilterName          = Get-PropertyValue -Object $assignment -Name 'filterName'
        FilterRule          = Get-PropertyValue -Object $assignment -Name 'filterRule'
        FilterPlatform      = Get-PropertyValue -Object $assignment -Name 'filterPlatform'
        GroupType           = Get-PropertyValue -Object $assignment -Name 'groupType'
        GroupMembershipRule = Get-PropertyValue -Object $assignment -Name 'groupMembershipRule'
        GroupMemberCount    = Get-PropertyValue -Object $assignment -Name 'groupMemberCount'
        IsExclusion         = $isExclusion
        ScopeTagKey         = $scopeTagKey
        TemplateFamily      = $templateFamily
      }
    }
  }
}

if (-not $records.Count) {
  throw 'No settings found to analyze. Ensure exports include policy bodies.'
}

# Exclusion targets remove a policy from devices; they never push a value, so comparing
# them against include targets invents conflicts that cannot occur in practice.
$excludedRecords = @($records | Where-Object { $_.IsExclusion })
$comparableRecords = @($records | Where-Object { -not $_.IsExclusion })

if (-not $comparableRecords.Count) {
  throw 'No non-exclusion settings found to analyze. Ensure exports include policy bodies.'
}

# With -SeparateByScopeTag, policies under different scope tags are administered by
# different teams and are grouped apart rather than reported as colliding.
$targetGrouping = if ($SeparateByScopeTag) {
  @{ Expression = { "$($_.TargetKey)| $($_.PlatformKey)| $($_.ScopeTagKey)" } }
}
else {
  @{ Expression = { "$($_.TargetKey)| $($_.PlatformKey)" } }
}

$targetSummaries = @()
foreach ($targetGroup in $comparableRecords | Group-Object -Property $targetGrouping) {
  $firstRecord = $targetGroup.Group | Select-Object -First 1
  $targetName = $targetGroup.Name
  $bySetting = @()

  foreach ($settingGroup in $targetGroup.Group | Group-Object -Property SettingPath) {
    $valueGroups = @($settingGroup.Group | Group-Object -Property SettingValue)
    $allPolicies = $settingGroup.Group | Select-Object PolicyName, PolicyId, Category, SourceFile, FilterName, FilterRule -Unique

    # Split into compliance vs configuration policies.
    $compliancePolicies = @($allPolicies | Where-Object { $_.Category -eq 'CompliancePolicies' })
    $configPolicies = @($allPolicies | Where-Object { $_.Category -ne 'CompliancePolicies' })
    $hasCompliance = $compliancePolicies.Count -gt 0
    $hasConfig = $configPolicies.Count -gt 0
    $isMixed = $hasCompliance -and $hasConfig

    if ($isMixed) {
      # Mixed compliance + config: classify by relationship, not raw value match.
      $complianceRecords = @($settingGroup.Group | Where-Object { $_.Category -eq 'CompliancePolicies' })
      $configRecords = @($settingGroup.Group | Where-Object { $_.Category -ne 'CompliancePolicies' })

      foreach ($cr in $complianceRecords) {
        foreach ($cfr in $configRecords) {
          # Direction matters: config stronger than the compliance threshold satisfies the
          # check. Only a genuinely weaker value is a violation.
          $relation = Get-ComplianceComparison -SettingPath $settingGroup.Name -ComplianceValue $cr.SettingValue -ConfigValue $cfr.SettingValue

          if ($relation -eq 'Equal' -or $relation -eq 'Stronger') {
            $bySetting += [pscustomobject]@{
              SettingPath = $settingGroup.Name
              Type        = 'ComplianceEnforced'
              Relation    = $relation
              Details     = @([pscustomobject]@{
                  Value    = $cr.SettingValue
                  Policies = @($cr, $cfr) | Select-Object PolicyName, PolicyId, Category, SourceFile, FilterName, FilterRule -Unique
                })
            }
          }
          else {
            # Weaker, or two non-numeric values that cannot be ranked.
            $bySetting += [pscustomobject]@{
              SettingPath = $settingGroup.Name
              Type        = 'ComplianceViolation'
              Relation    = $relation
              Details     = @(
                [pscustomobject]@{
                  Value    = $cr.SettingValue
                  Policies = @($cr) | Select-Object PolicyName, PolicyId, Category, SourceFile, FilterName, FilterRule
                }
                [pscustomobject]@{
                  Value    = $cfr.SettingValue
                  Policies = @($cfr) | Select-Object PolicyName, PolicyId, Category, SourceFile, FilterName, FilterRule
                }
              )
            }
          }
        }
      }

      # Check for compliance settings with no matching config setting at all.
      # (Already handled: if configRecords is empty, the foreach above doesn't run,
      #  so we catch the "compliance without config" case separately below.)
    }
    elseif ($hasCompliance -and -not $hasConfig) {
      # Compliance-only setting. Before calling it a gap, rule out the two cases that are
      # not gaps at all: settings that report device state and cannot be enforced by any
      # configuration profile, and settings enforced on this target under a different name.
      if ($compliancePolicies.Count -ge 1) {
        $leafName = ($settingGroup.Name -split '/')[-1]

        $findingType = 'ComplianceGap'
        $enforcedBy = $null

        if ($leafName -in $attestationOnlyComplianceSettings) {
          $findingType = 'ComplianceNotEnforceable'
        }
        else {
          $enforcedBy = Test-ComplianceEnforcedElsewhere `
            -SettingPath $settingGroup.Name `
            -ConfigRecords @($targetGroup.Group | Where-Object { $_.Category -ne 'CompliancePolicies' }) `
            -EquivalenceMap $complianceEnforcementEquivalents
          if ($null -ne $enforcedBy) { $findingType = 'ComplianceEnforcedIndirectly' }
        }

        $bySetting += [pscustomobject]@{
          SettingPath = $settingGroup.Name
          Type        = $findingType
          EnforcedBy  = $enforcedBy
          Details     = @([pscustomobject]@{
              Value    = $valueGroups[0].Name
              Policies = $compliancePolicies
            })
        }
      }
    }
    else {
      # Config-only: original conflict/overlap logic.
      if ($valueGroups.Count -gt 1) {
        $conflictValues = foreach ($vg in $valueGroups) {
          [pscustomobject]@{
            Value    = $vg.Name
            Policies = $vg.Group | Select-Object PolicyName, PolicyId, Category, SourceFile, FilterName, FilterRule -Unique
          }
        }
        $bySetting += [pscustomobject]@{
          SettingPath = $settingGroup.Name
          Type        = 'Conflict'
          Details     = $conflictValues
        }
      }
      elseif ($settingGroup.Count -gt 1) {
        $overlapPolicies = $settingGroup.Group | Select-Object PolicyName, PolicyId, Category, SourceFile, FilterName, FilterRule -Unique
        $bySetting += [pscustomobject]@{
          SettingPath = $settingGroup.Name
          Type        = 'Overlap'
          Details     = @([pscustomobject]@{
              Value    = $valueGroups[0].Name
              Policies = $overlapPolicies
            })
        }
      }
    }
  }

  # Collect distinct filters used by policies in this target group.
  $targetFilters = @($targetGroup.Group | Where-Object { $_.FilterName } | Select-Object FilterName, FilterRule -Unique)

  # Reach of this target, so a conflict hitting 3 devices and one hitting 3,000 can be
  # told apart. Null when neither -includeGroupMemberCounts nor -includeStatusSummaries
  # was used on the export -- an absent count must not read as zero.
  $targetMemberCount = $null
  foreach ($mc in @($targetGroup.Group | Where-Object { $null -ne $_.GroupMemberCount } | Select-Object -ExpandProperty GroupMemberCount -Unique)) {
    if ($null -eq $targetMemberCount) { $targetMemberCount = 0 }
    $targetMemberCount += [int]$mc
  }

  $targetDeviceCount = $null
  foreach ($groupPolicyId in @($targetGroup.Group | Select-Object -ExpandProperty PolicyId -Unique)) {
    if (-not $groupPolicyId -or -not $policyContext.ContainsKey("$groupPolicyId")) { continue }
    $br = $policyContext["$groupPolicyId"].BlastRadius
    if ($null -ne $br -and $null -ne $br.DeployedDeviceCount) {
      if ($null -eq $targetDeviceCount) { $targetDeviceCount = 0 }
      $targetDeviceCount = [Math]::Max($targetDeviceCount, [int]$br.DeployedDeviceCount)
    }
  }

  $scopeTagKeys = @($targetGroup.Group | Select-Object -ExpandProperty ScopeTagKey -Unique | Where-Object { $_ })

  $targetSummaries += [pscustomobject]@{
    TargetKey         = $targetName
    TargetLabel       = $firstRecord.Target
    PlatformKey       = $firstRecord.PlatformKey
    PolicyCount       = @($targetGroup.Group | Select-Object PolicyId -Unique).Count
    SettingFindings   = $bySetting
    Filters           = $targetFilters
    GroupMemberCount  = $targetMemberCount
    MaxDeviceCount    = $targetDeviceCount
    ScopeTags         = $scopeTagKeys
    SpansMultipleTags = ($scopeTagKeys.Count -gt 1)
  }
}

# Detect potential cross-target overlaps: AllDevices vs specific groups, and
# dynamic groups with identical membership rules targeting the same settings.
$potentialOverlaps = @()

# Index: platform+settingPath -> list of { TargetKey, PolicyName, PolicyId, SettingValue, GroupMembershipRule, Target }
$settingIndex = @{}
foreach ($r in $comparableRecords) {
  $indexKey = "$($r.PlatformKey)|$($r.SettingPath)"
  if (-not $settingIndex.ContainsKey($indexKey)) {
    $settingIndex[$indexKey] = New-Object System.Collections.Generic.List[object]
  }
  [void]$settingIndex[$indexKey].Add($r)
}

foreach ($entry in $settingIndex.GetEnumerator()) {
  $group = $entry.Value
  if ($group.Count -lt 2) { continue }

  $uniqueTargets = @($group | Select-Object -Property TargetKey -Unique)
  if ($uniqueTargets.Count -lt 2) { continue }

  $hasAllDevices = $group | Where-Object { $_.TargetKey -eq 'AllDevices' } | Select-Object -First 1
  $hasAllUsers = $group | Where-Object { $_.TargetKey -eq 'AllLicensedUsers' } | Select-Object -First 1

  # AllDevices/AllUsers overlaps with any group target
  if ($hasAllDevices -or $hasAllUsers) {
    $broadTarget = if ($hasAllDevices) { $hasAllDevices } else { $hasAllUsers }
    $groupTargets = $group | Where-Object { $_.TargetKey -ne 'AllDevices' -and $_.TargetKey -ne 'AllLicensedUsers' -and $_.TargetKey -ne '(Unassigned)' }
    foreach ($gt in $groupTargets) {
      if ($gt.PolicyId -eq $broadTarget.PolicyId) { continue }
      $valueMatch = if ($gt.SettingValue -eq $broadTarget.SettingValue) { 'SameValue' } else { 'DifferentValue' }
      $potentialOverlaps += [pscustomobject]@{
        Type           = 'BroadTargetOverlap'
        SettingPath    = $entry.Key
        ValueMatch     = $valueMatch
        BroadPolicy    = $broadTarget.PolicyName
        BroadPolicyId  = $broadTarget.PolicyId
        BroadTarget    = $broadTarget.Target
        BroadValue     = $broadTarget.SettingValue
        NarrowPolicy   = $gt.PolicyName
        NarrowPolicyId = $gt.PolicyId
        NarrowTarget   = $gt.Target
        NarrowValue    = $gt.SettingValue
      }
    }
  }

  # Dynamic groups with identical membership rules
  $dynamicRecords = @($group | Where-Object { $_.GroupType -eq 'DynamicMembership' -and $_.GroupMembershipRule })
  if ($dynamicRecords.Count -ge 2) {
    $byRule = $dynamicRecords | Group-Object -Property GroupMembershipRule
    foreach ($ruleGroup in $byRule) {
      $uniquePolicies = @($ruleGroup.Group | Select-Object PolicyId -Unique)
      if ($uniquePolicies.Count -ge 2) {
        $valueGroups = @($ruleGroup.Group | Group-Object -Property SettingValue)
        $valueMatch = if ($valueGroups.Count -eq 1) { 'SameValue' } else { 'DifferentValue' }
        $potentialOverlaps += [pscustomobject]@{
          Type             = 'IdenticalDynamicRule'
          SettingPath      = $entry.Key
          ValueMatch       = $valueMatch
          MembershipRule   = $ruleGroup.Name
          AffectedPolicies = @($ruleGroup.Group | Select-Object PolicyName, PolicyId, Target, SettingValue -Unique)
        }
      }
    }
  }
}

# ── Assignment filters defined but never referenced by any assignment ──
# Only meaningful when the export wrote the full tenant catalogue; before that the
# analyzer could only see filters that happened to be in use.
$unusedFilters = @()
if ($filterCatalog) {
  $usedFilterIds = @($records | Where-Object { $_.FilterId } | ForEach-Object { "$($_.FilterId)" } | Sort-Object -Unique)
  foreach ($f in @($filterCatalog)) {
    $fid = Get-PropertyValue -Object $f -Name 'id'
    if (-not $fid) { continue }
    if ("$fid" -notin $usedFilterIds) {
      $unusedFilters += [pscustomobject]@{
        FilterId    = $fid
        FilterName  = Get-PropertyValue -Object $f -Name 'displayName'
        Platform    = Get-PropertyValue -Object $f -Name 'platform'
        Rule        = Get-PropertyValue -Object $f -Name 'rule'
        Description = Get-PropertyValue -Object $f -Name 'description'
      }
    }
  }
}

# ── Export completeness, so the report can be trusted rather than merely read ──
$exportHealth = $null
if ($manifest) {
  $failedFetches = @()
  foreach ($entry in @(Get-PropertyValue -Object $manifest -Name 'Policies')) {
    $subResources = Get-PropertyValue -Object $entry -Name 'SubResources'
    $assignStatus = "$(Get-PropertyValue -Object $entry -Name 'Assignments')"
    $problems = @()
    if ($subResources) {
      foreach ($sp in $subResources.PSObject.Properties) {
        if ("$($sp.Value)" -like 'failed:*') { $problems += "$($sp.Name): $($sp.Value)" }
      }
    }
    if ($assignStatus -like 'failed:*') { $problems += "assignments: $assignStatus" }
    if ($problems.Count) {
      $failedFetches += [pscustomobject]@{
        PolicyName = Get-PropertyValue -Object $entry -Name 'DisplayName'
        PolicyId   = Get-PropertyValue -Object $entry -Name 'PolicyId'
        Category   = Get-PropertyValue -Object $entry -Name 'ProfileType'
        Problems   = $problems
      }
    }
  }

  $exportHealth = [pscustomobject]@{
    ExportedAtUtc      = Get-PropertyValue -Object $manifest -Name 'ExportedAtUtc'
    MissingScopes      = @(Get-PropertyValue -Object $manifest -Name 'MissingScopes')
    AnalyzedTypes      = @(Get-PropertyValue -Object $manifest -Name 'AnalyzedTypes')
    InventoryOnlyTypes = @(Get-PropertyValue -Object $manifest -Name 'InventoryOnlyTypes')
    FailedFetches      = $failedFetches
    DefinitionsLoaded  = $definitionIndex.Count
  }
}

# ── Profile-level conflicts: same PayloadIdentifier, or byte-identical payload ──
# These are NOT setting-level findings. macOS keys an installed profile by its top-level
# PayloadIdentifier, so two profiles sharing one replace each other on the device no matter
# what they contain -- a class of conflict that comparing setting values cannot surface.
$payloadIdentifierCollisions = @()
$duplicateProfiles = @()

$profilesWithIdentity = @($policyContext.GetEnumerator() | ForEach-Object {
    $ctx = $_.Value
    if ($null -eq $ctx.Identity) { return }
    [pscustomobject]@{
      PolicyId          = $_.Key
      PolicyName        = $ctx.PolicyName
      Category          = $ctx.Category
      PayloadIdentifier = $ctx.Identity.PayloadIdentifier
      PayloadTypes      = @($ctx.Identity.PayloadTypes)
      PayloadHash       = $ctx.PayloadHash
      Target            = $ctx.TargetLabel
      IsAssigned        = $ctx.IsAssigned
    }
  })

foreach ($group in $profilesWithIdentity | Group-Object PayloadIdentifier) {
  if ($group.Count -lt 2) { continue }
  $members = @($group.Group | Sort-Object PolicyName)
  $assignedMembers = @($members | Where-Object { $_.IsAssigned })
  $payloadIdentifierCollisions += [pscustomobject]@{
    PayloadIdentifier = $group.Name
    ProfileCount      = $members.Count
    AssignedCount     = $assignedMembers.Count
    # Only a collision in practice when more than one of them actually reaches a device.
    IsLive            = ($assignedMembers.Count -ge 2)
    PayloadTypes      = @($members | ForEach-Object { $_.PayloadTypes } | Where-Object { $_ } | Sort-Object -Unique)
    Profiles          = @($members | Select-Object PolicyName, PolicyId, Category, Target, IsAssigned)
  }
}

foreach ($group in $profilesWithIdentity | Where-Object { $_.PayloadHash } | Group-Object PayloadHash) {
  if ($group.Count -lt 2) { continue }
  $members = @($group.Group | Sort-Object PolicyName)
  $duplicateProfiles += [pscustomobject]@{
    PayloadHash   = $group.Name
    ProfileCount  = $members.Count
    AssignedCount = @($members | Where-Object { $_.IsAssigned }).Count
    Profiles      = @($members | Select-Object PolicyName, PolicyId, Category, Target, IsAssigned)
  }
}

# ── Naming convention pass ──
# Runs over every policy in the manifest, not just the analysed subset, so inventory-only
# types are covered too. Falls back to what was read from disk when no manifest exists.
$namingInput = @()
if ($manifest) {
  foreach ($entry in @(Get-PropertyValue -Object $manifest -Name 'Policies')) {
    $namingInput += [pscustomobject]@{
      PolicyId    = Get-PropertyValue -Object $entry -Name 'PolicyId'
      DisplayName = Get-PropertyValue -Object $entry -Name 'DisplayName'
      Category    = Get-PropertyValue -Object $entry -Name 'ProfileType'
      IsAssigned  = ([int](Get-PropertyValue -Object $entry -Name 'AssignmentCount') -gt 0)
    }
  }
}
else {
  foreach ($k in $policyContext.Keys) {
    $c = $policyContext[$k]
    $namingInput += [pscustomobject]@{
      PolicyId = $k; DisplayName = $c.PolicyName; Category = $c.Category; IsAssigned = $c.IsAssigned
    }
  }
}

$naming = Get-NamingFindings -Policies $namingInput -Convention $namingConvention

# ── Policies that exist but are assigned to nothing ──
# A policy with no assignment enforces nothing. This matters most when a compliance policy
# checks for a setting whose only enforcing policy turns out to be unassigned, which looks
# like working configuration right up until a device is audited.
$unassignedPolicies = @()
if ($manifest) {
  foreach ($entry in @(Get-PropertyValue -Object $manifest -Name 'Policies')) {
    $assignState = "$(Get-PropertyValue -Object $entry -Name 'Assignments')"
    $assignCount = Get-PropertyValue -Object $entry -Name 'AssignmentCount'
    if ($assignState -like 'ok*' -and [int]$assignCount -eq 0) {
      $unassignedPolicies += [pscustomobject]@{
        Category    = Get-PropertyValue -Object $entry -Name 'ProfileType'
        PolicyName  = Get-PropertyValue -Object $entry -Name 'DisplayName'
        PolicyId    = Get-PropertyValue -Object $entry -Name 'PolicyId'
      }
    }
  }
}

$report = [pscustomobject]@{
  GeneratedAtUtc     = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
  ExportPath         = $exportPath
  TotalPolicies      = @($records | Select-Object PolicyId -Unique).Count
  TotalTargets       = @($targetSummaries).Count
  AnalyzedCategories = $analyzableCategories
  ExportHealth       = $exportHealth
  Targets            = $targetSummaries
  PotentialOverlaps  = $potentialOverlaps
  MissingSettings    = $missingSettings
  PayloadIdentifierCollisions = $payloadIdentifierCollisions
  DuplicateProfiles  = $duplicateProfiles
  UnassignedPolicies = $unassignedPolicies
  Naming             = $naming
  UnusedFilters      = $unusedFilters
  ExclusionTargets   = @($excludedRecords | Select-Object PolicyName, PolicyId, Target, TargetKey -Unique)
  InventoryOnly      = $inventoryOnly
  PolicyContext      = $policyContext
}

# Optional policy-to-policy comparisons (pivot for duplication/differences).
$comparisons = @()

if ($null -ne $ComparePolicies -and @($ComparePolicies).Count -ge 2) {
  function Resolve-Policy {
    param(
      [string]$Key,
      [hashtable]$Cache
    )

    # Parentheses are load-bearing. PowerShell's -and and -or share precedence and are
    # left-associative (unlike C), so the unbracketed form
    #     $_.Id -and $_.Id -eq $Key -or $_.Name -and $_.Name -eq $Key
    # parses as ((($_.Id -and $_.Id -eq $Key) -or $_.Name) -and $_.Name -eq $Key),
    # which gates every match on the *name* matching and so never resolves by id.
    $match = $Cache.Values | Where-Object {
      (($_.Id) -and ($_.Id -eq $Key)) -or (($_.Name) -and ($_.Name -eq $Key))
    } | Select-Object -First 1

    # Fall back to a substring match on name or file path.
    if (-not $match) {
      $match = $Cache.Values | Where-Object {
        (($_.Name) -and ($_.Name -like "*$Key*")) -or (($_.File) -and ($_.File -like "*$Key*"))
      } | Select-Object -First 1
    }

    return $match
  }

  $policyCache = @{}

  foreach ($file in $policyFiles) {
    $category = Split-Path -Path $file.DirectoryName -Leaf
    $raw = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if (-not $raw) { continue }
    if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string]) -and $raw -isnot [pscustomobject]) {
      $raw = $raw | Select-Object -First 1
    }

    $displayName = Get-PropertyValue -Object $raw -Name 'displayName'
    if (-not $displayName) { $displayName = Get-PropertyValue -Object $raw -Name 'name' }
    if (-not $displayName) { $displayName = $file.BaseName }

    $policyId = Get-PropertyValue -Object $raw -Name 'id'
    if (-not $policyId) { $policyId = $file.BaseName }

    $settings = ConvertTo-ReadableSettings -Policy $raw -Category $category -DefinitionIndex $definitionIndex

    $policyCache[$policyId] = [pscustomobject]@{
      Id       = $policyId
      Name     = $displayName
      Category = $category
      File     = $file.FullName
      Settings = $settings
    }
  }

  $leftKey, $rightKey = $ComparePolicies[0], $ComparePolicies[1]
  $left = Resolve-Policy -Key $leftKey -Cache $policyCache
  $right = Resolve-Policy -Key $rightKey -Cache $policyCache

  if ($left -and $right) {
    $leftSettings = $left.Settings
    $rightSettings = $right.Settings

    # Plain hashtable lookups rather than [System.Linq.Enumerable]::Intersect/Except:
    # PowerShell cannot infer the generic type argument from a hashtable KeyCollection,
    # so those calls fail with "cannot find an overload ... argument count: 2" and the
    # comparison silently reports no differences.
    $commonKeys = @($leftSettings.Keys | Where-Object { $rightSettings.ContainsKey($_) })

    $same = @()
    $different = @()
    foreach ($key in $commonKeys) {
      $lVal = ConvertTo-NormalizedValue -Value $leftSettings[$key]
      $rVal = ConvertTo-NormalizedValue -Value $rightSettings[$key]
      if ($lVal -eq $rVal) {
        $same += [pscustomobject]@{ SettingPath = $key; Value = $lVal }
      }
      else {
        $different += [pscustomobject]@{ SettingPath = $key; LeftValue = $lVal; RightValue = $rVal }
      }
    }

    $leftOnly = @($leftSettings.Keys | Where-Object { -not $rightSettings.ContainsKey($_) } | ForEach-Object {
        [pscustomobject]@{ SettingPath = $_; Value = ConvertTo-NormalizedValue -Value $leftSettings[$_] }
      })
    $rightOnly = @($rightSettings.Keys | Where-Object { -not $leftSettings.ContainsKey($_) } | ForEach-Object {
        [pscustomobject]@{ SettingPath = $_; Value = ConvertTo-NormalizedValue -Value $rightSettings[$_] }
      })

    $comparisons += [pscustomobject]@{
      LeftPolicyName  = $left.Name
      LeftPolicyId    = $left.Id
      LeftCategory    = $left.Category
      LeftFile        = $left.File
      RightPolicyName = $right.Name
      RightPolicyId   = $right.Id
      RightCategory   = $right.Category
      RightFile       = $right.File
      SameSettings    = $same
      Different       = $different
      LeftOnly        = $leftOnly
      RightOnly       = $rightOnly
    }
  }
  else {
    Write-Warning "Could not resolve comparison pair: '$leftKey' vs '$rightKey'"
  }
}

if ($comparisons.Count) {
  $report | Add-Member -MemberType NoteProperty -Name Comparisons -Value $comparisons
}

Write-TextFile -Path $OutputJson -Content ($report | ConvertTo-Json -Depth 12)

# Build a concise text summary for quick viewing.
$lines = @()
$lines += 'Policy overlap report'
$lines += "Generated: $($report.GeneratedAtUtc)"
$lines += "Export: $exportPath"
$lines += "Policies: $($report.TotalPolicies)"
$lines += "Targets: $($report.TotalTargets)"
$lines += ''

foreach ($target in $targetSummaries | Sort-Object TargetKey) {
  $lines += "Target: $($target.TargetLabel) [$($target.PlatformKey)] ($($target.PolicyCount) policies)"
  if (-not $target.SettingFindings.Count) {
    $lines += '  No overlaps or conflicts detected.'
    continue
  }

  foreach ($finding in $target.SettingFindings) {
    $lines += "  [$($finding.Type)] $($finding.SettingPath)"
    foreach ($detail in $finding.Details) {
      $lines += " Value: $($detail.Value)"
      foreach ($policy in $detail.Policies) {
        if ($finding.Type -eq 'Conflict') {
          $lines += " - $($policy.PolicyName) ($($policy.PolicyId)) [$($policy.Category)] = $($detail.Value)"
        }
        else {
          $lines += " - $($policy.PolicyName) ($($policy.PolicyId)) [$($policy.Category)]"
        }
      }
    }
  }
  $lines += ''
}

if ($missingSettings.Count) {
  $lines += 'Policies without comparable settings:'
  foreach ($miss in $missingSettings) {
    $lines += " - $($miss.PolicyName) ($($miss.Category)) reported settingCount=$($miss.SettingCountReported)"
    $lines += "   reason: $($miss.Reason)"
    $lines += "   file: $($miss.File)"
  }
}

if ($payloadIdentifierCollisions.Count) {
  $lines += ''
  $lines += "Profile identifier collisions ($($payloadIdentifierCollisions.Count); live: $(@($payloadIdentifierCollisions | Where-Object { $_.IsLive }).Count)):"
  foreach ($c in $payloadIdentifierCollisions | Sort-Object -Property @{e={-not $_.IsLive}}, PayloadIdentifier) {
    $lines += "  [$(if($c.IsLive){'LIVE'}else{'latent'})] $($c.PayloadIdentifier)"
    foreach ($prof in $c.Profiles) {
      $lines += "     - $($prof.PolicyName)  ->  $($prof.Target)"
    }
  }
}

if ($duplicateProfiles.Count) {
  $lines += ''
  $lines += "Byte-identical duplicate profiles ($($duplicateProfiles.Count)):"
  foreach ($d in $duplicateProfiles) {
    $lines += "  payload $($d.PayloadHash) x$($d.ProfileCount)"
    foreach ($prof in $d.Profiles) { $lines += "     - $($prof.PolicyName)  ->  $($prof.Target)" }
  }
}

if (@($naming.DisabledButAssigned).Count) {
  $lines += ''
  $lines += "WARNING - retired in name only ($(@($naming.DisabledButAssigned).Count)): named as disabled but still assigned"
  foreach ($d in $naming.DisabledButAssigned) { $lines += "  - $($d.PolicyName)  [$($d.Category)]" }
}

if (@($naming.NonCanonicalPrefix).Count -or @($naming.DuplicateNames).Count -or @($naming.MarkersInUse).Count -gt 1) {
  $lines += ''
  $lines += 'Naming convention:'
  if (@($naming.MarkersInUse).Count -gt 1) {
    $lines += "  retirement markers in use: $((@($naming.MarkersInUse) | ForEach-Object { "$($_.Marker) x$($_.Count)" }) -join ', ')"
  }
  foreach ($g in $naming.NonCanonicalPrefix | Group-Object Found, Expected | Sort-Object Count -Descending) {
    $lines += "  prefix '$($g.Group[0].Found)' should be '$($g.Group[0].Expected)': $($g.Count) policies"
  }
  foreach ($d in $naming.DuplicateNames) { $lines += "  duplicate name x$($d.Count): $($d.DisplayName)" }
}

if ($unusedFilters.Count) {
  $lines += ''
  $lines += "Unused assignment filters ($($unusedFilters.Count)):"
  foreach ($uf in $unusedFilters | Sort-Object FilterName) {
    $lines += " - $($uf.FilterName) [$($uf.Platform)] $($uf.Rule)"
  }
}

if ($inventoryOnly.Count -and -not $IncludeInventoryOnly) {
  $lines += ''
  $lines += "Inventoried but not compared ($($inventoryOnly.Count)):"
  foreach ($g in $inventoryOnly | Group-Object Category | Sort-Object Name) {
    $lines += " - $($g.Name): $($g.Count)"
  }
}

if ($exportHealth) {
  if (@($exportHealth.MissingScopes).Count) {
    $lines += ''
    $lines += "WARNING - export ran without these scopes: $(@($exportHealth.MissingScopes) -join ', ')"
  }
  if (@($exportHealth.FailedFetches).Count) {
    $lines += ''
    $lines += "WARNING - $(@($exportHealth.FailedFetches).Count) policies had sub-resource fetch failures; their settings may be under-reported."
  }
}

if ($potentialOverlaps.Count) {
  $lines += ''
  $lines += "Potential cross-target overlaps ($($potentialOverlaps.Count) findings):"
  foreach ($po in $potentialOverlaps) {
    if ($po.Type -eq 'BroadTargetOverlap') {
      $lines += "  [$($po.ValueMatch)] $($po.SettingPath)"
      $lines += "    Broad : $($po.BroadPolicy) -> $($po.BroadTarget) = $($po.BroadValue)"
      $lines += "    Narrow: $($po.NarrowPolicy) -> $($po.NarrowTarget) = $($po.NarrowValue)"
    }
    elseif ($po.Type -eq 'IdenticalDynamicRule') {
      $lines += "  [$($po.ValueMatch)] $($po.SettingPath)"
      $lines += "    Membership rule: $($po.MembershipRule)"
      foreach ($ap in $po.AffectedPolicies) {
        $lines += "    - $($ap.PolicyName) -> $($ap.Target) = $($ap.SettingValue)"
      }
    }
  }
}

if ($comparisons.Count) {
  $lines += ''
  $lines += 'Policy comparisons (duplication vs differences):'
  foreach ($cmp in $comparisons) {
    $lines += "Compare: $($cmp.LeftPolicyName) ($($cmp.LeftPolicyId)) vs $($cmp.RightPolicyName) ($($cmp.RightPolicyId))"
    $lines += " Same settings: $($cmp.SameSettings.Count)"
    foreach ($s in $cmp.SameSettings | Sort-Object SettingPath) {
      $lines += " = $($s.SettingPath) -> $($s.Value)"
    }
    $lines += " Differing settings: $($cmp.Different.Count)"
    foreach ($d in $cmp.Different | Sort-Object SettingPath) {
      $lines += " * $($d.SettingPath)"
      $lines += " Left : $($d.LeftValue)"
      $lines += " Right: $($d.RightValue)"
    }
    $lines += " Left-only settings: $($cmp.LeftOnly.Count)"
    foreach ($l in $cmp.LeftOnly | Sort-Object SettingPath) {
      $lines += " -> $($l.Value)"
    }
    $lines += " Right-only settings: $($cmp.RightOnly.Count)"
    foreach ($r in $cmp.RightOnly | Sort-Object SettingPath) {
      $lines += " > $($r.SettingPath) -> $($r.Value)"
    }
    $lines += ''
  }
}

Write-TextFile -Path $OutputText -Content ($lines -join [Environment]::NewLine)

# Build a Markdown report for easy sharing.
$md = @()
$md += '# Intune Policy Overlap Report'
$md += ''
$md += '| Property | Value |'
$md += '|----------|-------|'
$md += ('| Generated | {0} |' -f $report.GeneratedAtUtc)
$md += ('| Export path | {0} |' -f $exportPath)
$md += ('| Policies analysed | {0} |' -f $report.TotalPolicies)
$md += ('| Assignment targets | {0} |' -f $report.TotalTargets)
$md += ''

# Summary counts
$conflictCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'Conflict' }).Count
$overlapCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'Overlap' }).Count
$violationCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'ComplianceViolation' }).Count
$gapCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'ComplianceGap' }).Count
$enforcedCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'ComplianceEnforced' }).Count
$indirectCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'ComplianceEnforcedIndirectly' }).Count
$notEnforceableCount = @($targetSummaries | ForEach-Object { $_.SettingFindings } | Where-Object { $_.Type -eq 'ComplianceNotEnforceable' }).Count
$unassignedCount = @($unassignedPolicies).Count
$potentialCount = @($potentialOverlaps).Count

if ($conflictCount -or $overlapCount -or $potentialCount -or $violationCount -or $gapCount -or $enforcedCount) {
  $md += '## Summary'
  $md += ''
  $md += ('| Finding type | Count |')
  $md += ('|-------------|------:|')
  if ($violationCount) { $md += ('| :red_circle: Compliance violations (config contradicts compliance) | {0} |' -f $violationCount) }
  if ($conflictCount) { $md += ('| :red_circle: Config conflicts (same target, different values) | {0} |' -f $conflictCount) }
  if (@($payloadIdentifierCollisions | Where-Object { $_.IsLive }).Count) { $md += ('| :red_circle: Profile identifier collisions (one profile replaces another on the device) | {0} |' -f @($payloadIdentifierCollisions | Where-Object { $_.IsLive }).Count) }
  if ($duplicateProfiles.Count) { $md += ('| :yellow_circle: Byte-identical duplicate profiles | {0} |' -f $duplicateProfiles.Count) }
  if ($gapCount) { $md += ('| :orange_circle: Compliance gaps (compliance check with no config enforcing it) | {0} |' -f $gapCount) }
  if ($unassignedCount) { $md += ('| :orange_circle: Unassigned policies (exist but enforce nothing) | {0} |' -f $unassignedCount) }
  if ($overlapCount) { $md += ('| :yellow_circle: Config overlaps (same target, same value) | {0} |' -f $overlapCount) }
  if ($enforcedCount) { $md += ('| :white_check_mark: Compliance enforced (config matches or exceeds compliance) | {0} |' -f $enforcedCount) }
  if ($indirectCount) { $md += ('| :white_check_mark: Compliance enforced indirectly (different setting name) | {0} |' -f $indirectCount) }
  if ($notEnforceableCount) { $md += ('| :grey_question: Compliance checks that no config can enforce (device state) | {0} |' -f $notEnforceableCount) }
  if ($potentialCount) { $md += ('| :large_blue_circle: Potential cross-target overlaps | {0} |' -f $potentialCount) }
  $md += ''
}

# ── Unassigned policies ──
if ($unassignedPolicies.Count) {
  $md += '## :orange_circle: Unassigned Policies'
  $md += ''
  $md += 'These policies exist in the tenant but are assigned to no group, so they enforce nothing. Worth checking against the compliance gaps above — a gap whose only enforcing policy is unassigned is a real exposure, not a reporting artefact.'
  $md += ''
  $md += '| Type | Policy |'
  $md += '|------|--------|'
  foreach ($u in $unassignedPolicies | Sort-Object Category, PolicyName) {
    $md += ('| {0} | {1} |' -f $u.Category, $u.PolicyName)
  }
  $md += ''
}

# ── Compliance checks nothing can enforce ──
if ($notEnforceableCount) {
  $md += ('<details><summary>:grey_question: Compliance checks that no configuration profile can enforce ({0})</summary>' -f $notEnforceableCount)
  $md += ''
  $md += 'These compliance settings report device state (Secure Boot, code integrity, jailbreak detection, OS version) rather than pushing a setting. No configuration profile can satisfy them directly, so they are listed separately rather than counted as gaps.'
  $md += ''
  $seen = @{}
  foreach ($t in $targetSummaries) {
    foreach ($f in @($t.SettingFindings | Where-Object { $_.Type -eq 'ComplianceNotEnforceable' })) {
      $k = "$($t.TargetLabel)|$($f.SettingPath)"
      if ($seen.ContainsKey($k)) { continue }
      $seen[$k] = $true
      $md += ('- **{0}** — {1} (checked by {2})' -f $f.SettingPath, $t.TargetLabel, (@($f.Details[0].Policies | ForEach-Object { $_.PolicyName }) -join ', '))
    }
  }
  $md += ''
  $md += '</details>'
  $md += ''
}

# ── Compliance enforced under a different setting name ──
if ($indirectCount) {
  $md += ('<details><summary>:white_check_mark: Compliance enforced indirectly ({0})</summary>' -f $indirectCount)
  $md += ''
  $md += 'A configuration policy on the same target enforces these checks under a different setting name, so they are not gaps.'
  $md += ''
  foreach ($t in $targetSummaries) {
    foreach ($f in @($t.SettingFindings | Where-Object { $_.Type -eq 'ComplianceEnforcedIndirectly' })) {
      $md += ('- **{0}** ({1}) — enforced by `{2}`' -f $f.SettingPath, $t.TargetLabel, $f.EnforcedBy.PolicyName)
    }
  }
  $md += ''
  $md += '</details>'
  $md += ''
}

# ── Data quality: what this report could and could not see ──
# A finding list is only as trustworthy as the export behind it, so any gap in the
# underlying data is stated up front rather than left for the reader to infer.
$dataCaveats = @()
if (-not $manifest) {
  $dataCaveats += 'No `export-manifest.json` found. Failed sub-resource fetches cannot be distinguished from policies that genuinely have no settings.'
}
if (-not $definitionIndex.Count) {
  $dataCaveats += 'No `setting-definitions.json` found. Settings Catalog rows show raw setting ids rather than display names.'
}
if ($exportHealth) {
  if (@($exportHealth.MissingScopes).Count) {
    $dataCaveats += ('The export ran without these permissions, so some data is absent by omission: `{0}`.' -f (@($exportHealth.MissingScopes) -join '`, `'))
  }
  if (@($exportHealth.FailedFetches).Count) {
    $dataCaveats += ('{0} policies had at least one sub-resource fail to export. Their settings may be under-reported below.' -f @($exportHealth.FailedFetches).Count)
  }
}
if ($inventoryOnly.Count -and -not $IncludeInventoryOnly) {
  $invCatList = (@($inventoryOnly | ForEach-Object { $_.Category }) | Sort-Object -Unique) -join '`, `'
  $dataCaveats += ('{0} policies in `{1}` were inventoried but not compared (own priority/ordering semantics). Re-run with `-IncludeInventoryOnly` to include them.' -f $inventoryOnly.Count, $invCatList)
}

if ($dataCaveats.Count) {
  $md += '## :information_source: Scope of this report'
  $md += ''
  foreach ($c in $dataCaveats) { $md += ('- {0}' -f $c) }
  $md += ''
  if ($exportHealth -and @($exportHealth.FailedFetches).Count) {
    $md += '<details><summary>Policies with failed sub-resource fetches</summary>'
    $md += ''
    $md += '| Policy | Type | Problem |'
    $md += '|--------|------|---------|'
    foreach ($ff in $exportHealth.FailedFetches) {
      $md += ('| {0} | {1} | {2} |' -f $ff.PolicyName, $ff.Category, ((@($ff.Problems) -join '; ') -replace '\|', '/'))
    }
    $md += ''
    $md += '</details>'
    $md += ''
  }
}

# ── Profile identifier collisions ──
# Deliberately ahead of the setting-level sections: when two profiles share an identifier,
# one simply replaces the other, so comparing their settings is beside the point.
if ($payloadIdentifierCollisions.Count) {
  $liveCollisions = @($payloadIdentifierCollisions | Where-Object { $_.IsLive })
  $latentCollisions = @($payloadIdentifierCollisions | Where-Object { -not $_.IsLive })

  if ($liveCollisions.Count) {
    $md += '## :red_circle: Profile Identifier Collisions'
    $md += ''
    $md += 'macOS keys an installed configuration profile by its top-level `PayloadIdentifier`. When two profiles share one, the second to arrive **replaces** the first rather than merging with it — and which one wins depends on delivery order, so it cannot be determined from the exported configuration alone. Setting-level comparison cannot detect this.'
    $md += ''
    foreach ($c in $liveCollisions) {
      $md += ('### `{0}`' -f $c.PayloadIdentifier)
      $md += ''
      if (@($c.PayloadTypes).Count) { $md += ('> Payload types: {0}' -f (@($c.PayloadTypes) -join ', ')); $md += '' }
      $md += '| Profile | Type | Assigned to |'
      $md += '|---------|------|-------------|'
      foreach ($prof in $c.Profiles) {
        $md += ('| {0} | {1} | {2} |' -f $prof.PolicyName, $prof.Category, $prof.Target)
      }
      $md += ''
      $md += ('Resolve by giving one profile a fresh unique `PayloadIdentifier`, or by retiring the duplicate if both carry the same configuration. Verify on a device with `sudo profiles show -output stdout-xml`.')
      $md += ''
    }
  }

  if ($latentCollisions.Count) {
    $md += ('<details><summary>Latent identifier collisions ({0}) — only one side is assigned</summary>' -f $latentCollisions.Count)
    $md += ''
    $md += 'These share an identifier but currently only one reaches devices, so nothing is being replaced today. They become live the moment the other is assigned.'
    $md += ''
    foreach ($c in $latentCollisions) {
      $md += ('- `{0}` — {1}' -f $c.PayloadIdentifier, (@($c.Profiles | ForEach-Object { '{0} ({1})' -f $_.PolicyName, $_.Target }) -join ' vs '))
    }
    $md += ''
    $md += '</details>'
    $md += ''
  }
}

# ── Naming convention ──
# A policy that says it is retired while still assigned is a real trap, so it is called out
# above the fold. Everything else here is hygiene and stays collapsed.
if (@($naming.DisabledButAssigned).Count) {
  $md += '## :red_circle: Retired In Name Only'
  $md += ''
  $md += 'These policies are named as if they were disabled, but they are still assigned and still reaching devices. Either the name or the assignment is wrong.'
  $md += ''
  $md += '| Policy | Type | Marker |'
  $md += '|--------|------|--------|'
  foreach ($d in $naming.DisabledButAssigned) {
    $md += ('| {0} | {1} | `{2}` |' -f $d.PolicyName, $d.Category, $d.Marker)
  }
  $md += ''
}

$namingIssueCount = @($naming.NonCanonicalPrefix).Count + @($naming.DuplicateNames).Count + [int](@($naming.MarkersInUse).Count -gt 1)
if ($namingIssueCount) {
  $md += ('<details><summary>:pencil2: Naming convention ({0} issues)</summary>' -f $namingIssueCount)
  $md += ''

  if (@($naming.MarkersInUse).Count -gt 1) {
    $md += ('**{0} different retirement markers in use.** Pick one so retired policies sort and search together — `{1}` is the current house style.' -f @($naming.MarkersInUse).Count, $namingConvention.PreferredMarker)
    $md += ''
    $md += '| Marker | Policies |'
    $md += '|--------|---------:|'
    foreach ($m in $naming.MarkersInUse) { $md += ('| `{0}` | {1} |' -f $m.Marker, $m.Count) }
    $md += ''
  }

  if (@($naming.NonCanonicalPrefix).Count) {
    $md += ('**{0} policies use a non-canonical platform prefix.** The prefix is what makes a policy list scannable; splitting one platform across several spellings defeats it.' -f @($naming.NonCanonicalPrefix).Count)
    $md += ''
    $md += '| Found | Expected | Policies |'
    $md += '|-------|----------|---------:|'
    foreach ($g in $naming.NonCanonicalPrefix | Group-Object Found, Expected | Sort-Object Count -Descending) {
      $first = $g.Group[0]
      $md += ('| `{0}` | `{1}` | {2} |' -f $first.Found, $first.Expected, $g.Count)
    }
    $md += ''
    foreach ($g in $naming.NonCanonicalPrefix | Group-Object Expected | Sort-Object Name) {
      $md += ('*{0}*' -f $g.Name)
      foreach ($p in $g.Group | Sort-Object PolicyName) { $md += ('- {0}  ({1})' -f $p.PolicyName, $p.Category) }
      $md += ''
    }
  }

  if (@($naming.DuplicateNames).Count) {
    $md += ('**{0} display names used by more than one policy.** Intune built-ins are excluded.' -f @($naming.DuplicateNames).Count)
    $md += ''
    foreach ($d in $naming.DuplicateNames) {
      $md += ('- **{0}** — {1} policies: {2}' -f $d.DisplayName, $d.Count, ((@($d.Policies | ForEach-Object { $_.Category }) | Sort-Object -Unique) -join ', '))
    }
    $md += ''
  }

  $md += '</details>'
  $md += ''
}

# ── Byte-identical duplicate profiles ──
if ($duplicateProfiles.Count) {
  $md += ('<details><summary>:yellow_circle: Byte-identical duplicate profiles ({0})</summary>' -f $duplicateProfiles.Count)
  $md += ''
  $md += 'These profiles carry exactly the same payload. Usually a copy made for a new target that was never consolidated back. Harmless in effect, but each one is a separate thing to maintain and to get wrong later.'
  $md += ''
  foreach ($d in $duplicateProfiles) {
    $md += ('- **{0} copies** (payload `{1}`)' -f $d.ProfileCount, $d.PayloadHash)
    foreach ($prof in $d.Profiles) {
      $md += ('  - {0} — {1}' -f $prof.PolicyName, $prof.Target)
    }
  }
  $md += ''
  $md += '</details>'
  $md += ''
}

# ── Conflicts section (config-only) ──
$conflictTargets = @($targetSummaries | Where-Object { $_.SettingFindings | Where-Object { $_.Type -eq 'Conflict' } })
if ($conflictTargets.Count) {
  $md += '## :red_circle: Config Conflicts'
  $md += ''
  $md += 'Multiple **configuration** policies assign **different values** to the same setting for the same target. Intune cannot resolve these deterministically.'
  $md += ''
  foreach ($target in $conflictTargets | Sort-Object TargetKey) {
    $md += ('### {0}' -f $target.TargetLabel)
    $md += ''
    $md += ('> Platform: {0} — {1} policies{2}' -f $target.PlatformKey, $target.PolicyCount, (Format-TargetReach -Target $target))
    if ($target.SpansMultipleTags) {
      $md += ('> Scope tags: {0} — these policies are administered under different scope tags and may be owned by different teams.' -f (@($target.ScopeTags) -join ', '))
    }
    if ($target.Filters -and @($target.Filters).Count) {
      $md += '>'
      foreach ($tf in @($target.Filters)) {
        $md += ('> Filter: **{0}** — {1}' -f $tf.FilterName, $tf.FilterRule)
      }
    }
    $md += ''
    $conflictFindings = @($target.SettingFindings | Where-Object { $_.Type -eq 'Conflict' })
    foreach ($finding in $conflictFindings) {
      $md += ('#### {0}' -f $finding.SettingPath)
      $md += ''
      $md += '| Policy | Category | Filter | Value |'
      $md += '|--------|----------|--------|-------|'
      foreach ($detail in $finding.Details) {
        foreach ($policy in $detail.Policies) {
          $filterCell = if ($policy.FilterName) { $policy.FilterName } else { '' }
          $md += ('| {0} | {1} | {2} | {3} |' -f $policy.PolicyName, $policy.Category, $filterCell, (Format-MarkdownValue -Value $detail.Value))
        }
      }
      $md += ''
    }
  }
}

# ── Compliance violations section ──
$violationTargets = @($targetSummaries | Where-Object { $_.SettingFindings | Where-Object { $_.Type -eq 'ComplianceViolation' } })
if ($violationTargets.Count) {
  $md += '## :red_circle: Compliance Violations'
  $md += ''
  $md += 'A configuration profile **enforces a value** that would cause devices to **fail** the compliance check. The configuration should be updated to match or exceed the compliance requirement.'
  $md += ''
  foreach ($target in $violationTargets | Sort-Object TargetKey) {
    $md += ('### {0}' -f $target.TargetLabel)
    $md += ''
    $md += ('> Platform: {0} — {1} policies{2}' -f $target.PlatformKey, $target.PolicyCount, (Format-TargetReach -Target $target))
    if ($target.SpansMultipleTags) {
      $md += ('> Scope tags: {0} — these policies are administered under different scope tags and may be owned by different teams.' -f (@($target.ScopeTags) -join ', '))
    }
    if ($target.Filters -and @($target.Filters).Count) {
      $md += '>'
      foreach ($tf in @($target.Filters)) {
        $md += ('> Filter: **{0}** — {1}' -f $tf.FilterName, $tf.FilterRule)
      }
    }
    $md += ''
    $violationFindings = @($target.SettingFindings | Where-Object { $_.Type -eq 'ComplianceViolation' })
    foreach ($finding in $violationFindings) {
      $md += ('#### {0}' -f $finding.SettingPath)
      $md += ''
      $md += '| Policy | Type | Filter | Value |'
      $md += '|--------|------|--------|-------|'
      foreach ($detail in $finding.Details) {
        foreach ($policy in $detail.Policies) {
          $filterCell = if ($policy.FilterName) { $policy.FilterName } else { '' }
          $policyType = if ($policy.Category -eq 'CompliancePolicies') { 'Compliance' } else { 'Configuration' }
          $md += ('| {0} | {1} | {2} | {3} |' -f $policy.PolicyName, $policyType, $filterCell, (Format-MarkdownValue -Value $detail.Value))
        }
      }
      $md += ''

      # What happens to a device that fails the check. A violation whose action is an
      # immediate block is the most severe combination there is: configuration is actively
      # pushing a value that fails a check which then blocks the device with no grace period.
      $actionNotes = @()
      foreach ($detail in $finding.Details) {
        foreach ($policy in $detail.Policies) {
          if ($policy.Category -ne 'CompliancePolicies') { continue }
          if (-not $policy.PolicyId -or -not $policyContext.ContainsKey("$($policy.PolicyId)")) { continue }
          $ca = $policyContext["$($policy.PolicyId)"].ComplianceActions
          if ($null -eq $ca) { continue }
          $note = if ($ca.IsImmediateBlock) {
            ':warning: **{0} acts on failure: {1}** — non-compliant devices are blocked with no grace period.' -f $policy.PolicyName, $ca.Summary
          }
          else {
            '{0} acts on failure: {1}' -f $policy.PolicyName, $ca.Summary
          }
          if ($note -notin $actionNotes) { $actionNotes += $note }
        }
      }
      if ($actionNotes.Count) {
        foreach ($n in $actionNotes) { $md += ('- {0}' -f $n) }
        $md += ''
      }
    }
  }
}

# ── Compliance gaps section ──
$gapTargets = @($targetSummaries | Where-Object { $_.SettingFindings | Where-Object { $_.Type -eq 'ComplianceGap' } })
if ($gapTargets.Count) {
  $md += '## :orange_circle: Compliance Gaps'
  $md += ''
  $md += 'A compliance policy **checks** a setting, but no configuration profile **enforces** it for the same target. Devices may fail compliance if users do not configure these settings themselves.'
  $md += ''
  foreach ($target in $gapTargets | Sort-Object TargetKey) {
    $md += ('### {0}' -f $target.TargetLabel)
    $md += ''
    $md += ('> Platform: {0} — {1} policies{2}' -f $target.PlatformKey, $target.PolicyCount, (Format-TargetReach -Target $target))
    if ($target.SpansMultipleTags) {
      $md += ('> Scope tags: {0} — these policies are administered under different scope tags and may be owned by different teams.' -f (@($target.ScopeTags) -join ', '))
    }
    if ($target.Filters -and @($target.Filters).Count) {
      $md += '>'
      foreach ($tf in @($target.Filters)) {
        $md += ('> Filter: **{0}** — {1}' -f $tf.FilterName, $tf.FilterRule)
      }
    }
    $md += ''
    $gapFindings = @($target.SettingFindings | Where-Object { $_.Type -eq 'ComplianceGap' })
    foreach ($finding in $gapFindings) {
      $md += ('- {0} = {1}' -f $finding.SettingPath, (Format-MarkdownValue -Value $finding.Details[0].Value))
      foreach ($policy in $finding.Details[0].Policies) {
        # What actually happens to a device that fails this check decides how urgent the
        # gap is: "mark non-compliant after 7 days" is not "retire immediately".
        $actionNote = ''
        if ($policy.PolicyId -and $policyContext.ContainsKey("$($policy.PolicyId)")) {
          $ca = $policyContext["$($policy.PolicyId)"].ComplianceActions
          if ($null -ne $ca) {
            $actionNote = if ($ca.IsImmediateBlock) {
              ' — **action: {0}**' -f $ca.Summary
            }
            else {
              ' — action: {0}' -f $ca.Summary
            }
          }
        }
        $md += ('  - {0} (compliance only — no config enforcing this){1}' -f $policy.PolicyName, $actionNote)
      }
    }
    $md += ''
  }
}

# ── Compliance enforced section ──
$enforcedTargets = @($targetSummaries | Where-Object { $_.SettingFindings | Where-Object { $_.Type -eq 'ComplianceEnforced' } })
if ($enforcedTargets.Count) {
  $md += '<details><summary>:white_check_mark: Compliance Enforced ({0} settings where config matches compliance)</summary>' -f $enforcedCount
  $md += ''
  $md += 'These settings are correctly aligned — a configuration profile enforces the same value that the compliance policy checks.'
  $md += ''
  foreach ($target in $enforcedTargets | Sort-Object TargetKey) {
    $md += ('### {0}' -f $target.TargetLabel)
    $md += ''
    $md += ('> Platform: {0}' -f $target.PlatformKey)
    $md += ''
    $enforcedFindings = @($target.SettingFindings | Where-Object { $_.Type -eq 'ComplianceEnforced' })
    foreach ($finding in $enforcedFindings) {
      $policyNames = @($finding.Details[0].Policies | ForEach-Object { '{0} ({1})' -f $_.PolicyName, $_.Category }) -join ' + '
      $md += ('- {0} = {1} — {2}' -f $finding.SettingPath, (Format-MarkdownValue -Value $finding.Details[0].Value), $policyNames)
    }
    $md += ''
  }
  $md += '</details>'
  $md += ''
}

# ── Overlaps section (config-only) ──
$overlapTargets = @($targetSummaries | Where-Object { $_.SettingFindings | Where-Object { $_.Type -eq 'Overlap' } })
if ($overlapTargets.Count) {
  $md += '## :yellow_circle: Config Overlaps'
  $md += ''
  $md += 'Multiple **configuration** policies assign the **same value** to the same setting for the same target. Not harmful, but indicates redundancy that can be consolidated.'
  $md += ''
  foreach ($target in $overlapTargets | Sort-Object TargetKey) {
    $md += ('### {0}' -f $target.TargetLabel)
    $md += ''
    $md += ('> Platform: {0} — {1} policies{2}' -f $target.PlatformKey, $target.PolicyCount, (Format-TargetReach -Target $target))
    if ($target.SpansMultipleTags) {
      $md += ('> Scope tags: {0} — these policies are administered under different scope tags and may be owned by different teams.' -f (@($target.ScopeTags) -join ', '))
    }
    if ($target.Filters -and @($target.Filters).Count) {
      $md += '>'
      foreach ($tf in @($target.Filters)) {
        $md += ('> Filter: **{0}** — {1}' -f $tf.FilterName, $tf.FilterRule)
      }
    }
    $md += ''
    $overlapFindings = @($target.SettingFindings | Where-Object { $_.Type -eq 'Overlap' })
    foreach ($finding in $overlapFindings) {
      $filterLabels = @($finding.Details[0].Policies | Where-Object { $_.FilterName } | ForEach-Object { $_.FilterName } | Select-Object -Unique)
      $filterSuffix = if ($filterLabels.Count) { ' (filter: {0})' -f ($filterLabels -join ', ') } else { '' }
      $md += ('- {0} = {1}{2}' -f $finding.SettingPath, (Format-MarkdownValue -Value $finding.Details[0].Value), $filterSuffix)
      foreach ($policy in $finding.Details[0].Policies) {
        $md += ('  - {0} ({1})' -f $policy.PolicyName, $policy.Category)
      }
    }
    $md += ''
  }
}

# ── Clean targets ──
$cleanTargets = @($targetSummaries | Where-Object { -not $_.SettingFindings.Count })
if ($cleanTargets.Count) {
  $md += '## Clean targets'
  $md += ''
  $md += 'These assignment targets have no detected conflicts or overlaps.'
  $md += ''
  $md += '| Target | Platform | Policies | Filter |'
  $md += '|--------|----------|--------:|--------|'
  foreach ($target in $cleanTargets | Sort-Object TargetKey) {
    $filterCell = if ($target.Filters -and @($target.Filters).Count) { (@($target.Filters) | ForEach-Object { $_.FilterName }) -join ', ' } else { '' }
    $md += ('| {0} | {1} | {2} | {3} |' -f $target.TargetLabel, $target.PlatformKey, $target.PolicyCount, $filterCell)
  }
  $md += ''
}

# ── Potential cross-target overlaps ──
if ($potentialOverlaps.Count) {
  $md += '## :large_blue_circle: Potential cross-target overlaps'
  $md += ''
  $md += 'These findings indicate settings that **may** conflict because the assignment targets overlap (e.g., "All Devices" is a superset of any group, or two dynamic groups share the same membership rule).'
  $md += ''

  $broadOverlaps = @($potentialOverlaps | Where-Object { $_.Type -eq 'BroadTargetOverlap' })
  $dynamicOverlaps = @($potentialOverlaps | Where-Object { $_.Type -eq 'IdenticalDynamicRule' })

  if ($broadOverlaps.Count) {
    $md += '### Broad target vs group'
    $md += ''
    $md += '| Setting | Broad policy | Broad target | Value | Narrow policy | Narrow target | Value | Match |'
    $md += '|---------|-------------|-------------|-------|--------------|--------------|-------|-------|'
    foreach ($po in $broadOverlaps) {
      $settingShort = ($po.SettingPath -split '\|', 2)[-1]
      $matchIcon = if ($po.ValueMatch -eq 'SameValue') { ':yellow_circle:' } else { ':red_circle:' }
      $md += ('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |' -f $settingShort, $po.BroadPolicy, $po.BroadTarget, (Format-MarkdownValue -Value $po.BroadValue), $po.NarrowPolicy, $po.NarrowTarget, (Format-MarkdownValue -Value $po.NarrowValue), $matchIcon)
    }
    $md += ''
  }

  if ($dynamicOverlaps.Count) {
    $md += '### Identical dynamic group membership rules'
    $md += ''
    foreach ($po in $dynamicOverlaps) {
      $settingShort = ($po.SettingPath -split '\|', 2)[-1]
      $matchIcon = if ($po.ValueMatch -eq 'SameValue') { ':yellow_circle: Same value' } else { ':red_circle: Different values' }
      $md += ('- {0} — {1}' -f $settingShort, $matchIcon)
      $md += ('  - Membership rule: {0}' -f $po.MembershipRule)
      foreach ($ap in $po.AffectedPolicies) {
        $md += ('  - {0} → {1} = {2}' -f $ap.PolicyName, $ap.Target, (Format-MarkdownValue -Value $ap.SettingValue))
      }
    }
    $md += ''
  }
}

# ── Missing settings ──
if ($missingSettings.Count) {
  $md += '## Policies missing settings'
  $md += ''
  $md += 'These policies were exported without detailed settings. The overlap analysis may be incomplete for them.'
  $md += ''
  $md += '| Policy | Category | Reported setting count |'
  $md += '|--------|----------|----------------------:|'
  foreach ($miss in $missingSettings) {
    $md += ('| {0} | {1} | {2} |' -f $miss.PolicyName, $miss.Category, $miss.SettingCountReported)
  }
  $md += ''
}

# ── Policy comparisons ──
if ($comparisons.Count) {
  $md += '## Policy comparisons'
  $md += ''
  foreach ($cmp in $comparisons) {
    $md += ('### {0} vs {1}' -f $cmp.LeftPolicyName, $cmp.RightPolicyName)
    $md += ''
    $md += '| | Policy | Category |'
    $md += '|---|--------|----------|'
    $md += ('| Left | {0} | {1} |' -f $cmp.LeftPolicyName, $cmp.LeftCategory)
    $md += ('| Right | {0} | {1} |' -f $cmp.RightPolicyName, $cmp.RightCategory)
    $md += ''

    if ($cmp.Different.Count) {
      $md += ('**Differing settings ({0})**' -f $cmp.Different.Count)
      $md += ''
      $md += '| Setting | Left value | Right value |'
      $md += '|---------|-----------|------------|'
      foreach ($d in $cmp.Different | Sort-Object SettingPath) {
        $md += ('| {0} | {1} | {2} |' -f $d.SettingPath, (Format-MarkdownValue -Value $d.LeftValue), (Format-MarkdownValue -Value $d.RightValue))
      }
      $md += ''
    }

    if ($cmp.SameSettings.Count) {
      $md += ('<details><summary>Identical settings ({0})</summary>' -f $cmp.SameSettings.Count)
      $md += ''
      $md += '| Setting | Value |'
      $md += '|---------|-------|'
      foreach ($s in $cmp.SameSettings | Sort-Object SettingPath) {
        $md += ('| {0} | {1} |' -f $s.SettingPath, (Format-MarkdownValue -Value $s.Value))
      }
      $md += ''
      $md += '</details>'
      $md += ''
    }

    if ($cmp.LeftOnly.Count) {
      $md += ('<details><summary>Left-only settings ({0})</summary>' -f $cmp.LeftOnly.Count)
      $md += ''
      $md += '| Setting | Value |'
      $md += '|---------|-------|'
      foreach ($l in $cmp.LeftOnly | Sort-Object SettingPath) {
        $md += ('| {0} | {1} |' -f $l.SettingPath, (Format-MarkdownValue -Value $l.Value))
      }
      $md += ''
      $md += '</details>'
      $md += ''
    }

    if ($cmp.RightOnly.Count) {
      $md += ('<details><summary>Right-only settings ({0})</summary>' -f $cmp.RightOnly.Count)
      $md += ''
      $md += '| Setting | Value |'
      $md += '|---------|-------|'
      foreach ($r in $cmp.RightOnly | Sort-Object SettingPath) {
        $md += ('| {0} | {1} |' -f $r.SettingPath, (Format-MarkdownValue -Value $r.Value))
      }
      $md += ''
      $md += '</details>'
      $md += ''
    }
  }
}

# ── Unused assignment filters ──
if ($unusedFilters.Count) {
  $md += ('<details><summary>:wastebasket: Unused assignment filters ({0})</summary>' -f $unusedFilters.Count)
  $md += ''
  $md += 'Filters defined in the tenant that no policy assignment references. Harmless, but they accumulate and make the filter list harder to reason about.'
  $md += ''
  $md += '| Filter | Platform | Rule |'
  $md += '|--------|----------|------|'
  foreach ($uf in $unusedFilters | Sort-Object FilterName) {
    $md += ('| {0} | {1} | {2} |' -f $uf.FilterName, $uf.Platform, (Format-MarkdownValue -Value $uf.Rule))
  }
  $md += ''
  $md += '</details>'
  $md += ''
}

# ── Exclusion targets ──
if ($excludedRecords.Count) {
  $exclusionSummary = @($excludedRecords | Select-Object PolicyName, Target -Unique)
  $md += ('<details><summary>:no_entry_sign: Exclusion targets ({0})</summary>' -f $exclusionSummary.Count)
  $md += ''
  $md += 'These assignments *remove* a policy from a group rather than applying it, so they are excluded from conflict comparison. Listed here because an exclusion is often what explains why an expected setting is not reaching a device.'
  $md += ''
  $md += '| Policy | Excluded target |'
  $md += '|--------|-----------------|'
  foreach ($ex in $exclusionSummary | Sort-Object PolicyName) {
    $md += ('| {0} | {1} |' -f $ex.PolicyName, $ex.Target)
  }
  $md += ''
  $md += '</details>'
  $md += ''
}

# ── Inventory-only policies ──
if ($inventoryOnly.Count -and -not $IncludeInventoryOnly) {
  $md += ('<details><summary>:package: Inventoried but not compared ({0})</summary>' -f $inventoryOnly.Count)
  $md += ''
  $md += 'Exported for completeness. Enrollment configurations, update rings and scripts resolve by their own priority and ordering rules, which setting-level overlap comparison does not model — including them would produce findings that do not correspond to real conflicts.'
  $md += ''
  $md += '| Type | Count |'
  $md += '|------|------:|'
  foreach ($g in $inventoryOnly | Group-Object Category | Sort-Object Name) {
    $md += ('| {0} | {1} |' -f $g.Name, $g.Count)
  }
  $md += ''
  $md += '</details>'
  $md += ''
}

Write-TextFile -Path $OutputMarkdown -Content ($md -join [Environment]::NewLine)

Write-Host 'Report written:' -ForegroundColor Green
Write-Host " JSON: $OutputJson"
Write-Host " Text: $OutputText"
Write-Host " Markdown: $OutputMarkdown"
