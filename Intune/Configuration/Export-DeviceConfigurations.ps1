<#
.SYNOPSIS
Exports Microsoft Intune configuration, compliance, app, enrollment, update and script
policies to JSON for offline analysis.

.DESCRIPTION
Connects to Microsoft Graph and exports Intune policy objects to JSON files, together with
resolved assignment targets, setting definitions, scope tag names and an export manifest.

Supported policy types (see -profileType):
- DeviceConfigurations          /deviceManagement/deviceConfigurations
- ConfigurationPolicies         /deviceManagement/configurationPolicies (Settings Catalog)
- GroupPolicyConfigurations     /deviceManagement/groupPolicyConfigurations (ADMX)
- EndpointSecurityPolicies      /deviceManagement/intents (legacy Endpoint Security)
- CompliancePolicies            /deviceManagement/deviceCompliancePolicies
- AppProtectionPolicies         /deviceAppManagement/managedAppPolicies (MAM)
- AppConfigurationPolicies      /deviceAppManagement/mobileAppConfigurations
- ManagedAppConfigurations      /deviceAppManagement/targetedManagedAppConfigurations
- EnrollmentConfigurations      /deviceManagement/deviceEnrollmentConfigurations (ESP, restrictions)
- WindowsDriverUpdateProfiles   /deviceManagement/windowsDriverUpdateProfiles
- WindowsQualityUpdateProfiles  /deviceManagement/windowsQualityUpdateProfiles
- WindowsFeatureUpdateProfiles  /deviceManagement/windowsFeatureUpdateProfiles
- DeviceHealthScripts           /deviceManagement/deviceHealthScripts (Proactive Remediations)
- DeviceManagementScripts       /deviceManagement/deviceManagementScripts (Windows PowerShell)
- DeviceShellScripts            /deviceManagement/deviceShellScripts (macOS)

You can export everything, or filter by a specific profile id, profile name (wildcards
supported), and/or an @odata.type value.

Windows Update rings are legacy device configuration profiles
(#microsoft.graph.windowsUpdateForBusinessConfiguration) and are covered by
-profileType DeviceConfigurations.

.PARAMETER outDir
Output base directory. Exports are written under <outDir>\<tenantId>\<yyyy-MM-dd>\<profileType>.

.PARAMETER profileType
Which policy endpoint(s) to export. 'All' exports every supported type.

.PARAMETER profileId
Export a single policy by id.

.PARAMETER profileName
Export policies whose displayName matches this pattern (wildcards supported).

.PARAMETER odataType
Optional filter by @odata.type (wildcards supported). Most useful for legacy deviceConfigurations.

.PARAMETER tenantId
Optional tenant id (GUID) or tenant domain name for authentication.

.PARAMETER graphApiVersion
Microsoft Graph API version to use for requests. Individual policy types that only exist in
beta are promoted automatically; this parameter controls the rest.

.PARAMETER emitConsolidated
Also write a single consolidated JSON file containing all exported policies to the output root.

.PARAMETER includeAssignmentsInConsolidated
With -emitConsolidated, embed resolved assignment targets into each consolidated item.

.PARAMETER includeStatusSummaries
Fetch aggregate deployment status (deviceStatusOverview / userStatusOverview) per policy so the
analyzer can weigh findings by how many devices are affected. Aggregate counts only -- per-device
and per-user status collections are never exported because they contain device names and UPNs.

.PARAMETER includeGroupMemberCounts
Resolve transitive member counts for assignment groups, to size the blast radius of a finding.
Counts only; no member identities are read or written. Requires Group.Read.All and adds one
Graph call per distinct group.

.PARAMETER maxRetryCount
How many times to retry a throttled (429) or transient (5xx) Graph request. Default 5.

.PARAMETER force
Overwrite existing JSON files and skip the tenant/account confirmation prompt.

.PARAMETER useDeviceCode
Use device-code authentication instead of opening a browser for interactive sign-in.
Note: device-code auth is commonly blocked by Conditional Access policies; prefer interactive
sign-in unless you know device-code is allowed.

.EXAMPLE
./Export-DeviceConfigurations.ps1

Exports all supported policy types to the default output folder.

.EXAMPLE
./Export-DeviceConfigurations.ps1 -profileType DeviceConfigurations -profileName '*BitLocker*'

Exports legacy device configuration profiles with displayName matching '*BitLocker*'.

.EXAMPLE
./Export-DeviceConfigurations.ps1 -emitConsolidated -includeAssignmentsInConsolidated -includeStatusSummaries

Full export with a consolidated file and aggregate deployment counts, ready for
Analyze-PolicyOverlap.ps1.

.EXAMPLE
./Export-DeviceConfigurations.ps1 -useDeviceCode

Uses device-code authentication (works even if the wrong browser is opening for interactive sign-in).

.NOTES
Requires the Microsoft Graph PowerShell SDK. Install with:
  Install-Module Microsoft.Graph -Scope CurrentUser

Delegated permissions requested (the script degrades gracefully and records any that are
missing in export-manifest.json):
  DeviceManagementConfiguration.Read.All   configuration, compliance and update policies
  DeviceManagementApps.Read.All            app protection and app configuration policies
  DeviceManagementServiceConfig.Read.All   enrollment configurations
  DeviceManagementScripts.Read.All         health scripts, platform scripts, shell scripts
  DeviceManagementRBAC.Read.All            scope tag name resolution
  Group.Read.All                           group names, dynamic membership rules, member counts
  User.Read.All                            user names on user-targeted assignments

Requested only when the switch that uses it is supplied:
  DeviceManagementManagedDevices.Read.All  aggregate deployment status (-includeStatusSummaries)

Deliberately NOT requested: Directory.Read.All. It backed a fallback that resolved an
assignment target which Group.Read.All/User.Read.All could not. That fallback now degrades to
reporting the raw object id rather than asking every operator to consent to reading the whole
directory. Where a tenant has already granted it, the fallback still runs.

Every scope above is read-only -- this script never writes to Intune.

Data handling: this export writes decoded custom-profile payloads (.payload.xml) which can
contain certificate material and embedded credentials. Per-device and per-user status
collections are deliberately never fetched.
#>

[CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess = $true, PositionalBinding = $false)]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$outDir = (Join-Path -Path $PSScriptRoot -ChildPath 'exports'),

  [Parameter()]
  [ValidateSet(
    'All',
    'DeviceConfigurations',
    'ConfigurationPolicies',
    'GroupPolicyConfigurations',
    'EndpointSecurityPolicies',
    'CompliancePolicies',
    'AppProtectionPolicies',
    'AppConfigurationPolicies',
    'ManagedAppConfigurations',
    'EnrollmentConfigurations',
    'WindowsDriverUpdateProfiles',
    'WindowsQualityUpdateProfiles',
    'WindowsFeatureUpdateProfiles',
    'DeviceHealthScripts',
    'DeviceManagementScripts',
    'DeviceShellScripts'
  )]
  [string[]]$profileType = 'All',

  [Parameter(ParameterSetName = 'ById', Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$profileId,

  [Parameter(ParameterSetName = 'ByName')]
  [ValidateNotNullOrEmpty()]
  [string]$profileName,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$odataType,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$tenantId,

  [Parameter()]
  [ValidateSet('v1.0', 'beta')]
  [string]$graphApiVersion = 'v1.0',

  [Parameter()]
  [switch]$useDeviceCode,

  [Parameter()]
  [switch]$emitConsolidated,

  [Parameter()]
  [switch]$includeAssignmentsInConsolidated,

  [Parameter()]
  [switch]$includeStatusSummaries,

  [Parameter()]
  [switch]$includeGroupMemberCounts,

  [Parameter()]
  [ValidateRange(0, 20)]
  [int]$maxRetryCount = 5,

  [Parameter()]
  [switch]$force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Profile type registry

# Single source of truth for every exportable policy type. Adding a type here is enough --
# the 'All' set, the required scope list and the README table are all derived from it.
#
#   Path        Graph path relative to the API root.
#   ForceBeta   Endpoint does not exist (or is incomplete) in v1.0.
#   Scope       Delegated permission the endpoint needs.
#   Assignments Endpoint exposes an /assignments navigation property.
#   Analyze     Participates in Analyze-PolicyOverlap.ps1 setting-level comparison.
#               Types set to $false are exported for inventory but have their own
#               priority/ordering semantics that overlap analysis does not model.
$script:ProfileTypeMap = [ordered]@{
  'DeviceConfigurations'         = @{ Path = 'deviceManagement/deviceConfigurations'; ForceBeta = $false; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $true }
  'ConfigurationPolicies'        = @{ Path = 'deviceManagement/configurationPolicies'; ForceBeta = $true; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $true }
  'GroupPolicyConfigurations'    = @{ Path = 'deviceManagement/groupPolicyConfigurations'; ForceBeta = $true; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $true }
  'EndpointSecurityPolicies'     = @{ Path = 'deviceManagement/intents'; ForceBeta = $true; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $true }
  'CompliancePolicies'           = @{ Path = 'deviceManagement/deviceCompliancePolicies'; ForceBeta = $false; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $true }
  'AppProtectionPolicies'        = @{ Path = 'deviceAppManagement/managedAppPolicies'; ForceBeta = $true; Scope = 'DeviceManagementApps.Read.All'; Assignments = $true; Analyze = $true }
  'AppConfigurationPolicies'     = @{ Path = 'deviceAppManagement/mobileAppConfigurations'; ForceBeta = $true; Scope = 'DeviceManagementApps.Read.All'; Assignments = $true; Analyze = $false }
  'ManagedAppConfigurations'     = @{ Path = 'deviceAppManagement/targetedManagedAppConfigurations'; ForceBeta = $true; Scope = 'DeviceManagementApps.Read.All'; Assignments = $true; Analyze = $false }
  'EnrollmentConfigurations'     = @{ Path = 'deviceManagement/deviceEnrollmentConfigurations'; ForceBeta = $true; Scope = 'DeviceManagementServiceConfig.Read.All'; Assignments = $true; Analyze = $false }
  'WindowsDriverUpdateProfiles'  = @{ Path = 'deviceManagement/windowsDriverUpdateProfiles'; ForceBeta = $true; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $false }
  'WindowsQualityUpdateProfiles' = @{ Path = 'deviceManagement/windowsQualityUpdateProfiles'; ForceBeta = $true; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $false }
  'WindowsFeatureUpdateProfiles' = @{ Path = 'deviceManagement/windowsFeatureUpdateProfiles'; ForceBeta = $true; Scope = 'DeviceManagementConfiguration.Read.All'; Assignments = $true; Analyze = $false }
  'DeviceHealthScripts'          = @{ Path = 'deviceManagement/deviceHealthScripts'; ForceBeta = $true; Scope = 'DeviceManagementScripts.Read.All'; Assignments = $true; Analyze = $false }
  'DeviceManagementScripts'      = @{ Path = 'deviceManagement/deviceManagementScripts'; ForceBeta = $true; Scope = 'DeviceManagementScripts.Read.All'; Assignments = $true; Analyze = $false }
  'DeviceShellScripts'           = @{ Path = 'deviceManagement/deviceShellScripts'; ForceBeta = $true; Scope = 'DeviceManagementScripts.Read.All'; Assignments = $true; Analyze = $false }
}

# App Protection / MAM is a polymorphic read-only collection: assignments live on the concrete
# subtype collection, not on managedAppPolicies itself.
$script:ManagedAppAssignmentPaths = @{
  '#microsoft.graph.iosManagedAppProtection'                = 'deviceAppManagement/iosManagedAppProtections'
  '#microsoft.graph.androidManagedAppProtection'            = 'deviceAppManagement/androidManagedAppProtections'
  '#microsoft.graph.windowsManagedAppProtection'            = 'deviceAppManagement/windowsManagedAppProtections'
  '#microsoft.graph.targetedManagedAppConfiguration'        = 'deviceAppManagement/targetedManagedAppConfigurations'
  '#microsoft.graph.mdmWindowsInformationProtectionPolicy'  = 'deviceAppManagement/mdmWindowsInformationProtectionPolicies'
  '#microsoft.graph.windowsInformationProtectionPolicy'     = 'deviceAppManagement/windowsInformationProtectionPolicies'
}

# Aggregate deployment status is only exposed as a navigation property on these types.
$script:StatusOverviewTypes = @('DeviceConfigurations', 'CompliancePolicies')

# Fail loudly if the ValidateSet above and the registry ever drift apart.
$validatedTypes = @(
  (Get-Variable -Name 'profileType').Attributes |
    Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
    ForEach-Object { $_.ValidValues }
) | Where-Object { $_ -ne 'All' }

$registryTypes = @($script:ProfileTypeMap.Keys)
$setDrift = @(
  @($validatedTypes | Where-Object { $_ -notin $registryTypes }) +
  @($registryTypes | Where-Object { $_ -notin $validatedTypes })
)
if ($setDrift.Count) {
  throw "Internal error: -profileType ValidateSet and ProfileTypeMap disagree on: $($setDrift -join ', ')"
}

#endregion

#region Graph plumbing

function Get-GraphProperty {
  <#
    StrictMode-safe property read. Invoke-MgGraphRequest returns a PSCustomObject with
    -OutputType PSObject and a Hashtable otherwise; under Set-StrictMode -Version Latest,
    touching a property that does not exist is a terminating error. Every read of a
    Graph response goes through here.
  #>
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [object]$InputObject,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$name
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

function Test-GraphProperty {
  <#
    Does the response carry this property at all?

    Distinct from Get-GraphProperty returning $null, because PowerShell unrolls an empty
    array on return: a collection response of { "value": [] } comes back from
    Get-GraphProperty as $null, indistinguishable from a single-entity response that has
    no 'value' property. Deciding collection-vs-entity on presence rather than value keeps
    an empty result set from being mistaken for one entity.
  #>
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [object]$InputObject,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$name
  )

  if ($null -eq $InputObject) { return $false }

  if ($InputObject -is [System.Collections.IDictionary]) {
    return $InputObject.Contains($name)
  }

  return [bool]$InputObject.PSObject.Properties[$name]
}

function Write-TextFile {
  <#
    Write UTF-8 text without a BOM, via .NET rather than Set-Content.

    Set-Content's -Encoding parameter is a portability hazard here: Windows PowerShell 5.1
    and PowerShell 7 disagree on whether 'utf8' emits a BOM, and the cmdlet can be shadowed
    by a proxy function or module that has no -Encoding parameter at all (which fails at
    runtime with "A parameter cannot be found that matches parameter name 'Encoding'").
    Going straight to .NET gives the same bytes on every host.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$path,

    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$content
  )

  $text = if ($null -eq $content) { '' } else { $content }
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
}

function Assert-GraphModuleInstalled {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$moduleName
  )

  if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    throw "Required module '$moduleName' is not installed. Install it with: Install-Module $moduleName -Scope CurrentUser"
  }
}

function Get-RequiredScopes {
  <#
    Ask for exactly what this run will use, and nothing else.

    A consent prompt is the one place a reader judges whether a tool is trustworthy, so a
    read-only export that asks for permissions it will not exercise is a real problem even
    though every scope here is read-only. Enrichment scopes are therefore gated on the switch
    that turns the enrichment on, rather than requested on every run for features that are off
    by default.

    Directory.Read.All is deliberately NOT requested. It backed a fallback lookup for an
    assignment target that Group.Read.All / User.Read.All could not resolve; that fallback now
    degrades to reporting the raw object id, which is a fair trade for not asking every
    operator to consent to reading the whole directory.
  #>
  [CmdletBinding()]
  param(
    [Parameter()]
    [switch]$includeStatusSummaries,

    [Parameter()]
    [switch]$includeGroupMemberCounts
  )

  # Endpoint scopes come from the registry so a new policy type cannot be added without
  # its permission.
  $scopes = [System.Collections.Generic.List[string]]::new()
  foreach ($entry in $script:ProfileTypeMap.Values) {
    if (-not $scopes.Contains($entry.Scope)) { [void]$scopes.Add($entry.Scope) }
  }

  # Always used: scope tags are resolved for every policy, and assignment targets are named on
  # every run, which needs to read the group or user each assignment points at.
  $always = @('DeviceManagementRBAC.Read.All', 'Group.Read.All', 'User.Read.All')

  # Only used by the feature that asks for it.
  # -includeGroupMemberCounts needs no extra scope: transitiveMembers is already covered by
  # the Group.Read.All above, so asking for GroupMember.Read.All as well would be requesting
  # a permission for access we already have.
  $conditional = @()
  if ($includeStatusSummaries) { $conditional += 'DeviceManagementManagedDevices.Read.All' }

  foreach ($extra in @($always + $conditional)) {
    if (-not $scopes.Contains($extra)) { [void]$scopes.Add($extra) }
  }

  return $scopes.ToArray()
}

function Connect-IntuneGraph {
  [CmdletBinding()]
  param(
    [Parameter()]
    [string]$tenantId,

    [Parameter()]
    [switch]$useDeviceCode,

    # Passed through so consent is requested for the enrichment this run will actually do.
    [Parameter()]
    [switch]$includeStatusSummaries,

    [Parameter()]
    [switch]$includeGroupMemberCounts
  )

  Assert-GraphModuleInstalled -moduleName 'Microsoft.Graph.Authentication'

  $requiredScopes = Get-RequiredScopes -includeStatusSummaries:$includeStatusSummaries -includeGroupMemberCounts:$includeGroupMemberCounts

  $ctx = $null
  try {
    $ctx = Get-MgContext
  }
  catch {
    $ctx = $null
  }

  if ($null -ne $ctx -and $ctx.Scopes) {
    $missing = $requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if (@($missing).Count -eq 0) {
      Write-Verbose "Already connected to Microsoft Graph as '$($ctx.Account)'."
      return $true
    }
    Write-Verbose ("Reconnecting to request additional scopes: {0}" -f (@($missing) -join ', '))
  }

  Write-Verbose 'Connecting to Microsoft Graph...'
  if ($useDeviceCode) {
    Write-Output 'Using device-code authentication. When prompted, open https://microsoft.com/devicelogin and enter the code to sign in.'
  }
  $connectParams = @{
    Scopes    = $requiredScopes
    NoWelcome = $true
  }
  if ($tenantId) {
    $connectParams.TenantId = $tenantId
  }
  if ($useDeviceCode) {
    $connectParams.UseDeviceCode = $true
  }

  Connect-MgGraph @connectParams | Out-Null

  $newCtx = $null
  try {
    $newCtx = Get-MgContext
  }
  catch {
    $newCtx = $null
  }

  if ($null -eq $newCtx -or -not $newCtx.Account -or -not $newCtx.TenantId) {
    if ($useDeviceCode) {
      throw 'Device-code sign-in did not complete. Re-run and complete the device login promptly, or omit -useDeviceCode to use interactive sign-in.'
    }

    throw 'Sign-in did not produce a Microsoft Graph context. Microsoft Graph uses your system default browser for interactive sign-in; set the correct default browser and try again.'
  }

  return $false
}

function Get-GrantedScope {
  [CmdletBinding()]
  param()

  $ctx = $null
  try { $ctx = Get-MgContext } catch { $ctx = $null }
  if ($null -eq $ctx -or -not $ctx.Scopes) { return @() }
  return @($ctx.Scopes)
}

function Get-RetryDelaySecond {
  <#
    Honour Retry-After when Graph sends it, otherwise back off exponentially with jitter.
    The exception shape varies between SDK versions, so every read is guarded.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [object]$errorRecord,

    [Parameter(Mandatory = $true)]
    [int]$attempt
  )

  $retryAfter = $null
  try {
    $response = $errorRecord.Exception.Response
    if ($null -ne $response -and $null -ne $response.Headers) {
      $header = $response.Headers.RetryAfter
      if ($null -ne $header) {
        if ($null -ne $header.Delta) { $retryAfter = [int]$header.Delta.TotalSeconds }
        elseif ($null -ne $header.Date) { $retryAfter = [int]([datetimeoffset]$header.Date - [datetimeoffset]::UtcNow).TotalSeconds }
      }
    }
  }
  catch {
    $retryAfter = $null
  }

  if ($null -ne $retryAfter -and $retryAfter -gt 0) {
    return [Math]::Min($retryAfter, 300)
  }

  $backoff = [Math]::Min([Math]::Pow(2, $attempt), 60)
  return [int]($backoff + (Get-Random -Minimum 0 -Maximum 3))
}

function Get-GraphStatusCode {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [object]$errorRecord
  )

  try {
    $response = $errorRecord.Exception.Response
    if ($null -ne $response -and $null -ne $response.StatusCode) {
      return [int]$response.StatusCode
    }
  }
  catch {
    # The exception shape differs between Graph SDK versions; fall through to sniffing
    # the message text rather than letting a shape mismatch mask the real error.
    Write-Debug "Could not read StatusCode from the exception ($($_.Exception.Message)); falling back to message matching."
  }

  $msg = $errorRecord.Exception.Message
  if ($msg -match '\b429\b' -or $msg -match 'Too Many Requests') { return 429 }
  if ($msg -match '\b503\b' -or $msg -match 'Service Unavailable') { return 503 }
  if ($msg -match '\b504\b' -or $msg -match 'Gateway Timeout') { return 504 }
  if ($msg -match '\b401\b' -or $msg -match 'Unauthorized') { return 401 }
  if ($msg -match '\b403\b' -or $msg -match 'Forbidden') { return 403 }
  if ($msg -match '\b404\b' -or $msg -match 'Not Found') { return 404 }
  return 0
}

function Invoke-GraphRequestWithRetry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$uri,

    [Parameter()]
    [hashtable]$headers
  )

  $attempt = 0
  while ($true) {
    try {
      $requestParams = @{
        Method     = 'GET'
        Uri        = $uri
        OutputType = 'PSObject'
      }
      if ($headers -and $headers.Count) { $requestParams.Headers = $headers }

      return Invoke-MgGraphRequest @requestParams
    }
    catch {
      $status = Get-GraphStatusCode -errorRecord $_

      # Qualified with script: so the retry budget comes from the script parameter
      # explicitly, rather than by relying on dynamic scope lookup.
      if (($status -eq 429 -or $status -ge 500) -and $attempt -lt $script:maxRetryCount) {
        $delay = Get-RetryDelaySecond -errorRecord $_ -attempt $attempt
        $attempt++
        Write-Verbose "Graph returned $status for $uri; retry $attempt of $($script:maxRetryCount) in ${delay}s."
        Start-Sleep -Seconds $delay
        continue
      }

      if ($status -eq 401 -or $status -eq 403) {
        throw "Microsoft Graph request failed with $status (missing permissions or admin consent) for: $uri. Original error: $($_.Exception.Message)"
      }

      throw
    }
  }
}

function Invoke-GraphGetAll {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$uri,

    [Parameter()]
    [hashtable]$headers
  )

  Assert-GraphModuleInstalled -moduleName 'Microsoft.Graph.Authentication'

  $items = New-Object System.Collections.Generic.List[object]
  $nextLink = $uri

  while ($nextLink) {
    Write-Verbose "GET $nextLink"
    $response = Invoke-GraphRequestWithRetry -uri $nextLink -headers $headers

    # A collection response has a 'value' array; a single-entity response (the -profileId
    # path) does not. Decide on the property's PRESENCE, not its value: an empty result set
    # ({ "value": [] }) would otherwise look like a single entity and get written out as a
    # bogus policy. Read defensively -- StrictMode makes a bare $response.value fatal.
    if (Test-GraphProperty -InputObject $response -name 'value') {
      $value = Get-GraphProperty -InputObject $response -name 'value'
      if ($null -ne $value) {
        foreach ($v in @($value)) {
          [void]$items.Add($v)
        }
      }
      $nextLink = Get-GraphProperty -InputObject $response -name '@odata.nextLink'
    }
    else {
      [void]$items.Add($response)
      $nextLink = $null
    }
  }

  return $items
}

function Get-GraphBaseForProfileType {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$profileType,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion
  )

  if (-not $script:ProfileTypeMap.Contains($profileType)) {
    throw "Unsupported profileType '$profileType'."
  }

  $effectiveVersion = $graphApiVersion
  if ($graphApiVersion -eq 'v1.0' -and $script:ProfileTypeMap[$profileType].ForceBeta) {
    Write-Verbose "$profileType is not available (or is incomplete) in v1.0; using 'beta' for this policy type."
    $effectiveVersion = 'beta'
  }

  return "https://graph.microsoft.com/$effectiveVersion"
}

#endregion

#region Policy fetching

function Get-IntuneProfiles {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$profileType,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter()]
    [string]$profileId
  )

  $graphBase = Get-GraphBaseForProfileType -profileType $profileType -graphApiVersion $graphApiVersion
  $path = $script:ProfileTypeMap[$profileType].Path

  $uri = if ($profileId) { "$graphBase/$path/$profileId" } else { "$graphBase/$path" }

  return Invoke-GraphGetAll -uri $uri
}

function Get-IntuneAssignments {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$profileType,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$profileId,

    [Parameter()]
    [AllowNull()]
    [string]$policyOdataType
  )

  # Always use beta for assignments -- the v1.0 endpoint does not return
  # deviceAndAppManagementAssignmentFilterId / FilterType on the target object.
  $graphBase = 'https://graph.microsoft.com/beta'
  $path = $script:ProfileTypeMap[$profileType].Path

  # managedAppPolicies is polymorphic and read-only: assignments hang off the concrete
  # subtype collection instead.
  if ($profileType -eq 'AppProtectionPolicies') {
    if (-not $policyOdataType -or -not $script:ManagedAppAssignmentPaths.ContainsKey($policyOdataType)) {
      Write-Verbose "No assignment endpoint known for managed app policy type '$policyOdataType'; skipping."
      return [pscustomobject]@{ Assignments = @(); Method = 'not-supported' }
    }
    $path = $script:ManagedAppAssignmentPaths[$policyOdataType]
  }

  $entityUri = "$graphBase/$path/$profileId"

  # 1) The standard child collection. Works for configuration, compliance and app policies.
  try {
    $direct = Invoke-GraphGetAll -uri "$entityUri/assignments"
    return [pscustomobject]@{ Assignments = @($direct); Method = 'assignments' }
  }
  catch {
    # Script types (deviceManagementScripts, deviceShellScripts, deviceHealthScripts) reject
    # a GET on /assignments with 400 "no method match route template", even though the
    # metadata advertises the navigation property. Fall through to the shapes that do work.
    $firstError = $_
    Write-Verbose "GET $entityUri/assignments failed ($($_.Exception.Message)); trying entity expand."
  }

  # 2) Expand the navigation from the entity itself.
  try {
    $entity = Invoke-GraphRequestWithRetry -uri "$entityUri`?`$expand=assignments"
    if (Test-GraphProperty -InputObject $entity -name 'assignments') {
      $expanded = Get-GraphProperty -InputObject $entity -name 'assignments'
      if ($null -eq $expanded) { return [pscustomobject]@{ Assignments = @(); Method = 'expand' } }
      return [pscustomobject]@{ Assignments = @($expanded); Method = 'expand' }
    }
  }
  catch {
    Write-Verbose "Entity expand failed for $entityUri ($($_.Exception.Message)); trying groupAssignments."
  }

  # 3) The legacy groupAssignments collection, which is the shape the script types document.
  try {
    $groupAssignments = Invoke-GraphGetAll -uri "$entityUri/groupAssignments"
    return [pscustomobject]@{
      Assignments = @(ConvertFrom-GroupAssignment -groupAssignments $groupAssignments)
      Method      = 'groupAssignments'
    }
  }
  catch {
    Write-Verbose "groupAssignments failed for $entityUri ($($_.Exception.Message))."
  }

  throw $firstError
}

function ConvertFrom-GroupAssignment {
  <#
    Normalise a legacy deviceManagementScriptGroupAssignment into the standard assignment
    shape, so Resolve-AssignmentTargets need not know which endpoint it came from. The
    legacy form carries targetGroupId directly instead of a nested target object, and marks
    exclusions with a boolean rather than a distinct target type.
  #>
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [object[]]$groupAssignments
  )

  foreach ($ga in @($groupAssignments)) {
    if ($null -eq $ga) { continue }

    $gid = Get-GraphProperty -InputObject $ga -name 'targetGroupId'
    if (-not $gid) { $gid = Get-GraphProperty -InputObject $ga -name 'groupId' }
    if (-not $gid) { continue }

    $excluded = [bool](Get-GraphProperty -InputObject $ga -name 'excludeGroup')

    [pscustomobject]@{
      id     = Get-GraphProperty -InputObject $ga -name 'id'
      source = 'groupAssignment'
      target = [pscustomobject]@{
        '@odata.type' = if ($excluded) { '#microsoft.graph.exclusionGroupAssignmentTarget' } else { '#microsoft.graph.groupAssignmentTarget' }
        groupId       = $gid
      }
    }
  }
}

function Get-ConfigurationPolicySettings {
  <#
    Settings Catalog settings carry only a settingDefinitionId by default, which is opaque
    ("device_vendor_msft_policy_config_..."). Expanding settingDefinitions gives the analyzer
    display names, data types, defaults and allowed options for each setting.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$policyId
  )

  $graphBase = Get-GraphBaseForProfileType -profileType 'ConfigurationPolicies' -graphApiVersion $graphApiVersion
  $uri = "$graphBase/deviceManagement/configurationPolicies('$policyId')/settings?`$expand=settingDefinitions&`$top=1000"

  try {
    return Invoke-GraphGetAll -uri $uri
  }
  catch {
    # $expand=settingDefinitions is beta-only and can be rejected on some tenants; the bare
    # settings are still worth having.
    Write-Verbose "settingDefinitions expand failed for '$policyId' ($($_.Exception.Message)); retrying without expand."
    return Invoke-GraphGetAll -uri "$graphBase/deviceManagement/configurationPolicies('$policyId')/settings?`$top=1000"
  }
}

function Get-GroupPolicyDefinitionValues {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$configurationId
  )

  $graphBase = Get-GraphBaseForProfileType -profileType 'GroupPolicyConfigurations' -graphApiVersion $graphApiVersion
  $uri = "$graphBase/deviceManagement/groupPolicyConfigurations/$configurationId/definitionValues?`$expand=definition(`$select=id,displayName,categoryPath,classType,policyType,explainText,supportedOn)"

  $definitionValues = Invoke-GraphGetAll -uri $uri

  foreach ($dv in $definitionValues) {
    $dvId = Get-GraphProperty -InputObject $dv -name 'id'
    if (-not $dvId) { continue }
    try {
      $pvUri = "$graphBase/deviceManagement/groupPolicyConfigurations/$configurationId/definitionValues/$dvId/presentationValues?`$expand=presentation"
      $presentationValues = Invoke-GraphGetAll -uri $pvUri
      $dv | Add-Member -NotePropertyName 'presentationValues' -NotePropertyValue $presentationValues -Force
    }
    catch {
      Write-Warning "Failed to fetch presentationValues for definitionValue '$dvId': $($_.Exception.Message)"
    }
  }

  return $definitionValues
}

function Get-EndpointSecurityIntentSettings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$intentId
  )

  $graphBase = Get-GraphBaseForProfileType -profileType 'EndpointSecurityPolicies' -graphApiVersion $graphApiVersion
  $settings = Invoke-GraphGetAll -uri "$graphBase/deviceManagement/intents/$intentId/settings"

  # Resolve the template name for richer context
  try {
    $intent = Invoke-GraphRequestWithRetry -uri "$graphBase/deviceManagement/intents/$intentId`?`$select=id,templateId"
    $templateId = Get-GraphProperty -InputObject $intent -name 'templateId'
    if ($templateId) {
      $template = Invoke-GraphRequestWithRetry -uri "$graphBase/deviceManagement/templates/$templateId`?`$select=id,displayName,description,templateType,platformType"
      return [PSCustomObject]@{
        templateId     = $templateId
        templateName   = Get-GraphProperty -InputObject $template -name 'displayName'
        templateType   = Get-GraphProperty -InputObject $template -name 'templateType'
        platformType   = Get-GraphProperty -InputObject $template -name 'platformType'
        settings       = $settings
      }
    }
  }
  catch {
    Write-Warning "Failed to resolve Endpoint Security template for intent '$intentId': $($_.Exception.Message)"
  }

  return [PSCustomObject]@{
    templateId   = $null
    templateName = $null
    templateType = $null
    platformType = $null
    settings     = $settings
  }
}

function Get-ComplianceScheduledActions {
  <#
    Grace period and the actions taken on non-compliance are not part of the base compliance
    policy object. Without them a "compliance gap" finding cannot distinguish "mark
    non-compliant after 7 days" from "retire the device immediately".
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$policyId
  )

  $graphBase = Get-GraphBaseForProfileType -profileType 'CompliancePolicies' -graphApiVersion $graphApiVersion
  $policyPath = "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId"

  # Graph rejects $expand=scheduledActionConfigurations on the scheduledActionsForRule
  # child collection with 400 Bad Request. The nested expand on the parent policy is the
  # shape that actually works, so try that first.
  try {
    $policy = Invoke-GraphRequestWithRetry -uri "$policyPath`?`$expand=scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
    if (Test-GraphProperty -InputObject $policy -name 'scheduledActionsForRule') {
      $rules = Get-GraphProperty -InputObject $policy -name 'scheduledActionsForRule'
      if ($null -eq $rules) { return @() }
      return @($rules)
    }
  }
  catch {
    Write-Verbose "Nested scheduledActionsForRule expand failed for '$policyId' ($($_.Exception.Message)); falling back to per-rule fetch."
  }

  # Fallback: the documented plain listing, then one call per rule for its action
  # configurations. More requests, but it works where the expand is unavailable.
  $rules = Invoke-GraphGetAll -uri "$policyPath/scheduledActionsForRule"

  foreach ($rule in $rules) {
    $ruleId = Get-GraphProperty -InputObject $rule -name 'id'
    if (-not $ruleId) { continue }
    try {
      $configs = Invoke-GraphGetAll -uri "$policyPath/scheduledActionsForRule/$ruleId/scheduledActionConfigurations"
      $rule | Add-Member -NotePropertyName 'scheduledActionConfigurations' -NotePropertyValue $configs -Force
    }
    catch {
      Write-Warning "Failed to fetch scheduledActionConfigurations for rule '$ruleId' on compliance policy '$policyId': $($_.Exception.Message)"
    }
  }

  return $rules
}

function Get-PolicyStatusOverview {
  <#
    Aggregate deployment counts only. Per-device (deviceStatuses) and per-user (userStatuses)
    collections return device names and UPNs and are deliberately never fetched.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$profileType,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$policyId
  )

  if ($profileType -notin $script:StatusOverviewTypes) { return $null }

  $graphBase = Get-GraphBaseForProfileType -profileType $profileType -graphApiVersion $graphApiVersion
  $path = $script:ProfileTypeMap[$profileType].Path

  $result = [ordered]@{}
  foreach ($nav in @('deviceStatusOverview', 'userStatusOverview')) {
    try {
      $overview = Invoke-GraphRequestWithRetry -uri "$graphBase/$path/$policyId/$nav"
      if ($null -ne $overview) {
        $clean = [ordered]@{}
        foreach ($field in @('pendingCount', 'notApplicableCount', 'successCount', 'errorCount', 'failedCount', 'conflictCount', 'lastUpdateDateTime', 'configurationVersion')) {
          $v = Get-GraphProperty -InputObject $overview -name $field
          if ($null -ne $v) { $clean[$field] = $v }
        }
        if ($clean.Count) { $result[$nav] = [pscustomobject]$clean }
      }
    }
    catch {
      Write-Verbose "No $nav for $profileType '$policyId': $($_.Exception.Message)"
    }
  }

  if (-not $result.Count) { return $null }
  return [pscustomobject]$result
}

function Get-RoleScopeTagMap {
  <#
    Policies carry roleScopeTagIds as bare GUIDs. Two policies under different scope tags are
    often administered by different teams and are not a genuine collision, so the analyzer
    needs the names.
  #>
  [CmdletBinding()]
  param()

  $map = @{}
  try {
    $tags = Invoke-GraphGetAll -uri 'https://graph.microsoft.com/beta/deviceManagement/roleScopeTags'
    foreach ($t in $tags) {
      $id = Get-GraphProperty -InputObject $t -name 'id'
      if (-not $id) { continue }
      $map["$id"] = [pscustomobject]@{
        id          = $id
        displayName = Get-GraphProperty -InputObject $t -name 'displayName'
        description = Get-GraphProperty -InputObject $t -name 'description'
        isBuiltIn   = Get-GraphProperty -InputObject $t -name 'isBuiltIn'
      }
    }
  }
  catch {
    Write-Warning "Failed to enumerate role scope tags (needs DeviceManagementRBAC.Read.All): $($_.Exception.Message)"
  }

  return $map
}

function Get-AssignmentFilterCatalog {
  <#
    Fetching the whole filter list (rather than only filters referenced by an assignment)
    makes unused filters visible, which is itself a finding.
  #>
  [CmdletBinding()]
  param()

  $catalog = @{}
  try {
    $filters = Invoke-GraphGetAll -uri 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters'
    foreach ($f in $filters) {
      $id = Get-GraphProperty -InputObject $f -name 'id'
      if (-not $id) { continue }
      $catalog["$id"] = [pscustomobject]@{
        id                             = $id
        displayName                    = Get-GraphProperty -InputObject $f -name 'displayName'
        description                    = Get-GraphProperty -InputObject $f -name 'description'
        rule                           = Get-GraphProperty -InputObject $f -name 'rule'
        platform                       = Get-GraphProperty -InputObject $f -name 'platform'
        assignmentFilterManagementType = Get-GraphProperty -InputObject $f -name 'assignmentFilterManagementType'
      }
    }
  }
  catch {
    Write-Warning "Failed to enumerate assignment filters: $($_.Exception.Message)"
  }

  return $catalog
}

function Get-GroupMemberCount {
  <#
    Transitive member count for blast-radius sizing. $count returns a bare integer body which
    does not always survive -OutputType PSObject, so ask for a page of one and read @odata.count.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$groupId
  )

  $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers?`$count=true&`$top=1&`$select=id"
  $response = Invoke-GraphRequestWithRetry -uri $uri -headers @{ ConsistencyLevel = 'eventual' }
  return Get-GraphProperty -InputObject $response -name '@odata.count'
}

#endregion

#region Assignment resolution

function Get-PayloadMetadata {
  <#
    Pull the profile-level identity out of a decoded .mobileconfig.

    macOS keys an installed profile by its top-level PayloadIdentifier: two profiles sharing
    one means the second REPLACES the first on the device rather than merging with it. That
    is invisible to setting-level comparison, so the identifier is promoted to a first-class
    field here rather than left buried in the payload XML for the analyzer to re-parse.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$decodedPayload
  )

  $result = [pscustomobject]@{
    PayloadIdentifier = $null
    PayloadUUID       = $null
    PayloadTypes      = @()
  }

  try {
    $doc = [xml]$decodedPayload
    $root = $doc.SelectSingleNode('/plist/dict')
    if ($null -eq $root) { return $result }

    foreach ($field in @('PayloadIdentifier', 'PayloadUUID')) {
      $node = $root.SelectSingleNode("key[.='$field']")
      if ($null -ne $node -and $null -ne $node.NextSibling) {
        $result.$field = $node.NextSibling.InnerText
      }
    }

    # Inner payload types say what the profile actually configures (TCC, kext, sysext, ...).
    $types = @($doc.SelectNodes("//key[.='PayloadType']") |
        ForEach-Object { $_.NextSibling.InnerText } |
        Where-Object { $_ -and $_ -ne 'Configuration' } |
        Sort-Object -Unique)
    $result.PayloadTypes = $types
  }
  catch {
    Write-Verbose "Could not parse payload metadata: $($_.Exception.Message)"
  }

  return $result
}

function Resolve-AssignmentTargets {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [object[]]$assignments,

    [Parameter(Mandatory = $true)]
    [hashtable]$groupCache,

    [Parameter(Mandatory = $true)]
    [hashtable]$userCache,

    [Parameter(Mandatory = $true)]
    [hashtable]$directoryCache,

    [Parameter(Mandatory = $true)]
    [hashtable]$filterCache,

    [Parameter(Mandatory = $true)]
    [hashtable]$memberCountCache,

    [Parameter()]
    [switch]$canResolveGroups,

    [Parameter()]
    [switch]$canResolveUsers,

    [Parameter()]
    [switch]$canResolveDirectory,

    [Parameter()]
    [switch]$includeGroupMemberCounts
  )

  if ($null -eq $assignments) {
    return @()
  }

  foreach ($a in @($assignments)) {
    $assignmentId = Get-GraphProperty -InputObject $a -name 'id'
    $assignmentSource = Get-GraphProperty -InputObject $a -name 'source'
    $assignmentIntent = Get-GraphProperty -InputObject $a -name 'intent'
    $assignmentType = Get-GraphProperty -InputObject $a -name '@odata.type'

    $target = Get-GraphProperty -InputObject $a -name 'target'
    if ($null -eq $target) { continue }

    $targetType = Get-GraphProperty -InputObject $target -name '@odata.type'
    $groupId = Get-GraphProperty -InputObject $target -name 'groupId'
    $userId = Get-GraphProperty -InputObject $target -name 'userId'
    $collectionId = Get-GraphProperty -InputObject $target -name 'collectionId'

    # Filter properties may appear on the target object OR on the parent assignment object
    # depending on the Graph API endpoint / policy type.
    $filterId = Get-GraphProperty -InputObject $target -name 'deviceAndAppManagementAssignmentFilterId'
    if (-not $filterId) { $filterId = Get-GraphProperty -InputObject $a -name 'deviceAndAppManagementAssignmentFilterId' }
    $filterType = Get-GraphProperty -InputObject $target -name 'deviceAndAppManagementAssignmentFilterType'
    if (-not $filterType) { $filterType = Get-GraphProperty -InputObject $a -name 'deviceAndAppManagementAssignmentFilterType' }

    $groupName = $null
    $groupType = $null
    $groupMembershipRule = $null
    $groupMembershipRuleProcessing = $null
    $groupMemberCount = $null
    $groupLookupError = $null
    if ($groupId) {
      if (-not $canResolveGroups) {
        $groupLookupError = 'Group name resolution skipped (missing Group.Read.All).'
      }
      else {
        if (-not $groupCache.ContainsKey($groupId)) {
          try {
            $g = Invoke-GraphRequestWithRetry -uri "https://graph.microsoft.com/v1.0/groups/$groupId`?`$select=id,displayName,groupTypes,membershipRule,membershipRuleProcessingState"
            $groupCache[$groupId] = @{
              displayName                   = Get-GraphProperty -InputObject $g -name 'displayName'
              groupTypes                    = Get-GraphProperty -InputObject $g -name 'groupTypes'
              membershipRule                = Get-GraphProperty -InputObject $g -name 'membershipRule'
              membershipRuleProcessingState = Get-GraphProperty -InputObject $g -name 'membershipRuleProcessingState'
            }
          }
          catch {
            $groupCache[$groupId] = $null
            $groupLookupError = $_.Exception.Message
          }
        }
        $cachedGroup = $groupCache[$groupId]
        if ($null -ne $cachedGroup) {
          $groupName = $cachedGroup.displayName
          $groupType = if ($cachedGroup.groupTypes -and ($cachedGroup.groupTypes -contains 'DynamicMembership')) { 'DynamicMembership' } else { 'Assigned' }
          $groupMembershipRule = $cachedGroup.membershipRule
          $groupMembershipRuleProcessing = $cachedGroup.membershipRuleProcessingState
        }

        if ($includeGroupMemberCounts) {
          if (-not $memberCountCache.ContainsKey($groupId)) {
            try {
              $memberCountCache[$groupId] = Get-GroupMemberCount -groupId $groupId
            }
            catch {
              $memberCountCache[$groupId] = $null
              Write-Verbose "Failed to count members for group '$groupId': $($_.Exception.Message)"
            }
          }
          $groupMemberCount = $memberCountCache[$groupId]
        }
      }
    }

    $userName = $null
    $userPrincipalName = $null
    $userLookupError = $null
    if ($userId) {
      if (-not $canResolveUsers) {
        $userLookupError = 'User name resolution skipped (missing User.Read.All).'
      }
      else {
        if (-not $userCache.ContainsKey($userId)) {
          try {
            $u = Invoke-GraphRequestWithRetry -uri "https://graph.microsoft.com/v1.0/users/$userId`?`$select=id,displayName,userPrincipalName"
            $userCache[$userId] = @{
              displayName       = Get-GraphProperty -InputObject $u -name 'displayName'
              userPrincipalName = Get-GraphProperty -InputObject $u -name 'userPrincipalName'
            }
          }
          catch {
            $userCache[$userId] = @{ displayName = $null; userPrincipalName = $null }
            $userLookupError = $_.Exception.Message
          }
        }

        $userName = $userCache[$userId].displayName
        $userPrincipalName = $userCache[$userId].userPrincipalName
      }
    }

    $filterName = $null
    $filterRule = $null
    $filterPlatform = $null
    $filterLookupError = $null
    if ($filterId) {
      if (-not $filterCache.ContainsKey($filterId)) {
        try {
          $f = Invoke-GraphRequestWithRetry -uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$filterId`?`$select=id,displayName,rule,platform,assignmentFilterManagementType"
          $filterCache[$filterId] = [pscustomobject]@{
            id                             = $filterId
            displayName                    = Get-GraphProperty -InputObject $f -name 'displayName'
            rule                           = Get-GraphProperty -InputObject $f -name 'rule'
            platform                       = Get-GraphProperty -InputObject $f -name 'platform'
            assignmentFilterManagementType = Get-GraphProperty -InputObject $f -name 'assignmentFilterManagementType'
          }
        }
        catch {
          $filterCache[$filterId] = $null
          $filterLookupError = $_.Exception.Message
        }
      }
      $cachedFilter = $filterCache[$filterId]
      if ($null -ne $cachedFilter) {
        $filterName = $cachedFilter.displayName
        $filterRule = $cachedFilter.rule
        $filterPlatform = $cachedFilter.platform
      }
    }

    # Fallback: resolve directory object displayName when group/user lookup fails
    if ($groupId -and -not $groupName -and $canResolveDirectory) {
      if (-not $directoryCache.ContainsKey($groupId)) {
        try {
          $d = Invoke-GraphRequestWithRetry -uri "https://graph.microsoft.com/v1.0/directoryObjects/$groupId`?`$select=id,displayName"
          $directoryCache[$groupId] = Get-GraphProperty -InputObject $d -name 'displayName'
        }
        catch {
          $directoryCache[$groupId] = $null
          if (-not $groupLookupError) { $groupLookupError = $_.Exception.Message }
        }
      }
      if (-not $groupName) { $groupName = $directoryCache[$groupId] }
    }

    if ($userId -and -not $userName -and $canResolveDirectory) {
      if (-not $directoryCache.ContainsKey($userId)) {
        try {
          $d = Invoke-GraphRequestWithRetry -uri "https://graph.microsoft.com/v1.0/directoryObjects/$userId`?`$select=id,displayName"
          $directoryCache[$userId] = Get-GraphProperty -InputObject $d -name 'displayName'
        }
        catch {
          $directoryCache[$userId] = $null
          if (-not $userLookupError) { $userLookupError = $_.Exception.Message }
        }
      }
      if (-not $userName) { $userName = $directoryCache[$userId] }
    }

    if ($groupId -and -not $groupName -and -not $groupLookupError) {
      $groupLookupError = 'Group name unresolved.'
    }
    if ($userId -and -not $userName -and -not $userLookupError) {
      $userLookupError = 'User name unresolved.'
    }
    if ($filterId -and -not $filterName -and -not $filterLookupError) {
      $filterLookupError = 'Filter name unresolved (check assignment filter permissions).'
    }

    [PSCustomObject]@{
      assignmentId                  = $assignmentId
      assignmentType                = $assignmentType
      assignmentSource              = $assignmentSource
      assignmentIntent              = $assignmentIntent
      targetType                    = $targetType
      groupId                       = $groupId
      groupName                     = $groupName
      groupType                     = $groupType
      groupMembershipRule           = $groupMembershipRule
      groupMembershipRuleProcessing = $groupMembershipRuleProcessing
      groupMemberCount              = $groupMemberCount
      groupLookupError              = $groupLookupError
      userId                        = $userId
      userDisplayName               = $userName
      userPrincipalName             = $userPrincipalName
      userLookupError               = $userLookupError
      collectionId                  = $collectionId
      filterId                      = $filterId
      filterName                    = $filterName
      filterType                    = $filterType
      filterRule                    = $filterRule
      filterPlatform                = $filterPlatform
      filterLookupError             = $filterLookupError
      isExclusion                   = ($targetType -eq '#microsoft.graph.exclusionGroupAssignmentTarget')
      allDevices                    = ($targetType -eq '#microsoft.graph.allDevicesAssignmentTarget')
      allLicensedUsers              = ($targetType -eq '#microsoft.graph.allLicensedUsersAssignmentTarget')
      rawTarget                     = $target
    }
  }
}

#endregion

#region Export

function New-SafeFileName {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [AllowNull()]
    [string]$name,

    [Parameter()]
    [ValidateRange(16, 200)]
    [int]$maxLength = 80
  )

  $safe = $name
  if ($null -eq $safe) {
    $safe = ''
  }
  if ([string]::IsNullOrWhiteSpace($safe)) {
    $safe = 'profile'
  }

  # Replace invalid Windows filename characters and control characters.
  $safe = ($safe -replace '[\\/:*?"<>|]', '_') -replace '[\x00-\x1F]', '_'
  $safe = $safe.Trim()

  # Reserved DOS device names cannot be used as a file name stem on Windows.
  if ($safe -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
    $safe = "_$safe"
  }

  # Policy name + '_' + GUID + '.assignments.json' has to stay inside MAX_PATH once the
  # tenant/date/type folders are prepended.
  if ($safe.Length -gt $maxLength) {
    $safe = $safe.Substring(0, $maxLength)
  }

  # A trailing dot or space is silently stripped by Windows and breaks Test-Path round-trips.
  $safe = $safe.TrimEnd('.', ' ')
  if ([string]::IsNullOrWhiteSpace($safe)) {
    $safe = 'profile'
  }

  return $safe
}

function Export-IntuneProfiles {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$profileType,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$graphApiVersion,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$baseOutDir,

    [Parameter()]
    [string]$profileId,

    [Parameter()]
    [string]$profileName,

    [Parameter()]
    [string]$odataType,

    [Parameter()]
    [switch]$force,

    [Parameter()]
    [AllowNull()]
    [System.Collections.Generic.List[psobject]]$ConsolidatedSink,

    [Parameter()]
    [switch]$includeAssignmentsInConsolidated,

    [Parameter()]
    [switch]$includeStatusSummaries,

    [Parameter()]
    [switch]$includeGroupMemberCounts,

    [Parameter(Mandatory = $true)]
    [hashtable]$sharedCaches,

    # AllowEmptyCollection is required: a Mandatory parameter applies an implicit
    # non-empty check to collection types, and this accumulator is empty on the first
    # policy type exported.
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[psobject]]$manifestSink,

    [Parameter(Mandatory = $true)]
    [hashtable]$settingDefinitionSink
  )

  $typeOutDir = Join-Path -Path $baseOutDir -ChildPath $profileType
  if (-not (Test-Path -Path $typeOutDir)) {
    New-Item -Path $typeOutDir -ItemType Directory -Force | Out-Null
  }

  $grantedScopes = $sharedCaches.GrantedScopes
  $requiredScope = $script:ProfileTypeMap[$profileType].Scope
  $hasScope = ($requiredScope -in $grantedScopes)

  if (-not $hasScope) {
    Write-Warning "Skipping ${profileType}: the signed-in session does not have '$requiredScope'."
    $manifestSink.Add([pscustomobject]@{
        ProfileType   = $profileType
        Status        = 'SkippedMissingScope'
        RequiredScope = $requiredScope
        Error         = "Missing delegated scope '$requiredScope'."
      })
    return [PSCustomObject]@{
      ProfileType = $profileType
      TotalFound  = 0
      Exported    = 0
      Skipped     = 0
      Failed      = 0
      OutputPath  = $typeOutDir
    }
  }

  $profiles = @()
  try {
    $profiles = Get-IntuneProfiles -profileType $profileType -profileId $profileId -graphApiVersion $graphApiVersion
  }
  catch {
    Write-Warning "Failed to list ${profileType}: $($_.Exception.Message)"
    $manifestSink.Add([pscustomobject]@{
        ProfileType   = $profileType
        Status        = 'ListFailed'
        RequiredScope = $requiredScope
        Error         = $_.Exception.Message
      })
    return [PSCustomObject]@{
      ProfileType = $profileType
      TotalFound  = 0
      Exported    = 0
      Skipped     = 0
      Failed      = 1
      OutputPath  = $typeOutDir
    }
  }

  if ($profileName) {
    $profiles = $profiles | Where-Object { (Get-GraphProperty -InputObject $_ -name 'displayName') -like $profileName }
  }

  if ($odataType) {
    $profiles = $profiles | Where-Object {
      $t = Get-GraphProperty -InputObject $_ -name '@odata.type'
      if ($null -eq $t) { return $false }
      return ($t -like $odataType)
    }
  }

  $exported = 0
  $skipped = 0
  $failed = 0

  $groupCache = $sharedCaches.Groups
  $userCache = $sharedCaches.Users
  $directoryCache = $sharedCaches.Directory
  $filterCache = $sharedCaches.Filters
  $memberCountCache = $sharedCaches.MemberCounts
  $scopeTagMap = $sharedCaches.ScopeTags

  $canResolveGroups = ('Group.Read.All' -in $grantedScopes)
  $canResolveUsers = ('User.Read.All' -in $grantedScopes)
  $canResolveDirectory = ('Directory.Read.All' -in $grantedScopes)
  $canReadStatus = ('DeviceManagementManagedDevices.Read.All' -in $grantedScopes)

  # Live per-policy progress. Write-Progress rather than console writes: it does not touch
  # the success stream (which carries this function's result object) and clears itself.
  $policyTotal = @($profiles).Count
  $policyIndex = 0

  foreach ($p in $profiles) {
    $policyIndex++

    $displayName = Get-GraphProperty -InputObject $p -name 'displayName'
    if (-not $displayName) { $displayName = Get-GraphProperty -InputObject $p -name 'name' }

    if ($policyTotal -gt 0) {
      Write-Progress -Id 1 -Activity "Exporting $profileType" `
        -Status ("{0} of {1}: {2}" -f $policyIndex, $policyTotal, $displayName) `
        -PercentComplete ([Math]::Min(100, [int](($policyIndex / $policyTotal) * 100)))
    }

    $id = Get-GraphProperty -InputObject $p -name 'id'
    if (-not $id) { $id = 'no-id' }

    $policyOdataType = Get-GraphProperty -InputObject $p -name '@odata.type'

    $safeName = New-SafeFileName -name $displayName
    $fileName = "${safeName}_${id}.json"
    $filePath = Join-Path -Path $typeOutDir -ChildPath $fileName

    # Remove any earlier export of this same policy under a different filename. A policy
    # renamed in Intune (or a change to how names are sanitised here) produces a new
    # filename for the same id, and -force only overwrites matching names -- it does not
    # delete the old one. Left behind, the analyzer reads both copies and reports phantom
    # conflicts between a policy and its own former self.
    $expectedPrefix = "${safeName}_${id}"
    foreach ($staleFile in @(Get-ChildItem -LiteralPath $typeOutDir -File -ErrorAction SilentlyContinue)) {
      if ($staleFile.Name -notmatch ([regex]::Escape("_$id") + '\.')) { continue }
      if ($staleFile.Name.StartsWith($expectedPrefix, [System.StringComparison]::Ordinal)) { continue }
      if ($PSCmdlet.ShouldProcess($staleFile.FullName, 'Remove stale export file for renamed policy')) {
        Remove-Item -LiteralPath $staleFile.FullName -Force
        Write-Verbose "Removed stale export file for renamed policy: $($staleFile.Name)"
      }
    }

    # -force governs every artefact for a policy, not just the main JSON, so a run never
    # leaves a stale policy file beside freshly rewritten sidecars.
    $skipProfileWrite = $false
    if (-not $force -and (Test-Path -Path $filePath)) {
      Write-Verbose "Skipping existing file: $filePath"
      $skipProfileWrite = $true
      $skipped++
    }

    $subResources = [ordered]@{}

    if ($profileType -eq 'ConfigurationPolicies') {
      try {
        $policySettings = Get-ConfigurationPolicySettings -graphApiVersion $graphApiVersion -policyId $id
        if ($null -ne $policySettings) {
          # Harvest expanded definitions into a shared dictionary and strip them from the
          # policy body. Inline definitions repeat the same multi-KB blob for every policy
          # that touches a setting and bloat the consolidated file by an order of magnitude.
          foreach ($s in @($policySettings)) {
            $defs = Get-GraphProperty -InputObject $s -name 'settingDefinitions'
            if ($null -eq $defs) { continue }
            foreach ($d in @($defs)) {
              $defId = Get-GraphProperty -InputObject $d -name 'id'
              if ($defId -and -not $settingDefinitionSink.ContainsKey($defId)) {
                $settingDefinitionSink[$defId] = $d
              }
            }
            if ($s.PSObject.Properties['settingDefinitions']) {
              $s.PSObject.Properties.Remove('settingDefinitions')
            }
          }
          $p | Add-Member -NotePropertyName 'settings' -NotePropertyValue $policySettings -Force
          $subResources['settings'] = 'ok'
        }
      }
      catch {
        Write-Warning "Failed to export settings for configuration policy '$displayName' ($id): $($_.Exception.Message)"
        $subResources['settings'] = "failed: $($_.Exception.Message)"
        $failed++
      }
    }
    elseif ($profileType -eq 'GroupPolicyConfigurations') {
      try {
        $definitionValues = Get-GroupPolicyDefinitionValues -graphApiVersion $graphApiVersion -configurationId $id
        if ($null -ne $definitionValues) {
          $p | Add-Member -NotePropertyName 'definitionValues' -NotePropertyValue $definitionValues -Force
          $subResources['definitionValues'] = 'ok'
        }
      }
      catch {
        Write-Warning "Failed to export definitionValues for administrative template '$displayName' ($id): $($_.Exception.Message)"
        $subResources['definitionValues'] = "failed: $($_.Exception.Message)"
        $failed++
      }
    }
    elseif ($profileType -eq 'EndpointSecurityPolicies') {
      try {
        $intentDetail = Get-EndpointSecurityIntentSettings -graphApiVersion $graphApiVersion -intentId $id
        if ($null -ne $intentDetail) {
          $p | Add-Member -NotePropertyName 'settings' -NotePropertyValue $intentDetail.settings -Force
          foreach ($field in @('templateName', 'templateId', 'templateType', 'platformType')) {
            $v = Get-GraphProperty -InputObject $intentDetail -name $field
            if ($v) { $p | Add-Member -NotePropertyName $field -NotePropertyValue $v -Force }
          }
          $subResources['settings'] = 'ok'
        }
      }
      catch {
        Write-Warning "Failed to export settings for endpoint security policy '$displayName' ($id): $($_.Exception.Message)"
        $subResources['settings'] = "failed: $($_.Exception.Message)"
        $failed++
      }
    }
    elseif ($profileType -eq 'CompliancePolicies') {
      try {
        $scheduledActions = Get-ComplianceScheduledActions -graphApiVersion $graphApiVersion -policyId $id
        if ($null -ne $scheduledActions) {
          $p | Add-Member -NotePropertyName 'scheduledActionsForRule' -NotePropertyValue $scheduledActions -Force
          $subResources['scheduledActionsForRule'] = 'ok'
        }
      }
      catch {
        Write-Warning "Failed to export scheduled actions for compliance policy '$displayName' ($id): $($_.Exception.Message)"
        $subResources['scheduledActionsForRule'] = "failed: $($_.Exception.Message)"
        $failed++
      }
    }

    # Modern Endpoint Security policies live under configurationPolicies with a
    # templateReference, not under /intents. Surface the family so the analyzer can classify
    # by what a policy *is* rather than by which endpoint returned it.
    $templateReference = Get-GraphProperty -InputObject $p -name 'templateReference'
    if ($null -ne $templateReference) {
      $family = Get-GraphProperty -InputObject $templateReference -name 'templateFamily'
      if ($family) {
        $p | Add-Member -NotePropertyName '_templateFamily' -NotePropertyValue $family -Force
      }
      $templateDisplay = Get-GraphProperty -InputObject $templateReference -name 'templateDisplayName'
      if ($templateDisplay) {
        $p | Add-Member -NotePropertyName '_templateDisplayName' -NotePropertyValue $templateDisplay -Force
      }
    }

    # Resolve scope tag GUIDs to names.
    $scopeTagIds = Get-GraphProperty -InputObject $p -name 'roleScopeTagIds'
    if ($null -ne $scopeTagIds -and $scopeTagMap.Count) {
      $resolved = @()
      foreach ($tagId in @($scopeTagIds)) {
        $key = "$tagId"
        if ($scopeTagMap.ContainsKey($key)) { $resolved += $scopeTagMap[$key] }
        else { $resolved += [pscustomobject]@{ id = $key; displayName = $null; description = $null; isBuiltIn = $null } }
      }
      $p | Add-Member -NotePropertyName '_roleScopeTags' -NotePropertyValue $resolved -Force
    }

    # Aggregate deployment counts, for weighing findings by blast radius.
    $statusOverview = $null
    if ($includeStatusSummaries -and $canReadStatus) {
      try {
        $statusOverview = Get-PolicyStatusOverview -profileType $profileType -graphApiVersion $graphApiVersion -policyId $id
        if ($null -ne $statusOverview) {
          $p | Add-Member -NotePropertyName '_statusOverview' -NotePropertyValue $statusOverview -Force
          $subResources['statusOverview'] = 'ok'
        }
      }
      catch {
        $subResources['statusOverview'] = "failed: $($_.Exception.Message)"
      }
    }

    # Assignments first, so they can be written alongside the policy under the same -force gate.
    $assignmentTargets = @()
    $assignmentStatus = 'not-supported'
    # Tracked separately from the status string: the status records WHICH endpoint shape
    # worked ("ok (expand)"), so it must not double as the did-it-succeed test.
    $assignmentsFetched = $false
    if ($script:ProfileTypeMap[$profileType].Assignments) {
      try {
        $assignmentResult = Get-IntuneAssignments -profileType $profileType -profileId $id -policyOdataType $policyOdataType
        $assignmentTargets = @(Resolve-AssignmentTargets `
            -assignments $assignmentResult.Assignments `
            -groupCache $groupCache `
            -userCache $userCache `
            -directoryCache $directoryCache `
            -filterCache $filterCache `
            -memberCountCache $memberCountCache `
            -canResolveGroups:$canResolveGroups `
            -canResolveUsers:$canResolveUsers `
            -canResolveDirectory:$canResolveDirectory `
            -includeGroupMemberCounts:$includeGroupMemberCounts)
        # Record which endpoint shape worked, so the manifest shows when a policy type
        # needed a fallback rather than the standard /assignments collection.
        $assignmentStatus = if ($assignmentResult.Method -eq 'assignments') { 'ok' } else { "ok ($($assignmentResult.Method))" }
        $assignmentsFetched = $true
      }
      catch {
        Write-Warning "Failed to export assignments for $profileType policy '$displayName' ($id): $($_.Exception.Message)"
        $assignmentStatus = "failed: $($_.Exception.Message)"
        $failed++
      }
    }

    # Decode the custom-profile payload BEFORE the policy JSON is written, so the profile's
    # own identity travels with the exported object instead of living only in the sidecar.
    $decodedPayload = $null
    if ($profileType -eq 'DeviceConfigurations') {
      $payloadValue = Get-GraphProperty -InputObject $p -name 'payload'
      if ($payloadValue) {
        try {
          $decodedPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadValue))
          $payloadMeta = Get-PayloadMetadata -decodedPayload $decodedPayload
          if ($payloadMeta.PayloadIdentifier) { $p | Add-Member -NotePropertyName '_payloadIdentifier' -NotePropertyValue $payloadMeta.PayloadIdentifier -Force }
          if ($payloadMeta.PayloadUUID) { $p | Add-Member -NotePropertyName '_payloadUUID' -NotePropertyValue $payloadMeta.PayloadUUID -Force }
          if (@($payloadMeta.PayloadTypes).Count) { $p | Add-Member -NotePropertyName '_payloadTypes' -NotePropertyValue $payloadMeta.PayloadTypes -Force }
        }
        catch {
          Write-Warning "Failed to decode payload for '$displayName' ($id): $($_.Exception.Message)"
          $subResources['payloadXml'] = "failed: $($_.Exception.Message)"
        }
      }
    }

    if (-not $skipProfileWrite) {
      # Write the policy JSON after enrichment so the file includes the fetched sub-resources.
      $json = $p | ConvertTo-Json -Depth 50
      if ($PSCmdlet.ShouldProcess($filePath, 'Export Intune policy')) {
        Write-TextFile -path $filePath -content $json
        $exported++
      }

      if ($assignmentsFetched) {
        $assignFilePath = [System.IO.Path]::ChangeExtension($filePath, '.assignments.json')
        if ($PSCmdlet.ShouldProcess($assignFilePath, 'Export Intune policy assignments')) {
          Write-TextFile -path $assignFilePath -content ($assignmentTargets | ConvertTo-Json -Depth 10)
        }
      }

      # Custom configuration profiles carry their real settings in a base64 payload
      # (mobileconfig plist or OMA-URI XML). Decode a readable sidecar for review and diff.
      #
      # NOTE: decoded mobileconfig can contain certificate material and embedded credentials.
      # Treat the exports folder accordingly, or delete this block if that is not acceptable.
      if ($decodedPayload) {
        $payloadFilePath = [System.IO.Path]::ChangeExtension($filePath, '.payload.xml')
        if ($PSCmdlet.ShouldProcess($payloadFilePath, 'Export decoded payload')) {
          Write-TextFile -path $payloadFilePath -content $decodedPayload
        }
        $subResources['payloadXml'] = 'ok'
      }
    }

    $manifestSink.Add([pscustomobject]@{
        ProfileType     = $profileType
        Status          = if ($skipProfileWrite) { 'SkippedExisting' } else { 'Exported' }
        PolicyId        = $id
        DisplayName     = $displayName
        OdataType       = $policyOdataType
        TemplateFamily  = (Get-GraphProperty -InputObject $p -name '_templateFamily')
        # Profile-level identity. Two profiles sharing a PayloadIdentifier replace each other
        # on the device, so this is what a collision check keys on.
        PayloadIdentifier = (Get-GraphProperty -InputObject $p -name '_payloadIdentifier')
        PayloadUUID       = (Get-GraphProperty -InputObject $p -name '_payloadUUID')
        PayloadTypes      = (Get-GraphProperty -InputObject $p -name '_payloadTypes')
        File            = $filePath
        SubResources    = [pscustomobject]$subResources
        Assignments     = $assignmentStatus
        AssignmentCount = @($assignmentTargets).Count
        SettingCount    = (Get-GraphProperty -InputObject $p -name 'settingCount')
        Analyzed        = $script:ProfileTypeMap[$profileType].Analyze
      })

    if ($null -ne $ConsolidatedSink) {
      try {
        $consolidatedItem = [pscustomobject]@{
          ProfileType          = $profileType
          Id                   = $id
          DisplayName          = $displayName
          OdataType            = $policyOdataType
          TemplateFamily       = (Get-GraphProperty -InputObject $p -name '_templateFamily')
          PayloadIdentifier    = (Get-GraphProperty -InputObject $p -name '_payloadIdentifier')
          PayloadUUID          = (Get-GraphProperty -InputObject $p -name '_payloadUUID')
          PayloadTypes         = (Get-GraphProperty -InputObject $p -name '_payloadTypes')
          Platforms            = (Get-GraphProperty -InputObject $p -name 'platforms')
          Technologies         = (Get-GraphProperty -InputObject $p -name 'technologies')
          SettingCount         = (Get-GraphProperty -InputObject $p -name 'settingCount')
          IsAssigned           = (Get-GraphProperty -InputObject $p -name 'isAssigned')
          CreatedDateTime      = (Get-GraphProperty -InputObject $p -name 'createdDateTime')
          LastModifiedDateTime = (Get-GraphProperty -InputObject $p -name 'lastModifiedDateTime')
          RoleScopeTagIds      = (Get-GraphProperty -InputObject $p -name 'roleScopeTagIds')
          RoleScopeTags        = (Get-GraphProperty -InputObject $p -name '_roleScopeTags')
          StatusOverview       = $statusOverview
          Analyzed             = $script:ProfileTypeMap[$profileType].Analyze
          Payload              = $p
        }

        if ($includeAssignmentsInConsolidated) {
          $consolidatedItem | Add-Member -NotePropertyName 'Assignments' -NotePropertyValue $assignmentTargets -Force
        }

        $ConsolidatedSink.Add($consolidatedItem)
      }
      catch {
        Write-Warning "Failed to add policy '$displayName' ($id) to consolidated sink: $($_.Exception.Message)"
      }
    }
  }

  if ($policyTotal -gt 0) { Write-Progress -Id 1 -Activity "Exporting $profileType" -Completed }

  return [PSCustomObject]@{
    ProfileType = $profileType
    TotalFound  = @($profiles).Count
    Exported    = $exported
    Skipped     = $skipped
    Failed      = $failed
    OutputPath  = $typeOutDir
  }
}

#endregion

#region Session

function Confirm-GraphContext {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [object]$context,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$outDir,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$typesToExport,

    [Parameter()]
    [switch]$prompt,

    [Parameter()]
    [switch]$force,

    # Needed so the "not consented" warning compares against the scopes this run actually
    # requires, rather than a fixed superset.
    [Parameter()]
    [switch]$includeStatusSummaries,

    [Parameter()]
    [switch]$includeGroupMemberCounts
  )

  $account = $context.Account
  $tenant = $context.TenantId

  Write-Output 'Connected to Microsoft Graph:'
  Write-Output "  Account : $account"
  Write-Output "  Tenant  : $tenant"
  Write-Verbose ('Scopes: {0}' -f (@($context.Scopes) -join ', '))
  Write-Output "  Export  : $($typesToExport -join ', ')"
  Write-Output "  Output  : $outDir"

  $missingScopes = @(Get-RequiredScopes -includeStatusSummaries:$includeStatusSummaries -includeGroupMemberCounts:$includeGroupMemberCounts | Where-Object { $_ -notin @($context.Scopes) })
  if ($missingScopes.Count) {
    Write-Warning ("Not consented: {0}. Affected policy types and lookups will be skipped and recorded in export-manifest.json." -f ($missingScopes -join ', '))
  }

  if (-not $prompt -or $force) {
    return $true
  }

  $caption = 'Confirm tenant and account'
  $message = "Continue exporting Intune policies from tenant '$tenant' as '$account'? Use -force to skip this prompt."
  return [bool]$PSCmdlet.ShouldContinue($message, $caption)
}

function Disconnect-Graph {
  [CmdletBinding()]
  param()

  Assert-GraphModuleInstalled -moduleName 'Microsoft.Graph.Authentication'

  try {
    Disconnect-MgGraph | Out-Null
  }
  catch {
    Write-Verbose "Disconnect-MgGraph failed or was not necessary: $($_.Exception.Message)"
  }
}

function New-ExportReadme {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$tenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$account,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$typesToExport
  )

  $exportDate = Get-Date -Format 'yyyy-MM-dd'

  # Build the folder table from the registry so it can never describe a type that is not
  # exported (or omit one that is).
  $folderRows = foreach ($t in $typesToExport) {
    $entry = $script:ProfileTypeMap[$t]
    $analyzed = if ($entry.Analyze) { 'Yes' } else { 'Inventory only' }
    '| `{0}/` | `/{1}` | {2} |' -f $t, $entry.Path, $analyzed
  }

  return @"
# Intune Configuration Export

| Property | Value |
|----------|-------|
| Tenant | $tenantId |
| Account | $account |
| Exported | $exportDate |

## Folder structure

Each subfolder holds one Intune policy type. Every policy produces up to four files:

| File pattern | Contents |
|---|---|
| ``{name}_{id}.json`` | Raw Microsoft Graph response plus fetched sub-resources. Source of truth. |
| ``{name}_{id}.assignments.json`` | Resolved assignment targets -- groups (with membership rules and, with ``-includeGroupMemberCounts``, transitive member counts), users, filters (name + rule + platform), exclusions, and built-in targets. |
| ``{name}_{id}.payload.xml`` | Decoded mobileconfig plist (macOS/iOS custom profiles only). |

Root-level files:

| File | Contents |
|---|---|
| ``export-manifest.json`` | What this run actually fetched: Graph version per type, granted vs. missing scopes, and a per-policy record of which sub-resources succeeded or failed. Read this before trusting an absence in the data. |
| ``setting-definitions.json`` | Shared dictionary of Settings Catalog setting definitions keyed by ``settingDefinitionId`` (display name, data type, default, allowed options). Emitted once rather than inline per policy. |
| ``assignment-filters.json`` | Every assignment filter in the tenant, including filters no policy references. |
| ``role-scope-tags.json`` | Scope tag id to display name. |
| ``consolidated-config-profiles.json`` | All policies in one envelope (``-emitConsolidated``). |

## Policy type folders

| Folder | Graph endpoint | Setting-level analysis |
|---|---|---|
$($folderRows -join "`n")

Types marked *Inventory only* are exported for completeness but are excluded from
setting-level overlap analysis: enrollment configurations, update rings and scripts have
their own priority and ordering semantics that overlap comparison does not model.

## Where settings live, by type

| Type | Settings location |
|---|---|
| ``CompliancePolicies`` | Top-level JSON properties. ``scheduledActionsForRule`` holds the grace period and the action taken on non-compliance. These **check** device state; they do not push settings. |
| ``ConfigurationPolicies`` | ``settings`` array. Each entry has a ``settingDefinitionId`` plus a nested value (``choiceSettingValue``, ``simpleSettingValue``, ``groupSettingCollectionValue``). Resolve the id against ``setting-definitions.json`` for the display name. |
| ``DeviceConfigurations`` | Typed profiles keep settings as top-level properties; custom profiles use a base64 ``payload`` or an ``omaSettings`` array. Windows Update rings live here as ``windowsUpdateForBusinessConfiguration``. |
| ``EndpointSecurityPolicies`` | ``settings`` array with ``definitionId`` and ``valueJson``/``value``; ``templateName`` identifies the baseline. Modern Endpoint Security policies appear under ``ConfigurationPolicies`` instead, tagged with ``_templateFamily``. |
| ``GroupPolicyConfigurations`` | ``definitionValues`` array, each with a ``definition`` (``displayName``, ``categoryPath``) and ``presentationValues``. |
| ``AppProtectionPolicies`` | Top-level MAM properties (data transfer, PIN, wipe). |

## Analyzer-added fields

Fields prefixed with ``_`` are added by the export, not returned by Graph:

| Field | Meaning |
|---|---|
| ``_templateFamily`` | ``templateReference.templateFamily`` -- classifies a Settings Catalog policy as antivirus, firewall, diskEncryption, endpointDetectionAndResponse, etc. |
| ``_templateDisplayName`` | Human-readable baseline/template name. |
| ``_roleScopeTags`` | ``roleScopeTagIds`` resolved to names. |
| ``_statusOverview`` | Aggregate deployment counts (``-includeStatusSummaries``). Aggregates only -- per-device and per-user status are never exported. |

## Overlap report

Run ``Analyze-PolicyOverlap.ps1`` against this export to generate:
- ``policy-overlap-report.json`` -- machine-readable findings
- ``policy-overlap-report.md`` -- formatted Markdown report
- ``policy-overlap-report.txt`` -- plain text summary

Findings are classified as:
- **Compliance Violation** -- a config profile enforces a value that would fail the compliance check
- **Config Conflict** -- two config profiles push different values for the same setting to the same target
- **Compliance Gap** -- compliance checks a setting but no config profile enforces it
- **Config Overlap** -- two config profiles push the same value (redundant)
- **Compliance Enforced** -- config correctly matches what compliance checks
- **Potential cross-target overlap** -- settings that may conflict across different group targets

## Key conventions

- Compliance policies **evaluate** device state (pass/fail); configuration profiles **enforce** settings.
- A compliance setting with no matching config is a **gap**; a config setting that contradicts compliance is a **violation**.
- Assignment filters narrow which devices within a group receive a policy. Exclusion group targets are flagged with ``isExclusion``.
- ``.payload.xml`` sidecars contain decoded mobileconfig, which can include certificate material and credentials. Handle this folder accordingly.
"@
}

#endregion

#region Main

try {
  $wasAlreadyConnected = Connect-IntuneGraph -tenantId $tenantId -useDeviceCode:$useDeviceCode -includeStatusSummaries:$includeStatusSummaries -includeGroupMemberCounts:$includeGroupMemberCounts

  if (-not (Test-Path -Path $outDir)) {
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null
  }

  $typesToExport = if ($profileType -contains 'All') {
    @($script:ProfileTypeMap.Keys)
  }
  else {
    @($profileType)
  }

  $consolidated = if ($emitConsolidated.IsPresent) {
    Write-Verbose 'Creating consolidated export object.'
    New-Object System.Collections.Generic.List[psobject]
  }
  else {
    $null
  }

  $ctx = Get-MgContext
  if ($null -eq $ctx -or -not $ctx.Account -or -not $ctx.TenantId) {
    throw 'Not connected to Microsoft Graph. Run again and sign in when prompted.'
  }

  $dateFolder = Join-Path -Path (Join-Path -Path $outDir -ChildPath $ctx.TenantId) -ChildPath (Get-Date -Format 'yyyy-MM-dd')
  if (-not (Test-Path -Path $dateFolder)) {
    New-Item -Path $dateFolder -ItemType Directory -Force | Out-Null
  }

  $confirmed = Confirm-GraphContext -context $ctx -outDir $dateFolder -typesToExport $typesToExport -prompt:$wasAlreadyConnected -force:$force
  if (-not $confirmed) {
    Write-Verbose 'User did not confirm current Graph account/tenant; reconnecting...'
    Disconnect-Graph
    [void](Connect-IntuneGraph -tenantId $tenantId -useDeviceCode:$useDeviceCode -includeStatusSummaries:$includeStatusSummaries -includeGroupMemberCounts:$includeGroupMemberCounts)

    $ctx = Get-MgContext
    if ($null -eq $ctx -or -not $ctx.Account -or -not $ctx.TenantId) {
      throw 'Reconnect failed; not connected to Microsoft Graph.'
    }

    $dateFolder = Join-Path -Path (Join-Path -Path $outDir -ChildPath $ctx.TenantId) -ChildPath (Get-Date -Format 'yyyy-MM-dd')
    if (-not (Test-Path -Path $dateFolder)) {
      New-Item -Path $dateFolder -ItemType Directory -Force | Out-Null
    }

    # Show the new context (no prompt since this is a fresh connection)
    [void](Confirm-GraphContext -context $ctx -outDir $dateFolder -typesToExport $typesToExport -prompt:$false -force:$force -includeStatusSummaries:$includeStatusSummaries -includeGroupMemberCounts:$includeGroupMemberCounts)
  }

  $grantedScopes = Get-GrantedScope
  $missingScopes = @(Get-RequiredScopes -includeStatusSummaries:$includeStatusSummaries -includeGroupMemberCounts:$includeGroupMemberCounts | Where-Object { $_ -notin $grantedScopes })

  Write-Host 'Fetching tenant-wide reference data (scope tags, assignment filters)...'
  $scopeTagMap = if ('DeviceManagementRBAC.Read.All' -in $grantedScopes) { Get-RoleScopeTagMap } else { @{} }
  $filterCatalog = if ('DeviceManagementConfiguration.Read.All' -in $grantedScopes) { Get-AssignmentFilterCatalog } else { @{} }

  # Seed the per-assignment filter cache from the full catalog so resolving a referenced
  # filter costs nothing, and unreferenced filters remain visible in their own file.
  $filterCache = @{}
  foreach ($k in $filterCatalog.Keys) { $filterCache[$k] = $filterCatalog[$k] }

  $sharedCaches = @{
    Groups        = @{}
    Users         = @{}
    Directory     = @{}
    Filters       = $filterCache
    MemberCounts  = @{}
    ScopeTags     = $scopeTagMap
    GrantedScopes = $grantedScopes
  }

  $manifestEntries = New-Object System.Collections.Generic.List[psobject]
  $settingDefinitions = @{}

  # Collected into a List rather than captured from the pipeline, so progress lines in this
  # loop cannot end up mixed into the results objects.
  $results = New-Object System.Collections.Generic.List[psobject]
  $typeIndex = 0
  $typeCount = @($typesToExport).Count
  $runTimer = [System.Diagnostics.Stopwatch]::StartNew()

  foreach ($t in $typesToExport) {
    $typeIndex++
    # Deliberately not -NoNewline: warnings raised while a type is exporting would otherwise
    # be appended to this line ("AppProtectionPoliciesWARNING: Skipping...").
    Write-Host ("[{0,2}/{1}] {2}" -f $typeIndex, $typeCount, $t)
    $typeTimer = [System.Diagnostics.Stopwatch]::StartNew()

    $typeResult = Export-IntuneProfiles `
      -profileType $t `
      -graphApiVersion $graphApiVersion `
      -baseOutDir $dateFolder `
      -profileId $profileId `
      -profileName $profileName `
      -odataType $odataType `
      -force:$force `
      -ConsolidatedSink $consolidated `
      -includeAssignmentsInConsolidated:$includeAssignmentsInConsolidated `
      -includeStatusSummaries:$includeStatusSummaries `
      -includeGroupMemberCounts:$includeGroupMemberCounts `
      -sharedCaches $sharedCaches `
      -manifestSink $manifestEntries `
      -settingDefinitionSink $settingDefinitions

    $typeTimer.Stop()
    $results.Add($typeResult)

    $detail = if ($typeResult.TotalFound -eq 0) { 'none' }
    else {
      $parts = @("$($typeResult.Exported) exported")
      if ($typeResult.Skipped) { $parts += "$($typeResult.Skipped) skipped" }
      if ($typeResult.Failed) { $parts += "$($typeResult.Failed) failed" }
      "$($typeResult.TotalFound) found, $($parts -join ', ')"
    }
    Write-Host ("         {0}  ({1:n1}s)" -f $detail, $typeTimer.Elapsed.TotalSeconds) -ForegroundColor DarkGray
  }

  $runTimer.Stop()
  Write-Host ("Policy export finished in {0:n1}s" -f $runTimer.Elapsed.TotalSeconds)
  Write-Host ''

  $results | Sort-Object ProfileType | Format-Table -AutoSize

  # Shared reference files -------------------------------------------------------------

  if ($settingDefinitions.Count) {
    $defsFile = Join-Path -Path $dateFolder -ChildPath 'setting-definitions.json'
    if ($PSCmdlet.ShouldProcess($defsFile, 'Write Settings Catalog definition dictionary')) {
      Write-TextFile -path $defsFile -content ($settingDefinitions | ConvertTo-Json -Depth 20)
      Write-Output "Setting definitions: $defsFile ($($settingDefinitions.Count) definitions)"
    }
  }

  if ($filterCatalog.Count) {
    $filtersFile = Join-Path -Path $dateFolder -ChildPath 'assignment-filters.json'
    if ($PSCmdlet.ShouldProcess($filtersFile, 'Write assignment filter catalog')) {
      Write-TextFile -path $filtersFile -content (@($filterCatalog.Values) | ConvertTo-Json -Depth 10)
    }
  }

  if ($scopeTagMap.Count) {
    $tagsFile = Join-Path -Path $dateFolder -ChildPath 'role-scope-tags.json'
    if ($PSCmdlet.ShouldProcess($tagsFile, 'Write role scope tag catalog')) {
      Write-TextFile -path $tagsFile -content (@($scopeTagMap.Values) | ConvertTo-Json -Depth 10)
    }
  }

  # Manifest ---------------------------------------------------------------------------
  # Every failure above is a Write-Warning to a console that scrolls away. Without this file
  # the analyzer cannot tell "this policy has no settings" from "the settings fetch threw".

  $graphVersionsUsed = [ordered]@{}
  foreach ($t in $typesToExport) {
    $graphVersionsUsed[$t] = (Get-GraphBaseForProfileType -profileType $t -graphApiVersion $graphApiVersion) -replace '^https://graph\.microsoft\.com/', ''
  }

  $manifest = [pscustomobject]@{
    ExportedAtUtc      = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    TenantId           = $ctx.TenantId
    Account            = $ctx.Account
    ScriptVersion      = '2.0'
    RequestedTypes     = $typesToExport
    GraphVersionByType = [pscustomobject]$graphVersionsUsed
    GrantedScopes      = $grantedScopes
    MissingScopes      = $missingScopes
    Options            = [pscustomobject]@{
      emitConsolidated         = [bool]$emitConsolidated
      includeAssignments       = [bool]$includeAssignmentsInConsolidated
      includeStatusSummaries   = [bool]$includeStatusSummaries
      includeGroupMemberCounts = [bool]$includeGroupMemberCounts
      force                    = [bool]$force
      profileNameFilter        = $profileName
      odataTypeFilter          = $odataType
    }
    AnalyzedTypes      = @($typesToExport | Where-Object { $script:ProfileTypeMap[$_].Analyze })
    InventoryOnlyTypes = @($typesToExport | Where-Object { -not $script:ProfileTypeMap[$_].Analyze })
    Totals             = $results | Sort-Object ProfileType
    Policies           = $manifestEntries
  }

  $manifestFile = Join-Path -Path $dateFolder -ChildPath 'export-manifest.json'
  if ($PSCmdlet.ShouldProcess($manifestFile, 'Write export manifest')) {
    Write-TextFile -path $manifestFile -content ($manifest | ConvertTo-Json -Depth 20)
    Write-Output "Export manifest: $manifestFile"
  }

  # Consolidated -----------------------------------------------------------------------

  if ($null -ne $consolidated) {
    $consolidatedFile = Join-Path -Path $dateFolder -ChildPath 'consolidated-config-profiles.json'
    $consolidatedEnvelope = [pscustomobject]@{
      ExportedAtUtc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
      TenantId      = $ctx.TenantId
      ProfileTypes  = $typesToExport
      ItemCount     = $consolidated.Count
      Items         = $consolidated
    }
    if ($PSCmdlet.ShouldProcess($consolidatedFile, 'Write consolidated export')) {
      Write-TextFile -path $consolidatedFile -content ($consolidatedEnvelope | ConvertTo-Json -Depth 100)
      Write-Output "Consolidated export: $consolidatedFile"
    }
  }

  # README -----------------------------------------------------------------------------

  $readmePath = Join-Path -Path $dateFolder -ChildPath 'README.md'
  $readmeContent = New-ExportReadme -tenantId $ctx.TenantId -account $ctx.Account -typesToExport $typesToExport
  if ($PSCmdlet.ShouldProcess($readmePath, 'Write export README')) {
    Write-TextFile -path $readmePath -content $readmeContent
  }

  if ($missingScopes.Count) {
    Write-Warning ("Export completed with missing scopes: {0}. See MissingScopes in export-manifest.json." -f ($missingScopes -join ', '))
  }
}
catch {
  Write-Error $_
  throw
}

#endregion
