<#
.SYNOPSIS
Phase 1 of macOS 27 (Golden Gate) readiness: creates the version assignment filter and the
matching compliance policy, following the tenant's existing per-version pattern.

.DESCRIPTION
macOS 27 "Golden Gate" shipped 14 September 2026. The tenant scopes macOS compliance by
major version using an assignment filter plus a per-version policy:

    macOS: Sequoia (15.x)  -> _MacOS Devices + filter macOSSequoiaDevices  (osVersion startsWith "15")
    macOS: Tahoe (26.x)    -> _MacOS Devices + filter macOSTahoeDevices    (osVersion startsWith "26")

No filter matches "27", so a Mac that takes the 27 upgrade currently falls out of
version-based compliance entirely and is left with only 'macOS: Base compliance'. This
script closes that gap by adding the missing tier:

    macOS: Golden Gate (27.x) -> _MacOS Devices + filter macOSGoldenGateDevices

It does NOT touch the Sequoia or Tahoe policies. Intel Macs cannot run macOS 27 and stay on
the Tahoe tier, which is why that policy is deliberately left alone.

The script is idempotent: existing objects with the same display name are reused rather than
duplicated, so it is safe to re-run. Use -WhatIf for a dry run.

.PARAMETER osMinimumVersion
Minimum macOS 27 build required for compliance. Defaults to '27.0' (the shipping release).
Raise this as Apple ships patches, the same way the Tahoe tier sits at 26.6.1.

.PARAMETER targetGroupName
Entra group the policy is assigned to. Defaults to the group the other macOS version
policies use.

.PARAMETER tenantId
Optional tenant id or domain for authentication.

.PARAMETER skipAssignment
Create the filter and policy but do not assign the policy. Use this if you want to review
the policy in the admin center before it reaches any device.

.EXAMPLE
./New-MacOSGoldenGateCompliance.ps1 -WhatIf

Shows exactly what would be created and assigned, without writing anything.

.EXAMPLE
./New-MacOSGoldenGateCompliance.ps1

Creates the filter and policy and assigns the policy to _MacOS Devices.

.EXAMPLE
./New-MacOSGoldenGateCompliance.ps1 -skipAssignment

Creates both objects but leaves the policy unassigned for manual review.

.NOTES
Requires delegated permission DeviceManagementConfiguration.ReadWrite.All (to create the
filter, the policy and the assignment) and Group.Read.All (to resolve the target group).
These are WRITE scopes -- broader than Export-DeviceConfigurations.ps1 uses -- so expect a
fresh consent prompt.

Re-run Export-DeviceConfigurations.ps1 and Analyze-PolicyOverlap.ps1 afterwards to confirm
the new tier appears and no macOS policy is left unassigned.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [ValidatePattern('^27(\.\d+){0,2}$')]
  [string]$osMinimumVersion = '27.0',

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$targetGroupName = '_MacOS Devices',

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$tenantId,

  # Intune notification message template ids. These are tenant-specific objects, so they are
  # parameters rather than literals -- this repo is public. The all-zero id is Intune's "no
  # template" value, which makes the scheduled action fire without sending a message, so the
  # script runs correctly out of the box and carries no tenant data.
  #
  # Find yours under Devices > Compliance policies > Notifications.
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$notificationTemplateId = '00000000-0000-0000-0000-000000000000',

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$escalationTemplateId = '00000000-0000-0000-0000-000000000000',

  [Parameter()]
  [switch]$skipAssignment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Names follow the existing tiers exactly; changing them breaks the naming convention the
# other macOS policies and filters use.
$filterDisplayName = 'macOSGoldenGateDevices'
$filterRule = '(device.osVersion -startsWith "27")'
$policyDisplayName = 'macOS: Golden Gate (27.x)'

$graphBase = 'https://graph.microsoft.com/beta'

#region Helpers

function Get-GraphProperty {
  # StrictMode-safe property read; Graph responses vary in shape between calls.
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
    [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PATCH')][string]$method,
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

function Find-ByDisplayName {
  # Returns the first object in a collection endpoint whose displayName matches exactly.
  param(
    [Parameter(Mandatory = $true)][string]$uri,
    [Parameter(Mandatory = $true)][string]$displayName
  )
  $response = Invoke-Graph -method GET -uri $uri
  foreach ($item in @(Get-GraphProperty -InputObject $response -name 'value')) {
    if ((Get-GraphProperty -InputObject $item -name 'displayName') -eq $displayName) { return $item }
  }
  return $null
}

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
}

$requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')

$ctx = $null
try { $ctx = Get-MgContext } catch { $ctx = $null }

$needConnect = $true
if ($null -ne $ctx -and $ctx.Scopes) {
  $missing = @($requiredScopes | Where-Object { $_ -notin $ctx.Scopes })
  if ($missing.Count -eq 0) { $needConnect = $false }
  else { Write-Verbose ("Reconnecting for: {0}" -f ($missing -join ', ')) }
}

if ($needConnect) {
  $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
  if ($tenantId) { $connectParams.TenantId = $tenantId }
  Connect-MgGraph @connectParams | Out-Null
  $ctx = Get-MgContext
}

if ($null -eq $ctx -or -not $ctx.Account -or -not $ctx.TenantId) {
  throw 'Not connected to Microsoft Graph.'
}

Write-Output 'Connected to Microsoft Graph:'
Write-Output "  Account : $($ctx.Account)"
Write-Output "  Tenant  : $($ctx.TenantId)"
Write-Output ''

#endregion

#region 1. Assignment filter

Write-Output "[1/3] Assignment filter '$filterDisplayName'"

$filter = Find-ByDisplayName -uri "$graphBase/deviceManagement/assignmentFilters" -displayName $filterDisplayName

if ($null -ne $filter) {
  $existingRule = Get-GraphProperty -InputObject $filter -name 'rule'
  Write-Output "      Already exists (id $(Get-GraphProperty -InputObject $filter -name 'id'))"
  if ($existingRule -ne $filterRule) {
    Write-Warning "      Existing rule differs from expected.`n        expected: $filterRule`n        actual  : $existingRule"
  }
}
else {
  $filterBody = [ordered]@{
    '@odata.type'                    = '#microsoft.graph.deviceAndAppManagementAssignmentFilter'
    displayName                      = $filterDisplayName
    description                      = 'Macs running macOS 27 (Golden Gate). Scopes the 27.x compliance tier.'
    platform                         = 'macOS'
    rule                             = $filterRule
    assignmentFilterManagementType   = 'devices'
  }

  if ($PSCmdlet.ShouldProcess($filterDisplayName, "Create macOS assignment filter with rule $filterRule")) {
    $filter = Invoke-Graph -method POST -uri "$graphBase/deviceManagement/assignmentFilters" -body $filterBody
    Write-Output "      Created (id $(Get-GraphProperty -InputObject $filter -name 'id'))"
  }
  else {
    Write-Output "      WhatIf: would create with rule $filterRule"
  }
}

$filterId = Get-GraphProperty -InputObject $filter -name 'id'

#endregion

#region 2. Compliance policy

Write-Output ''
Write-Output "[2/3] Compliance policy '$policyDisplayName'"

$policy = Find-ByDisplayName -uri "$graphBase/deviceManagement/deviceCompliancePolicies" -displayName $policyDisplayName

if ($null -ne $policy) {
  Write-Output "      Already exists (id $(Get-GraphProperty -InputObject $policy -name 'id'))"
  $existingMin = Get-GraphProperty -InputObject $policy -name 'osMinimumVersion'
  if ($existingMin -ne $osMinimumVersion) {
    Write-Warning "      osMinimumVersion is '$existingMin', expected '$osMinimumVersion'. Not changed -- adjust in the admin center if intended."
  }
}
else {
  # scheduledActionsForRule is REQUIRED on create for any per-platform compliance policy.
  # These action/grace pairs and notification template ids are cloned from
  # 'macOS: Tahoe (26.x)' so the 27 tier escalates identically to the tier it succeeds.
  $policyBody = [ordered]@{
    '@odata.type'                               = '#microsoft.graph.macOSCompliancePolicy'
    displayName                                 = $policyDisplayName
    description                                 = 'macOS 27 (Golden Gate) version tier. Scoped by the macOSGoldenGateDevices filter. Mirrors the Tahoe (26.x) tier.'
    osMinimumVersion                            = $osMinimumVersion
    passwordRequiredType                        = 'deviceDefault'
    deviceThreatProtectionRequiredSecurityLevel = 'unavailable'
    roleScopeTagIds                             = @()
    scheduledActionsForRule                     = @(
      [ordered]@{
        ruleName                      = 'PasswordRequired'
        scheduledActionConfigurations = @(
          [ordered]@{ actionType = 'block'; gracePeriodHours = 72; notificationTemplateId = '00000000-0000-0000-0000-000000000000'; notificationMessageCCList = @() }
          [ordered]@{ actionType = 'notification'; gracePeriodHours = 72; notificationTemplateId = $notificationTemplateId; notificationMessageCCList = @() }
          [ordered]@{ actionType = 'notification'; gracePeriodHours = 336; notificationTemplateId = $notificationTemplateId; notificationMessageCCList = @() }
          [ordered]@{ actionType = 'notification'; gracePeriodHours = 480; notificationTemplateId = $escalationTemplateId; notificationMessageCCList = @() }
          [ordered]@{ actionType = 'remoteLock'; gracePeriodHours = 504; notificationTemplateId = '00000000-0000-0000-0000-000000000000'; notificationMessageCCList = @() }
        )
      }
    )
  }

  if ($PSCmdlet.ShouldProcess($policyDisplayName, "Create macOS compliance policy requiring osMinimumVersion $osMinimumVersion")) {
    $policy = Invoke-Graph -method POST -uri "$graphBase/deviceManagement/deviceCompliancePolicies" -body $policyBody
    Write-Output "      Created (id $(Get-GraphProperty -InputObject $policy -name 'id'))"
  }
  else {
    Write-Output "      WhatIf: would create requiring osMinimumVersion $osMinimumVersion"
  }
}

$policyId = Get-GraphProperty -InputObject $policy -name 'id'

#endregion

#region 3. Assignment

Write-Output ''
Write-Output '[3/3] Assignment'

if ($skipAssignment) {
  Write-Output "      Skipped (-skipAssignment). Policy exists but reaches no device."
}
elseif (-not $policyId -or -not $filterId) {
  Write-Output '      Skipped: filter or policy not created (WhatIf run).'
}
else {
  # Resolve the target group by display name rather than hardcoding its id.
  $groupResponse = Invoke-Graph -method GET -uri ("https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '{0}'&`$select=id,displayName" -f $targetGroupName.Replace("'", "''"))
  $group = @(Get-GraphProperty -InputObject $groupResponse -name 'value') | Select-Object -First 1
  if ($null -eq $group) { throw "Target group '$targetGroupName' not found." }
  $groupId = Get-GraphProperty -InputObject $group -name 'id'

  # The assign action REPLACES the full assignment list, so send the intended final state.
  $assignBody = @{
    assignments = @(
      [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceCompliancePolicyAssignment'
        target        = [ordered]@{
          '@odata.type'                              = '#microsoft.graph.groupAssignmentTarget'
          groupId                                    = $groupId
          deviceAndAppManagementAssignmentFilterId   = $filterId
          deviceAndAppManagementAssignmentFilterType = 'include'
        }
      }
    )
  }

  if ($PSCmdlet.ShouldProcess($policyDisplayName, "Assign to group '$targetGroupName' filtered by '$filterDisplayName' (include)")) {
    Invoke-Graph -method POST -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId/assign" -body $assignBody | Out-Null
    Write-Output "      Assigned to '$targetGroupName' ($groupId) with include filter '$filterDisplayName'"
  }
  else {
    Write-Output "      WhatIf: would assign to '$targetGroupName' with include filter '$filterDisplayName'"
  }
}

#endregion

#region Verify

Write-Output ''
Write-Output '--- Verification (read back from Graph) ---'

if ($policyId) {
  $check = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId"
  Write-Output ("  Policy      : {0}" -f (Get-GraphProperty -InputObject $check -name 'displayName'))
  Write-Output ("  osMinimum   : {0}" -f (Get-GraphProperty -InputObject $check -name 'osMinimumVersion'))

  # Graph rejects $expand=scheduledActionConfigurations on the scheduledActionsForRule CHILD
  # collection with 400 "No method match route template". The nested expand on the parent
  # policy is the shape that works; fall back to the plain listing if even that is refused.
  $ruleList = @()
  try {
    $withActions = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId`?`$expand=scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
    $ruleList = @(Get-GraphProperty -InputObject $withActions -name 'scheduledActionsForRule')
  }
  catch {
    Write-Verbose "Nested expand failed ($($_.Exception.Message)); falling back to per-rule fetch."
    $plain = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId/scheduledActionsForRule"
    foreach ($rule in @(Get-GraphProperty -InputObject $plain -name 'value')) {
      $ruleId = Get-GraphProperty -InputObject $rule -name 'id'
      if (-not $ruleId) { continue }
      $cfg = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId/scheduledActionsForRule/$ruleId/scheduledActionConfigurations"
      $rule | Add-Member -NotePropertyName 'scheduledActionConfigurations' -NotePropertyValue @(Get-GraphProperty -InputObject $cfg -name 'value') -Force
      $ruleList += $rule
    }
  }

  foreach ($rule in $ruleList) {
    $cfgs = @(Get-GraphProperty -InputObject $rule -name 'scheduledActionConfigurations') |
      ForEach-Object { '{0}/{1}h' -f (Get-GraphProperty -InputObject $_ -name 'actionType'), (Get-GraphProperty -InputObject $_ -name 'gracePeriodHours') }
    if ($cfgs) { Write-Output ("  Actions     : {0}" -f ($cfgs -join ', ')) }
  }

  $asg = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceCompliancePolicies/$policyId/assignments"
  $asgList = @(Get-GraphProperty -InputObject $asg -name 'value')
  if ($asgList.Count -eq 0) {
    Write-Output '  Assignments : NONE (policy currently reaches no device)'
  }
  foreach ($a in $asgList) {
    $t = Get-GraphProperty -InputObject $a -name 'target'
    Write-Output ("  Assignment  : group {0} filter {1} [{2}]" -f `
      (Get-GraphProperty -InputObject $t -name 'groupId'), `
      (Get-GraphProperty -InputObject $t -name 'deviceAndAppManagementAssignmentFilterId'), `
      (Get-GraphProperty -InputObject $t -name 'deviceAndAppManagementAssignmentFilterType'))
  }
}
else {
  Write-Output '  (WhatIf run -- nothing created, nothing to verify)'
}

Write-Output ''
Write-Output 'Next: re-run Export-DeviceConfigurations.ps1 then Analyze-PolicyOverlap.ps1 to confirm the new tier.'

#endregion
