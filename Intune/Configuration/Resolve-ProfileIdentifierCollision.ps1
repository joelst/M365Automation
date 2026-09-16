<#
.SYNOPSIS
Resolves a macOS profile identifier collision by retiring one side of the pair.

.DESCRIPTION
macOS keys an installed configuration profile by its top-level PayloadIdentifier. Two
profiles sharing one do not merge -- the second to arrive REPLACES the first, and which wins
depends on delivery order. This script retires one side: it renames the profile with a
[disabled] prefix and removes all of its assignments, leaving the kept profile untouched.

The collision itself is the safety check. Both profiles are read first and the script
refuses to proceed unless they genuinely share a PayloadIdentifier, so it cannot be pointed
at an unrelated pair by a mistyped id.

Payloads are never modified. The Intune displayName is metadata -- the .mobileconfig
delivered to the Mac is the 'payload' property, which is hashed before and after and
reported if it changes.

Retiring rather than deleting is deliberate: unassigning is reversible, deletion is not.
Delete the [disabled] profile by hand once you are satisfied.

Supersedes Resolve-MacOSOnboardingDuplicate.ps1, which did this for one specific pair.

.PARAMETER keepId
Id of the profile to keep. Left untouched apart from an optional rename.

.PARAMETER retireId
Id of the profile to rename and unassign.

.PARAMETER retireNewName
New display name for the retired profile. Defaults to its current name with a
'[disabled] ' prefix.

.PARAMETER keepNewName
Optional new display name for the kept profile. Omit to leave its name alone.

.PARAMETER allowDifferentIdentifiers
Proceed even when the two profiles do NOT share a PayloadIdentifier. Only for retiring a
duplicate that is not, strictly speaking, an identifier collision.

.PARAMETER tenantId
Optional tenant id or domain for authentication.

.EXAMPLE
./Resolve-ProfileIdentifierCollision.ps1 -keepId <keep-profile-id> -retireId <retire-profile-id> -WhatIf

Dry run for the com.microsoft.wdav.sysext collision: keeps sysext_restricted, retires sysext.

.EXAMPLE
./Resolve-ProfileIdentifierCollision.ps1 -keepId <keep-profile-id> -retireId <retire-profile-id>

Applies it.

.NOTES
Requires DeviceManagementConfiguration.ReadWrite.All.

Find collisions with Analyze-PolicyOverlap.ps1 -- they appear under
PayloadIdentifierCollisions in the JSON report and as "Profile Identifier Collisions" in the
Markdown.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$keepId,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$retireId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$retireNewName,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$keepNewName,

  [Parameter()]
  [switch]$allowDifferentIdentifiers,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$tenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'

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
    [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$method,
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

function Get-PayloadFingerprint {
  # Hash rather than content: the payload can carry certificate and onboarding material.
  param([Parameter()][AllowNull()][object]$payload)
  if (-not $payload) { return '<none>' }
  $bytes = [System.Text.Encoding]::UTF8.GetBytes(("$payload" -replace '\s', ''))
  return [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  ).Replace('-', '').Substring(0, 16).ToLower()
}

function Get-ProfileIdentity {
  # Top-level PayloadIdentifier and the inner payload types, read from the .mobileconfig.
  param([Parameter()][AllowNull()][object]$payload)
  if (-not $payload) { return [pscustomobject]@{ PayloadIdentifier = $null; PayloadTypes = @() } }
  try {
    $xml = [xml][System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$payload"))
    $node = $xml.SelectSingleNode("/plist/dict/key[.='PayloadIdentifier']")
    $identifier = if ($null -ne $node -and $null -ne $node.NextSibling) { $node.NextSibling.InnerText } else { $null }
    $types = @($xml.SelectNodes("//key[.='PayloadType']") |
        ForEach-Object { $_.NextSibling.InnerText } |
        Where-Object { $_ -and $_ -ne 'Configuration' } |
        Sort-Object -Unique)
    return [pscustomobject]@{ PayloadIdentifier = $identifier; PayloadTypes = $types }
  }
  catch {
    return [pscustomobject]@{ PayloadIdentifier = $null; PayloadTypes = @() }
  }
}

function Get-AssignmentSummary {
  param([Parameter(Mandatory = $true)][string]$configurationId)
  $r = @(Get-GraphProperty -InputObject (Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$configurationId/assignments") -name 'value')
  if ($r.Count -eq 0) { return 'none' }
  return (@($r | ForEach-Object {
        $t = Get-GraphProperty -InputObject $_ -name 'target'
        switch -Wildcard ("$(Get-GraphProperty -InputObject $t -name '@odata.type')") {
          '*allDevicesAssignmentTarget' { 'All devices' }
          '*allLicensedUsersAssignmentTarget' { 'All licensed users' }
          default { "group $(Get-GraphProperty -InputObject $t -name 'groupId')" }
        }
      }) -join ', ')
}

function Remove-AllAssignment {
  # The assign action replaces the whole list, so an empty collection unassigns. Any
  # straggler is then deleted individually -- "no assignments" is the point of this step
  # and must be verified, not assumed.
  param([Parameter(Mandatory = $true)][string]$configurationId)

  Invoke-Graph -method POST -uri "$graphBase/deviceManagement/deviceConfigurations/$configurationId/assign" -body @{ assignments = @() } | Out-Null

  $remaining = @(Get-GraphProperty -InputObject (Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$configurationId/assignments") -name 'value')
  foreach ($a in $remaining) {
    $aid = Get-GraphProperty -InputObject $a -name 'id'
    if (-not $aid) { continue }
    Write-Verbose "assign-empty left assignment $aid; deleting individually."
    Invoke-Graph -method DELETE -uri "$graphBase/deviceManagement/deviceConfigurations/$configurationId/assignments/$aid" | Out-Null
  }
}

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

$requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
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

#region Inspect

$keep = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$keepId"
$retire = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$retireId"

$keepName = Get-GraphProperty -InputObject $keep -name 'displayName'
$retireName = Get-GraphProperty -InputObject $retire -name 'displayName'
$keepIdentity = Get-ProfileIdentity -payload (Get-GraphProperty -InputObject $keep -name 'payload')
$retireIdentity = Get-ProfileIdentity -payload (Get-GraphProperty -InputObject $retire -name 'payload')
$keepFingerprintBefore = Get-PayloadFingerprint -payload (Get-GraphProperty -InputObject $keep -name 'payload')
$retireFingerprintBefore = Get-PayloadFingerprint -payload (Get-GraphProperty -InputObject $retire -name 'payload')

Write-Output '--- Before ---'
Write-Output ("  KEEP    : '{0}'" -f $keepName)
Write-Output ("            assignments : {0}" -f (Get-AssignmentSummary -configurationId $keepId))
Write-Output ("            identifier  : {0}" -f $keepIdentity.PayloadIdentifier)
Write-Output ("            payloads    : {0}" -f (@($keepIdentity.PayloadTypes) -join ', '))
Write-Output ("            payload sha : {0}" -f $keepFingerprintBefore)
Write-Output ("  RETIRE  : '{0}'" -f $retireName)
Write-Output ("            assignments : {0}" -f (Get-AssignmentSummary -configurationId $retireId))
Write-Output ("            identifier  : {0}" -f $retireIdentity.PayloadIdentifier)
Write-Output ("            payloads    : {0}" -f (@($retireIdentity.PayloadTypes) -join ', '))
Write-Output ("            payload sha : {0}" -f $retireFingerprintBefore)
Write-Output ''

if ($keepId -eq $retireId) { throw 'keepId and retireId are the same profile.' }

# The shared identifier IS the collision. Requiring it means a mistyped id cannot quietly
# retire an unrelated profile.
if ($keepIdentity.PayloadIdentifier -ne $retireIdentity.PayloadIdentifier) {
  if (-not $allowDifferentIdentifiers) {
    throw ("These profiles do not share a PayloadIdentifier ('{0}' vs '{1}'), so this is not an identifier collision. Re-check the ids, or pass -allowDifferentIdentifiers if retiring a duplicate deliberately." -f $keepIdentity.PayloadIdentifier, $retireIdentity.PayloadIdentifier)
  }
  Write-Warning 'Profiles do not share a PayloadIdentifier; proceeding because -allowDifferentIdentifiers was given.'
}
else {
  Write-Output ("Confirmed collision on PayloadIdentifier '{0}'." -f $keepIdentity.PayloadIdentifier)
  Write-Output ''
}

if (-not $retireNewName) {
  # Only add the prefix once -- re-running must not produce '[disabled] [disabled] ...'.
  $disabledPrefix = '[disabled] '
  $retireNewName = if ($retireName.StartsWith($disabledPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    $retireName
  }
  else {
    "$disabledPrefix$retireName"
  }
}

#endregion

#region Apply

Write-Output '--- Changes ---'

if ($keepNewName -and $keepName -ne $keepNewName) {
  if ($PSCmdlet.ShouldProcess($keepName, "Rename to '$keepNewName'")) {
    Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$keepId" -body @{
      '@odata.type' = '#microsoft.graph.macOSCustomConfiguration'
      displayName   = $keepNewName
    } | Out-Null
    Write-Output "  [1/3] Renamed kept profile -> '$keepNewName'"
  }
}
else {
  Write-Output '  [1/3] Kept profile left as-is'
}

if ($retireName -eq $retireNewName) {
  Write-Output "  [2/3] Retired profile already named '$retireNewName'"
}
elseif ($PSCmdlet.ShouldProcess($retireName, "Rename to '$retireNewName'")) {
  Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$retireId" -body @{
    '@odata.type' = '#microsoft.graph.macOSCustomConfiguration'
    displayName   = $retireNewName
  } | Out-Null
  Write-Output "  [2/3] Renamed '$retireName' -> '$retireNewName'"
}

if ($PSCmdlet.ShouldProcess($retireNewName, 'Remove all assignments')) {
  Remove-AllAssignment -configurationId $retireId
  Write-Output '  [3/3] Removed all assignments from the retired profile'
}

#endregion

#region Verify

Write-Output ''
Write-Output '--- After (read back from Graph) ---'

$keepAfter = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$keepId"
$retireAfter = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$retireId"
$keepFingerprintAfter = Get-PayloadFingerprint -payload (Get-GraphProperty -InputObject $keepAfter -name 'payload')
$retireFingerprintAfter = Get-PayloadFingerprint -payload (Get-GraphProperty -InputObject $retireAfter -name 'payload')

$keepAssignments = Get-AssignmentSummary -configurationId $keepId
$retireAssignments = Get-AssignmentSummary -configurationId $retireId

Write-Output ("  KEEP    : '{0}'  ->  {1}" -f (Get-GraphProperty -InputObject $keepAfter -name 'displayName'), $keepAssignments)
Write-Output ("  RETIRE  : '{0}'  ->  {1}" -f (Get-GraphProperty -InputObject $retireAfter -name 'displayName'), $retireAssignments)
Write-Output ''

$ok = $true
if ($keepFingerprintAfter -ne $keepFingerprintBefore) {
  Write-Error "PAYLOAD CHANGED on the KEPT profile ($keepFingerprintBefore -> $keepFingerprintAfter)."
  $ok = $false
}
if ($retireFingerprintAfter -ne $retireFingerprintBefore) {
  Write-Warning "Payload changed on the retired profile ($retireFingerprintBefore -> $retireFingerprintAfter)."
  $ok = $false
}
if ($WhatIfPreference) {
  # Nothing was written, so do not report the end state as if it had been reached.
  Write-Output '  WhatIf: no changes made. The state above is unchanged from Before.'
}
else {
  if ($retireAssignments -ne 'none') {
    Write-Error "Retired profile still has assignments: $retireAssignments"
    $ok = $false
  }
  if ($ok) { Write-Output '  Payloads unchanged; retired profile reaches no devices.' }
}

Write-Output ''
Write-Output 'Next:'
Write-Output '  - Re-run Export-DeviceConfigurations.ps1 and Analyze-PolicyOverlap.ps1 to confirm the collision is gone'
Write-Output '  - Delete the [disabled] profile once satisfied (unassigning is reversible, deleting is not)'

#endregion
