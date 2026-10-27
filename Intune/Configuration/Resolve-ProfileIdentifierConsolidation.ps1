<#
.SYNOPSIS
Consolidates a set of macOS custom profiles that share one top-level PayloadIdentifier, in two
deliberately separate phases.

.DESCRIPTION
macOS keeps one installed profile per PayloadIdentifier. When several assigned profiles share
an identifier, one wins on each Mac and the rest are silently replaced -- and nothing in the
Intune console says which won where.

While the colliding profiles are IDENTICAL this is latent rather than harmful: whichever wins
delivers the same settings. It stops being latent the moment one of them is edited, because
the change then applies only to the Macs where that copy happened to win, with every dashboard
still green.

That is why this runs in two phases, and why it refuses to do both in one invocation:

  -Converge   Apply the setting change to EVERY profile sharing the identifier, so all copies
              are equivalent. The collision still exists and nothing is unassigned. After this,
              it genuinely does not matter which copy a Mac installed.

  -Retire     Unassign the non-survivors and mark them with a [disabled] prefix. Safe only
              once Converge has been verified on real devices, because unassigning the copy
              that WON on a Mac pulls the profile, and there is a window before the survivor
              installs. During that window the Mac loses Defender's Full Disk Access, the DLP
              grant and system extension approval. A gap in a security profile is worse than a
              duplicate, so Converge first makes the removal a no-op rather than a transition.

Retire refuses to touch any profile whose payload is not equivalent to the survivor's, so a
copy carrying unique settings can never be silently dropped.

Nothing is deleted. Retired profiles are left in place, unassigned and renamed, so the change
is reversible from the console.

.PARAMETER Identifier
Top-level PayloadIdentifier shared by the colliding profiles.

.PARAMETER SurvivorId
Id of the profile to keep. Its assignments are left exactly as they are.

.PARAMETER Converge
Phase 1. Set AllowUserOverrides to false on every profile sharing the identifier.

.PARAMETER Retire
Phase 2. Unassign and rename every profile except the survivor.

.PARAMETER DisabledPrefix
Prefix applied to retired profiles. Match whatever convention your tenant already uses.

.EXAMPLE
.\Resolve-ProfileIdentifierConsolidation.ps1 -Identifier <uuid> -SurvivorId <id> -Converge -WhatIf

.EXAMPLE
.\Resolve-ProfileIdentifierConsolidation.ps1 -Identifier <uuid> -SurvivorId <id> -Retire
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$Identifier,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$SurvivorId,

  [Parameter()]
  [switch]$Converge,

  [Parameter()]
  [switch]$Retire,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$DisabledPrefix = '[disabled] ',

  [Parameter()]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'

if (-not $Converge -and -not $Retire) { throw 'Specify -Converge or -Retire.' }
if ($Converge -and $Retire) {
  throw 'Run -Converge and -Retire separately. Converge must be verified on real devices before anything is unassigned; doing both in one run defeats the safety the split exists for.'
}

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

function Invoke-Graph {
  param([Parameter(Mandatory)][string]$method, [Parameter(Mandatory)][string]$uri, [Parameter()][object]$body)
  $params = @{ Method = $method; Uri = $uri; OutputType = 'PSObject' }
  if ($null -ne $body) {
    $params.Body = ($body | ConvertTo-Json -Depth 32 -Compress)
    $params.ContentType = 'application/json'
  }
  return Invoke-MgGraphRequest @params
}

function ConvertFrom-Payload {
  param([Parameter()][AllowNull()][object]$payload)
  if (-not $payload) { return '' }
  try { return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$payload")) } catch { return '' }
}

function Get-TopLevelIdentifier {
  <#
    The top-level PayloadIdentifier, i.e. the one directly under /plist/dict. Nested payloads
    carry their own, so a plain text search finds a sub-payload and silently identifies the
    wrong profile.

    Navigates by XPath rather than PowerShell's XML property adapter. Under
    Set-StrictMode -Version Latest, "$x.plist.dict" throws "The property 'dict' cannot be found
    on this object" for these plists, and the whole lookup then returns nothing -- which shows
    up as "no profile has this identifier" rather than as an error. SelectSingleNode is
    unaffected, and is the pattern Restore-ProfilePayload.ps1 already uses.
  #>
  param([Parameter(Mandatory)][string]$text)
  try {
    [xml]$x = $text
    $key = $x.SelectSingleNode("/plist/dict/key[.='PayloadIdentifier']")
    if ($null -eq $key) { return $null }

    # Skip whitespace and comments between the key and its value.
    $node = $key.NextSibling
    while ($null -ne $node -and $node.NodeType -ne [System.Xml.XmlNodeType]::Element) {
      $node = $node.NextSibling
    }
    if ($null -eq $node) { return $null }
    return $node.InnerText
  }
  catch { return $null }
}

function Get-NormalizedPayload {
  # Whitespace between tags is meaningless in a plist, and the exported copies differ only by
  # trailing newlines. AllowUserOverrides is normalised out too, because Converge is what makes
  # that field agree -- comparing it would make every pre-Converge profile look different.
  param([Parameter(Mandatory)][string]$text)
  $t = $text -replace '(?s)<!--.*?-->', ''
  $t = $t -replace '<key>AllowUserOverrides</key>\s*<(true|false)\s*/>', '<key>AllowUserOverrides</key><X/>'
  $t = $t -replace '>\s+<', '><'
  return $t.Trim()
}

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

$isDryRun = [bool]$WhatIfPreference
$accessLevel = if ($isDryRun) { 'Read' } else { 'ReadWrite' }
$requiredScopes = @("DeviceManagementConfiguration.$accessLevel.All")

if ($isDryRun) {
  Write-Output '  ==============================================================='
  Write-Output '   DRY RUN (-WhatIf). Nothing will be changed.'
  Write-Output '   Read-only Graph scopes are requested; no write consent needed.'
  Write-Output '  ==============================================================='
  Write-Output ''
}

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

Write-Output "Connected as $($ctx.Account) on tenant $($ctx.TenantId)"
Write-Output ''

#endregion

#region Discover

Write-Output "Finding profiles whose top-level PayloadIdentifier is $Identifier"

$all = @(Get-GraphProperty -InputObject (Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations") -name 'value')
$candidates = @($all | Where-Object { "$(Get-GraphProperty -InputObject $_ -name '@odata.type')" -eq '#microsoft.graph.macOSCustomConfiguration' })

$members = @()
foreach ($c in $candidates) {
  $id = "$(Get-GraphProperty -InputObject $c -name 'id')"
  $payload = Get-GraphProperty -InputObject $c -name 'payload'
  # The collection response does not always include the payload; fetch the profile when it is
  # absent rather than skipping it, or a colliding profile could go unnoticed.
  if (-not $payload) {
    $full = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$id"
    $payload = Get-GraphProperty -InputObject $full -name 'payload'
  }
  $text = ConvertFrom-Payload -payload $payload
  if (-not $text) { continue }
  if ((Get-TopLevelIdentifier -text $text) -ne $Identifier) { continue }

  $members += [pscustomobject]@{
    Id          = $id
    DisplayName = "$(Get-GraphProperty -InputObject $c -name 'displayName')"
    OdataType   = "$(Get-GraphProperty -InputObject $c -name '@odata.type')"
    Text        = $text
    IsSurvivor  = ($id -eq $SurvivorId)
  }
}

if (-not $members.Count) { throw "No macOS custom profile has top-level PayloadIdentifier $Identifier." }
if (-not @($members | Where-Object { $_.IsSurvivor }).Count) {
  throw "SurvivorId $SurvivorId is not among the profiles sharing this identifier. Refusing to proceed."
}

Write-Output ''
foreach ($m in $members) {
  $auo = if ($m.Text -match '<key>AllowUserOverrides</key>\s*<(true|false)\s*/>') { $Matches[1] } else { 'absent' }
  Write-Output ("  {0,-9} {1,-56} AllowUserOverrides={2}" -f $(if ($m.IsSurvivor) { 'SURVIVOR' } else { 'retire' }), $m.DisplayName, $auo)
}
Write-Output ''

#endregion

#region Converge

$results = [ordered]@{}

if ($Converge) {
  Write-Output '--- Phase 1: converge (AllowUserOverrides = false on every copy) ---'

  foreach ($m in $members) {
    $results[$m.DisplayName] = 'skipped'
    try {
      $hits = [regex]::Matches($m.Text, '<key>AllowUserOverrides</key>\s*<true\s*/>')
      $already = [regex]::Matches($m.Text, '<key>AllowUserOverrides</key>\s*<false\s*/>')

      if ($hits.Count -eq 0 -and $already.Count -ge 1) {
        Write-Output "  $($m.DisplayName): already false"
        $results[$m.DisplayName] = 'no-op'
        continue
      }
      if ($hits.Count -ne 1) { throw "expected exactly one AllowUserOverrides=true, found $($hits.Count)" }

      $updated = $m.Text.Replace($hits[0].Value, ($hits[0].Value -replace '<true\s*/>', '<false/>'))

      # '<false/>' is one character longer than '<true/>'. Any other delta means the
      # replacement matched something it should not have.
      $delta = $updated.Length - $m.Text.Length
      if ($delta -ne 1) { throw "payload length changed by $delta characters, expected exactly 1" }
      try { [xml]$null = $updated } catch { throw "modified payload is not valid XML: $($_.Exception.Message)" }

      Write-Output "  $($m.DisplayName): true -> false"

      if ($PSCmdlet.ShouldProcess($m.DisplayName, 'Set AllowUserOverrides to false')) {
        Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$($m.Id)" `
          -body @{ '@odata.type' = $m.OdataType; payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($updated)) } | Out-Null

        $verify = ConvertFrom-Payload -payload (Get-GraphProperty -InputObject (
          Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$($m.Id)") -name 'payload')

        if ([regex]::Matches($verify, '<key>AllowUserOverrides</key>\s*<true\s*/>').Count -eq 0) {
          $results[$m.DisplayName] = 'converged'
        }
        else {
          Write-Warning "  $($m.DisplayName): PATCH reported success but AllowUserOverrides is still true."
          $results[$m.DisplayName] = 'failed'
        }
      }
      else { $results[$m.DisplayName] = 'dry run' }
    }
    catch {
      Write-Warning "  $($m.DisplayName): $($_.Exception.Message)"
      $results[$m.DisplayName] = 'failed'
    }
  }
  Write-Output ''
}

#endregion

#region Retire

if ($Retire) {
  Write-Output '--- Phase 2: retire the non-survivors ---'

  $survivor = @($members | Where-Object { $_.IsSurvivor })[0]
  $survivorNorm = Get-NormalizedPayload -text $survivor.Text

  # Converge must have happened first. If any copy still allows user overrides, retiring the
  # others could leave that copy installed on some Macs -- the exact non-determinism this is
  # meant to remove.
  $stillTrue = @($members | Where-Object { $_.Text -match '<key>AllowUserOverrides</key>\s*<true\s*/>' })
  if ($stillTrue.Count) {
    Write-Warning 'These profiles still have AllowUserOverrides=true:'
    foreach ($s in $stillTrue) { Write-Warning "    $($s.DisplayName)" }
    throw 'Run -Converge first and verify it on real devices. Refusing to retire while the copies disagree.'
  }

  foreach ($m in @($members | Where-Object { -not $_.IsSurvivor })) {
    $results[$m.DisplayName] = 'skipped'
    try {
      # Never drop a profile that carries settings the survivor does not. If the payloads
      # differ, this is a merge, not a consolidation, and it needs a human.
      if ((Get-NormalizedPayload -text $m.Text) -cne $survivorNorm) {
        throw 'payload is NOT equivalent to the survivor. Refusing to retire it; review the difference by hand.'
      }

      $assignments = @(Get-GraphProperty -InputObject (
        Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$($m.Id)/assignments") -name 'value')

      $newName = if ($m.DisplayName.StartsWith($DisabledPrefix, [System.StringComparison]::Ordinal)) {
        $m.DisplayName
      } else { "$DisabledPrefix$($m.DisplayName)" }

      Write-Output "  $($m.DisplayName): $($assignments.Count) assignment(s) -> 0, rename to '$newName'"

      if ($PSCmdlet.ShouldProcess($m.DisplayName, 'Unassign and mark disabled')) {
        # Empty assignment list replaces whatever was there.
        Invoke-Graph -method POST -uri "$graphBase/deviceManagement/deviceConfigurations/$($m.Id)/assign" `
          -body @{ assignments = @() } | Out-Null

        if ($newName -cne $m.DisplayName) {
          Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$($m.Id)" `
            -body @{ '@odata.type' = $m.OdataType; displayName = $newName } | Out-Null
        }

        $after = @(Get-GraphProperty -InputObject (
          Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$($m.Id)/assignments") -name 'value')

        if ($after.Count -eq 0) { $results[$m.DisplayName] = 'retired' }
        else {
          Write-Warning "  $($m.DisplayName): still has $($after.Count) assignment(s) after unassigning."
          $results[$m.DisplayName] = 'failed'
        }
      }
      else { $results[$m.DisplayName] = 'dry run' }
    }
    catch {
      Write-Warning "  $($m.DisplayName): $($_.Exception.Message)"
      $results[$m.DisplayName] = 'failed'
    }
  }
  Write-Output ''
}

#endregion

#region Summary

Write-Output '--- Result ---'
foreach ($k in $results.Keys) { Write-Output ("  {0,-56} {1}" -f $k, $results[$k]) }

if ($isDryRun) {
  Write-Output ''
  Write-Output '  NOTHING WAS CHANGED. Re-run without -WhatIf to apply.'
}
elseif ($Converge -and @($results.Values | Where-Object { $_ -eq 'converged' }).Count) {
  Write-Output ''
  Write-Output '  Next: let the Macs check in, then confirm on real devices before -Retire:'
  Write-Output "    profiles list -verbose | grep -A5 $Identifier"
  Write-Output '    mdatp health --field full_disk_access_enabled'
  Write-Output '    systemextensionsctl list'
  Write-Output '  The Detect-DefenderPermissions shell script reports this fleet-wide.'
}

if (@($results.Values | Where-Object { $_ -eq 'failed' }).Count) { exit 1 }

#endregion
