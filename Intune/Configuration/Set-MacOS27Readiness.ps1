<#
.SYNOPSIS
Applies the two tenant changes needed for macOS 27 readiness: the declarative software update
delay, and the system/kernel extension user-override setting.

.DESCRIPTION
Two independent changes, each skippable, each verified against live state before and after:

  1. UPDATE DELAY -- macOS 27 removed legacy software update management outright. The legacy
     deferrals (major 14 / minor 1 / system 1) stop functioning, leaving only the declarative
     'Delay In Days'.

     The target is 3 days, which is what the tenant already has, so this is normally a verified
     no-op. It is kept in the script because it asserts the value rather than assuming it, and
     because it is the mechanism if the number ever changes.

     3 days is a deliberate choice to keep SECURITY updates fast. It is not a way to slow major
     OS upgrades: Intune's settings catalog exposes a single Delay In Days that applies to
     whatever 'the latest version' happens to be, major or minor, so this one knob cannot
     express 'fast for security, slow for 26 -> 27'. Controlling the major-version jump needs a
     different mechanism and is NOT solved here.

     The legacy block is NOT removed. It still functions on macOS 26 and below, which is now
     the permanent Intel population, so it is left exactly as it is.

  2. KEXT/SYSEXT USER OVERRIDE -- two assigned profiles disagree on AllowUserOverrides. The
     Purview one allows a standard user to approve arbitrary extensions; the other forbids it.
     On a company-owned device holding company content, that is not a user decision, so this
     sets it to false.

Both changes read live state from Graph rather than from an export: an export is a snapshot,
and acting on a snapshot is how a tool ends up confidently doing the wrong thing.

.PARAMETER SkipUpdateDelay
Leave the declarative update delay alone.

.PARAMETER SkipKextOverride
Leave AllowUserOverrides alone.

.PARAMETER DelayInDays
Target value for the declarative update delay. Defaults to 3, which keeps security updates
fast. See the note above: this does not control major-version upgrades.

.PARAMETER UpdatePolicyId
Settings catalog policy holding the software update configuration.

.PARAMETER KextProfileId
Custom configuration profile holding the extension policy.

.PARAMETER TenantId
Tenant to connect to. Optional.

.EXAMPLE
.\Set-MacOS27Readiness.ps1 -UpdatePolicyId <id> -KextProfileId <id> -WhatIf
Shows both changes and writes nothing. Requests read-only Graph scopes.

.EXAMPLE
.\Set-MacOS27Readiness.ps1 -UpdatePolicyId <id> -KextProfileId <id> -SkipUpdateDelay
Applies only the security change, leaving update cadence for a separate decision.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [switch]$SkipUpdateDelay,

  [Parameter()]
  [switch]$SkipKextOverride,

  [Parameter()]
  [ValidateRange(0, 90)]
  [int]$DelayInDays = 3,

  # No defaults. These are tenant-specific object ids and this repo is public. Find them in the
  # Intune portal URL when the policy is open, or in an export produced by
  # Export-DeviceConfigurations.ps1.
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$UpdatePolicyId,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$KextProfileId,

  [Parameter()]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'

#region Helpers

function Get-GraphProperty {
  # StrictMode-safe read: a missing property is $null, not a terminating error.
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
  param(
    [Parameter(Mandatory)][string]$method,
    [Parameter(Mandatory)][string]$uri,
    [Parameter()][object]$body
  )
  $params = @{ Method = $method; Uri = $uri; OutputType = 'PSObject' }
  if ($null -ne $body) {
    $params.Body = ($body | ConvertTo-Json -Depth 64 -Compress)
    $params.ContentType = 'application/json'
  }
  return Invoke-MgGraphRequest @params
}

function Get-SettingLeaf {
  <#
    Flatten a settings tree to "definitionId = value" strings.

    This is the safety net for the update change. There is no way to PATCH a single nested
    leaf in a settings catalog policy -- the whole settings collection goes back -- so a bug in
    the mutation walk would silently drop the legacy softwareupdate block that macOS 26 Intel
    Macs still honour. Comparing the flattened leaves before and after makes that impossible to
    miss: anything other than delayindays changing aborts the run.
  #>
  param([Parameter()][AllowNull()][object]$node, [string]$currentId = '')

  $out = New-Object System.Collections.Generic.List[string]
  if ($null -eq $node) { return $out }

  if ($node -is [System.Object[]]) {
    foreach ($n in $node) { foreach ($leaf in (Get-SettingLeaf -node $n -currentId $currentId)) { [void]$out.Add($leaf) } }
    return $out
  }

  if ($node -is [System.Collections.IDictionary] -or $node -is [psobject]) {
    $id = "$(Get-GraphProperty -InputObject $node -name 'settingDefinitionId')"
    if ($id) { $currentId = $id }

    $simple = Get-GraphProperty -InputObject $node -name 'simpleSettingValue'
    if ($null -ne $simple) { [void]$out.Add("$currentId = $(Get-GraphProperty -InputObject $simple -name 'value')") }

    $choice = Get-GraphProperty -InputObject $node -name 'choiceSettingValue'
    if ($null -ne $choice) { [void]$out.Add("$currentId = $(Get-GraphProperty -InputObject $choice -name 'value')") }

    $coll = Get-GraphProperty -InputObject $node -name 'simpleSettingCollectionValue'
    if ($null -ne $coll) {
      [void]$out.Add("$currentId = [$((@($coll) | ForEach-Object { Get-GraphProperty -InputObject $_ -name 'value' }) -join '|')]")
    }

    foreach ($child in @('settingInstance', 'children', 'groupSettingCollectionValue', 'choiceSettingValue')) {
      $value = Get-GraphProperty -InputObject $node -name $child
      if ($null -ne $value) { foreach ($leaf in (Get-SettingLeaf -node $value -currentId $currentId)) { [void]$out.Add($leaf) } }
    }
  }

  return $out
}

function Set-DelayInDays {
  # Mutate only the delayindays leaf, in place. Returns how many it changed.
  param([Parameter()][AllowNull()][object]$node, [Parameter(Mandatory)][int]$value)

  $changed = 0
  if ($null -eq $node) { return 0 }

  if ($node -is [System.Object[]]) {
    foreach ($n in $node) { $changed += Set-DelayInDays -node $n -value $value }
    return $changed
  }

  if ($node -is [psobject]) {
    $id = "$(Get-GraphProperty -InputObject $node -name 'settingDefinitionId')"
    if ($id -eq 'ddm-latestsoftwareupdate_delayindays') {
      $simple = Get-GraphProperty -InputObject $node -name 'simpleSettingValue'
      if ($null -ne $simple) {
        $simple.value = $value
        $changed++
      }
    }
    foreach ($child in @('settingInstance', 'children', 'groupSettingCollectionValue', 'choiceSettingValue')) {
      $sub = Get-GraphProperty -InputObject $node -name $child
      if ($null -ne $sub) { $changed += Set-DelayInDays -node $sub -value $value }
    }
  }

  return $changed
}

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

# Read-only under -WhatIf. A dry run that asks for write consent is not a dry run, and consent
# granted for a preview is consent the operator did not knowingly give.
# Read $WhatIfPreference rather than probing with ShouldProcess: a probe call emits its own
# "What if: Performing the operation 'probe'" line, which reads like a real pending change.
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

#region Change 1 -- declarative update delay

$updateResult = 'skipped'

if (-not $SkipUpdateDelay) {
  Write-Output '--- Change 1: declarative software update delay ---'

  # Fault-isolated from change 2. These are unrelated changes, and the security one must not be
  # blocked by a failure in the update-cadence one -- a 403 or a schema change here is no reason
  # to leave users able to approve their own extensions.
  try {

  $policy = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/configurationPolicies/$UpdatePolicyId"
  $policyName = "$(Get-GraphProperty -InputObject $policy -name 'name')"
  Write-Output "  policy : $policyName"

  $settings = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/configurationPolicies/$UpdatePolicyId/settings"
  $settingsValue = Get-GraphProperty -InputObject $settings -name 'value'
  if ($null -eq $settingsValue) { throw "Could not read settings for policy $UpdatePolicyId." }

  $before = @(Get-SettingLeaf -node $settingsValue)
  $delayLeaves = @($before | Where-Object { $_ -like 'ddm-latestsoftwareupdate_delayindays = *' })

  if ($delayLeaves.Count -ne 1) {
    throw "Expected exactly one delayindays setting, found $($delayLeaves.Count). Refusing to guess."
  }

  $currentDelay = ($delayLeaves[0] -split ' = ')[-1]
  Write-Output "  Delay In Days : $currentDelay -> $DelayInDays"

  if ("$currentDelay" -eq "$DelayInDays") {
    Write-Output '  already at the target value; nothing to do.'
    $updateResult = 'no-op'
  }
  else {
    # Clone by JSON round-trip rather than by rebuilding the tree. A hand-written recursive
    # copy silently collapses a single-element array into a bare object -- [{...}] becomes
    # {...} -- because 'return @(...)' unrolls it, and every leaf VALUE survives that, so a
    # value-level diff never sees it. A round-trip through the same serialiser Graph uses is
    # byte-identical by construction and cannot reshape anything.
    $payload = $settingsValue | ConvertTo-Json -Depth 64 | ConvertFrom-Json
    $changed = Set-DelayInDays -node $payload -value $DelayInDays
    if ($changed -ne 1) { throw "Mutation touched $changed delayindays settings, expected exactly 1. Aborting." }

    # Structural guard: the ONLY leaf allowed to differ is delayindays. The legacy
    # softwareupdate block in this same policy still governs macOS 26 Intel Macs, and a
    # mutation walk that reshaped it would take those deferrals away silently.
    $after = @(Get-SettingLeaf -node $payload)
    $diff = @(Compare-Object -ReferenceObject $before -DifferenceObject $after |
      Where-Object { $_.InputObject -notlike 'ddm-latestsoftwareupdate_delayindays = *' })

    if ($diff.Count) {
      Write-Warning 'Settings other than delayindays would change. Nothing has been written.'
      foreach ($d in $diff) { Write-Warning "    $($d.SideIndicator) $($d.InputObject)" }
      throw 'Aborting: refusing to rewrite settings this change does not own.'
    }

    # Shape guard. The leaf comparison above proves no VALUE moved, but it is blind to the tree
    # being RESHAPED -- an array collapsing to an object preserves every leaf.
    #
    # Rather than diff two serialisations and try to mask out the one value that is meant to
    # differ (which needs a regex that could mask a genuine change elsewhere), set the delay
    # back on a copy and require byte equality with what Graph returned. Exact, and it catches
    # any reshaping or stray edit anywhere in the tree.
    $proof = $payload | ConvertTo-Json -Depth 64 | ConvertFrom-Json
    [void](Set-DelayInDays -node $proof -value ([int]$currentDelay))

    $shapeBefore = ($settingsValue | ConvertTo-Json -Depth 64 -Compress)
    $shapeAfter = ($proof | ConvertTo-Json -Depth 64 -Compress)

    if ($shapeAfter -cne $shapeBefore) {
      Write-Warning 'The settings tree would change in ways beyond the delay value.'
      Write-Warning "  Graph returned : $($shapeBefore.Length) chars"
      Write-Warning "  would send     : $($shapeAfter.Length) chars (delay reverted for comparison)"
      throw 'Aborting: the rebuilt settings tree does not match what Graph returned.'
    }

    Write-Output "  $($before.Count) settings read; 1 changed, $($before.Count - 1) preserved."

    if ($PSCmdlet.ShouldProcess($policyName, "Set declarative update Delay In Days to $DelayInDays")) {
      Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/configurationPolicies/$UpdatePolicyId" `
        -body @{ settings = $payload } | Out-Null

      # Verify against live state. Both assertions matter: the first proves the change landed,
      # the second proves nothing else was lost on the way.
      $verify = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/configurationPolicies/$UpdatePolicyId/settings"
      $verifyLeaves = @(Get-SettingLeaf -node (Get-GraphProperty -InputObject $verify -name 'value'))

      $nowDelay = @($verifyLeaves | Where-Object { $_ -like 'ddm-latestsoftwareupdate_delayindays = *' })
      $nowMajor = @($verifyLeaves | Where-Object { $_ -like '*softwareupdate_deferrals_majorperiodindays = *' })
      $wasMajor = @($before | Where-Object { $_ -like '*softwareupdate_deferrals_majorperiodindays = *' })

      if ($nowDelay.Count -ne 1 -or ($nowDelay[0] -split ' = ')[-1] -ne "$DelayInDays") {
        Write-Warning "  PATCH reported success but Delay In Days did not persist (now: $($nowDelay -join ', '))."
        $updateResult = 'failed'
      }
      elseif ($wasMajor.Count -and -not $nowMajor.Count) {
        Write-Warning '  Delay In Days changed but the legacy deferral block is GONE. Investigate immediately.'
        $updateResult = 'failed'
      }
      else {
        Write-Output "  applied and verified ($($verifyLeaves.Count) settings still present)."
        $updateResult = 'applied'
      }
    }
    else {
      $updateResult = 'dry run'
    }
  }

  }
  catch {
    Write-Warning "Update delay change failed: $($_.Exception.Message)"
    $updateResult = 'failed'
  }
  Write-Output ''
}

#endregion

#region Change 2 -- AllowUserOverrides

$kextResult = 'skipped'

if (-not $SkipKextOverride) {
  Write-Output '--- Change 2: AllowUserOverrides ---'

  try {

  $liveProfile = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$KextProfileId"
  $profileName = "$(Get-GraphProperty -InputObject $liveProfile -name 'displayName')"
  $encoded = "$(Get-GraphProperty -InputObject $liveProfile -name 'payload')"
  if (-not $encoded) { throw "Profile $KextProfileId has no payload." }

  Write-Output "  profile : $profileName"

  $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))

  $needle = '<key>AllowUserOverrides</key><true/>'
  $hits = ([regex]::Matches($decoded, [regex]::Escape($needle))).Count

  if ($hits -eq 0) {
    # Whitespace between the key and its value varies by how the plist was authored, so fall
    # back to a whitespace-tolerant match rather than reporting "already correct" when the
    # setting is actually still true in a differently formatted file.
    $loose = [regex]::Matches($decoded, '<key>AllowUserOverrides</key>\s*<true\s*/>')
    $hits = $loose.Count
    if ($hits -eq 1) { $needle = $loose[0].Value }
  }

  $alreadyFalse = ([regex]::Matches($decoded, '<key>AllowUserOverrides</key>\s*<false\s*/>')).Count

  if ($hits -eq 0 -and $alreadyFalse -ge 1) {
    Write-Output '  already false; nothing to do.'
    $kextResult = 'no-op'
  }
  elseif ($hits -ne 1) {
    throw "Expected exactly one AllowUserOverrides=true in the live payload, found $hits. Refusing to guess."
  }
  else {
    $replacement = $needle -replace '<true\s*/>', '<false/>'
    $updated = $decoded.Replace($needle, $replacement)

    # Byte-level guard: '<false/>' is exactly one character longer than '<true/>', so a correct
    # single replacement grows the payload by exactly 1. Any other delta means the replacement
    # matched something it should not have.
    $delta = $updated.Length - $decoded.Length
    if ($delta -ne 1) { throw "Payload length changed by $delta characters, expected exactly 1. Aborting." }

    try { [xml]$null = $updated } catch { throw "Modified payload is not valid XML: $($_.Exception.Message)" }

    Write-Output '  AllowUserOverrides : true -> false'
    Write-Output "  payload : $($decoded.Length) -> $($updated.Length) chars, XML valid"

    if ($PSCmdlet.ShouldProcess($profileName, 'Set AllowUserOverrides to false')) {
      $reencoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($updated))
      Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$KextProfileId" `
        -body @{ '@odata.type' = "$(Get-GraphProperty -InputObject $liveProfile -name '@odata.type')"; payload = $reencoded } | Out-Null

      $verify = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$KextProfileId"
      $verifyDecoded = [System.Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String("$(Get-GraphProperty -InputObject $verify -name 'payload')"))

      if (([regex]::Matches($verifyDecoded, '<key>AllowUserOverrides</key>\s*<true\s*/>')).Count -eq 0) {
        Write-Output '  applied and verified.'
        $kextResult = 'applied'
      }
      else {
        Write-Warning '  PATCH reported success but AllowUserOverrides is still true.'
        $kextResult = 'failed'
      }
    }
    else {
      $kextResult = 'dry run'
    }
  }

  }
  catch {
    Write-Warning "AllowUserOverrides change failed: $($_.Exception.Message)"
    $kextResult = 'failed'
  }
  Write-Output ''
}

#endregion

#region Summary

Write-Output '--- Result ---'
Write-Output "  update delay        : $updateResult"
Write-Output "  AllowUserOverrides  : $kextResult"

if ($isDryRun) {
  Write-Output ''
  Write-Output '  NOTHING WAS CHANGED. Re-run without -WhatIf to apply.'
}
elseif ($updateResult -eq 'applied' -or $kextResult -eq 'applied') {
  Write-Output ''
  Write-Output '  Next: re-run Export-DeviceConfigurations.ps1 to refresh the export,'
  Write-Output '        then Analyze-PolicyOverlap.ps1 to confirm the AllowUserOverrides'
  Write-Output '        conflict no longer appears.'
}

if ($updateResult -eq 'failed' -or $kextResult -eq 'failed') { exit 1 }

#endregion
