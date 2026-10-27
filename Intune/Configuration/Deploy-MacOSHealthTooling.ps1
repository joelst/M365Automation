<#
.SYNOPSIS
Deploys the macOS health tooling: the Defender DLP enforcement block, and the detection shell
scripts, to Intune.

.DESCRIPTION
Two independent changes, each skippable, each verified against live state afterwards.

  1. DLP ENFORCEMENT -- updates the custom profile that carries the merged com.microsoft.wdav
     preferences with an 'accessibility/enforcement' block setting unallowedBrowserMode and
     pasteToBrowserMode to 'enforce'.

     Both keys already default to enforce, so this changes no behaviour today. It is worth
     doing because the primary DLP control should not rest on an undeclared default that a
     future client version could change, and because the value is then visible to anyone
     reading the profile.

     Requires Endpoint DLP client 101.26072 or later to be honoured at all. Get-DlpClientVersion.sh
     (deployed by change 2) reports which Macs are below that floor.

  2. SHELL SCRIPTS -- creates the macOS detection scripts as Intune shell scripts, matching the
     conventions the existing macOS scripts use: run as system, daily, one retry.

     Scripts are matched by display name. An existing script with the same name is UPDATED, not
     duplicated, so this is safe to re-run.

NOT handled here, deliberately: mdtap-combined.mobileconfig. Its top-level PayloadIdentifier
(23FE3F82-71F0-11EF-89EE-26DE397E1932) is easily shared by several profiles built from the same
source. On a Mac receiving more than one, macOS keeps a single profile per identifier and the
others are silently replaced. Pushing another copy would add to the collision rather than
resolve it, so that needs a consolidation decision first -- Test-MacOSTenantState.ps1 shows
whether you have the collision, and Resolve-ProfileIdentifierCollision.ps1 exists to fix it.

.PARAMETER TamperProtectionProfileId
Custom configuration profile holding the merged com.microsoft.wdav preferences.

.PARAMETER ScriptAssignmentGroupId
Entra group id to assign the scripts to. Omit to create them unassigned for review, which is
the default because assignment is what makes a script run on real machines.

.PARAMETER AssignToAllDevices
Assign the scripts to All Devices, matching the existing macOS scripts.

.PARAMETER SkipProfile
Leave the Defender profile alone.

.PARAMETER SkipScripts
Leave the shell scripts alone.

.EXAMPLE
.\Deploy-MacOSHealthTooling.ps1 -TamperProtectionProfileId <id> -WhatIf
Shows every change and writes nothing. Requests read-only Graph scopes.

.EXAMPLE
.\Deploy-MacOSHealthTooling.ps1 -TamperProtectionProfileId <id> -AssignToAllDevices
Applies both changes and assigns the scripts to All Devices.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$TamperProtectionProfileId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$ScriptAssignmentGroupId,

  [Parameter()]
  [switch]$AssignToAllDevices,

  [Parameter()]
  [switch]$SkipProfile,

  [Parameter()]
  [switch]$SkipScripts,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$MacScriptRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'macos'),

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$MergedProfilePath = (Join-Path $PSScriptRoot 'com.microsoft.wdav.merged.mobileconfig'),

  [Parameter()]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'

# Deployed as Intune macOS shell scripts. Names match the file names so the portal, the repo
# and the device output all agree on what a given result came from.
$script:ShellScripts = @(
  [ordered]@{ File = 'Detect-MacManagementHealth.sh'; DisplayName = 'macOS: Detect Management Health (PSSO, bootstrap token, FileVault, time)' }
  [ordered]@{ File = 'Detect-DefenderPermissions.sh'; DisplayName = 'macOS: Detect Defender and DLP Permissions' }
  [ordered]@{ File = 'Set-NetworkTime.sh';            DisplayName = 'macOS: Enforce Network Time' }
  [ordered]@{ File = 'Get-DlpClientVersion.sh';       DisplayName = 'macOS: Report Endpoint DLP Client Version' }
)

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
  param(
    [Parameter(Mandatory)][string]$method,
    [Parameter(Mandatory)][string]$uri,
    [Parameter()][object]$body
  )
  $params = @{ Method = $method; Uri = $uri; OutputType = 'PSObject' }
  if ($null -ne $body) {
    $params.Body = ($body | ConvertTo-Json -Depth 32 -Compress)
    $params.ContentType = 'application/json'
  }
  return Invoke-MgGraphRequest @params
}

function ConvertTo-Base64Utf8 {
  # LF only. A CR in a shebang makes macOS look for an interpreter named "/bin/bash\r", which
  # fails as "bad interpreter" -- and the file looks perfectly fine in every editor. The repo
  # pins these to LF via .gitattributes; this is the second line of defence, because the file
  # could have been touched on a machine that ignored it.
  param([Parameter(Mandatory)][string]$path)
  $text = [System.IO.File]::ReadAllText($path) -replace "`r`n", "`n" -replace "`r", "`n"
  return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text))
}

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

$isDryRun = [bool]$WhatIfPreference
$accessLevel = if ($isDryRun) { 'Read' } else { 'ReadWrite' }

$requiredScopes = @("DeviceManagementConfiguration.$accessLevel.All")
if (-not $SkipScripts) { $requiredScopes += "DeviceManagementScripts.$accessLevel.All" }

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

#region Change 1 -- DLP enforcement block

$profileResult = 'skipped'

if (-not $SkipProfile) {
  Write-Output '--- Change 1: Defender DLP enforcement block ---'
  try {

    if (-not $TamperProtectionProfileId) {
      throw 'TamperProtectionProfileId is required for this change. Pass -SkipProfile to skip it.'
    }
    if (-not (Test-Path -LiteralPath $MergedProfilePath)) {
      throw "Merged profile not found: $MergedProfilePath"
    }

    $localText = [System.IO.File]::ReadAllText($MergedProfilePath)

    # Refuse to upload something that is not the profile this change is about, or that macOS
    # would reject. An invalid plist deploys as a profile that silently never applies.
    try { [xml]$null = $localText } catch { throw "Local profile is not valid XML: $($_.Exception.Message)" }
    # The repo copy is a template. Uploading it unedited would replace the tenant's real values.
    if ($localText -match '<string>Your Organization</string>') {
      throw "Local profile still has the 'Your Organization' placeholder. Pass -MergedProfilePath to your own copy."
    }
    if ($localText -notmatch '<key>unallowedBrowserMode</key>\s*<string>enforce</string>') {
      throw 'Local profile does not contain unallowedBrowserMode=enforce. Refusing to upload.'
    }
    if ($localText -notmatch '<key>pasteToBrowserMode</key>\s*<string>enforce</string>') {
      throw 'Local profile does not contain pasteToBrowserMode=enforce. Refusing to upload.'
    }

    $live = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$TamperProtectionProfileId"
    $liveName = "$(Get-GraphProperty -InputObject $live -name 'displayName')"
    $liveOdata = "$(Get-GraphProperty -InputObject $live -name '@odata.type')"
    $livePayload = "$(Get-GraphProperty -InputObject $live -name 'payload')"

    Write-Output "  profile : $liveName"

    if ($liveOdata -ne '#microsoft.graph.macOSCustomConfiguration') {
      throw "Profile $TamperProtectionProfileId is $liveOdata, not a macOS custom configuration. Refusing."
    }

    $liveText = if ($livePayload) { [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($livePayload)) } else { '' }

    # Confirm this really is the wdav preferences profile before overwriting its payload.
    if ($liveText -notmatch 'com\.microsoft\.wdav') {
      throw "Live profile payload does not contain com.microsoft.wdav. Wrong profile id? Refusing."
    }

    if ($liveText -match '<key>unallowedBrowserMode</key>\s*<string>enforce</string>' -and
        $liveText -match '<key>pasteToBrowserMode</key>\s*<string>enforce</string>') {
      Write-Output '  enforcement block already present; nothing to do.'
      $profileResult = 'no-op'
    }
    else {
      Write-Output "  payload : $($liveText.Length) -> $($localText.Length) chars, adding accessibility/enforcement"

      if ($PSCmdlet.ShouldProcess($liveName, 'Upload merged Defender profile with DLP enforcement block')) {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($localText))
        Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$TamperProtectionProfileId" `
          -body @{ '@odata.type' = $liveOdata; payload = $encoded; payloadName = 'com.microsoft.wdav' } | Out-Null

        $verify = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$TamperProtectionProfileId"
        $verifyText = [System.Text.Encoding]::UTF8.GetString(
          [Convert]::FromBase64String("$(Get-GraphProperty -InputObject $verify -name 'payload')"))

        if ($verifyText -match '<key>unallowedBrowserMode</key>\s*<string>enforce</string>') {
          Write-Output '  applied and verified.'
          $profileResult = 'applied'
        }
        else {
          Write-Warning '  PATCH reported success but the enforcement block is not in the live payload.'
          $profileResult = 'failed'
        }
      }
      else { $profileResult = 'dry run' }
    }

  }
  catch {
    Write-Warning "DLP enforcement change failed: $($_.Exception.Message)"
    $profileResult = 'failed'
  }
  Write-Output ''
}

#endregion

#region Change 2 -- shell scripts

$scriptResults = [ordered]@{}

if (-not $SkipScripts) {
  Write-Output '--- Change 2: macOS shell scripts ---'

  $existing = @()
  try {
    $existing = @(Get-GraphProperty -InputObject (Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceShellScripts") -name 'value')
  }
  catch {
    Write-Warning "Could not list existing shell scripts: $($_.Exception.Message)"
  }

  foreach ($entry in $script:ShellScripts) {
    $name = $entry.DisplayName
    $path = Join-Path $MacScriptRoot $entry.File
    $scriptResults[$entry.File] = 'skipped'

    try {
      if (-not (Test-Path -LiteralPath $path)) { throw "Script file not found: $path" }

      $encoded = ConvertTo-Base64Utf8 -path $path

      $match = @($existing | Where-Object { "$(Get-GraphProperty -InputObject $_ -name 'displayName')" -eq $name })
      if ($match.Count -gt 1) { throw "$($match.Count) existing scripts share the name '$name'. Refusing to guess which to update." }

      $body = [ordered]@{
        displayName                 = $name
        description                 = "Deployed from $($entry.File). See the script header for what it checks and why."
        scriptContent               = $encoded
        fileName                    = $entry.File
        runAsAccount                = 'system'
        blockExecutionNotifications = $true
        executionFrequency          = 'P1D'
        retryCount                  = 1
        roleScopeTagIds             = @('0')
      }

      $wantAssign = ($AssignToAllDevices -or $ScriptAssignmentGroupId)
      $verb = if ($match.Count -eq 1) { 'Update existing' } else { 'Create' }
      $id = $null

      if ($match.Count -eq 1) {
        $id = "$(Get-GraphProperty -InputObject $match[0] -name 'id')"
        Write-Output "  $($entry.File) -> updating existing$(if ($wantAssign) { ' + assigning' })"
        if ($PSCmdlet.ShouldProcess($name, "$verb macOS shell script")) {
          Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceShellScripts/$id" -body $body | Out-Null
          $scriptResults[$entry.File] = 'updated'
        }
        else { $scriptResults[$entry.File] = 'dry run'; $id = $null }
      }
      else {
        Write-Output "  $($entry.File) -> creating$(if ($wantAssign) { ' + assigning' })"
        if ($PSCmdlet.ShouldProcess($name, "$verb macOS shell script")) {
          $created = Invoke-Graph -method POST -uri "$graphBase/deviceManagement/deviceShellScripts" -body $body
          $id = "$(Get-GraphProperty -InputObject $created -name 'id')"
          $scriptResults[$entry.File] = 'created'
        }
        else { $scriptResults[$entry.File] = 'dry run' }
      }

      # Assignment is what makes a script actually run. Without it the script exists, reports
      # nothing, and is indistinguishable in the portal from a script that is passing.
      #
      # This runs for an UPDATED script as well as a created one. An earlier version only
      # assigned on create, so re-running against scripts that already existed reported
      # "updated" and left every one of them unassigned -- the exact silent-success failure
      # this script warns about elsewhere.
      #
      # /assign replaces the whole assignment list, so it is idempotent: re-running does not
      # stack duplicate assignments.
      if ($id -and $wantAssign) {
        $target = if ($AssignToAllDevices) {
          @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
        }
        else {
          @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $ScriptAssignmentGroupId }
        }
        Invoke-Graph -method POST -uri "$graphBase/deviceManagement/deviceShellScripts/$id/assign" `
          -body @{ deviceManagementScriptAssignments = @(@{ target = $target }) } | Out-Null

        # Verify against live state rather than trusting the POST. An assignment that did not
        # stick is the whole failure being fixed here.
        # $expand from the parent: deviceShellScripts/{id}/assignments returns 400
        # "No method match route template".
        $check = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceShellScripts/$id`?`$expand=assignments"
        $count = @(Get-GraphProperty -InputObject $check -name 'assignments').Count
        if ($count -ge 1) {
          $scriptResults[$entry.File] = "$($scriptResults[$entry.File]) + assigned"
        }
        else {
          Write-Warning "  $($entry.File): assignment reported success but the script has no assignments."
          $scriptResults[$entry.File] = 'failed'
        }
      }
    }
    catch {
      Write-Warning "  $($entry.File): $($_.Exception.Message)"
      $scriptResults[$entry.File] = 'failed'
    }
  }
  Write-Output ''
}

#endregion

#region Summary

Write-Output '--- Result ---'
Write-Output "  DLP enforcement block : $profileResult"
foreach ($k in $scriptResults.Keys) { Write-Output ("  {0,-34} {1}" -f $k, $scriptResults[$k]) }

if (-not $SkipScripts -and -not $AssignToAllDevices -and -not $ScriptAssignmentGroupId -and -not $isDryRun) {
  Write-Output ''
  Write-Warning 'Scripts were created UNASSIGNED and will not run on any device.'
  Write-Warning 'Assign them in the portal, or re-run with -AssignToAllDevices.'
}

if ($isDryRun) {
  Write-Output ''
  Write-Output '  NOTHING WAS CHANGED. Re-run without -WhatIf to apply.'
}

$failed = @(@($profileResult) + @($scriptResults.Values) | Where-Object { $_ -eq 'failed' })
if ($failed.Count) { exit 1 }

#endregion
