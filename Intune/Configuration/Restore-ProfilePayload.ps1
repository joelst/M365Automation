<#
.SYNOPSIS
Restores a macOS custom configuration profile's payload from a previous export.

.DESCRIPTION
Recovers a profile whose .mobileconfig was overwritten by an accidental upload, by writing
back the exact payload captured in an earlier export run.

The base64 payload is restored VERBATIM from the export -- it is never decoded and
re-encoded, because a round trip through text could change line endings, encoding or a BOM
and produce a subtly different profile.

Safety: the export record and the live profile must agree on both id and displayName before
anything is written. That guard exists precisely because the failure being repaired here is
"the right file uploaded to the wrong profile".

.PARAMETER profileId
Id of the profile to restore.

.PARAMETER exportRoot
Root of the exports tree. The most recent date folder containing this profile is used unless
-exportDate is given.

.PARAMETER exportDate
Specific export date folder (yyyy-MM-dd) to restore from.

.PARAMETER tenantId
Optional tenant id or domain for authentication.

.EXAMPLE
./Restore-ProfilePayload.ps1 -profileId <profile-id> -WhatIf

Shows what would be restored, including the before/after payload fingerprints.

.EXAMPLE
./Restore-ProfilePayload.ps1 -profileId <profile-id>

Restores the payload, payloadName and payloadFileName from the most recent export.

.NOTES
Requires DeviceManagementConfiguration.ReadWrite.All.

Written for profiles like 'macOS: Enable Intune client as background service', whose
original payload is Microsoft's
background_services.mobileconfig -- the com.apple.servicemanagement grant that allows the
Defender (com.microsoft.fresno) and Purview DLP (com.microsoft.dlp) daemons to run in the
background on macOS 13 and later.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  # No default. A profile id is tenant-specific, and this repo is public -- hardcoding one ties
  # the script to a single tenant and quietly invites it to be run against the wrong object.
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$profileId,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$exportRoot = (Join-Path $PSScriptRoot 'exports'),

  [Parameter()]
  [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
  [string]$exportDate,

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

function Get-PayloadFingerprint {
  param([Parameter()][AllowNull()][object]$payload)
  if (-not $payload) { return '<none>' }
  $bytes = [System.Text.Encoding]::UTF8.GetBytes(("$payload" -replace '\s', ''))
  return [System.BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  ).Replace('-', '').Substring(0, 16).ToLower()
}

function Get-PayloadSummary {
  # What the payload actually configures, so the restore can be sanity-checked by eye.
  param([Parameter()][AllowNull()][object]$payload)
  if (-not $payload) { return '<none>' }
  try {
    $xml = [xml][System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$payload"))
    $types = @($xml.SelectNodes("//key[.='PayloadType']") |
        ForEach-Object { $_.NextSibling.InnerText } |
        Where-Object { $_ -and $_ -ne 'Configuration' } |
        Sort-Object -Unique)
    $ident = $xml.SelectSingleNode("/plist/dict/key[.='PayloadIdentifier']")
    $identValue = if ($null -ne $ident -and $null -ne $ident.NextSibling) { $ident.NextSibling.InnerText } else { '<none>' }
    return "identifier=$identValue  payloads=$($types -join ', ')"
  }
  catch {
    return '<unparseable>'
  }
}

#endregion

#region Locate the export record

if (-not (Test-Path -Path $exportRoot)) { throw "Export root not found: $exportRoot" }

# A policy file sits at <root>\<tenant>\<date>\<ProfileType>\<name>_<id>.json, so the date
# folder is two levels up -- not one. Getting this wrong would silently sort every candidate
# under the same key and could restore from an older export than intended.
function Get-ExportDateFolder {
  param([Parameter(Mandatory = $true)][System.IO.FileInfo]$file)
  return Split-Path (Split-Path (Split-Path $file.FullName -Parent) -Parent) -Leaf
}

# Find every exported copy of this profile, newest date first.
$candidates = @(Get-ChildItem -Path $exportRoot -Recurse -File -Filter "*_$profileId.json" |
    Where-Object { $_.Name -notlike '*.assignments.json' } |
    Sort-Object { Get-ExportDateFolder -file $_ } -Descending)

if ($exportDate) {
  $candidates = @($candidates | Where-Object { (Get-ExportDateFolder -file $_) -eq $exportDate })
}

if (-not $candidates.Count) {
  throw "No export record found for profile $profileId under $exportRoot$(if ($exportDate) { " (date $exportDate)" })."
}

$sourceFile = $candidates[0]
$sourceDate = Get-ExportDateFolder -file $sourceFile
$source = Get-Content -Path $sourceFile.FullName -Raw | ConvertFrom-Json

$sourcePayload = Get-GraphProperty -InputObject $source -name 'payload'
if (-not $sourcePayload) { throw "Export record $($sourceFile.Name) has no payload to restore." }

$sourceName = Get-GraphProperty -InputObject $source -name 'displayName'
$sourceOdataType = Get-GraphProperty -InputObject $source -name '@odata.type'

Write-Output "Restoring from export : $sourceDate"
Write-Output "  file                : $($sourceFile.Name)"
Write-Output "  displayName         : $sourceName"
Write-Output "  payload             : sha $(Get-PayloadFingerprint -payload $sourcePayload)"
Write-Output "  contents            : $(Get-PayloadSummary -payload $sourcePayload)"
Write-Output ''

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

#region Compare

$live = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$profileId"
$liveName = Get-GraphProperty -InputObject $live -name 'displayName'
$livePayload = Get-GraphProperty -InputObject $live -name 'payload'
$liveFingerprint = Get-PayloadFingerprint -payload $livePayload
$sourceFingerprint = Get-PayloadFingerprint -payload $sourcePayload

Write-Output 'Live profile now:'
Write-Output "  displayName         : $liveName"
Write-Output "  payload             : sha $liveFingerprint"
Write-Output "  contents            : $(Get-PayloadSummary -payload $livePayload)"
Write-Output ''

# The mistake being repaired is an upload to the wrong profile, so confirm the export record
# and the live profile are genuinely the same profile before writing anything back.
if ($liveName -ne $sourceName) {
  throw "Safety check failed: live profile is named '$liveName' but the export record is '$sourceName'. Confirm -profileId before restoring."
}

if ($liveFingerprint -eq $sourceFingerprint) {
  Write-Output 'Payload already matches the export -- nothing to restore.'
  return
}

Write-Warning "Payload differs from the export ($liveFingerprint vs $sourceFingerprint). Restoring."

#endregion

#region Restore

$body = [ordered]@{
  '@odata.type' = $(if ($sourceOdataType) { $sourceOdataType } else { '#microsoft.graph.macOSCustomConfiguration' })
  payload       = $sourcePayload
}
foreach ($field in @('payloadName', 'payloadFileName')) {
  $v = Get-GraphProperty -InputObject $source -name $field
  if ($v) { $body[$field] = $v }
}

if ($PSCmdlet.ShouldProcess($liveName, "Restore payload from the $sourceDate export (sha $sourceFingerprint)")) {
  Invoke-Graph -method PATCH -uri "$graphBase/deviceManagement/deviceConfigurations/$profileId" -body $body | Out-Null
  Write-Output 'Payload restored.'
}
else {
  Write-Output 'WhatIf: no change made.'
  return
}

#endregion

#region Verify

Write-Output ''
Write-Output '--- After (read back from Graph) ---'
$after = Invoke-Graph -method GET -uri "$graphBase/deviceManagement/deviceConfigurations/$profileId"
$afterPayload = Get-GraphProperty -InputObject $after -name 'payload'
$afterFingerprint = Get-PayloadFingerprint -payload $afterPayload

Write-Output "  displayName         : $(Get-GraphProperty -InputObject $after -name 'displayName')"
Write-Output "  payloadName         : $(Get-GraphProperty -InputObject $after -name 'payloadName')"
Write-Output "  payload             : sha $afterFingerprint"
Write-Output "  contents            : $(Get-PayloadSummary -payload $afterPayload)"
Write-Output ''

if ($afterFingerprint -eq $sourceFingerprint) {
  Write-Output "RESTORED: payload matches the $sourceDate export exactly."
}
else {
  Write-Error "Restore did not take: payload is $afterFingerprint, expected $sourceFingerprint."
}

Write-Output ''
Write-Output 'Next: on a Mac, confirm the profile is back and the daemons are permitted:'
Write-Output '  sudo profiles show -output stdout-xml | grep -A3 servicemanagement'
Write-Output '  mdatp health'

#endregion
