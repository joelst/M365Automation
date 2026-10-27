<#
.SYNOPSIS
Replaces the content of an existing Intune macOS PKG app with a new .pkg, in place.

.DESCRIPTION
Uploads a new content version to an existing macOSPkgApp rather than creating a second app.
Updating in place keeps the app id, its assignments, and its reporting history -- a new app
would need re-assigning and leaves the old one installing the old version alongside it.

Steps, each verified against live state:

  1. READ THE PKG -- bundle ids and versions are taken from the pkg's own Distribution file,
     not typed in. The primary bundle id must match the app being updated; a pkg for a
     different product is refused. Optionally the file hash is checked against a published
     digest.

  2. UPLOAD -- creates a content version, encrypts the pkg the way Intune requires
     (AES-256-CBC + HMAC-SHA256, ProfileVersion1), uploads it to the storage SAS in blocks,
     and commits it.

  3. PATCH THE APP -- points committedContentVersion at the new content and updates fileName,
     primaryBundleVersion and includedApps to match.

     ignoreVersionDetection is set to FALSE by default. With it true, Intune only checks the
     bundle id is present, so every Mac that already has an older version reports
     "installed" and never receives the update. Only leave it true for apps that update
     themselves (pass -IgnoreVersionDetection $true).

  4. ASSIGNMENT -- with -AssignToAllDevices, ensures a Required assignment to All Devices
     exists. For a macOS app that is every Mac. Existing assignments are never removed: the
     assignment is added with POST /assignments, not /assign, because /assign replaces the
     whole list.

.PARAMETER AppId
Id of the existing macOSPkgApp to update.

.PARAMETER PkgPath
Path to the new .pkg.

.PARAMETER ExpectedSha256
Published SHA-256 of the pkg (hex). When given, a mismatch stops the script before upload.

.PARAMETER IgnoreVersionDetection
Value for the app's ignoreVersionDetection. Defaults to $false so existing installs upgrade.

.PARAMETER AssignToAllDevices
Ensure a Required assignment to All Devices exists.

.EXAMPLE
.\Update-MacOSPkgApp.ps1 -AppId <id> -PkgPath .\powershell-7.6.9-osx-arm64.pkg -WhatIf
Reads and validates the pkg, shows the change, writes nothing. Requests read-only scopes.

.EXAMPLE
.\Update-MacOSPkgApp.ps1 -AppId <id> -PkgPath .\powershell-7.6.9-osx-arm64.pkg -ExpectedSha256 <hex> -AssignToAllDevices
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)]
  [ValidateNotNullOrEmpty()]
  [string]$AppId,

  [Parameter(Mandatory)]
  [ValidateNotNullOrEmpty()]
  [string]$PkgPath,

  [Parameter()]
  [ValidatePattern('^[0-9a-fA-F]{64}$')]
  [string]$ExpectedSha256,

  [Parameter()]
  [bool]$IgnoreVersionDetection = $false,

  [Parameter()]
  [switch]$AssignToAllDevices,

  [Parameter()]
  [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphBase = 'https://graph.microsoft.com/beta'
$chunkSize = 6MB

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

function ConvertFrom-BigEndian {
  param([Parameter(Mandatory)][byte[]]$bytes)
  [Array]::Reverse($bytes)
  return , $bytes
}

function Read-PkgDistribution {
  # A .pkg is a xar archive: a fixed header, a zlib-compressed XML table of contents, then a
  # heap holding the files. Only the Distribution file is needed, so read it directly rather
  # than depending on xar or 7-Zip being installed on a Windows admin box.
  param([Parameter(Mandatory)][string]$path)

  $fs = [System.IO.File]::OpenRead($path)
  try {
    $br = New-Object System.IO.BinaryReader $fs
    $magic = [System.Text.Encoding]::ASCII.GetString($br.ReadBytes(4))
    if ($magic -ne 'xar!') { throw "Not a flat .pkg (xar header missing): $path" }

    $headerSize = [BitConverter]::ToUInt16((ConvertFrom-BigEndian $br.ReadBytes(2)), 0)
    $null = $br.ReadBytes(2)
    $tocCompressed = [BitConverter]::ToUInt64((ConvertFrom-BigEndian $br.ReadBytes(8)), 0)

    $fs.Position = $headerSize
    $tocStream = New-Object System.IO.MemoryStream(, $br.ReadBytes([int]$tocCompressed))
    $zlib = New-Object System.IO.Compression.ZLibStream($tocStream, [System.IO.Compression.CompressionMode]::Decompress)
    [xml]$toc = (New-Object System.IO.StreamReader $zlib).ReadToEnd()

    $entry = @($toc.xar.toc.file | Where-Object { $_.name -eq 'Distribution' }) | Select-Object -First 1
    if ($null -eq $entry) { throw 'pkg has no Distribution file; it is a component pkg, which Intune cannot detect.' }

    $fs.Position = $headerSize + [int64]$tocCompressed + [int64]$entry.data.offset
    $raw = $br.ReadBytes([int]$entry.data.length)
    if ("$($entry.data.encoding.style)" -match 'gzip') {
      $dataStream = New-Object System.IO.MemoryStream(, $raw)
      $inflate = New-Object System.IO.Compression.ZLibStream($dataStream, [System.IO.Compression.CompressionMode]::Decompress)
      return [xml](New-Object System.IO.StreamReader $inflate).ReadToEnd()
    }
    return [xml][System.Text.Encoding]::UTF8.GetString($raw)
  }
  finally { $fs.Dispose() }
}

function Wait-ContentFileState {
  param([Parameter(Mandatory)][string]$uri, [Parameter(Mandatory)][string]$success, [int]$timeoutSeconds = 600)
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    $file = Invoke-Graph -method GET -uri $uri
    $state = "$(Get-GraphProperty -InputObject $file -name 'uploadState')"
    if ($state -eq $success) { return $file }
    if ($state -match 'Failed|TimedOut') { throw "Content file entered state '$state' waiting for '$success'." }
    Start-Sleep -Seconds 5
  }
  throw "Timed out after $timeoutSeconds s waiting for '$success'."
}

#endregion

#region Read the pkg

$PkgPath = (Resolve-Path -LiteralPath $PkgPath).Path
$pkgFile = Get-Item -LiteralPath $PkgPath
Write-Output "--- pkg: $($pkgFile.Name) ($([math]::Round($pkgFile.Length / 1MB, 1)) MB) ---"

$sha256 = (Get-FileHash -LiteralPath $PkgPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ExpectedSha256) {
  if ($sha256 -ne $ExpectedSha256.ToLowerInvariant()) {
    throw "SHA-256 mismatch. Expected $($ExpectedSha256.ToLowerInvariant()), got $sha256. Refusing to upload."
  }
  Write-Output '  sha256  : matches published digest'
}
else { Write-Output "  sha256  : $sha256 (not checked; pass -ExpectedSha256)" }

$dist = Read-PkgDistribution -path $PkgPath

# includedApps is what Intune uses for detection, so take every bundle the pkg declares.
$bundles = @($dist.SelectNodes('//pkg-ref/bundle-version/bundle') | ForEach-Object {
    [ordered]@{ bundleId = $_.id; bundleVersion = $_.CFBundleShortVersionString }
  })
if ($bundles.Count -eq 0) { throw 'pkg Distribution declares no bundles; Intune would have nothing to detect.' }

$hostArch = "$(@($dist.SelectNodes('//options[@hostArchitectures]') | ForEach-Object { $_.hostArchitectures }) -join ',')"
foreach ($b in $bundles) { Write-Output "  bundle  : $($b.bundleId) $($b.bundleVersion)" }
if ($hostArch) { Write-Output "  arch    : $hostArch" }
Write-Output ''

#endregion

#region Connect

if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
  throw "Required module 'Microsoft.Graph.Authentication' is not installed."
}

$isDryRun = [bool]$WhatIfPreference
$accessLevel = if ($isDryRun) { 'Read' } else { 'ReadWrite' }
$requiredScopes = @("DeviceManagementApps.$accessLevel.All")

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

#region Compare with the live app

$appUri = "$graphBase/deviceAppManagement/mobileApps/$AppId"
$app = Invoke-Graph -method GET -uri "$appUri`?`$expand=assignments"
$appName = "$(Get-GraphProperty -InputObject $app -name 'displayName')"
$appOdata = "$(Get-GraphProperty -InputObject $app -name '@odata.type')"
$liveBundleId = "$(Get-GraphProperty -InputObject $app -name 'primaryBundleId')"
$liveVersion = "$(Get-GraphProperty -InputObject $app -name 'primaryBundleVersion')"
$liveContent = "$(Get-GraphProperty -InputObject $app -name 'committedContentVersion')"

if ($appOdata -ne '#microsoft.graph.macOSPkgApp') {
  throw "App $AppId is $appOdata, not a macOS PKG app. Refusing."
}

# The primary bundle must be the product this app already installs. Uploading another
# product's pkg would leave every Mac failing detection for an app it never had.
$primary = @($bundles | Where-Object { $_.bundleId -eq $liveBundleId }) | Select-Object -First 1
if ($null -eq $primary) {
  throw "pkg does not contain bundle '$liveBundleId' (the app's primaryBundleId). Wrong pkg? Refusing."
}

Write-Output "--- app: $appName ---"
Write-Output "  bundle  : $liveBundleId"
Write-Output "  version : $liveVersion -> $($primary.bundleVersion)"
Write-Output "  file    : $(Get-GraphProperty -InputObject $app -name 'fileName') -> $($pkgFile.Name)"
Write-Output "  ignoreVersionDetection : $(Get-GraphProperty -InputObject $app -name 'ignoreVersionDetection') -> $IgnoreVersionDetection"

$assignments = @(Get-GraphProperty -InputObject $app -name 'assignments')
$hasAllDevicesRequired = @($assignments | Where-Object {
    "$(Get-GraphProperty -InputObject $_ -name 'intent')" -eq 'required' -and
    "$(Get-GraphProperty -InputObject (Get-GraphProperty -InputObject $_ -name 'target') -name '@odata.type')" -eq '#microsoft.graph.allDevicesAssignmentTarget'
  }).Count -gt 0
Write-Output "  assigned: $($assignments.Count) assignment(s); Required/All Devices present: $hasAllDevicesRequired"
Write-Output ''

#endregion

#region Upload

$uploadResult = 'skipped'
$encryptedDir = $null

if ($PSCmdlet.ShouldProcess($appName, "Upload $($pkgFile.Name) as a new content version and set version $($primary.bundleVersion)")) {
  try {
    # Encrypted copy goes in its own temp folder, never next to the source pkg.
    $encryptedDir = Join-Path ([System.IO.Path]::GetTempPath()) "intune-pkg-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $encryptedDir | Out-Null
    $encryptedPath = Join-Path $encryptedDir "$($pkgFile.Name).bin"

    Write-Output '--- Encrypt ---'
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey(); $aes.GenerateIV()
    $macKey = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($macKey)

    # Layout Intune expects: HMAC(32) | IV(16) | ciphertext, with the HMAC taken over IV +
    # ciphertext. Write a placeholder for the HMAC, stream the rest, then fill it in.
    $out = [System.IO.File]::Open($encryptedPath, [System.IO.FileMode]::CreateNew)
    try {
      $out.Write([byte[]]::new(32), 0, 32)
      $out.Write($aes.IV, 0, $aes.IV.Length)
      $crypto = New-Object System.Security.Cryptography.CryptoStream($out, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write, $true)
      $in = [System.IO.File]::OpenRead($PkgPath)
      try { $in.CopyTo($crypto) } finally { $in.Dispose() }
      $crypto.FlushFinalBlock(); $crypto.Dispose()

      $out.Position = 32
      $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
      $mac = $hmac.ComputeHash($out)
      $hmac.Dispose()
      $out.Position = 0
      $out.Write($mac, 0, $mac.Length)
    }
    finally { $out.Dispose() }

    $encryptionInfo = [ordered]@{
      encryptionKey        = [Convert]::ToBase64String($aes.Key)
      macKey               = [Convert]::ToBase64String($macKey)
      initializationVector = [Convert]::ToBase64String($aes.IV)
      mac                  = [Convert]::ToBase64String($mac)
      profileIdentifier    = 'ProfileVersion1'
      fileDigest           = [Convert]::ToBase64String([Convert]::FromHexString($sha256))
      fileDigestAlgorithm  = 'SHA256'
    }
    $aes.Dispose()
    $encryptedSize = (Get-Item -LiteralPath $encryptedPath).Length
    Write-Output "  $($pkgFile.Length) -> $encryptedSize bytes"

    Write-Output '--- Upload ---'
    $cvBase = "$appUri/microsoft.graph.macOSPkgApp/contentVersions"
    $cv = "$(Get-GraphProperty -InputObject (Invoke-Graph -method POST -uri $cvBase -body @{}) -name 'id')"
    Write-Output "  content version: $cv"

    $fileBody = [ordered]@{
      '@odata.type' = '#microsoft.graph.mobileAppContentFile'
      name          = $pkgFile.Name
      size          = $pkgFile.Length
      sizeEncrypted = $encryptedSize
      manifest      = $null
      isDependency  = $false
    }
    $fileId = "$(Get-GraphProperty -InputObject (Invoke-Graph -method POST -uri "$cvBase/$cv/files" -body $fileBody) -name 'id')"
    $fileUri = "$cvBase/$cv/files/$fileId"
    $file = Wait-ContentFileState -uri $fileUri -success 'azureStorageUriRequestSuccess'
    $sas = "$(Get-GraphProperty -InputObject $file -name 'azureStorageUri')"
    $sasIssued = Get-Date

    # Straight to Azure storage with plain web requests: Invoke-MgGraphRequest would attach
    # the Graph bearer token to a non-Graph URL.
    $blockIds = [System.Collections.Generic.List[string]]::new()
    $buffer = [byte[]]::new($chunkSize)
    $src = [System.IO.File]::OpenRead($encryptedPath)
    try {
      $index = 0
      while (($read = $src.Read($buffer, 0, $buffer.Length)) -gt 0) {
        # The SAS is short-lived; renew it well before it expires on a slow link.
        if (((Get-Date) - $sasIssued).TotalMinutes -gt 7) {
          Invoke-Graph -method POST -uri "$fileUri/renewUpload" | Out-Null
          $file = Wait-ContentFileState -uri $fileUri -success 'azureStorageUriRenewalSuccess'
          $sas = "$(Get-GraphProperty -InputObject $file -name 'azureStorageUri')"
          $sasIssued = Get-Date
        }
        # Block ids must all be the same length before encoding, hence the fixed width.
        $blockId = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(('{0:D6}' -f $index)))
        $chunk = $buffer
        if ($read -lt $buffer.Length) { $chunk = [byte[]]::new($read); [Array]::Copy($buffer, $chunk, $read) }
        Invoke-WebRequest -Method Put -Uri "$sas&comp=block&blockid=$([uri]::EscapeDataString($blockId))" `
          -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -ContentType 'application/octet-stream' -Body $chunk | Out-Null
        $blockIds.Add($blockId)
        $index++
      }
    }
    finally { $src.Dispose() }

    $blockList = '<?xml version="1.0" encoding="utf-8"?><BlockList>' +
      (($blockIds | ForEach-Object { "<Latest>$_</Latest>" }) -join '') + '</BlockList>'
    Invoke-WebRequest -Method Put -Uri "$sas&comp=blocklist" -ContentType 'application/xml' -Body $blockList | Out-Null
    Write-Output "  uploaded $($blockIds.Count) block(s)"

    Write-Output '--- Commit ---'
    Invoke-Graph -method POST -uri "$fileUri/commit" -body @{ fileEncryptionInfo = $encryptionInfo } | Out-Null
    Wait-ContentFileState -uri $fileUri -success 'commitFileSuccess' | Out-Null
    Write-Output '  committed'

    Invoke-Graph -method PATCH -uri $appUri -body ([ordered]@{
        '@odata.type'           = '#microsoft.graph.macOSPkgApp'
        committedContentVersion = $cv
        fileName                = $pkgFile.Name
        primaryBundleVersion    = $primary.bundleVersion
        includedApps            = $bundles
        ignoreVersionDetection  = $IgnoreVersionDetection
      }) | Out-Null
    $uploadResult = "content version $cv"
  }
  catch {
    Write-Warning "Upload failed: $($_.Exception.Message)"
    $uploadResult = 'failed'
  }
  finally {
    if ($encryptedDir -and (Test-Path -LiteralPath $encryptedDir)) { Remove-Item -LiteralPath $encryptedDir -Recurse -Force }
  }
  Write-Output ''
}
else { $uploadResult = 'dry run' }

#endregion

#region Assignment

$assignResult = if ($hasAllDevicesRequired) { 'already present' } elseif ($AssignToAllDevices) { 'skipped' } else { 'not requested' }

if ($AssignToAllDevices -and -not $hasAllDevicesRequired -and $uploadResult -ne 'failed') {
  if ($PSCmdlet.ShouldProcess($appName, 'Add Required assignment to All Devices')) {
    try {
      Invoke-Graph -method POST -uri "$appUri/assignments" -body @{
        '@odata.type' = '#microsoft.graph.mobileAppAssignment'
        intent        = 'required'
        target        = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }
      } | Out-Null
      $assignResult = 'added'
    }
    catch {
      Write-Warning "Assignment failed: $($_.Exception.Message)"
      $assignResult = 'failed'
    }
  }
  else { $assignResult = 'dry run' }
}

#endregion

#region Verify

Write-Output '--- Result ---'
if (-not $isDryRun -and $uploadResult -ne 'failed') {
  # Verify against live state rather than trusting the PATCH. isAssigned is not used: it has
  # been seen reporting false on apps that do have assignments.
  $check = Invoke-Graph -method GET -uri "$appUri`?`$expand=assignments"
  $checkVersion = "$(Get-GraphProperty -InputObject $check -name 'primaryBundleVersion')"
  $checkContent = "$(Get-GraphProperty -InputObject $check -name 'committedContentVersion')"
  $checkState = "$(Get-GraphProperty -InputObject $check -name 'publishingState')"
  $checkIgnore = Get-GraphProperty -InputObject $check -name 'ignoreVersionDetection'
  $checkAssign = @(Get-GraphProperty -InputObject $check -name 'assignments')

  Write-Output "  version            : $checkVersion"
  Write-Output "  content version    : $liveContent -> $checkContent"
  Write-Output "  publishingState    : $checkState"
  Write-Output "  ignoreVersionDetection : $checkIgnore"
  foreach ($a in $checkAssign) {
    $t = Get-GraphProperty -InputObject $a -name 'target'
    Write-Output ("  assignment         : {0} -> {1}{2}" -f (Get-GraphProperty -InputObject $a -name 'intent'),
      ("$(Get-GraphProperty -InputObject $t -name '@odata.type')" -replace '^#microsoft\.graph\.', ''),
      $(if ($g = Get-GraphProperty -InputObject $t -name 'groupId') { " ($g)" } else { '' }))
  }

  if ($checkVersion -ne $primary.bundleVersion -or $checkState -ne 'published' -or $checkIgnore -ne $IgnoreVersionDetection) {
    Write-Warning 'Live app does not match what was uploaded.'
    $uploadResult = 'failed'
  }
  if ($checkAssign.Count -eq 0) {
    Write-Warning 'App has NO assignments and will not install on any Mac. Re-run with -AssignToAllDevices.'
  }
}
Write-Output "  upload             : $uploadResult"
Write-Output "  All Devices        : $assignResult"

if ($isDryRun) {
  Write-Output ''
  Write-Output '  NOTHING WAS CHANGED. Re-run without -WhatIf to apply.'
}

if ($uploadResult -eq 'failed' -or $assignResult -eq 'failed') { exit 1 }

#endregion
