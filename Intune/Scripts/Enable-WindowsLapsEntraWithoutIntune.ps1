<#
.SYNOPSIS
    Configures Windows LAPS for Entra ID backup via registry without GPO or Intune.

.DESCRIPTION
    Writes Windows LAPS policy registry keys targeting Entra ID (BackupDirectory=1).
    On Windows 11 24H2+/Server 2025+, uses AutomaticAccountManagement to let LAPS
    create and manage the local admin account automatically.
    On older builds, auto-detects the local administrator account using a priority order:
      1. 'localadmin' (preferred)
      2. Built-in Administrator by RID-500 SID
      3. First enabled member of the local Administrators group
      4. Create 'localadmin' if none found
    Triggers policy processing and outputs device ID for manual password retrieval.

.NOTES
    Deployment:     Action1 RMM
    Requirements:   Windows 11 22H2+ or Server 2022 Oct 2022 CU+
                    Device must be Entra ID Joined (not merely registered)
                    LAPS must be enabled in Entra Admin Center:
                    Devices > Device Settings > Enable LAPS = Yes
    Exit Codes:     0 = Success
                    1 = Fatal error — LAPS not configured
#>
# Set Variables
[int]$PasswordAgeDays = 28
[int]$PasswordLength = 20
[int]$PasswordComplexity = 8
[int]$PostAuthenticationActions = 11
[int]$PostAuthenticationResetDelay = 8
# Requires Windows 11 24H2+/Windows Server 2025
[int]$AutomaticAccountManagementTarget = 1
[string]$AutomaticAccountManagementNameOrPrefix = 'localadmin'
[int]$AutomaticAccountManagementEnabled = 1
[int]$AutomaticAccountManagementRandomizeName = 0
[int]$PassphraseLength = 5
[int]$PasswordExpirationProtectionEnabled = 1

$ErrorActionPreference = 'Stop'

#region --- CONSTANTS ---

$RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
$PreferredAccount = $AutomaticAccountManagementNameOrPrefix
$Is24H2OrLater = $false

try {
  $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  $buildNumber = [int]$osInfo.BuildNumber

  # Windows 11 24H2 and Windows Server 2025 share build 26100+.
  if ($buildNumber -ge 26100) {
    $Is24H2OrLater = $true
  }
}
catch {
  Write-Warning "Unable to determine OS build for AutomaticAccountManagement gating: $($_.Exception.Message)"
}

#endregion

#region --- FUNCTIONS ---

function Get-LAPSTargetAccount {
  <#
    .SYNOPSIS
        Resolves the local admin account LAPS should manage.
    .OUTPUTS
        [string] Account name, or empty string to trigger RID-500 SID fallback in LAPS itself.
    #>

  # Priority 1: Preferred account by name
  $preferred = Get-LocalUser -Name $PreferredAccount -ErrorAction SilentlyContinue

  if ($null -ne $preferred) {
    if ($preferred.Enabled) {
      Write-Host "INFO: Target account '$PreferredAccount' found and enabled."
      return $PreferredAccount
    }

    Write-Warning "'$PreferredAccount' exists but is disabled. Attempting to enable."
    try {
      Enable-LocalUser -Name $PreferredAccount
      Write-Host "INFO: '$PreferredAccount' successfully enabled."
      return $PreferredAccount
    }
    catch {
      Write-Warning "Failed to enable '$PreferredAccount': $($_.Exception.Message)"
    }
  }
  else {
    Write-Warning "Preferred account '$PreferredAccount' not found on this device."
  }

  # Priority 2: Built-in Administrator by RID-500 SID (rename-proof)
  $rid500 = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }

  if ($null -ne $rid500) {
    if ($rid500.Enabled) {
      Write-Host "INFO: Falling back to built-in Administrator (RID-500): '$($rid500.Name)'."
      return $rid500.Name
    }
    Write-Warning "RID-500 account '$($rid500.Name)' is disabled — skipping."
  }

  # Priority 3: First enabled member of local Administrators group
  try {
    $adminGroup = [ADSI]'WinNT://./Administrators,group'
    $memberNames = @(
      $adminGroup.Invoke('Members') | ForEach-Object {
        $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
      }
    )

    $fallback = Get-LocalUser | Where-Object {
      $_.Enabled -and
      ($_.Name -in $memberNames) -and
      ($_.SID.Value -notmatch '-500$')
    } | Select-Object -First 1

    if ($null -ne $fallback) {
      Write-Warning "Using fallback local admin account: '$($fallback.Name)'."
      return $fallback.Name
    }
  }
  catch {
    Write-Warning "Could not enumerate Administrators group: $($_.Exception.Message)"
  }

  # Priority 4: Create 'localadmin' account
  Write-Host "INFO: No usable local admin account found. Creating '$PreferredAccount'..."
  try {
    $secPwd = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(32)
    $secPwd.GetBytes($bytes)
    $tempPassword = [Convert]::ToBase64String($bytes)

    $securePass = ConvertTo-SecureString -String $tempPassword -AsPlainText -Force
    New-LocalUser -Name $PreferredAccount -Password $securePass -Description 'LAPS-managed local admin' -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
    Add-LocalGroupMember -Group 'Administrators' -Member $PreferredAccount -ErrorAction Stop
    Enable-LocalUser -Name $PreferredAccount -ErrorAction Stop
    Write-Host "INFO: Created and enabled local admin account '$PreferredAccount'."
    return $PreferredAccount
  }
  catch {
    Write-Warning "Failed to create '$PreferredAccount': $($_.Exception.Message)"
  }

  # All options exhausted
  Write-Warning 'All account resolution and creation attempts failed. Returning empty — LAPS will attempt RID-500 SID resolution.'
  return ''
}

function Get-DSRegStatus {
  <#
    .SYNOPSIS
        Runs dsregcmd /status once and caches the output.
    .OUTPUTS
        [string[]] dsregcmd output lines.
    #>
  if (-not $script:_DSRegCache) {
    $script:_DSRegCache = dsregcmd /status 2>&1
  }
  return $script:_DSRegCache
}

function Test-EntraJoined {
  <#
    .SYNOPSIS
        Confirms the device is Entra ID Joined (not merely registered).
    .OUTPUTS
        [bool]
    #>
  $dsreg = Get-DSRegStatus
  return ($dsreg | Select-String 'AzureAdJoined\s*:\s*YES') -as [bool]
}

function Get-EntraDeviceId {
  <#
    .SYNOPSIS
        Parses the Entra Device ID from dsregcmd output.
    .OUTPUTS
        [string] Device ID GUID, or empty string on failure.
    #>
  $match = Get-DSRegStatus | Select-String 'DeviceId\s*:\s*(\S+)'
  if ($match) {
    return $match.Matches[0].Groups[1].Value.Trim()
  }
  return ''
}

function Set-LAPSRegistryPolicy {
  <#
    .SYNOPSIS
        Writes LAPS configuration keys to the registry.
    #>
  param(
    [hashtable]$Config,
    [string]$Path
  )

  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
    Write-Host "INFO: Created registry path: $Path"
  }

  foreach ($entry in $Config.GetEnumerator()) {
    $type = if ($entry.Value -is [string]) { 'String' } else { 'DWord' }
    Set-ItemProperty -Path $Path -Name $entry.Key -Value $entry.Value -Type $type
    Write-Host "INFO: Set $($entry.Key) = $($entry.Value) [$type]"
  }
}

#endregion

#region --- PREFLIGHT ---

Write-Output '--- Windows LAPS Entra ID Configuration ---'
Write-Output "INFO: Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "INFO: Computer:  $env:COMPUTERNAME"

if (-not (Test-EntraJoined)) {
  Write-Error 'Device is not Entra ID Joined. LAPS backup to Entra ID requires full Join, not Workplace Registration. Aborting.'
  exit 1
}
Write-Output 'INFO: Entra ID Join confirmed.'

#endregion

#region --- ACCOUNT DETECTION ---

if ($Is24H2OrLater) {
  Write-Host 'INFO: Windows 11 24H2+ / Server 2025+ detected. AutomaticAccountManagement will handle account creation.'
  $targetAccount = ''
}
else {
  Write-Host 'INFO: Pre-24H2 OS detected. Using manual account detection.'
  $targetAccount = Get-LAPSTargetAccount

  if ($targetAccount -eq '') {
    $rid500Check = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
    if ($null -eq $rid500Check -or -not $rid500Check.Enabled) {
      Write-Error 'All account detection and creation failed, and RID-500 is disabled. LAPS cannot manage any account. Aborting.'
      exit 1
    }
    Write-Host 'INFO: No named account resolved. LAPS will fall back to the enabled RID-500 built-in Administrator.'
  }
}

#endregion

#region --- BUILD CONFIG ---

$lapsConfig = [ordered]@{
  BackupDirectory                     = 1   # Microsoft Entra ID
  PasswordAgeDays                     = $PasswordAgeDays
  PasswordLength                      = $PasswordLength
  PassphraseLength                    = $PassphraseLength
  PasswordComplexity                  = $PasswordComplexity
  PasswordExpirationProtectionEnabled = $PasswordExpirationProtectionEnabled
  PostAuthenticationActions           = $PostAuthenticationActions
  PostAuthenticationResetDelay        = $PostAuthenticationResetDelay
}

if ($Is24H2OrLater) {
  $lapsConfig['AutomaticAccountManagementEnabled'] = $AutomaticAccountManagementEnabled
  $lapsConfig['AutomaticAccountManagementTarget'] = $AutomaticAccountManagementTarget
  $lapsConfig['AutomaticAccountManagementNameOrPrefix'] = $AutomaticAccountManagementNameOrPrefix
  $lapsConfig['AutomaticAccountManagementRandomizeName'] = $AutomaticAccountManagementRandomizeName
  Write-Host "INFO: AutomaticAccountManagement enabled — LAPS will manage account '$AutomaticAccountManagementNameOrPrefix'."
}
else {
  $lapsConfig['AdministratorAccountName'] = $targetAccount
}

#endregion

#region --- APPLY ---

try {
  Set-LAPSRegistryPolicy -Config $lapsConfig -Path $RegPath
}
catch {
  Write-Error "Failed to write LAPS registry configuration: $($_.Exception.Message)"
  exit 1
}

#endregion

#region --- TRIGGER & VALIDATE ---

Write-Output 'INFO: Triggering LAPS policy processing...'
try {
  Invoke-LapsPolicyProcessing
  Write-Output 'INFO: Policy processing completed.'
}
catch {
  Write-Warning "Invoke-LapsPolicyProcessing failed: $($_.Exception.Message). LAPS may still apply on next cycle."
}

Write-Output 'INFO: Running LAPS diagnostics...'
try {
  Get-LapsDiagnosticsInfo
}
catch {
  Write-Warning "Get-LapsDiagnosticsInfo failed: $($_.Exception.Message)"
}

#endregion

#region --- OUTPUT DEVICE ID FOR RETRIEVAL ---

$deviceId = Get-EntraDeviceId
if ($deviceId) {
  Write-Output "INFO: Entra Device ID: $deviceId"
  Write-Output 'INFO: To retrieve the LAPS password, run from a device with Microsoft.Graph access:'
  Write-Output "      Get-LapsAADPassword -DeviceId '$deviceId' -IncludePasswords"
  Write-Output "      Or: Entra Admin Center > Devices > $env:COMPUTERNAME > Local administrator password"
}
else {
  Write-Warning 'Could not parse Device ID from dsregcmd. Verify Entra Join status manually.'
}

Write-Output 'INFO: LAPS configuration completed successfully.'
exit 0

#endregion