<#
.SYNOPSIS
    Ultimate Windows IR Initial Collection — Hybrid v3.0 (Action1 RMM)
.DESCRIPTION
    Action1-compatible variant. Forensic-first, read-only, SYSTEM-ready (32/64-bit safe).
    Full volatile (network, accounts, drivers, ETW, BITS, named pipes),
    exhaustive Defender/ASR posture (19 ASR rules + 11 Defender settings),
    dual-view registry, browser artifacts (extensions, history, RDP cache),
    persistence evidence (autorun, WMI repo, jump lists, recycle bin),
    dynamic MITRE gaps, hashed ZIP + sidecar.
.NOTES
    Forged by Joel @jstidley — February 2026
    Action1 variant: no #Requires, no CmdletBinding/param at script level.
    Action1 runs as SYSTEM — admin elevation is implicit.

Written by Joel Stidley - @joelst
#>

$ErrorActionPreference = 'Continue'

# ── Setup
$Start = Get-Date -Format 'yyyyMMdd_HHmmss'
$Root = 'C:\ProgramData\IR'
$Dir = Join-Path $Root "IR_$Start"
$HashManifest = [System.Collections.ArrayList]::new()
$Findings = [System.Collections.ArrayList]::new()
$Warnings = [System.Collections.ArrayList]::new()
$OfflineHints = [System.Collections.ArrayList]::new()

$HybridMode = $true
$CreateOfflineHints = $true
$CleanupWorkingDirectory = $true

New-Item -Path $Root -ItemType Directory -Force | Out-Null
New-Item -Path $Dir -ItemType Directory -Force | Out-Null

# Minimum recommended log sizes (bytes)
$RecSizes = @{
  'Security'                                                               = 268435456   # 256MB
  'System'                                                                 = 134217728   # 128MB
  'Application'                                                            = 134217728
  'Microsoft-Windows-PowerShell/Operational'                               = 134217728
  'Microsoft-Windows-WMI-Activity/Operational'                             = 67108864
  'Microsoft-Windows-WinRM/Operational'                                    = 67108864
  'Microsoft-Windows-TaskScheduler/Operational'                            = 67108864
  'Microsoft-Windows-Windows Defender/Operational'                         = 134217728
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'     = 67108864
  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 67108864
  'Microsoft-Windows-Sysmon/Operational'                                   = 268435456
}

# All current ASR rule GUIDs → names (Feb 2026)
$ASRRules = @{
  '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abused vulnerable signed drivers'
  '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader child processes'
  'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps creating child processes'
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
  'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
  '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless prevalence/age/trust'
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block obfuscated script execution'
  'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBS launching downloaded content'
  '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office creating executable content'
  '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office injected code'
  '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office comms app child processes'
  'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence via WMI event subscription'
  'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec/WMI'
  'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned USB processes'
  '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
  'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced ransomware protection'
  'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied/impersonated system tools'
  '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode (preview)'
  'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
}

# ── Helpers
function New-Folder {
  param([string]$path)
  $folderPath = Join-Path $Dir $path
  New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
  return $folderPath
}

function Add-Hash {
  param([string]$filePath)
  if (Test-Path $filePath) {
    $hash = (Get-FileHash $filePath -Algorithm SHA256).Hash
    $relativePath = $filePath.Replace($Dir, '').TrimStart('\')
    $fileItem = Get-Item $filePath
    [void]$HashManifest.Add([pscustomobject]@{
        SHA256 = $hash
        Path   = $relativePath
        Size   = $fileItem.Length
        Time   = (Get-Date).ToUniversalTime().ToString('o')
      })
  }
}

function Add-Finding {
  param(
    [string]$category,
    [string]$item,
    [string]$value,
    [string]$source,
    [string]$status
  )
  [void]$Findings.Add([pscustomobject]@{
      Category = $category
      Item     = $item
      Value    = $value
      Source   = $source
      Status   = $status
    })
  if ($status -in 'WARNING', 'CRITICAL') {
    [void]$Warnings.Add("[${status}] ${category} - ${item}: ${value} (${source})")
  }
}

function Get-HintNextStep {
  param([string]$category, [string]$item)

  switch -Wildcard ($item) {
    'TamperProtection' { return 'Validate tamper state and verify policy enforcement source (GPO/MDM).' }
    'RealTimeProtection' { return 'Confirm Defender RTP status and review exclusion tampering.' }
    'BehaviorMonitoring' { return 'Review Defender behavior monitoring disablement and policy drift.' }
    'Amcache.hve' { return 'Parse Amcache for execution evidence and compare against timeline.' }
    'Temp Suspicious Samples' { return 'Hash and detonate suspicious temp samples in isolated sandbox.' }
    '*Directories' { return 'Inspect tool directory contents for operator logs, config, and exfil traces.' }
    '*Services' { return 'Validate service binary paths and startup types for unauthorized remote tooling.' }
    '*Registry Exports' { return 'Review exported keys for persistence, beacon endpoints, and policy overrides.' }
    '*Events' { return 'Pivot provider events to Security/System logs for full session reconstruction.' }
    default {
      switch ($category) {
        'Defender' { return 'Validate security control posture and investigate downgrade/tamper indicators.' }
        'Artifacts' { return 'Correlate artifact with process, user, and network timeline.' }
        'EventLog' { return 'Cross-reference event channel health and retention to identify visibility gaps.' }
        default { return 'Review in offline triage and correlate against host timeline.' }
      }
    }
  }
}

function Add-OfflineHint {
  param(
    [string]$priority,
    [string]$category,
    [string]$item,
    [string]$value,
    [string]$source
  )

  [void]$OfflineHints.Add([pscustomobject]@{
      Priority          = $priority
      Category          = $category
      Item              = $item
      Value             = $value
      Source            = $source
      SuggestedNextStep = Get-HintNextStep -category $category -item $item
    })
}

function Read-RegDual {
  param([string]$regPath, [string]$valueName)
  $result = [pscustomobject]@{ Reg64 = $null; Reg32 = $null; Effective = $null; Source = 'NotConfigured' }
  foreach ($view in 'Registry64', 'Registry32') {
    try {
      $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', [Microsoft.Win32.RegistryView]::$view)
      $key = $base.OpenSubKey($regPath)
      if ($key) {
        $value = $key.GetValue($valueName, $null)
        if ($null -ne $value) { $result."$view" = $value }
        $key.Close()
      }
      $base.Close()
    }
    catch {}
  }
  if ($null -ne $result.Reg64) { $result.Effective = $result.Reg64; $result.Source = 'Registry64' }
  elseif ($null -ne $result.Reg32) { $result.Effective = $result.Reg32; $result.Source = 'Registry32' }
  return $result
}

function Invoke-SafeCommand {
  param(
    [string]$description,
    [string]$outputPath,
    [scriptblock]$scriptBlock
  )
  try {
    $data = & $scriptBlock 2>&1
    if ($outputPath) {
      $shouldWrite = $true
      if (Test-Path $outputPath) {
        $existing = Get-Item $outputPath
        if ($existing.Length -gt 0) { $shouldWrite = $false }
      }
      if ($shouldWrite -and $null -ne $data) {
        $data | Out-File $outputPath -Encoding UTF8
      }
      if (Test-Path $outputPath) { Add-Hash $outputPath }
    }
    return $data
  }
  catch {
    $msg = "Unavailable: $_"
    Write-Output "WARNING $description`: $msg"
    if ($outputPath) {
      $msg | Out-File $outputPath -Encoding UTF8
      Add-Hash $outputPath
    }
    Add-Finding 'Volatile' $description 'Modern cmdlet unavailable (fallback evidence may exist)' 'PowerShell' 'INFO'
  }
}

function Invoke-SafeSection {
  param([string]$description, [scriptblock]$scriptBlock)
  try {
    & $scriptBlock
  }
  catch {
    $msg = "Section failed: $_"
    Write-Output "ERROR $description`: $msg"
    Add-Finding 'Collection' $description 'Section failed' 'PowerShell' 'WARNING'
  }
}

function Invoke-WithoutDefaultParams {
  param([scriptblock]$scriptBlock)
  $previousDefaults = $PSDefaultParameterValues
  $PSDefaultParameterValues = @{}
  try { & $scriptBlock }
  finally { $PSDefaultParameterValues = $previousDefaults }
}

function Copy-LockedFile {
  param([string]$sourcePath, [string]$destinationPath, [string]$description)
  if (-not (Test-Path $sourcePath)) { return $false }
  try {
    Copy-Item $sourcePath $destinationPath -Force -ErrorAction Stop
    Add-Hash $destinationPath
    return $true
  }
  catch {
    $esent = Get-Command esentutl.exe -ErrorAction SilentlyContinue
    if ($null -ne $esent) {
      try {
        & $esent.Source /y $sourcePath /d $destinationPath /o 2>$null | Out-Null
        if (Test-Path $destinationPath) {
          Add-Hash $destinationPath
          Add-Finding 'Artifacts' $description 'Copied (esentutl)' 'esentutl' 'INFO'
          return $true
        }
      }
      catch {}

      try {
        & $esent.Source /y $sourcePath /d $destinationPath /o /vss 2>$null | Out-Null
        if (Test-Path $destinationPath) {
          Add-Hash $destinationPath
          Add-Finding 'Artifacts' $description 'Copied (esentutl /vss)' 'esentutl' 'INFO'
          return $true
        }
      }
      catch {}
    }

    $robocopy = Get-Command robocopy.exe -ErrorAction SilentlyContinue
    if ($null -ne $robocopy) {
      try {
        $sourceDirectory = Split-Path -Path $sourcePath -Parent
        $sourceFileName = Split-Path -Path $sourcePath -Leaf
        $destinationDirectory = Split-Path -Path $destinationPath -Parent
        New-Item -Path $destinationDirectory -ItemType Directory -Force | Out-Null

        & $robocopy.Source $sourceDirectory $destinationDirectory $sourceFileName /B /R:0 /W:0 /NFL /NDL /NJH /NJS /NP 2>$null | Out-Null
        if (Test-Path $destinationPath) {
          Add-Hash $destinationPath
          Add-Finding 'Artifacts' $description 'Copied (robocopy /B)' 'robocopy' 'INFO'
          return $true
        }
      }
      catch {}
    }

    Add-Finding 'Artifacts' $description 'Copy failed (file locked)' 'Filesystem' 'WARNING'
    return $false
  }
}

# ── Structure
$evtx = New-Folder 'EventLogs'
$vol = New-Folder 'Volatile'
$reg = New-Folder 'Registry'
$art = New-Folder 'Artifacts'
$post = New-Folder 'Posture'

# Metadata
$meta = Join-Path $Dir 'Metadata.txt'
@"
Collection: IR_$Start
UTC: $((Get-Date).ToUniversalTime())
Host: $env:COMPUTERNAME  User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
OS: $((Get-CimInstance Win32_OperatingSystem).Caption) Build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)
PS: $($PSVersionTable.PSVersion) Bitness: $([IntPtr]::Size*8)-bit
Source: Action1 RMM
Note: Interactive user HKCU hives not collected (SYSTEM context requires explicit profile load)
"@ | Out-File $meta -Encoding UTF8
Add-Hash $meta

Add-Finding 'Registry' 'HKCU (Interactive Users)' 'Not collected — SYSTEM context; requires loading user profiles' 'N/A' 'INFO'

# ── 1. Event Logs
Invoke-SafeSection -description 'Event Logs' -scriptBlock {
  $logs = 'Security', 'System', 'Application',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-WMI-Activity/Operational',
  'Microsoft-Windows-WinRM/Operational',
  'Microsoft-Windows-TaskScheduler/Operational',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'

  if (wevtutil el | Select-String -Quiet 'Sysmon') { $logs += 'Microsoft-Windows-Sysmon/Operational' }

  foreach ($l in $logs) {
    $safe = $l -replace '[/\\]', '_'
    $file = Join-Path $evtx "$safe.evtx"
    $gliOutput = & wevtutil gli $l 2>&1
    $gliExitCode = $LASTEXITCODE
    if ($gliExitCode -eq 0) {
      $eplOutput = & wevtutil epl $l $file /ow:true 2>&1
      $exitCode = $LASTEXITCODE
      if (Test-Path $file) {
        Add-Hash $file
      }
      else {
        Add-Finding 'EventLog' $l "Export failed (code $exitCode)" 'wevtutil' 'WARNING'
        if ($eplOutput) {
          $errFile = Join-Path $evtx "$safe.err.txt"
          $eplOutput | Out-File $errFile -Encoding UTF8
          Add-Hash $errFile
        }
      }
      $info = ($gliOutput | Out-String)
      if ($info -match '(?im)^\s*max\s*size\s*:\s*(\d+)\s*$|^\s*maxsize\s*:\s*(\d+)\s*$') {
        $sizeToken = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
        $size = [uint64]$sizeToken
      }
      else {
        $size = 0
      }

      $retFromCli = $info -match '(?im)^\s*retention\s*:\s*true\s*$'
      $autoBackupFromCli = $info -match '(?im)^\s*auto\s*backup\s*:\s*true\s*$|^\s*autobackup\s*:\s*true\s*$'
      $logConfig = Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue
      if ($size -eq 0 -and $null -ne $logConfig -and $logConfig.MaximumSizeInBytes) {
        $size = [uint64]$logConfig.MaximumSizeInBytes
      }
      $ret = $false
      if ($retFromCli -and -not $autoBackupFromCli) {
        $ret = $true
      }
      elseif ($null -ne $logConfig -and $logConfig.LogMode -eq 'Retain') {
        $ret = $true
      }
      $rec = $RecSizes[$l] / 1MB
      $cur = [math]::Round($size / 1MB)
      $stat = if ($size -lt $RecSizes[$l]) { 'WARNING' } else { 'OK' }
      Add-Finding 'EventLog' $l "$cur MB (rec ≥$rec MB)" 'wevtutil' $stat
      if ($ret) {
        Add-Finding 'EventLog' $l 'Retention enabled — log stops when full' 'wevtutil' 'WARNING'
        & wevtutil sl $l /rt:false 2>&1 | Out-Null
        Add-Finding 'EventLog' $l 'Set to overwrite oldest events' 'wevtutil' 'INFO'
      }
    }
    else {
      Add-Finding 'EventLog' $l 'Not present' 'N/A' 'WARNING'
    }
  }
}

# ── 2. PowerShell Logging
Invoke-SafeSection -description 'PowerShell Logging' -scriptBlock {
  $psChecks = @(
    @{Name = 'ScriptBlockLogging'; Path = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Val = 'EnableScriptBlockLogging'; Exp = 1 }
    @{Name = 'InvocationLogging'; Path = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Val = 'EnableScriptBlockInvocationLogging'; Exp = 1 }
    @{Name = 'ModuleLogging'; Path = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Val = 'EnableModuleLogging'; Exp = 1 }
    @{Name = 'Transcription'; Path = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Val = 'EnableTranscripting'; Exp = 1 }
  )

  foreach ($c in $psChecks) {
    $r = Read-RegDual $c.Path $c.Val
    $eff = if ($null -eq $r.Effective) { 'NotConfigured' } else { $r.Effective }
    $stat = if ($eff -eq 'NotConfigured' -or $eff -ne $c.Exp) { 'WARNING' } else { 'OK' }
    Add-Finding 'PowerShell' $c.Name $eff $r.Source $stat
  }

  Invoke-SafeCommand 'ExecutionPolicy' (Join-Path $vol 'ExecutionPolicy.txt') { Get-ExecutionPolicy -List | Out-String }
}

# ── 3. Defender Posture
Invoke-SafeSection -description 'Defender Posture' -scriptBlock {
  $t = Read-RegDual 'SOFTWARE\Microsoft\Windows Defender\Features' 'TamperProtection'
  $tamper = if ($null -eq $t.Effective) { 'NotConfigured' } elseif ($t.Effective -in 0, 4) { 'Disabled' } else { 'Enabled' }
  Add-Finding 'Defender' 'TamperProtection' $tamper $t.Source $(if ($tamper -like '*Disabled*') { 'CRITICAL' }else { 'OK' })

  $asrGlobal = Read-RegDual 'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' 'ExploitGuard_ASR_Rules'
  $globalVal = if ($null -ne $asrGlobal.Effective) { $asrGlobal.Effective } else { 'NotConfigured' }
  Add-Finding 'Defender' 'ASR Global Policy (heuristic)' "$globalVal — per-rule states authoritative" $asrGlobal.Source $(if ($globalVal -eq 1) { 'OK' }else { 'WARNING' })

  foreach ($guid in $ASRRules.Keys) {
    $pol = Read-RegDual 'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' $guid
    $prod = Read-RegDual 'SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' $guid
    $eff = if ($null -ne $pol.Effective) { $pol } else { $prod }
    $state = switch ($eff.Effective) { 0 { 'Disabled' }; 1 { 'Block' }; 2 { 'Audit' }; 6 { 'Warn' }; default { 'NotSet' } }
    $stat = if ($state -in 'Disabled', 'NotSet') { 'WARNING' } elseif ($state -eq 'Audit') { 'INFO' } else { 'OK' }
    Add-Finding 'Defender ASR' "$($ASRRules[$guid]) [$guid]" $state $eff.Source $stat
  }

  # Expanded Defender posture
  try {
    $mpPref = Get-MpPreference -ErrorAction Stop

    $np = switch ($mpPref.EnableNetworkProtection) { 0 { 'Disabled' }; 1 { 'Enabled' }; 2 { 'Audit' }; default { 'NotConfigured' } }
    Add-Finding 'Defender' 'NetworkProtection' $np 'Get-MpPreference' $(if ($np -ne 'Enabled') { 'WARNING' } else { 'OK' })

    $cfa = switch ($mpPref.EnableControlledFolderAccess) { 0 { 'Disabled' }; 1 { 'Enabled' }; 2 { 'Audit' }; default { 'NotConfigured' } }
    Add-Finding 'Defender' 'ControlledFolderAccess' $cfa 'Get-MpPreference' $(if ($cfa -ne 'Enabled') { 'WARNING' } else { 'OK' })

    $cbl = switch ($mpPref.CloudBlockLevel) { 0 { 'Default' }; 1 { 'Moderate' }; 2 { 'High' }; 4 { 'HighPlus' }; 6 { 'ZeroTolerance' }; default { "Unknown($($mpPref.CloudBlockLevel))" } }
    Add-Finding 'Defender' 'CloudBlockLevel' $cbl 'Get-MpPreference' $(if ($mpPref.CloudBlockLevel -lt 2) { 'WARNING' } else { 'OK' })

    $cet = $mpPref.CloudExtendedTimeout
    Add-Finding 'Defender' 'CloudExtendedTimeout' "${cet}s" 'Get-MpPreference' $(if ($cet -lt 50) { 'WARNING' } else { 'OK' })

    $rtp = if ($mpPref.DisableRealtimeMonitoring) { 'Disabled' } else { 'Enabled' }
    Add-Finding 'Defender' 'RealTimeProtection' $rtp 'Get-MpPreference' $(if ($rtp -eq 'Disabled') { 'CRITICAL' } else { 'OK' })

    $pua = switch ($mpPref.PUAProtection) { 0 { 'Disabled' }; 1 { 'Enabled' }; 2 { 'Audit' }; default { 'NotConfigured' } }
    Add-Finding 'Defender' 'PUAProtection' $pua 'Get-MpPreference' $(if ($pua -ne 'Enabled') { 'WARNING' } else { 'OK' })

    $bafs = if ($mpPref.DisableBlockAtFirstSeen) { 'Disabled' } else { 'Enabled' }
    Add-Finding 'Defender' 'BlockAtFirstSight' $bafs 'Get-MpPreference' $(if ($bafs -eq 'Disabled') { 'WARNING' } else { 'OK' })

    $maps = switch ($mpPref.MAPSReporting) { 0 { 'Disabled' }; 1 { 'Basic' }; 2 { 'Advanced' }; default { 'NotConfigured' } }
    Add-Finding 'Defender' 'MAPSReporting' $maps 'Get-MpPreference' $(if ($mpPref.MAPSReporting -lt 2) { 'WARNING' } else { 'OK' })

    $bm = if ($mpPref.DisableBehaviorMonitoring) { 'Disabled' } else { 'Enabled' }
    Add-Finding 'Defender' 'BehaviorMonitoring' $bm 'Get-MpPreference' $(if ($bm -eq 'Disabled') { 'CRITICAL' } else { 'OK' })

    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
      $sigAge = $mpStatus.AntivirusSignatureAge
      Add-Finding 'Defender' 'SignatureAge' "${sigAge} days" 'Get-MpComputerStatus' $(if ($sigAge -gt 3) { 'WARNING' } else { 'OK' })
      Add-Finding 'Defender' 'AMEngineVersion' $mpStatus.AMEngineVersion 'Get-MpComputerStatus' 'INFO'
    }
  }
  catch {
    Add-Finding 'Defender' 'Get-MpPreference' 'Unavailable — Defender cmdlets not present' 'PowerShell' 'WARNING'
  }

  $lsaPPL = Read-RegDual 'SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
  $lsaVal = if ($null -eq $lsaPPL.Effective) { 'NotConfigured' } else { $lsaPPL.Effective }
  Add-Finding 'Defender' 'LSA Protection (RunAsPPL)' $lsaVal $lsaPPL.Source $(if ($lsaVal -ne 1) { 'WARNING' } else { 'OK' })

  $credGuard = Read-RegDual 'SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity'
  $cgVal = if ($null -eq $credGuard.Effective) { 'NotConfigured' } else { $credGuard.Effective }
  Add-Finding 'Defender' 'Credential Guard (VBS)' $cgVal $credGuard.Source $(if ($cgVal -ne 1) { 'WARNING' } else { 'OK' })
}

# ── 3b. MDM & Policy Manager
Invoke-SafeSection -description 'MDM & Policy Manager' -scriptBlock {
  $mdmDst = New-Folder 'Posture\MDM'

  # Device join and MDM enrollment status
  Invoke-SafeCommand 'DSRegStatus' (Join-Path $mdmDst 'DSRegCmd_Status.txt') { dsregcmd /status 2>&1 | Out-String }

  # MDM Enrollment details
  $enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
  if (Test-Path $enrollPath) {
    $enrollCsv = Join-Path $mdmDst 'MDM_Enrollments.csv'
    $enrollments = Get-ChildItem $enrollPath -ErrorAction SilentlyContinue | ForEach-Object {
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      [pscustomobject]@{
        EnrollmentID    = $_.PSChildName
        ProviderID      = $props.ProviderID
        UPN             = $props.UPN
        AADResourceID   = $props.AADResourceID
        EnrollmentType  = $props.EnrollmentType
        EnrollmentState = $props.EnrollmentState
      }
    }
    $enrollments | Export-Csv -Path $enrollCsv -NoTypeInformation
    Add-Hash $enrollCsv
    $mdmCount = ($enrollments | Where-Object ProviderID).Count
    Add-Finding 'MDM' 'Enrollments' "$mdmCount enrollment(s) with a ProviderID" 'Registry' $(if ($mdmCount -gt 0) { 'INFO' } else { 'WARNING' })
  }
  else {
    Add-Finding 'MDM' 'Enrollments' 'No MDM enrollments found' 'Registry' 'INFO'
  }

  # PolicyManager current device — active MDM-pushed policies
  $pmCurrentPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
  if (Test-Path $pmCurrentPath) {
    $pmCsv = Join-Path $mdmDst 'PolicyManager_CurrentDevice.csv'
    $policies = Get-ChildItem $pmCurrentPath -ErrorAction SilentlyContinue | ForEach-Object {
      $area = $_.PSChildName
      $areaProps = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      if ($areaProps) {
        $areaProps.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
          [pscustomobject]@{
            PolicyArea = $area
            PolicyName = $_.Name
            Value      = ($_.Value | Out-String).Trim()
          }
        }
      }
    }
    if ($policies) {
      $policies | Export-Csv -Path $pmCsv -NoTypeInformation
      Add-Hash $pmCsv
      Add-Finding 'MDM' 'PolicyManager (current device)' "$($policies.Count) active MDM policies" 'Registry' 'INFO'
    }
  }
  else {
    Add-Finding 'MDM' 'PolicyManager (current device)' 'No PolicyManager policies found' 'Registry' 'INFO'
  }

  # PolicyManager providers — who is pushing policies
  $pmProvidersPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'
  if (Test-Path $pmProvidersPath) {
    $providersCsv = Join-Path $mdmDst 'PolicyManager_Providers.csv'
    $providers = Get-ChildItem $pmProvidersPath -ErrorAction SilentlyContinue | ForEach-Object {
      $providerGuid = $_.PSChildName
      $providerDevicePath = Join-Path $_.PSPath 'default\Device'
      $policyAreas = @()
      if (Test-Path $providerDevicePath) {
        $policyAreas = @((Get-ChildItem $providerDevicePath -ErrorAction SilentlyContinue).PSChildName)
      }
      [pscustomobject]@{
        ProviderGUID = $providerGuid
        PolicyAreas  = ($policyAreas -join ', ')
        AreaCount    = $policyAreas.Count
      }
    }
    if ($providers) {
      $providers | Export-Csv -Path $providersCsv -NoTypeInformation
      Add-Hash $providersCsv
      Add-Finding 'MDM' 'PolicyManager Providers' "$($providers.Count) provider(s)" 'Registry' 'INFO'
    }
  }

  # Full registry exports for offline analysis
  $regExportKeys = @(
    @{ Name = 'PolicyManager'; Key = 'HKLM\SOFTWARE\Microsoft\PolicyManager' }
    @{ Name = 'Enrollments'; Key = 'HKLM\SOFTWARE\Microsoft\Enrollments' }
    @{ Name = 'IntuneManagementExtension'; Key = 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension' }
    @{ Name = 'OMADM_Accounts'; Key = 'HKLM\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts' }
  )

  foreach ($export in $regExportKeys) {
    $psPath = $export.Key -replace '^HKLM\\', 'HKLM:\\'
    if (Test-Path $psPath) {
      $regFile = Join-Path $mdmDst "$($export.Name).reg"
      & reg.exe export $export.Key $regFile /y 2>$null | Out-Null
      if (Test-Path $regFile) {
        Add-Hash $regFile
        Add-Finding 'MDM' "$($export.Name) Registry Export" 'Exported for offline analysis' 'reg.exe' 'INFO'
      }
    }
    else {
      Add-Finding 'MDM' "$($export.Name) Registry Export" 'Key not present' 'Registry' 'INFO'
    }
  }

  # Intune Management Extension logs
  $imeLogs = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
  if (Test-Path $imeLogs) {
    $imeLogDst = New-Folder 'Posture\MDM\IME_Logs'
    Get-ChildItem $imeLogs -File -ErrorAction SilentlyContinue | ForEach-Object {
      Copy-Item $_.FullName (Join-Path $imeLogDst $_.Name) -Force -ErrorAction SilentlyContinue
      if (Test-Path (Join-Path $imeLogDst $_.Name)) { Add-Hash (Join-Path $imeLogDst $_.Name) }
    }
    $imeLogCount = (Get-ChildItem $imeLogDst -File -ErrorAction SilentlyContinue).Count
    Add-Finding 'MDM' 'Intune ME Logs' "$imeLogCount log file(s) collected" 'Filesystem' 'INFO'
  }
  else {
    Add-Finding 'MDM' 'Intune ME Logs' 'IME log directory not present' 'Filesystem' 'INFO'
  }
}

# ── 4. Volatile
Invoke-SafeSection -description 'Volatile Data' -scriptBlock {
  $processesPath = Join-Path $vol 'Processes.csv'
  Invoke-SafeCommand 'Processes' $processesPath {
    Invoke-WithoutDefaultParams {
      Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine, CreationDate | Export-Csv -Path $processesPath -NoTypeInformation
    }
  }

  $servicesPath = Join-Path $vol 'Services.csv'
  Invoke-SafeCommand 'Services' $servicesPath {
    Invoke-WithoutDefaultParams {
      Get-CimInstance Win32_Service | Select-Object Name, State, StartMode, PathName | Export-Csv -Path $servicesPath -NoTypeInformation
    }
  }

  Invoke-SafeCommand 'Netstat' (Join-Path $vol 'Netstat.txt') { netstat -anob }
  Invoke-SafeCommand 'NetSession' (Join-Path $vol 'NetSession.txt') { net session }
  Invoke-SafeCommand 'NetShare' (Join-Path $vol 'NetShare.txt') { net share }

  Invoke-SafeCommand 'IPConfig' (Join-Path $vol 'IPConfig.txt') { ipconfig /all }
  Invoke-SafeCommand 'DNSCache' (Join-Path $vol 'DNSCache.txt') { Get-DnsClientCache | Format-Table -AutoSize | Out-String -Width 300 }
  Invoke-SafeCommand 'ARPTable' (Join-Path $vol 'ARPTable.txt') { arp -a }
  Invoke-SafeCommand 'RouteTable' (Join-Path $vol 'RouteTable.txt') { route print }

  $localUsersPath = Join-Path $vol 'LocalUsers.csv'
  Invoke-SafeCommand 'LocalUsers' $localUsersPath {
    Invoke-WithoutDefaultParams {
      Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, UserMayChangePassword, AccountExpires, SID |
        Export-Csv -Path $localUsersPath -NoTypeInformation
    }
  }

  $localGroupsPath = Join-Path $vol 'LocalGroups.csv'
  Invoke-SafeCommand 'LocalGroups' $localGroupsPath {
    Invoke-WithoutDefaultParams {
      $groups = Get-LocalGroup
      $members = foreach ($g in $groups) {
        try {
          Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Group = $g.Name; Name = $_.Name; ObjectClass = $_.ObjectClass; PrincipalSource = $_.PrincipalSource; SID = $_.SID }
          }
        }
        catch {}
      }
      $members | Export-Csv -Path $localGroupsPath -NoTypeInformation
    }
  }

  Invoke-SafeCommand 'LoggedOnUsers' (Join-Path $vol 'LoggedOnUsers.txt') {
    $output = query user 2>&1
    if ($LASTEXITCODE -ne 0) { 'No interactive sessions' } else { $output }
  }
  Invoke-SafeCommand 'RDPSessions' (Join-Path $vol 'RDPSessions.txt') {
    $output = qwinsta 2>&1
    if ($LASTEXITCODE -ne 0) { 'No RDP sessions' } else { $output }
  }

  $hotfixPath = Join-Path $vol 'Hotfixes.csv'
  Invoke-SafeCommand 'Hotfixes' $hotfixPath {
    Invoke-WithoutDefaultParams {
      Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn | Export-Csv -Path $hotfixPath -NoTypeInformation
    }
  }

  $installedSoftwarePath = Join-Path $vol 'InstalledSoftware.csv'
  Invoke-SafeCommand 'InstalledSoftware' $installedSoftwarePath {
    Invoke-WithoutDefaultParams {
      $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
      )
      Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString |
        Sort-Object DisplayName |
        Export-Csv -Path $installedSoftwarePath -NoTypeInformation
    }
  }

  Invoke-SafeCommand 'AuditPolicy' (Join-Path $vol 'AuditPolicy.txt') { auditpol /get /category:* }

  $gprPath = Join-Path $vol 'GPResult.html'
  Invoke-SafeCommand 'GPResult' $null { gpresult /H $gprPath /F 2>&1 }
  if (Test-Path $gprPath) { Add-Hash $gprPath }

  Invoke-SafeCommand 'NamedPipes' (Join-Path $vol 'NamedPipes.txt') {
    Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Select-Object Name | Sort-Object Name | Out-String
  }

  $driversPath = Join-Path $vol 'Drivers.csv'
  Invoke-SafeCommand 'Drivers' $driversPath {
    Invoke-WithoutDefaultParams {
      Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, State, StartMode, PathName |
        Export-Csv -Path $driversPath -NoTypeInformation
    }
  }

  $envPath = Join-Path $vol 'Environment.csv'
  Invoke-SafeCommand 'Environment' $envPath {
    Invoke-WithoutDefaultParams {
      Get-ChildItem Env: | Select-Object Name, Value | Export-Csv -Path $envPath -NoTypeInformation
    }
  }

  Invoke-SafeCommand 'ETWSessions' (Join-Path $vol 'ETWSessions.txt') { logman query -ets 2>&1 | Out-String }
  Invoke-SafeCommand 'ShadowCopies' (Join-Path $vol 'ShadowCopies.txt') { vssadmin list shadows 2>&1 | Out-String }

  $bitsPath = Join-Path $vol 'BITSJobs.csv'
  Invoke-SafeCommand 'BITSJobs' $bitsPath {
    Invoke-WithoutDefaultParams {
      Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
        Select-Object DisplayName, JobState, TransferType, FileList, OwnerAccount, CreationTime |
        Export-Csv -Path $bitsPath -NoTypeInformation
    }
  }

  $smbSessionsPath = Join-Path $vol 'SMBSessions.csv'
  Invoke-SafeCommand 'SMBSessions' $smbSessionsPath {
    Invoke-WithoutDefaultParams {
      Get-SmbSession | Export-Csv -Path $smbSessionsPath -NoTypeInformation
    }
  }

  $smbOpenFilesPath = Join-Path $vol 'SMBOpenFiles.csv'
  Invoke-SafeCommand 'SMBOpenFiles' $smbOpenFilesPath {
    Invoke-WithoutDefaultParams {
      Get-SmbOpenFile | Export-Csv -Path $smbOpenFilesPath -NoTypeInformation
    }
  }

  $scheduledTasksPath = Join-Path $vol 'ScheduledTasks.xml'
  Invoke-SafeCommand 'ScheduledTasks' $scheduledTasksPath {
    Invoke-WithoutDefaultParams {
      Get-ScheduledTask | Export-Clixml -Path $scheduledTasksPath -Depth 4
    }
  }

  $firewallRulesPath = Join-Path $vol 'FirewallRules.csv'
  Invoke-SafeCommand 'FirewallRules' $firewallRulesPath {
    Invoke-WithoutDefaultParams {
      Get-NetFirewallRule -Enabled True | Export-Csv -Path $firewallRulesPath -NoTypeInformation
    }
  }
}

# ── 5. Registry Hives
Invoke-SafeSection -description 'Registry Hives' -scriptBlock {
  $hives = 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY'
  foreach ($h in $hives) {
    $file = Join-Path $reg "$h.hiv"
    reg save "HKLM\$h" $file /y | Out-Null
    if (Test-Path $file) { Add-Hash $file }
  }

  $def = "$env:SystemDrive\Users\Default\NTUSER.DAT"
  if (Test-Path $def) {
    Copy-Item $def (Join-Path $reg 'NTUSER_DEFAULT.hiv') -Force
    Add-Hash (Join-Path $reg 'NTUSER_DEFAULT.hiv')
    Add-Finding 'Registry' 'Default User Profile' 'NTUSER_DEFAULT.hiv collected' 'Filesystem' 'INFO'
  }
}

# ── 6. Artifacts
Invoke-SafeSection -description 'Artifacts' -scriptBlock {
  $pfSrc = "$env:SystemRoot\Prefetch"
  if (Test-Path $pfSrc) {
    $pfDst = New-Folder 'Artifacts\Prefetch'
    Get-ChildItem "$pfSrc\*.pf" | Copy-Item -Destination $pfDst -Force
    foreach ($pf in (Get-ChildItem $pfDst)) {
      Add-Hash $pf.FullName
    }
  }

  $amPathCandidates = @(
    "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    "$env:windir\appcompat\Programs\Amcache.hve"
  ) | Select-Object -Unique
  $am = $amPathCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

  if ($am) {
    $amDest = Join-Path $art 'Amcache.hve'
    $amCopied = Copy-LockedFile -sourcePath $am -destinationPath $amDest -description 'Amcache.hve'
    if ($amCopied) {
      Add-Finding 'Artifacts' 'Amcache.hve' 'Collected' 'Filesystem' 'INFO'
    }
    else {
      $amRegCopied = $false
      $amRegKeyExists = Test-Path 'HKLM:\AMCACHE'
      $amRegSaveExitCode = $null
      if ($amRegKeyExists) {
        Remove-Item -Path $amDest -Force -ErrorAction SilentlyContinue
        & reg.exe save HKLM\AMCACHE $amDest /y 2>$null | Out-Null
        $amRegSaveExitCode = $LASTEXITCODE
        if (Test-Path $amDest) {
          Add-Hash $amDest
          Add-Finding 'Artifacts' 'Amcache.hve' 'Collected (reg save HKLM\AMCACHE)' 'reg.exe' 'INFO'
          $amRegCopied = $true
        }
      }

      $amShadowCopied = $false
      $amVssReturnValue = $null
      $amVssCreateError = $null
      $amVssDeviceObject = $null
      $amVssShadowPathExists = $false
      if (-not $amRegCopied) {
        try {
          $shadowCreate = Invoke-WmiMethod -Class Win32_ShadowCopy -Name Create -ArgumentList @($env:SystemDrive, 'ClientAccessible') -ErrorAction Stop
          $amVssReturnValue = $shadowCreate.ReturnValue
          if ($shadowCreate.ReturnValue -eq 0 -and $shadowCreate.ShadowID) {
            $shadowInstance = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue |
              Where-Object { $_.ID -eq $shadowCreate.ShadowID } |
              Select-Object -First 1

            if ($shadowInstance -and $shadowInstance.DeviceObject) {
              $amVssDeviceObject = $shadowInstance.DeviceObject
              $shadowAmcache = Join-Path $shadowInstance.DeviceObject 'Windows\AppCompat\Programs\Amcache.hve'
              $amVssShadowPathExists = Test-Path $shadowAmcache
              if (Test-Path $shadowAmcache) {
                Remove-Item -Path $amDest -Force -ErrorAction SilentlyContinue
                Copy-Item -Path $shadowAmcache -Destination $amDest -Force -ErrorAction SilentlyContinue
                if (Test-Path $amDest) {
                  Add-Hash $amDest
                  Add-Finding 'Artifacts' 'Amcache.hve' 'Collected (VSS shadow copy)' 'WMI Win32_ShadowCopy' 'INFO'
                  $amShadowCopied = $true
                }
              }

              Invoke-WmiMethod -InputObject $shadowInstance -Name Delete -ErrorAction SilentlyContinue | Out-Null
            }
          }
        }
        catch {
          $amVssCreateError = $_.Exception.Message
        }
      }

      if (-not $amRegCopied -and -not $amShadowCopied) {
        $amDiag = Join-Path $art 'Amcache_Collection_Status.txt'
        @(
          'Amcache collection failed.'
          "Source attempted: $am"
          'Fallbacks attempted: Copy-Item, esentutl, robocopy /B, reg save HKLM\\AMCACHE, VSS shadow copy'
          "Registry key HKLM\\AMCACHE exists: $amRegKeyExists"
          "reg.exe save exit code: $amRegSaveExitCode"
          "VSS create return value: $amVssReturnValue"
          "VSS device object: $amVssDeviceObject"
          "VSS Amcache path exists: $amVssShadowPathExists"
          "VSS exception: $amVssCreateError"
        ) | Out-File -FilePath $amDiag -Encoding UTF8
        Add-Hash $amDiag
        Add-Finding 'Artifacts' 'Amcache.hve' 'Present but could not be copied' 'Filesystem' 'WARNING'

        $amParent = Split-Path -Path $am -Parent
        $amBase = Split-Path -Path $am -Leaf
        $amSidecars = @(
          "$amBase.LOG1",
          "$amBase.LOG2"
        )
        $sidecarCopied = 0
        foreach ($sidecar in $amSidecars) {
          $sidecarSource = Join-Path $amParent $sidecar
          $sidecarDest = Join-Path $art $sidecar
          if (Copy-LockedFile -sourcePath $sidecarSource -destinationPath $sidecarDest -description "Amcache sidecar $sidecar") {
            $sidecarCopied++
          }
        }
        Add-Finding 'Artifacts' 'Amcache sidecar logs' "$sidecarCopied copied" 'Filesystem' 'INFO'
      }
    }
  }
  else {
    Add-Finding 'Artifacts' 'Amcache.hve' 'Missing' 'Filesystem' 'INFO'
    $amDiag = Join-Path $art 'Amcache_Collection_Status.txt'
    @(
      'Amcache not found at expected paths.'
      "Checked: $($amPathCandidates -join '; ')"
    ) | Out-File -FilePath $amDiag -Encoding UTF8
    Add-Hash $amDiag
  }

  $srum = "$env:SystemRoot\System32\sru\SRUDB.dat"
  if (Test-Path $srum) {
    $srumDest = Join-Path $art 'SRUDB.dat'
    [void](Copy-LockedFile -sourcePath $srum -destinationPath $srumDest -description 'SRUDB.dat')
  }

  $wmiRepo = "$env:SystemRoot\System32\wbem\Repository\OBJECTS.DATA"
  if (Test-Path $wmiRepo) {
    $wmiDest = Join-Path $art 'OBJECTS.DATA'
    [void](Copy-LockedFile -sourcePath $wmiRepo -destinationPath $wmiDest -description 'WMI Repository')
  }

  $usbPath = Join-Path $art 'USBHistory.csv'
  Invoke-SafeCommand 'USBHistory' $usbPath {
    Invoke-WithoutDefaultParams {
      $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
      if (Test-Path $regPath) {
        $devices = Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
          $deviceKey = $_
          Get-ChildItem $deviceKey.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $serial = $_.PSChildName
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            [pscustomobject]@{
              Device       = $deviceKey.PSChildName
              SerialNumber = $serial
              FriendlyName = $props.FriendlyName
              LastSeen     = if ($props.LastArrivalDate) { $props.LastArrivalDate } else { 'Unknown' }
            }
          }
        }
        $devices | Export-Csv -Path $usbPath -NoTypeInformation
      }
    }
  }

  $histDst = New-Folder 'Artifacts\PSHistory'
  $profileRoot = "$env:SystemDrive\Users"
  Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $histFile = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $histFile) {
      $destName = "$($_.Name)_ConsoleHost_history.txt"
      Copy-Item $histFile (Join-Path $histDst $destName) -Force -ErrorAction SilentlyContinue
      if (Test-Path (Join-Path $histDst $destName)) {
        Add-Hash (Join-Path $histDst $destName)
        Add-Finding 'Artifacts' "PSHistory ($($_.Name))" 'Collected' 'Filesystem' 'INFO'
      }
    }
  }

  $browserDst = New-Folder 'Artifacts\BrowserExtensions'
  Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $user = $_.Name
    $userPath = $_.FullName

    $chromeExt = Join-Path $userPath 'AppData\Local\Google\Chrome\User Data\Default\Extensions'
    if (Test-Path $chromeExt) {
      $extList = Get-ChildItem $chromeExt -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extId = $_.Name
        $manifest = Get-ChildItem $_.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue | Select-Object -First 1
        $name = $extId
        if ($manifest) {
          try {
            $mj = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($mj.name -and $mj.name -notmatch '^__MSG_') { $name = $mj.name }
          }
          catch {}
        }
        [pscustomobject]@{ User = $user; Browser = 'Chrome'; ExtensionId = $extId; Name = $name }
      }
      if ($extList) {
        $extFile = Join-Path $browserDst "${user}_Chrome_Extensions.csv"
        $extList | Export-Csv -Path $extFile -NoTypeInformation
        Add-Hash $extFile
      }
    }

    $edgeExt = Join-Path $userPath 'AppData\Local\Microsoft\Edge\User Data\Default\Extensions'
    if (Test-Path $edgeExt) {
      $extList = Get-ChildItem $edgeExt -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extId = $_.Name
        $manifest = Get-ChildItem $_.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue | Select-Object -First 1
        $name = $extId
        if ($manifest) {
          try {
            $mj = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($mj.name -and $mj.name -notmatch '^__MSG_') { $name = $mj.name }
          }
          catch {}
        }
        [pscustomobject]@{ User = $user; Browser = 'Edge'; ExtensionId = $extId; Name = $name }
      }
      if ($extList) {
        $extFile = Join-Path $browserDst "${user}_Edge_Extensions.csv"
        $extList | Export-Csv -Path $extFile -NoTypeInformation
        Add-Hash $extFile
      }
    }

    $ffProfiles = Join-Path $userPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (Test-Path $ffProfiles) {
      Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extJson = Join-Path $_.FullName 'extensions.json'
        if (Test-Path $extJson) {
          $destName = "${user}_Firefox_$($_.Name)_extensions.json"
          Copy-Item $extJson (Join-Path $browserDst $destName) -Force -ErrorAction SilentlyContinue
          if (Test-Path (Join-Path $browserDst $destName)) { Add-Hash (Join-Path $browserDst $destName) }
        }
      }
    }
  }

  $browserHistDst = New-Folder 'Artifacts\BrowserHistory'
  Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $user = $_.Name
    $userPath = $_.FullName

    $chromeHist = Join-Path $userPath 'AppData\Local\Google\Chrome\User Data\Default\History'
    if (Test-Path $chromeHist) {
      [void](Copy-LockedFile -sourcePath $chromeHist -destinationPath (Join-Path $browserHistDst "${user}_Chrome_History") -description "Chrome History ($user)")
    }

    $edgeHist = Join-Path $userPath 'AppData\Local\Microsoft\Edge\User Data\Default\History'
    if (Test-Path $edgeHist) {
      [void](Copy-LockedFile -sourcePath $edgeHist -destinationPath (Join-Path $browserHistDst "${user}_Edge_History") -description "Edge History ($user)")
    }

    $ffProfiles = Join-Path $userPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
    if (Test-Path $ffProfiles) {
      Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $places = Join-Path $_.FullName 'places.sqlite'
        if (Test-Path $places) {
          [void](Copy-LockedFile -sourcePath $places -destinationPath (Join-Path $browserHistDst "${user}_Firefox_$($_.Name)_places.sqlite") -description "Firefox History ($user)")
        }
      }
    }
  }

  $tempDst = New-Folder 'Artifacts\Temp'
  $tempSampleDst = New-Folder 'Artifacts\Temp\SuspiciousSamples'
  $tempInventoryPath = Join-Path $tempDst 'TempInventory.csv'
  $tempRoots = [System.Collections.Generic.List[string]]::new()
  foreach ($path in @("$env:SystemRoot\Temp", "$env:SystemDrive\Temp", $env:TEMP)) {
    if ($path -and -not $tempRoots.Contains($path)) {
      [void]$tempRoots.Add($path)
    }
  }

  Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $userTemp = Join-Path $_.FullName 'AppData\Local\Temp'
    if (-not $tempRoots.Contains($userTemp)) {
      [void]$tempRoots.Add($userTemp)
    }
  }

  $tempCutoff = (Get-Date).AddDays(-7)
  $tempRootFileLimit = 2000
  $tempInventoryLimit = 5000
  $tempSuspiciousSampleLimit = 300
  $suspiciousExtensions = @('.exe', '.dll', '.sys', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.wsh', '.hta', '.scr', '.lnk', '.zip', '.7z', '.rar', '.iso', '.cab', '.msi')

  $tempInventory = foreach ($tempRoot in $tempRoots) {
    if (Test-Path $tempRoot) {
      Get-ChildItem $tempRoot -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $tempCutoff } |
        Select-Object -First $tempRootFileLimit |
        ForEach-Object {
          [pscustomobject]@{
            FullPath         = $_.FullName
            Size             = $_.Length
            CreationTimeUtc  = $_.CreationTimeUtc
            LastWriteTimeUtc = $_.LastWriteTimeUtc
            Extension        = $_.Extension
            IsSuspicious     = ($suspiciousExtensions -contains $_.Extension.ToLowerInvariant())
          }
        }
    }
  }

  if ($tempInventory) {
    $tempInventory = $tempInventory |
      Sort-Object LastWriteTimeUtc -Descending |
      Select-Object -First $tempInventoryLimit

    $tempInventory | Export-Csv -Path $tempInventoryPath -NoTypeInformation
    Add-Hash $tempInventoryPath
    Add-Finding 'Artifacts' 'Temp Inventory' "$($tempInventory.Count) recent files (last 7 days)" 'Filesystem' 'INFO'

    $suspiciousTemp = $tempInventory |
      Where-Object { $_.IsSuspicious } |
      Select-Object -First $tempSuspiciousSampleLimit

    $tempCopied = 0
    $tempIndex = 0
    foreach ($tempItem in $suspiciousTemp) {
      $tempIndex++
      $sanitizedBaseName = [System.IO.Path]::GetFileName($tempItem.FullPath) -replace '[^A-Za-z0-9._-]', '_'
      $tempSampleName = '{0:D4}_{1}' -f $tempIndex, $sanitizedBaseName
      $tempSamplePath = Join-Path $tempSampleDst $tempSampleName
      Copy-Item -Path $tempItem.FullPath -Destination $tempSamplePath -Force -ErrorAction SilentlyContinue
      if (Test-Path $tempSamplePath) {
        Add-Hash $tempSamplePath
        $tempCopied++
      }
    }

    Add-Finding 'Artifacts' 'Temp Suspicious Samples' "$tempCopied copied / $($suspiciousTemp.Count) selected" 'Filesystem' 'INFO'
  }
  else {
    Add-Finding 'Artifacts' 'Temp Inventory' 'No recent temp files found (last 7 days)' 'Filesystem' 'INFO'
  }

  $rdpCacheDst = New-Folder 'Artifacts\RDPCache'
  Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $rdpCache = Join-Path $_.FullName 'AppData\Local\Microsoft\Terminal Server Client\Cache'
    if (Test-Path $rdpCache) {
      $cacheFiles = Get-ChildItem $rdpCache -File -ErrorAction SilentlyContinue
      foreach ($cf in $cacheFiles) {
        $destName = "$($_.Name)_$($cf.Name)"
        Copy-Item $cf.FullName (Join-Path $rdpCacheDst $destName) -Force -ErrorAction SilentlyContinue
        if (Test-Path (Join-Path $rdpCacheDst $destName)) { Add-Hash (Join-Path $rdpCacheDst $destName) }
      }
    }
  }

  $werSrc = "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
  if (Test-Path $werSrc) {
    $werDst = New-Folder 'Artifacts\WER'
    $werReports = Get-ChildItem $werSrc -Directory -ErrorAction SilentlyContinue | Select-Object -First 50
    foreach ($report in $werReports) {
      $reportDst = Join-Path $werDst $report.Name
      New-Item -Path $reportDst -ItemType Directory -Force | Out-Null
      Get-ChildItem $report.FullName -File -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $reportDst $_.Name) -Force -ErrorAction SilentlyContinue
        if (Test-Path (Join-Path $reportDst $_.Name)) { Add-Hash (Join-Path $reportDst $_.Name) }
      }
    }
    Add-Finding 'Artifacts' 'WER Reports' "$($werReports.Count) reports collected" 'Filesystem' 'INFO'
  }

  $recycleDst = New-Folder 'Artifacts\RecycleBin'
  $recycleBin = "$env:SystemDrive\`$Recycle.Bin"
  if (Test-Path $recycleBin) {
    Get-ChildItem $recycleBin -Recurse -Filter '$I*' -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $sidFolder = $_.Directory.Name
      $destName = "${sidFolder}_$($_.Name)"
      Copy-Item $_.FullName (Join-Path $recycleDst $destName) -Force -ErrorAction SilentlyContinue
      if (Test-Path (Join-Path $recycleDst $destName)) { Add-Hash (Join-Path $recycleDst $destName) }
    }
  }

  $jumpDst = New-Folder 'Artifacts\JumpLists'
  Get-ChildItem $profileRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $autoDestPath = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'
    if (Test-Path $autoDestPath) {
      Get-ChildItem $autoDestPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        $destName = "$($_.Directory.Parent.Parent.Parent.Parent.Parent.Name)_$($_.Name)"
        Copy-Item $_.FullName (Join-Path $jumpDst $destName) -Force -ErrorAction SilentlyContinue
        if (Test-Path (Join-Path $jumpDst $destName)) { Add-Hash (Join-Path $jumpDst $destName) }
      }
    }
  }

  $autorunPath = Join-Path $art 'AutoRunKeys.csv'
  Invoke-SafeCommand 'AutoRunKeys' $autorunPath {
    Invoke-WithoutDefaultParams {
      $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
      )
      $results = foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
          $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
          $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            [pscustomobject]@{ Key = $rk; Name = $_.Name; Value = $_.Value }
          }
        }
      }
      $results | Export-Csv -Path $autorunPath -NoTypeInformation
    }
  }

  $blPath = Join-Path $art 'BitLocker.csv'
  Invoke-SafeCommand 'BitLocker' $blPath {
    Invoke-WithoutDefaultParams {
      Get-BitLockerVolume -ErrorAction SilentlyContinue |
        Select-Object MountPoint, VolumeStatus, EncryptionMethod, EncryptionPercentage, ProtectionStatus, LockStatus, KeyProtector |
        Export-Csv -Path $blPath -NoTypeInformation
    }
  }

  $certPath = Join-Path $art 'Certificates.csv'
  Invoke-SafeCommand 'Certificates' $certPath {
    Invoke-WithoutDefaultParams {
      $stores = @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher', 'Cert:\LocalMachine\CA')
      $certs = foreach ($store in $stores) {
        if (Test-Path $store) {
          Get-ChildItem $store -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
              Store      = $store.Replace('Cert:\LocalMachine\', '')
              Subject    = $_.Subject
              Issuer     = $_.Issuer
              Thumbprint = $_.Thumbprint
              NotBefore  = $_.NotBefore
              NotAfter   = $_.NotAfter
              HasPrivKey = $_.HasPrivateKey
            }
          }
        }
      }
      $certs | Export-Csv -Path $certPath -NoTypeInformation
    }
  }

  # Remote access tool artifacts (logs + config)
  $remoteToolsRoot = New-Folder 'Artifacts\RemoteAccess'
  $remoteSearchRoots = @(
    "${env:ProgramFiles(x86)}"
    $env:ProgramFiles
    $env:ProgramData
    "$env:SystemRoot\Temp"
  ) | Where-Object { $_ }
  $remoteFileExtensions = @('.log', '.txt', '.db', '.xml', '.config', '.json', '.ini')
  $remoteMaxFilesPerDirectory = 300
  $remoteEventScanMax = 5000
  $remoteEventExportMax = 500
  $remoteEventStart = (Get-Date).AddDays(-30)

  $applicationEvents = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $remoteEventStart } -MaxEvents $remoteEventScanMax -ErrorAction SilentlyContinue

  $remoteTools = @(
    @{
      Name                  = 'Action1'
      DirectoryPatterns     = @('Action1*')
      ServicePatterns       = @('Action1*')
      RegistryKeys          = @('HKLM\SOFTWARE\Action1', 'HKLM\SOFTWARE\WOW6432Node\Action1')
      EventPatterns         = @('Action1*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'Bomgar_BeyondTrust'
      DirectoryPatterns     = @('Bomgar*', 'BeyondTrust*')
      ServicePatterns       = @('bomgar*', 'beyondtrust*')
      RegistryKeys          = @('HKLM\SOFTWARE\Bomgar', 'HKLM\SOFTWARE\BeyondTrust', 'HKLM\SOFTWARE\WOW6432Node\Bomgar', 'HKLM\SOFTWARE\WOW6432Node\BeyondTrust')
      EventPatterns         = @('Bomgar*', 'BeyondTrust*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'TeamViewer'
      DirectoryPatterns     = @('TeamViewer*')
      ServicePatterns       = @('TeamViewer*')
      RegistryKeys          = @('HKLM\SOFTWARE\TeamViewer', 'HKLM\SOFTWARE\WOW6432Node\TeamViewer')
      EventPatterns         = @('TeamViewer*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'ScreenConnect'
      DirectoryPatterns     = @('ScreenConnect*', 'ConnectWise*')
      ServicePatterns       = @('ScreenConnect*', 'ScreenConnect Client*')
      RegistryKeys          = @('HKLM\SOFTWARE\ScreenConnect Client', 'HKLM\SOFTWARE\ConnectWiseControl', 'HKLM\SOFTWARE\WOW6432Node\ScreenConnect Client', 'HKLM\SOFTWARE\WOW6432Node\ConnectWiseControl')
      EventPatterns         = @('ScreenConnect*', 'ConnectWise*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'VNC_RealVNC'
      DirectoryPatterns     = @('RealVNC*', 'VNC*')
      ServicePatterns       = @('vnc*', 'VNC*', 'RFB*')
      RegistryKeys          = @('HKLM\SOFTWARE\RealVNC', 'HKLM\SOFTWARE\WOW6432Node\RealVNC')
      EventPatterns         = @('VNC*', 'RealVNC*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'VNC_TightVNC'
      DirectoryPatterns     = @('TightVNC*', 'tvnserver*', 'tvnviewer*')
      ServicePatterns       = @('tvnserver*', 'TightVNC*')
      RegistryKeys          = @('HKLM\SOFTWARE\TightVNC', 'HKLM\SOFTWARE\WOW6432Node\TightVNC')
      EventPatterns         = @('TightVNC*', 'tvnserver*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'VNC_UltraVNC'
      DirectoryPatterns     = @('UltraVNC*', 'uvnc*')
      ServicePatterns       = @('uvnc*', 'UltraVNC*')
      RegistryKeys          = @('HKLM\SOFTWARE\UltraVNC', 'HKLM\SOFTWARE\WOW6432Node\UltraVNC')
      EventPatterns         = @('UltraVNC*', 'uvnc*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'VNC_TigerVNC'
      DirectoryPatterns     = @('TigerVNC*', 'winvnc*')
      ServicePatterns       = @('TigerVNC*', 'winvnc*')
      RegistryKeys          = @('HKLM\SOFTWARE\TigerVNC', 'HKLM\SOFTWARE\WOW6432Node\TigerVNC')
      EventPatterns         = @('TigerVNC*', 'winvnc*')
      UserDirectorySuffixes = @()
    }
    @{
      Name                  = 'RustDesk'
      DirectoryPatterns     = @('RustDesk*')
      ServicePatterns       = @('RustDesk*')
      RegistryKeys          = @('HKLM\SOFTWARE\RustDesk', 'HKLM\SOFTWARE\WOW6432Node\RustDesk')
      EventPatterns         = @('RustDesk*')
      UserDirectorySuffixes = @('AppData\Roaming\RustDesk', 'AppData\Local\RustDesk')
    }
    @{
      Name                  = 'ChromeRemoteDesktop'
      DirectoryPatterns     = @('Chrome Remote Desktop*', 'ChromeRemoteDesktop*', 'Chromoting*')
      ServicePatterns       = @('ChromeRemoteDesktop*', 'chromoting*')
      RegistryKeys          = @('HKLM\SOFTWARE\Google\Chrome Remote Desktop', 'HKLM\SOFTWARE\WOW6432Node\Google\Chrome Remote Desktop')
      EventPatterns         = @('Chrome*Remote*Desktop*', 'Chromoting*')
      UserDirectorySuffixes = @('AppData\Local\Google\Chrome Remote Desktop', 'AppData\Local\Chromoting', 'AppData\Roaming\Chromoting')
    }
  )

  foreach ($tool in $remoteTools) {
    $toolSafeName = ($tool.Name -replace '[^A-Za-z0-9_-]', '_')
    $toolDst = New-Folder ("Artifacts\RemoteAccess\$toolSafeName")

    $toolDirectories = foreach ($rootPath in $remoteSearchRoots) {
      if (Test-Path $rootPath) {
        foreach ($pattern in $tool.DirectoryPatterns) {
          Get-ChildItem $rootPath -Directory -Filter $pattern -ErrorAction SilentlyContinue
        }
      }
    }

    if ($tool.UserDirectorySuffixes -and $tool.UserDirectorySuffixes.Count -gt 0) {
      Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($suffix in $tool.UserDirectorySuffixes) {
          $candidatePath = Join-Path $_.FullName $suffix
          if (Test-Path $candidatePath) {
            Get-Item $candidatePath -ErrorAction SilentlyContinue
          }
        }
      }
    }

    $toolDirectories = $toolDirectories | Sort-Object FullName -Unique

    $toolCopied = 0
    if ($toolDirectories) {
      foreach ($toolDir in $toolDirectories) {
        $candidateFiles = Get-ChildItem $toolDir.FullName -File -Recurse -ErrorAction SilentlyContinue |
          Where-Object { $remoteFileExtensions -contains $_.Extension.ToLowerInvariant() } |
          Select-Object -First $remoteMaxFilesPerDirectory

        foreach ($file in $candidateFiles) {
          $relativePath = $file.FullName.Replace($toolDir.FullName, '').TrimStart('\') -replace '\\', '_'
          $userContext = 'SYSTEM'
          if ($file.FullName -match '\\Users\\([^\\]+)\\') {
            $userContext = $Matches[1] -replace '[^A-Za-z0-9._-]', '_'
          }
          $destinationName = "${userContext}_$(($toolDir.Name -replace '[^A-Za-z0-9._-]', '_'))_$relativePath"
          $destinationPath = Join-Path $toolDst $destinationName
          Copy-Item $file.FullName $destinationPath -Force -ErrorAction SilentlyContinue
          if (Test-Path $destinationPath) {
            Add-Hash $destinationPath
            $toolCopied++
          }
        }
      }
      Add-Finding 'Artifacts' "$($tool.Name) Directories" "$($toolDirectories.Count) found" 'Filesystem' 'INFO'
    }
    else {
      Add-Finding 'Artifacts' "$($tool.Name) Directories" 'Not found' 'Filesystem' 'INFO'
    }

    $serviceKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue |
      Where-Object {
        $svcName = $_.PSChildName
        $tool.ServicePatterns | Where-Object { $svcName -like $_ }
      }

    if ($serviceKeys) {
      $servicesPath = Join-Path $toolDst "$toolSafeName`_Services.csv"
      $serviceData = foreach ($serviceKey in $serviceKeys) {
        $serviceProperties = Get-ItemProperty $serviceKey.PSPath -ErrorAction SilentlyContinue
        [pscustomobject]@{
          ServiceName = $serviceKey.PSChildName
          ImagePath   = $serviceProperties.ImagePath
          Start       = $serviceProperties.Start
          DisplayName = $serviceProperties.DisplayName
        }
      }
      $serviceData | Export-Csv -Path $servicesPath -NoTypeInformation
      Add-Hash $servicesPath
      Add-Finding 'Artifacts' "$($tool.Name) Services" "$($serviceKeys.Count) service key(s) found" 'Registry' 'INFO'
    }
    else {
      Add-Finding 'Artifacts' "$($tool.Name) Services" 'Not found' 'Registry' 'INFO'
    }

    $regExports = 0
    foreach ($registryKey in $tool.RegistryKeys) {
      $registryPsPath = $registryKey -replace '^HKLM\\', 'HKLM:\\'
      if (Test-Path $registryPsPath) {
        $registrySuffix = ($registryKey -replace '^HKLM\\', '') -replace '[\\/:*?"<>|]', '_'
        $registryPath = Join-Path $toolDst "Registry_$registrySuffix.reg"
        & reg.exe export $registryKey $registryPath /y 2>$null | Out-Null
        if (Test-Path $registryPath) {
          Add-Hash $registryPath
          $regExports++
        }
      }
    }
    Add-Finding 'Artifacts' "$($tool.Name) Registry Exports" "$regExports key export(s)" 'reg.exe' 'INFO'

    $toolEvents = $applicationEvents | Where-Object {
      $providerName = $_.ProviderName
      if (-not $providerName) { return $false }
      $isMatch = $false
      foreach ($eventPattern in $tool.EventPatterns) {
        if ($providerName -like $eventPattern) {
          $isMatch = $true
          break
        }
      }
      $isMatch
    } | Select-Object -First $remoteEventExportMax

    if ($toolEvents) {
      $eventsPath = Join-Path $toolDst "$toolSafeName`_Events.csv"
      $toolEvents |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Export-Csv -Path $eventsPath -NoTypeInformation
      Add-Hash $eventsPath
      Add-Finding 'Artifacts' "$($tool.Name) Events" "$($toolEvents.Count) event(s) exported" 'Application Log' 'INFO'
    }
    else {
      Add-Finding 'Artifacts' "$($tool.Name) Events" 'No matching application events in last 30 days' 'Application Log' 'INFO'
    }

    Add-Finding 'Artifacts' "$($tool.Name) File Copies" "$toolCopied file(s) copied" 'Filesystem' 'INFO'
  }
}

# ── 7. Summary + Dynamic MITRE
Invoke-SafeSection -description 'Summary' -scriptBlock {
  $summary = Join-Path $post 'Summary.txt'
  $lines = [System.Collections.ArrayList]::new()
  [void]$lines.Add("IR COLLECTION SUMMARY — $Start UTC")
  [void]$lines.Add("Host: $env:COMPUTERNAME  Warnings: $($Warnings.Count)")
  [void]$lines.Add('')

  foreach ($cat in ($Findings | Group-Object Category | Sort-Object Name)) {
    [void]$lines.Add("=== $($cat.Name) ===")
    foreach ($f in $cat.Group) {
      $icon = switch ($f.Status) { 'OK' { '[+]' }; 'INFO' { '[i]' }; 'WARNING' { '[!]' }; 'CRITICAL' { '[!!]' } }
      [void]$lines.Add(" $icon $($f.Item): $($f.Value) ($($f.Source))")
    }
    [void]$lines.Add('')
  }

  [void]$lines.Add('VISIBILITY GAPS — MITRE ATT&CK')
  $map = @(
    @{Tech = 'T1059'; Name = 'PowerShell'; Gaps = {
        $g = @(); $sb = $Findings | Where-Object Item -EQ 'ScriptBlockLogging'
        if ($sb.Status -ne 'OK') { $g += 'No Script Block Logging → full command content invisible' }
        if (($Findings | Where-Object Item -Like '*PowerShell*Operational').Status -ne 'OK') { $g += 'PS log undersized → historical evidence lost' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1021.006'; Name = 'WinRM'; Gaps = {
        $g = @(); if (($Findings | Where-Object Item -Like '*WinRM*').Status -ne 'OK') { $g += 'No WinRM Operational → remote PS invisible' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1047'; Name = 'WMI'; Gaps = {
        $g = @(); if (($Findings | Where-Object Item -Like '*WMI*').Status -ne 'OK') { $g += 'No WMI-Activity → WMI execution blind' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1562.001'; Name = 'Impair Defenses'; Gaps = {
        $g = @(); $tp = $Findings | Where-Object Item -EQ 'TamperProtection'
        if ($tp.Status -eq 'CRITICAL') { $g += 'Tamper off → Defender silently crippleable' }
        $rtp = $Findings | Where-Object Item -EQ 'RealTimeProtection'
        if ($rtp.Status -eq 'CRITICAL') { $g += 'Real-time protection disabled' }
        $bm = $Findings | Where-Object Item -EQ 'BehaviorMonitoring'
        if ($bm.Status -eq 'CRITICAL') { $g += 'Behavior monitoring disabled' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1071'; Name = 'App Layer Protocol (C2)'; Gaps = {
        $g = @(); $np = $Findings | Where-Object Item -EQ 'NetworkProtection'
        if ($np -and $np.Status -ne 'OK') { $g += 'Network Protection not enforcing → malicious connections unblocked' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1003'; Name = 'Credential Dumping'; Gaps = {
        $g = @(); $lsa = $Findings | Where-Object Item -Like 'LSA Protection*'
        if ($lsa -and $lsa.Status -ne 'OK') { $g += 'LSA not running as PPL → credential theft easier' }
        $cg = $Findings | Where-Object Item -Like 'Credential Guard*'
        if ($cg -and $cg.Status -ne 'OK') { $g += 'Credential Guard not enabled → pass-the-hash risk' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1176'; Name = 'Browser Extensions'; Gaps = {
        $g = @(); $be = $Findings | Where-Object { $_.Category -eq 'Artifacts' -and $_.Item -like '*Extension*' }
        if (-not $be) { $g += 'No browser extensions found — may indicate collection issue or clean system' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1197'; Name = 'BITS Jobs'; Gaps = {
        $g = @(); $bits = $Findings | Where-Object Item -EQ 'BITSJobs'
        if ($bits -and $bits.Value -like '*Unavailable*') { $g += 'BITS transfer enumeration failed → stealthy downloads invisible' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1562.006'; Name = 'Indicator Blocking (ETW)'; Gaps = {
        $g = @(); $etw = $Findings | Where-Object Item -EQ 'ETWSessions'
        if ($etw -and $etw.Value -like '*Unavailable*') { $g += 'ETW session enumeration failed → trace tampering undetectable' }
        $g -join ' | '
      }
    }
    @{Tech = 'T1490'; Name = 'Inhibit System Recovery'; Gaps = {
        $g = @(); $vss = $Findings | Where-Object Item -EQ 'ShadowCopies'
        if ($vss -and $vss.Value -like '*no shadow*') { $g += 'No shadow copies → recovery impossible after ransomware' }
        $g -join ' | '
      }
    }
  )

  foreach ($m in $map) {
    $gap = & $m.Gaps
    if ($gap) { [void]$lines.Add("$($m.Tech) $($m.Name): $gap") }
  }

  if ($HybridMode -and $CreateOfflineHints) {
    $hintPath = Join-Path $post 'Offline-Hints.csv'
    $hintCandidates = $Findings | Where-Object {
      $_.Status -in 'CRITICAL', 'WARNING' -or
      $_.Item -in 'Amcache.hve', 'Temp Suspicious Samples', 'TamperProtection', 'RealTimeProtection', 'BehaviorMonitoring' -or
      $_.Item -like '*Directories' -or
      $_.Item -like '*Services' -or
      $_.Item -like '*Registry Exports' -or
      $_.Item -like '*Events'
    }

    foreach ($candidate in $hintCandidates) {
      $priority = switch ($candidate.Status) {
        'CRITICAL' { 'HIGH' }
        'WARNING' { 'MEDIUM' }
        default { 'LOW' }
      }
      Add-OfflineHint -priority $priority -category $candidate.Category -item $candidate.Item -value $candidate.Value -source $candidate.Source
    }

    if ($OfflineHints.Count -gt 0) {
      $OfflineHints |
        Sort-Object Priority, Category, Item |
        Export-Csv -Path $hintPath -NoTypeInformation
      Add-Hash $hintPath
      Add-Finding 'Collection' 'Offline Hints' "$($OfflineHints.Count) hints written" 'HybridMode' 'INFO'
    }
  }

  $lines | Out-File $summary -Encoding UTF8
  Add-Hash $summary

  # Action1: Write summary to stdout so it appears in the Action1 console
  Write-Output ''
  Write-Output '══════════════════════════════════════════════════'
  Write-Output "  IR Collection Complete — $env:COMPUTERNAME"
  Write-Output "  Output: $zip"
  Write-Output "  Findings: $($Findings.Count)  Warnings: $($Warnings.Count)"
  Write-Output '══════════════════════════════════════════════════'
  if ($Warnings.Count -gt 0) {
    Write-Output ''
    Write-Output 'TOP WARNINGS:'
    $Warnings | Select-Object -First 20 | ForEach-Object { Write-Output "  $_" }
  }
}

# ── 8. Finalize
Invoke-SafeSection -description 'Finalize' -scriptBlock {
  $manifest = Join-Path $Dir 'Hashes.csv'
  $HashManifest | Export-Csv $manifest -NoTypeInformation
  Add-Hash $manifest

  $zip = "$Root\IR_$Start.zip"
  Compress-Archive -Path "$Dir\*" -DestinationPath $zip -Force
  $zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash
  Add-Hash $zip

  "$zipHash  IR_$Start.zip" | Out-File "$zip.sha256" -Encoding UTF8

  'Collection complete.' | Out-File (Join-Path $Dir 'COMPLETE.txt')

  if ($HybridMode -and $CleanupWorkingDirectory -and (Test-Path $Dir)) {
    Remove-Item -Path $Dir -Recurse -Force -ErrorAction SilentlyContinue
  }
}
