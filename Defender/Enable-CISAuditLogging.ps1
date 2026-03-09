<#
.SYNOPSIS
    Enables CIS Level 1 style audit and logging settings for Windows 10/11.
.DESCRIPTION
    Applies Advanced Audit Policy, PowerShell logging, and event log sizing/retention.
    Optionally configures auditing (SACL) on a list of folders.

    Notes:
    - Run from an elevated PowerShell session.
    - Subcategories that do not exist on the OS are skipped with a warning.

.PARAMETER auditFolders
    One or more folder paths to apply auditing (SACL) to.
.PARAMETER reportPath
    Directory where before/after reports are written.
.PARAMETER applyAuditPolicy
    Enables Advanced Audit Policy subcategories.
.PARAMETER applyPowerShellLogging
    Enables PowerShell Script Block, Module, and Transcription logging.
.PARAMETER applyEventLogSettings
    Sets event log sizes and retention.
.PARAMETER auditRule
    Default audit rule for folder auditing.
.PARAMETER transcriptionDir
    Output directory for PowerShell transcription.

Written by Joel Stidley - @joelst

#>

[cmdletBinding()]
param(
    [Parameter()]
    [string[]]$auditFolders = @(),
    [Parameter()]
    [string]$reportPath = "C:\CIS_Audit_Report",
    [Parameter()]
    [switch]$applyAuditPolicy,
    [Parameter()]
    [switch]$applyPowerShellLogging,
    [Parameter()]
    [switch]$applyEventLogSettings,
    [Parameter()]
    [ValidateSet('SuccessFailure_ModifyRead', 'SuccessOnly_ModifyRead', 'SuccessFailure_FullControl')]
    [string]$auditRule = 'SuccessFailure_ModifyRead',
    [Parameter()]
    [string]$transcriptionDir = "C:\CIS_PowerShell_Transcripts"
)

  Set-StrictMode -Version Latest
  $ErrorActionPreference = 'Stop'

  function New-ReportFolder {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$basePath
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $folderPath = Join-Path $basePath "CIS_Audit_$timestamp"
    $newItemParams = @{
      Path     = $folderPath
      ItemType = 'Directory'
      Force    = $true
    }
    New-Item @newItemParams | Out-Null
    return $folderPath
  }

  function Write-ReportFile {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$path,
      [Parameter(Mandatory = $true)]
      [object]$content
    )

    $outParams = @{
      FilePath = $path
      Encoding = 'UTF8'
      Force    = $true
    }
    if ($content -is [string]) {
      $content | Out-File @outParams
      return
    }

    $content | Out-File @outParams
  }

  function Invoke-SafeAction {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$description,
      [Parameter(Mandatory = $true)]
      [scriptblock]$scriptBlock
    )

    try {
      & $scriptBlock
      Write-Verbose "${description}: OK"
    }
    catch {
      Write-Warning "$description failed: $_"
    }
  }

  function Test-RequiredCommand {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$name
    )

    $command = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $command) {
      Write-Error "Required command not found: $name"
      return $false
    }

    return $true
  }

  function Test-IsAdmin {
    [CmdletBinding()]
    param()

    try {
      $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
      $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
      return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
      return $false
    }
  }

  function Get-AuditPolicyText {
    [CmdletBinding()]
    param()

    $output = & auditpol.exe /get /category:* 2>&1
    return $output
  }

  function Set-AuditPolicySubcategory {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$subcategory,
      [Parameter(Mandatory = $true)]
      [ValidateSet('enable', 'disable')]
      [string]$success,
      [Parameter(Mandatory = $true)]
      [ValidateSet('enable', 'disable')]
      [string]$failure
    )

    $output = & auditpol.exe /set /subcategory:$subcategory /success:$success /failure:$failure 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Audit policy not applied for '$subcategory': $output"
    }
  }

  function Set-EventLogSettings {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [hashtable]$logSizes
    )

    foreach ($logName in $logSizes.Keys) {
      $size = $logSizes[$logName]
      $output = & wevtutil.exe sl $logName /ms:$size /rt:false 2>&1
      if ($LASTEXITCODE -ne 0) {
        Write-Warning "Event log settings not applied for '$logName': $output"
      }
    }
  }

  function Set-RegistryValue {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$path,
      [Parameter(Mandatory = $true)]
      [string]$name,
      [Parameter(Mandatory = $true)]
      [object]$value,
      [Parameter(Mandatory = $true)]
      [Microsoft.Win32.RegistryValueKind]$type
    )

    $newItemParams = @{
      Path  = $path
      Force = $true
    }
    New-Item @newItemParams | Out-Null

    $setItemParams = @{
      Path  = $path
      Name  = $name
      Value = $value
      Type  = $type
      Force = $true
    }
    Set-ItemProperty @setItemParams | Out-Null
  }

  function Get-PowerShellLoggingState {
    [CmdletBinding()]
    param()

    $paths = @(
      'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
      'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
      'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames',
      'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    )

    $results = foreach ($path in $paths) {
      if (Test-Path $path) {
        $item = Get-ItemProperty -Path $path
        [pscustomobject]@{
          Path   = $path
          Values = $item.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } | ForEach-Object {
            @{ Name = $_.Name; Value = $_.Value }
          }
        }
      }
      else {
        [pscustomobject]@{ Path = $path; Values = @() }
      }
    }

    return $results
  }

  function Enable-PowerShellLogging {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$logPath
    )

    $scriptBlockPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    Set-RegistryValue -path $scriptBlockPath -name 'EnableScriptBlockLogging' -value 1 -type DWord
    Set-RegistryValue -path $scriptBlockPath -name 'EnableScriptBlockInvocationLogging' -value 1 -type DWord

    $moduleLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    Set-RegistryValue -path $moduleLogPath -name 'EnableModuleLogging' -value 1 -type DWord
    $moduleNamesPath = Join-Path $moduleLogPath 'ModuleNames'
    Set-RegistryValue -path $moduleNamesPath -name '*' -value '*' -type String

    $transcriptionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    Set-RegistryValue -path $transcriptionPath -name 'EnableTranscripting' -value 1 -type DWord
    Set-RegistryValue -path $transcriptionPath -name 'EnableInvocationHeader' -value 1 -type DWord
    Set-RegistryValue -path $transcriptionPath -name 'OutputDirectory' -value $logPath -type String

    $newItemParams = @{
      Path     = $logPath
      ItemType = 'Directory'
      Force    = $true
    }
    New-Item @newItemParams | Out-Null
  }

  function Set-FolderAuditRule {
    [CmdletBinding()]
    param(
      [Parameter(Mandatory = $true)]
      [string]$path,
      [Parameter(Mandatory = $true)]
      [string]$rule
    )

    if (-not (Test-Path $path)) {
      Write-Warning "Folder not found: $path"
      return
    }

    $rights = [System.Security.AccessControl.FileSystemRights]::Modify -bor
    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
    [System.Security.AccessControl.FileSystemRights]::ListDirectory

    if ($rule -eq 'SuccessFailure_FullControl') {
      $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    }

    $auditFlags = [System.Security.AccessControl.AuditFlags]::Success -bor
    [System.Security.AccessControl.AuditFlags]::Failure

    if ($rule -eq 'SuccessOnly_ModifyRead') {
      $auditFlags = [System.Security.AccessControl.AuditFlags]::Success
    }

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None

    $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
      $everyone,
      $rights,
      $inheritanceFlags,
      $propagationFlags,
      $auditFlags
    )

    $acl = Get-Acl -Path $path
    $acl.SetAuditRule($auditRule)
    Set-Acl -Path $path -AclObject $acl
  }

  $auditPolicy = @(
    @{ Subcategory = 'Credential Validation'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Kerberos Service Ticket Operations'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Kerberos Authentication Service'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Other Account Logon Events'; Success = 'enable'; Failure = 'enable' }

    @{ Subcategory = 'Application Group Management'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Computer Account Management'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Security Group Management'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'User Account Management'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Other Account Management Events'; Success = 'enable'; Failure = 'enable' }

    @{ Subcategory = 'Logon'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Logoff'; Success = 'enable'; Failure = 'disable' }
    @{ Subcategory = 'Account Lockout'; Success = 'enable'; Failure = 'disable' }
    @{ Subcategory = 'Special Logon'; Success = 'enable'; Failure = 'disable' }
    @{ Subcategory = 'Other Logon/Logoff Events'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Group Membership'; Success = 'enable'; Failure = 'disable' }

    @{ Subcategory = 'File System'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Registry'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Removable Storage'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Other Object Access Events'; Success = 'enable'; Failure = 'enable' }

    @{ Subcategory = 'Audit Policy Change'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Authentication Policy Change'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Authorization Policy Change'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'MPSSVC Rule-Level Policy Change'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Filtering Platform Policy Change'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Other Policy Change Events'; Success = 'enable'; Failure = 'enable' }

    @{ Subcategory = 'Sensitive Privilege Use'; Success = 'enable'; Failure = 'enable' }

    @{ Subcategory = 'Process Creation'; Success = 'enable'; Failure = 'disable' }
    @{ Subcategory = 'Process Termination'; Success = 'enable'; Failure = 'disable' }
    @{ Subcategory = 'RPC Events'; Success = 'enable'; Failure = 'disable' }

    @{ Subcategory = 'Security System Extension'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'System Integrity'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'IPsec Driver'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Other System Events'; Success = 'enable'; Failure = 'enable' }
    @{ Subcategory = 'Security State Change'; Success = 'enable'; Failure = 'enable' }
  )

  $eventLogSizes = @{
    'Security'                                                               = 268435456
    'System'                                                                 = 134217728
    'Application'                                                            = 134217728
    'Microsoft-Windows-PowerShell/Operational'                               = 134217728
    'Microsoft-Windows-WMI-Activity/Operational'                             = 67108864
    'Microsoft-Windows-WinRM/Operational'                                    = 67108864
    'Microsoft-Windows-TaskScheduler/Operational'                            = 67108864
    'Microsoft-Windows-Windows Defender/Operational'                         = 134217728
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'     = 67108864
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 67108864
  }

  $reportBaseParams = @{
    Path     = $reportPath
    ItemType = 'Directory'
    Force    = $true
  }
  New-Item @reportBaseParams | Out-Null

  $reportFolder = New-ReportFolder -basePath $reportPath

  $isAdmin = Test-IsAdmin
  if (-not $isAdmin) {
    Write-Warning 'Not running as Administrator. Policy, logging, and SACL changes will be skipped.'
  }

  Invoke-SafeAction -description 'Capture audit policy (before)' -scriptBlock {
    $auditBefore = Get-AuditPolicyText
    Write-ReportFile -path (Join-Path $reportFolder 'AuditPolicy_Before.txt') -content $auditBefore
  }

  Invoke-SafeAction -description 'Capture event log settings (before)' -scriptBlock {
    $eventBefore = & wevtutil.exe gl * 2>&1
    Write-ReportFile -path (Join-Path $reportFolder 'EventLogs_Before.txt') -content $eventBefore
  }

  Invoke-SafeAction -description 'Capture PowerShell logging (before)' -scriptBlock {
    $psBefore = Get-PowerShellLoggingState | ConvertTo-Json -Depth 4
    Write-ReportFile -path (Join-Path $reportFolder 'PowerShellLogging_Before.json') -content $psBefore
  }

  if ($applyAuditPolicy -and $isAdmin) {
    if (-not (Test-RequiredCommand -name 'auditpol.exe')) {
      $applyAuditPolicy = $false
    }

    Invoke-SafeAction -description 'Apply audit policy' -scriptBlock {
      foreach ($item in $auditPolicy) {
        Set-AuditPolicySubcategory -subcategory $item.Subcategory -success $item.Success -failure $item.Failure
      }
    }
  }

  if ($applyEventLogSettings -and $isAdmin) {
    if (-not (Test-RequiredCommand -name 'wevtutil.exe')) {
      $applyEventLogSettings = $false
    }

    Invoke-SafeAction -description 'Apply event log settings' -scriptBlock {
      Set-EventLogSettings -logSizes $eventLogSizes
    }
  }

  if ($applyPowerShellLogging -and $isAdmin) {
    Invoke-SafeAction -description 'Enable PowerShell logging' -scriptBlock {
      Enable-PowerShellLogging -logPath $transcriptionDir
    }
  }

  if ($auditFolders.Count -gt 0 -and $isAdmin) {
    Invoke-SafeAction -description 'Apply folder auditing' -scriptBlock {
      foreach ($folder in $auditFolders) {
        Set-FolderAuditRule -path $folder -rule $auditRule
      }
    }
  }

  Invoke-SafeAction -description 'Capture audit policy (after)' -scriptBlock {
    $auditAfter = Get-AuditPolicyText
    Write-ReportFile -path (Join-Path $reportFolder 'AuditPolicy_After.txt') -content $auditAfter
  }

  Invoke-SafeAction -description 'Capture event log settings (after)' -scriptBlock {
    $eventAfter = & wevtutil.exe gl * 2>&1
    Write-ReportFile -path (Join-Path $reportFolder 'EventLogs_After.txt') -content $eventAfter
  }

  Invoke-SafeAction -description 'Capture PowerShell logging (after)' -scriptBlock {
    $psAfter = Get-PowerShellLoggingState | ConvertTo-Json -Depth 4
    Write-ReportFile -path (Join-Path $reportFolder 'PowerShellLogging_After.json') -content $psAfter
  }

  Write-Output "CIS Level 1 audit/logging configuration complete. Reports: $reportFolder"
