# OpenClaw Detection Script for MDM deployment (Windows)
# Exit codes: 0 = not-installed (clean), 1 = found/error (non-compliant)

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$script:Profile = $env:OPENCLAW_PROFILE
$script:DefaultPort = if ($env:OPENCLAW_GATEWAY_PORT) { [int]$env:OPENCLAW_GATEWAY_PORT } else { 18789 }
$script:Output = [System.Collections.ArrayList]::new()
$script:OpenClawPattern = '(?i)openclaw|clawdbot|moltbot|clawd'
$script:VendorPattern = '(?i)knostic'

function Add-OutputLine {
  param([string]$line)
  [void]$script:Output.Add($line)
}
function Get-FirstExistingPath {
  param(
    [string[]]$paths,
    [ValidateSet('Leaf', 'Container')]
    [string]$pathType = 'Leaf'
  )

  foreach ($path in $paths) {
    if (Test-Path $path -PathType $pathType) {
      return $path
    }
  }

  return $null
}

function Join-UniqueValue {
  param([string[]]$values)

  $filtered = $values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  if (-not $filtered) {
    return $null
  }

  return ($filtered | Sort-Object -Unique) -join ', '
}

function Write-CatchVerbose {
  param(
    [string]$context,
    [System.Management.Automation.ErrorRecord]$errorRecord
  )

  Write-Verbose "[$context] $($errorRecord.Exception.Message)"
}

function Get-StateDir {
  param([string]$homeDir)
  if ($script:Profile) {
    return Join-Path $homeDir ".openclaw-$($script:Profile)"
  }
  return Join-Path $homeDir '.openclaw'
}

function Get-UsersToCheck {
  $users = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -notin @('Public', 'Default', 'Default User', 'All Users')
  } | ForEach-Object { $_.Name }

  if (-not $users -or $users.Count -eq 0) {
    return @($env:USERNAME)
  }

  return @($users)
}

function Get-HomeDir {
  param([string]$user)
  return Join-Path 'C:\Users' $user
}

function Get-CliFromPath {
  $names = @('openclaw', 'clawdbot', 'moltbot', 'clawd')
  foreach ($name in $names) {
    try {
      $command = Get-Command $name -ErrorAction SilentlyContinue
      if ($command) {
        return $command.Source
      }
    }
    catch {
      Write-CatchVerbose -context "Get-CliFromPath:$name" -errorRecord $_
    }
  }
  return $null
}

function Get-CliFromGlobalLocation {
  $locations = @(
    'C:\Program Files\openclaw\openclaw.exe',
    'C:\Program Files (x86)\openclaw\openclaw.exe',
    'C:\Program Files\clawdbot\clawdbot.exe',
    'C:\Program Files (x86)\clawdbot\clawdbot.exe',
    'C:\Program Files\moltbot\moltbot.exe',
    'C:\Program Files (x86)\moltbot\moltbot.exe'
  )
  return Get-FirstExistingPath -paths $locations -pathType Leaf
}

function Get-CliFromUserLocation {
  param([string]$homeDir)

  $locations = @(
    (Join-Path $homeDir 'AppData\Local\Programs\openclaw\openclaw.exe'),
    (Join-Path $homeDir 'AppData\Local\Programs\clawdbot\clawdbot.exe'),
    (Join-Path $homeDir 'AppData\Local\Programs\moltbot\moltbot.exe'),
    (Join-Path $homeDir 'AppData\Roaming\npm\openclaw.cmd'),
    (Join-Path $homeDir 'AppData\Roaming\npm\clawdbot.cmd'),
    (Join-Path $homeDir 'AppData\Roaming\npm\moltbot.cmd'),
    (Join-Path $homeDir 'AppData\Local\pnpm\openclaw.cmd'),
    (Join-Path $homeDir 'AppData\Local\pnpm\clawdbot.cmd'),
    (Join-Path $homeDir 'AppData\Local\pnpm\moltbot.cmd'),
    (Join-Path $homeDir '.volta\bin\openclaw.exe'),
    (Join-Path $homeDir '.volta\bin\clawdbot.exe'),
    (Join-Path $homeDir '.volta\bin\moltbot.exe'),
    (Join-Path $homeDir 'scoop\shims\openclaw.exe'),
    (Join-Path $homeDir 'scoop\shims\clawdbot.exe'),
    (Join-Path $homeDir 'scoop\shims\moltbot.exe')
  )

  return Get-FirstExistingPath -paths $locations -pathType Leaf
}

function Get-AnyStateDir {
  param([string]$homeDir)

  $dirs = @(
    (Join-Path $homeDir '.openclaw'),
    (Join-Path $homeDir '.clawdbot'),
    (Join-Path $homeDir '.moltbot'),
    (Join-Path $homeDir ".openclaw-$($script:Profile)")
  )

  return Get-FirstExistingPath -paths ($dirs | Sort-Object -Unique) -pathType Container
}

function Test-Config {
  param([string]$stateDir)
  return Test-Path (Join-Path $stateDir 'openclaw.json') -PathType Leaf
}

function Get-ConfiguredPort {
  param([string]$configFile)
  if (Test-Path $configFile -PathType Leaf) {
    try {
      $content = Get-Content $configFile -Raw
      if ($content -match '"port"\s*:\s*(\d+)') {
        return [int]$matches[1]
      }
    }
    catch {
      Write-CatchVerbose -context "Get-ConfiguredPort:$configFile" -errorRecord $_
    }
  }
  return $null
}

function Get-ScheduledTaskEvidence {
  $hits = [System.Collections.Generic.List[string]]::new()

  try {
    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
      $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -match $script:OpenClawPattern -or $_.TaskPath -match $script:OpenClawPattern
      }
      foreach ($task in $tasks) {
        [void]$hits.Add("$($task.TaskPath)$($task.TaskName)")
      }
    }
  }
  catch {
    Write-CatchVerbose -context 'Get-ScheduledTaskEvidence:Get-ScheduledTask' -errorRecord $_
  }

  # Fallback to schtasks for systems without ScheduledTasks module.
  if ($hits.Count -eq 0) {
    try {
      $taskList = schtasks /Query /FO LIST /V 2>$null
      if ($LASTEXITCODE -eq 0 -and $taskList) {
        $found = $taskList | Select-String -Pattern $script:OpenClawPattern
        foreach ($item in $found) {
          [void]$hits.Add([string]$item.Line)
        }
      }
    }
    catch {
      Write-CatchVerbose -context 'Get-ScheduledTaskEvidence:schtasks' -errorRecord $_
    }
  }

  if ($hits.Count -gt 0) {
    return Join-UniqueValue -values $hits
  }
  return $null
}

function Get-ProcessEvidence {
  $hits = [System.Collections.Generic.List[string]]::new()
  try {
    $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    foreach ($process in $processes) {
      $name = [string]$process.Name
      $commandLine = [string]$process.CommandLine
      if ($name -match $script:OpenClawPattern -or $commandLine -match $script:OpenClawPattern) {
        [void]$hits.Add("$name (PID=$($process.ProcessId))")
      }
    }
  }
  catch {
    Write-CatchVerbose -context 'Get-ProcessEvidence' -errorRecord $_
  }

  if ($hits.Count -gt 0) {
    return Join-UniqueValue -values $hits
  }
  return $null
}

function Get-PortEvidence {
  param([int[]]$ports)

  $listeningPorts = [System.Collections.Generic.List[string]]::new()
  $matchingListeners = [System.Collections.Generic.List[string]]::new()

  foreach ($port in ($ports | Sort-Object -Unique)) {
    try {
      $listeners = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
      foreach ($listener in $listeners) {
        [void]$listeningPorts.Add([string]$port)
        $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" -ErrorAction SilentlyContinue
        $name = [string]$process.Name
        $commandLine = [string]$process.CommandLine
        if ($name -match $script:OpenClawPattern -or $commandLine -match $script:OpenClawPattern) {
          [void]$matchingListeners.Add("port $port -> $name (PID=$($listener.OwningProcess))")
        }
      }
    }
    catch {
      Write-CatchVerbose -context "Get-PortEvidence:$port" -errorRecord $_
    }
  }

  return [PSCustomObject]@{
    AnyListening    = ($listeningPorts.Count -gt 0)
    AnyMatching     = ($matchingListeners.Count -gt 0)
    ListeningPorts  = (Join-UniqueValue -values $listeningPorts)
    MatchingDetails = (Join-UniqueValue -values $matchingListeners)
  }
}

function Get-DockerEvidence {
  param([string[]]$dockerArgument)

  try {
    $command = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $command) {
      return $null
    }

    $dockerOutput = & docker @dockerArgument 2>$null
    if ($LASTEXITCODE -ne 0) {
      return $null
    }

    $matchingLines = $dockerOutput | Select-String -Pattern $script:OpenClawPattern
    if ($matchingLines) {
      return Join-UniqueValue -values ($matchingLines | ForEach-Object { $_.Line.Trim() })
    }
  }
  catch {
    Write-CatchVerbose -context 'Get-DockerEvidence' -errorRecord $_
  }
  return $null
}

function Get-UninstallEvidence {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )

  $hits = [System.Collections.Generic.List[string]]::new()
  foreach ($path in $paths) {
    try {
      $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
      foreach ($entry in $entries) {
        $displayName = [string]$entry.DisplayName
        $publisher = [string]$entry.Publisher
        if ($displayName -match $script:OpenClawPattern -or $publisher -match $script:VendorPattern) {
          [void]$hits.Add($displayName)
        }
      }
    }
    catch {
      Write-CatchVerbose -context "Get-UninstallEvidence:$path" -errorRecord $_
    }
  }

  if ($hits.Count -gt 0) {
    return Join-UniqueValue -values $hits
  }
  return $null
}

function Get-WingetEvidence {
  $hits = [System.Collections.Generic.List[string]]::new()
  try {
    $root = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
    if (Test-Path $root -PathType Container) {
      $folders = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $script:OpenClawPattern
      }
      foreach ($folder in $folders) {
        [void]$hits.Add($folder.Name)
      }
    }
  }
  catch {
    Write-CatchVerbose -context 'Get-WingetEvidence' -errorRecord $_
  }

  if ($hits.Count -gt 0) {
    return Join-UniqueValue -values $hits
  }
  return $null
}

try {
  $cliFound = $false
  $stateFound = $false
  $processRunning = $false
  $serviceRunning = $false
  $dockerRunning = $false
  $dockerInstalled = $false
  $uninstallFound = $false
  $wingetFound = $false

  Add-OutputLine 'platform: windows'

  $cliPath = Get-CliFromPath
  if (-not $cliPath) {
    $cliPath = Get-CliFromGlobalLocation
  }

  if ($cliPath) {
    $cliFound = $true
    Add-OutputLine "cli: $cliPath"
  }

  $users = @(Get-UsersToCheck)
  $multiUser = $users.Count -gt 1
  $portsToCheck = [System.Collections.Generic.List[int]]::new()
  [void]$portsToCheck.Add($script:DefaultPort)

  foreach ($user in $users) {
    $homeDir = Get-HomeDir $user
    $stateDir = Get-StateDir $homeDir
    $anyStateDir = Get-AnyStateDir $homeDir
    $configFile = Join-Path $stateDir 'openclaw.json'

    if ($multiUser) {
      Add-OutputLine "user: $user"
    }

    if (-not $cliFound) {
      $userCli = Get-CliFromUserLocation $homeDir
      if ($userCli) {
        $cliFound = $true
        Add-OutputLine "cli: $userCli"
      }
    }

    if (Test-Path $stateDir -PathType Container) {
      $stateFound = $true
      Add-OutputLine "state-dir: $stateDir"
    }
    elseif ($anyStateDir) {
      $stateFound = $true
      Add-OutputLine "state-dir: $anyStateDir"
    }

    if (Test-Config $stateDir) {
      Add-OutputLine "config: $configFile"
    }

    $configPort = Get-ConfiguredPort $configFile
    if ($configPort) {
      [void]$portsToCheck.Add($configPort)
      Add-OutputLine "config-port: $configPort"
    }
  }

  if (-not $cliFound) {
    Add-OutputLine 'cli: not-found'
  }
  if (-not $stateFound) {
    Add-OutputLine 'state-dir: not-found'
  }

  $taskEvidence = Get-ScheduledTaskEvidence
  if ($taskEvidence) {
    $serviceRunning = $true
    Add-OutputLine "gateway-service: $taskEvidence"
  }
  else {
    Add-OutputLine 'gateway-service: not-found'
  }

  $portEvidence = Get-PortEvidence -ports $portsToCheck
  if ($portEvidence.AnyListening) {
    if ($portEvidence.AnyMatching) {
      $serviceRunning = $true
      Add-OutputLine "gateway-port: $($portEvidence.MatchingDetails)"
    }
    else {
      Add-OutputLine "gateway-port: listening-on-$($portEvidence.ListeningPorts)"
    }
  }
  else {
    Add-OutputLine 'gateway-port: not-listening'
  }

  $processEvidence = Get-ProcessEvidence
  if ($processEvidence) {
    $processRunning = $true
    Add-OutputLine "process: $processEvidence"
  }
  else {
    Add-OutputLine 'process: not-found'
  }

  $dockerContainers = Get-DockerEvidence -dockerArgument @('ps', '--format', '{{.Names}} ({{.Image}})')
  if ($dockerContainers) {
    $dockerRunning = $true
    Add-OutputLine "docker-container: $dockerContainers"
  }
  else {
    Add-OutputLine 'docker-container: not-found'
  }

  $dockerImages = Get-DockerEvidence -dockerArgument @('images', '--format', '{{.Repository}}:{{.Tag}}')
  if ($dockerImages) {
    $dockerInstalled = $true
    Add-OutputLine "docker-image: $dockerImages"
  }
  else {
    Add-OutputLine 'docker-image: not-found'
  }

  $uninstallEvidence = Get-UninstallEvidence
  if ($uninstallEvidence) {
    $uninstallFound = $true
    Add-OutputLine "uninstall-registry: $uninstallEvidence"
  }
  else {
    Add-OutputLine 'uninstall-registry: not-found'
  }

  $wingetEvidence = Get-WingetEvidence
  if ($wingetEvidence) {
    $wingetFound = $true
    Add-OutputLine "winget-artifact: $wingetEvidence"
  }
  else {
    Add-OutputLine 'winget-artifact: not-found'
  }

  $installed = $cliFound -or $stateFound -or $dockerInstalled -or $uninstallFound -or $wingetFound
  $running = $processRunning -or $serviceRunning -or $dockerRunning

  # Running is prioritized so process/service evidence cannot be marked compliant.
  if ($running) {
    Write-Output 'summary: installed-and-running'
    $script:Output | ForEach-Object { Write-Output $_ }
    exit 1
  }

  if ($installed) {
    Write-Output 'summary: installed-not-running'
    $script:Output | ForEach-Object { Write-Output $_ }
    exit 1
  }

  Write-Output 'summary: not-installed'
  $script:Output | ForEach-Object { Write-Output $_ }
  exit 0
}
catch {
  Write-Output 'summary: error'
  Write-Output "error: $_"
  exit 1
}