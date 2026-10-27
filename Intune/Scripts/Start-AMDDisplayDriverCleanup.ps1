<#
.SYNOPSIS
    Removes orphaned AMD display driver from the Windows Driver Store.
    Identifies the active driver via WMI and removes any non-active duplicates.
    Safe to deploy via Intune - will exit without changes if it cannot confirm the active driver.
#>

$LogPath = 'C:\ProgramData\IT\Logs\AMD-DriverCleanup.log'
$LogDir = Split-Path $LogPath
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $Entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
  Add-Content -Path $LogPath -Value $Entry
  Write-Output $Entry
}

Write-Log '=== AMD Display Driver Cleanup Started ==='

# --- Step 1: Identify the active AMD display driver via WMI ---
try {
  $GPU = Get-CimInstance Win32_VideoController |
    Where-Object { $_.Name -match 'AMD|Radeon' } |
    Select-Object -First 1

  if (-not $GPU) {
    Write-Log 'No AMD/Radeon display adapter found. Nothing to do.' 'WARN'
    exit 0
  }

  Write-Log "Active GPU   : $($GPU.Name)"
  Write-Log "Driver ver   : $($GPU.DriverVersion)"
  Write-Log "Active INF   : $($GPU.InfName)"
  $ActivePublishedName = $GPU.InfName

}
catch {
  Write-Log "Failed to query active display driver: $_" 'ERROR'
  exit 1
}

# --- Step 2: Enumerate all Display class drivers via pnputil ---
try {
  $RawOutput = & pnputil.exe /enum-drivers /class display 2>&1
}
catch {
  Write-Log "Failed to run pnputil: $_" 'ERROR'
  exit 1
}

# --- Step 3: Parse pnputil output into objects ---
$Drivers = @()
$Block = @{}

foreach ($Line in $RawOutput) {
  $Line = $Line.Trim()
  switch -Regex ($Line) {
    '^Published Name:\s+(.+)$' { if ($Block.Count) { $Drivers += [PSCustomObject]$Block }; $Block = @{ PublishedName = $Matches[1].Trim() } }
    '^Original Name:\s+(.+)$' { $Block['OriginalName'] = $Matches[1].Trim() }
    '^Provider Name:\s+(.+)$' { $Block['Provider'] = $Matches[1].Trim() }
    '^Driver Version:\s+(.+)$' { $Block['DriverVersion'] = $Matches[1].Trim() }
    '^Class Name:\s+(.+)$' { $Block['ClassName'] = $Matches[1].Trim() }
  }
}
if ($Block.Count) { $Drivers += [PSCustomObject]$Block }

# Filter to AMD display drivers only
$AmdDrivers = $Drivers | Where-Object { $_.Provider -match 'Advanced Micro Devices|AMD' }

Write-Log "AMD display drivers found in Driver Store: $($AmdDrivers.Count)"
foreach ($d in $AmdDrivers) {
  Write-Log "  > $($d.PublishedName)  |  $($d.OriginalName)  |  $($d.DriverVersion)"
}

# --- Step 4: Bail out if no duplicates ---
if ($AmdDrivers.Count -le 1) {
  Write-Log 'Only one AMD display driver present - no cleanup needed.'
  exit 0
}

# --- Step 5: Identify active vs. orphan(s) ---
if ($ActivePublishedName) {
  Write-Log "Matching by published INF name: $ActivePublishedName"
  $ActiveDriver = $AmdDrivers | Where-Object { $_.PublishedName -eq $ActivePublishedName }
  $OrphanDrivers = $AmdDrivers | Where-Object { $_.PublishedName -ne $ActivePublishedName }
}
else {
  # Fallback: Win32_VideoController.InfName can be empty on some AMD drivers.
  # Match by driver version instead.
  Write-Log "InfName is empty - falling back to driver version match: $($GPU.DriverVersion)" 'WARN'
  $ActiveDriver = $AmdDrivers | Where-Object { $_.DriverVersion -match [regex]::Escape($GPU.DriverVersion) }
  $OrphanDrivers = $AmdDrivers | Where-Object { $_.DriverVersion -notmatch [regex]::Escape($GPU.DriverVersion) }
}

if (-not $ActiveDriver) {
  Write-Log 'Cannot match active driver to any pnputil entry. Aborting for safety.' 'ERROR'
  exit 1
}

if ($ActiveDriver.Count -gt 1) {
  Write-Log 'Multiple drivers matched the active version - ambiguous. Aborting for safety.' 'ERROR'
  exit 1
}

Write-Log "Confirmed active : $($ActiveDriver.PublishedName) ($($ActiveDriver.OriginalName))"
Write-Log "Orphan(s) to remove: $($OrphanDrivers.Count)"

# --- Step 6: Remove orphan driver(s) ---
$Errors = 0
foreach ($Orphan in $OrphanDrivers) {
  Write-Log "Removing: $($Orphan.PublishedName) ($($Orphan.OriginalName) - $($Orphan.DriverVersion))"
  try {
    $Result = & pnputil.exe /delete-driver $Orphan.PublishedName /uninstall /force 2>&1
    Write-Log "pnputil output: $Result"
    if ($LASTEXITCODE -eq 0) {
      Write-Log "Successfully removed $($Orphan.PublishedName)"
    }
    else {
      Write-Log "pnputil exit code $LASTEXITCODE for $($Orphan.PublishedName)" 'WARN'
      $Errors++
    }
  }
  catch {
    Write-Log "Exception removing $($Orphan.PublishedName): $_" 'ERROR'
    $Errors++
  }
}

Write-Log "=== Cleanup Complete. Errors: $Errors ==="

# Exit 1 if any removals failed so Intune reports it
exit $Errors