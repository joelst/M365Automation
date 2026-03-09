<#
.SYNOPSIS
  Searches a Security EVTX file for selected event IDs and time range, then exports matches to CSV.

.DESCRIPTION
  Reads events from an exported .evtx file, filters by event ID list and UTC time window,
  normalizes message whitespace, and writes results to a UTF8 CSV.

.PARAMETER evtxPath
  Full path to the source .evtx file.

.PARAMETER outPath
  Full path to the output .csv file.

.PARAMETER startTime
  Start of the filter window (local time accepted; converted to UTC for XPath).

.PARAMETER endTime
  End of the filter window (local time accepted; converted to UTC for XPath).

.PARAMETER targetIds
  Event IDs to include in the filter.

.EXAMPLE
  .\Invoke-DFIRSearching.ps1 -evtxPath 'C:\IR\Security.evtx' -outPath 'C:\IR\Security-Filtered.csv'

.EXAMPLE
  .\Invoke-DFIRSearching.ps1 -evtxPath 'C:\IR\Security.evtx' -outPath 'C:\IR\AuthEvents.csv' -startTime (Get-Date).AddDays(-7) -targetIds 4624,4625,4648
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$evtxPath,

  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$outPath,

  [Parameter()]
  [datetime]$startTime = (Get-Date).AddDays(-30),

  [Parameter()]
  [datetime]$endTime = (Get-Date),

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [int[]]$targetIds = @(4688, 4624, 4625, 4648, 4657, 4720, 4732)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
  if (-not (Test-Path -Path $evtxPath -PathType Leaf)) {
    throw "EVTX file not found: $evtxPath"
  }

  if ($endTime -lt $startTime) {
    throw 'endTime must be greater than or equal to startTime.'
  }

  $uniqueIds = $targetIds | Sort-Object -Unique
  if ($uniqueIds.Count -eq 0) {
    throw 'targetIds cannot be empty.'
  }

  $eventIdClause = ($uniqueIds | ForEach-Object { "EventID=$_" }) -join ' or '
  $startUtc = $startTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $endUtc = $endTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

  $filterXPath = "*[System[($eventIdClause) and TimeCreated[@SystemTime>='$startUtc' and @SystemTime<='$endUtc']]]"

  $outputDirectory = Split-Path -Path $outPath -Parent
  if ($outputDirectory -and -not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
  }

  $events = Get-WinEvent -Path $evtxPath -FilterXPath $filterXPath -ErrorAction Stop |
    Select-Object TimeCreated, Id,
    @{ Name = 'Message'; Expression = { ($_.Message -replace '\s+', ' ').Trim() } }

  $events | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8
  Write-Output "Exported $(@($events).Count) event(s) to $outPath"
}
catch {
  Write-Error "DFIR search export failed: $($_.Exception.Message)"
  exit 1
}