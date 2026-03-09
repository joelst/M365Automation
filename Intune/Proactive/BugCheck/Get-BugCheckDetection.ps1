<#
.SYNOPSIS
Detects Blue Screen of Death (Bug Check) events on Windows systems for proactive monitoring.

DESCRIPTION
This script monitors for Bug Check events by checking Windows minidump files and correlating them
with system event log entries. It's designed for use with Microsoft Intune Proactive Remediations
to detect and report system stability issues.

The script performs the following actions:
1. Checks for the existence of the Windows Minidump folder
2. Identifies the most recent minidump (.dmp) file
3. Determines if the minidump occurred within the specified alert threshold
4. Correlates minidump timing with system event log bugcheck entries
5. Logs all findings and returns appropriate exit codes for Intune reporting

Exit Codes:
- 0: No Bug Check detected (healthy state)
- 1: Bug Check detected within alert threshold (requires attention)

.PARAMETER DelayAlertDays
Number of days to look back for Bug Check events. Default is 45 days.

.PARAMETER IgnoreCachedFiles
When specified, ignores existing .analysis files and triggers alerts even for previously analyzed dumps.
By default, the script will not alert for dumps that have corresponding .analysis files.

.EXAMPLE
.\Get-BugCheckDetection.ps1
Runs the script with default 30-day lookback period.

.EXAMPLE
.\Get-BugCheckDetection.ps1 -DelayAlertDays 7
Checks for Bug Check events within the last 7 days.

.EXAMPLE
.\Get-BugCheckDetection.ps1 -DelayAlertDays 30 -IgnoreCachedFiles
Checks for Bug Check events within the last 30 days, ignoring any existing analysis files.

.OUTPUTS
String output indicating Bug Check detection status, suitable for Intune Proactive Remediation reporting.
Detailed logging written to BugCheckDetection.log in the user's temp directory.

.NOTES
Author: MEMAppFactory
Created: 2024
Purpose: Intune Proactive Remediation - Bug Check Detection
Requirements: Local Administrator rights to access minidump folder and system event logs
Compatibility: Windows 10/11, Windows Server 2016+

.REQUIREMENTS
- PowerShell 5.1 or later
- Local Administrator privileges (to access C:\Windows\Minidump and System event log)
- Windows Event Log service running

.LINK
https://docs.microsoft.com/en-us/mem/intune/fundamentals/remediations
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$DelayAlertDays = 90,

    [Parameter(Mandatory = $false)]
    [switch]$IgnoreCachedFiles
)

# Set strict mode and error handling for better script reliability
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Initialize logging
$LogFile = Join-Path -Path $Env:TEMP -ChildPath 'BugCheckDetection.log'
if (-not (Test-Path -Path $LogFile)) {
    try {
        New-Item -Path $LogFile -ItemType File -Force | Out-Null
    }
    catch {
        Write-Warning "Failed to create log file: $_"
        # Continue without logging if file creation fails
        $LogFile = $null
    }
}

function Write-LogEntry {
    <#
    .SYNOPSIS
    Writes timestamped log entries to both log file and console output.

    .DESCRIPTION
    Creates formatted log entries with timestamp, message type, and message content.
    Handles cases where log file creation failed gracefully.

    .PARAMETER MessageType
    Type of message (INFO, WARNING, ERROR, etc.)

    .PARAMETER Message
    The message content to log
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$MessageType,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    try {
        $timestamp = '[{0:MM/dd/yy} {0:HH:mm:ss}]' -f (Get-Date)
        $logEntry = "$timestamp - $MessageType : $Message"

        # Write to log file if available
        if ($LogFile -and (Test-Path -Path $LogFile)) {
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
        }

        # Always write to console
        Write-Host $logEntry
    }
    catch {
        Write-Warning "Failed to write log entry: $_"
    }
}

# Main script logic
try {
    Write-LogEntry -MessageType 'INFO' -Message "Starting Bug Check detection script with $DelayAlertDays day(s) lookback period"

    # Define minidump folder path
    $MinidumpFolder = 'C:\Windows\Minidump'

    # Check if minidump folder exists
    if (-not (Test-Path -Path $MinidumpFolder)) {
        Write-LogEntry -MessageType 'INFO' -Message 'Minidump folder not found - no dump files available'
        Write-Output 'No DMP files found'
        exit 0
    }

    Write-LogEntry -MessageType 'INFO' -Message "Checking minidump folder: $MinidumpFolder"

    # Get the most recent minidump files (up to 3)
    $recentDumpFiles = @(Get-ChildItem -Path $MinidumpFolder -Filter '*.dmp' -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 3)

    if ($null -eq $recentDumpFiles -or $recentDumpFiles.Count -eq 0) {
        Write-LogEntry -MessageType 'INFO' -Message 'No minidump files found in the folder'
        Write-Output 'No new Bug Check found'
        exit 0
    }

    # Get the most recent dump file for primary analysis
    $lastDumpFile = $recentDumpFiles[0]

    # Calculate days since last dump file
    $lastDumpDate = $lastDumpFile.LastWriteTime
    $currentDate = Get-Date
    $daysSinceLastDump = ($currentDate - $lastDumpDate).Days

    Write-LogEntry -MessageType 'INFO' -Message "Last minidump file: $($lastDumpFile.Name) (Date: $lastDumpDate, $daysSinceLastDump days ago)"

    # Log information about all dump files
    Write-LogEntry -MessageType 'INFO' -Message "Dump files: $($recentDumpFiles.Count)"
    foreach ($dumpFile in $recentDumpFiles) {
        $daysAgo = ($currentDate - $dumpFile.LastWriteTime).Days
        Write-LogEntry -MessageType 'INFO' -Message "  - $($dumpFile.Name): $($dumpFile.LastWriteTime) ($daysAgo days ago)"
    }

    # Check for analysis cache files for all dump files
    $dumpAnalysisStatus = @()
    $unanalyzedDumps = @()

    foreach ($dumpFile in $recentDumpFiles) {
        $analysisFile = Join-Path -Path $MinidumpFolder -ChildPath "$($dumpFile.BaseName).analysis"
        $hasAnalysisFile = Test-Path -Path $analysisFile

        if ($hasAnalysisFile) {
            $analysisInfo = Get-Item -Path $analysisFile -ErrorAction SilentlyContinue
            $analysisDate = if ($analysisInfo) { $analysisInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } else { 'Unknown' }
            $status = "Analyzed ($analysisDate)"
            Write-LogEntry -MessageType 'INFO' -Message "Analysis file exists for $($dumpFile.Name): $analysisFile"
        }
        else {
            $status = "Not analyzed"
            $unanalyzedDumps += $dumpFile
            Write-LogEntry -MessageType 'INFO' -Message "No analysis file found for $($dumpFile.Name)"
        }

        $dumpAnalysisStatus += "$($dumpFile.Name) [$status]"
    }

    # Prepare cache status output
    $cacheStatusOutput = "Cache status: $($dumpAnalysisStatus -join ', ')"
    Write-LogEntry -MessageType 'INFO' -Message $cacheStatusOutput

    # Check if the dump file is within our alert threshold
    if ($daysSinceLastDump -le $DelayAlertDays) {
        # Determine if remediation is needed based on unanalyzed dumps or IgnoreCachedFiles parameter
        $needsRemediation = $false

        if ($IgnoreCachedFiles) {
            $needsRemediation = $true
            Write-LogEntry -MessageType 'INFO' -Message "IgnoreCachedFiles specified - triggering remediation regardless of cache status"
        }
        elseif ($unanalyzedDumps.Count -gt 0) {
            $needsRemediation = $true
            Write-LogEntry -MessageType 'INFO' -Message "Found $($unanalyzedDumps.Count) unanalyzed dump file(s) - triggering remediation"
        }
        else {
            Write-LogEntry -MessageType 'INFO' -Message "All dump files have been analyzed - no remediation needed"
        }

        if (-not $needsRemediation) {
            $dumpDates = $recentDumpFiles | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
            Write-Output "No Bug Check alert (all analyzed) | Dumps: $($dumpDates -join ', ') | $cacheStatusOutput"
            exit 0
        }

        Write-LogEntry -MessageType 'WARNING' -Message 'Bug Check detected within alert threshold'
        Write-LogEntry -MessageType 'INFO' -Message "Minidump file: $($lastDumpFile.FullName)"

        # Try to correlate with system event log
        try {
            Write-LogEntry -MessageType 'INFO' -Message 'Checking system event log for corresponding bugcheck events'

            # Use Get-WinEvent instead of deprecated Get-EventLog
            $bugCheckEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                Id = 1001  # BugCheck event ID
            } -MaxEvents 10 -ErrorAction SilentlyContinue

            if ($bugCheckEvents) {
                $lastBugCheckEvent = $bugCheckEvents[0]
                $lastBugCheckEventDate = $lastBugCheckEvent.TimeCreated
                $lastBugCheckEventMessage = $lastBugCheckEvent.Message

                Write-LogEntry -MessageType 'INFO' -Message "Last bugcheck event found: $lastBugCheckEventDate"

                # Check if event log entry correlates with dump file (within 1 hour tolerance)
                $timeDifference = [Math]::Abs(($lastDumpDate - $lastBugCheckEventDate).TotalHours)

                if ($timeDifference -le 1) {
                    Write-LogEntry -MessageType 'INFO' -Message 'Corresponding bugcheck event found in system log'
                    Write-LogEntry -MessageType 'INFO' -Message "Event time: $lastBugCheckEventDate"
                    Write-LogEntry -MessageType 'INFO' -Message "Event message: $lastBugCheckEventMessage"

                    # Create comprehensive output with dump file dates and cache status
                    $dumpDates = $recentDumpFiles | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
                    $outputMessage = "Bug Check detected: $($lastDumpDate.ToString('yyyy-MM-dd HH:mm')) | Dumps: $($dumpDates -join ', ') | $cacheStatusOutput"
                    Write-Output $outputMessage
                    exit 1
                }
                else {
                    Write-LogEntry -MessageType 'WARNING' -Message 'Minidump found but no corresponding event log entry'
                    $dumpDates = $recentDumpFiles | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
                    Write-Output "Bug Check detected: $($lastDumpDate.ToString('yyyy-MM-dd HH:mm')) | Dumps: $($dumpDates -join ', ') | No correlating event | $cacheStatusOutput"
                    exit 1
                }
            }
            else {
                Write-LogEntry -MessageType 'WARNING' -Message 'No bugcheck events found in system log'
                $dumpDates = $recentDumpFiles | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
                Write-Output "Bug Check detected: $($lastDumpDate.ToString('yyyy-MM-dd HH:mm')) | Dumps: $($dumpDates -join ', ') | No event log entries | $cacheStatusOutput"
                exit 1
            }
        }
        catch {
            Write-LogEntry -MessageType 'ERROR' -Message "Failed to query event log: $_"
            $dumpDates = $recentDumpFiles | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
            Write-Output "Bug Check detected: $($lastDumpDate.ToString('yyyy-MM-dd HH:mm')) | Dumps: $($dumpDates -join ', ') | Event log query failed | $cacheStatusOutput"
            exit 1
        }
    }
    else {
        Write-LogEntry -MessageType 'INFO' -Message "Last Bug Check is older than $DelayAlertDays days - no issues detected"

        # Still show cache status even for older dumps
        if ($recentDumpFiles.Count -gt 0) {
            $dumpDates = $recentDumpFiles | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
            Write-Output "No new Bug Check found | Older dumps: $($dumpDates -join ', ') | $cacheStatusOutput"
        }
        else {
            Write-Output 'No new Bug Check found | No dump files in lookback period'
        }
        exit 0
    }
}
catch {
    $errorMessage = "Script execution failed: $($_.Exception.Message)"
    Write-LogEntry -MessageType 'ERROR' -Message $errorMessage
    Write-Error $errorMessage
    exit 1
}
finally {
    # Only log to file, not console, to avoid interfering with Intune output
    if ($LogFile -and (Test-Path -Path $LogFile)) {
        $timestamp = '[{0:MM/dd/yy} {0:HH:mm:ss}]' -f (Get-Date)
        $logEntry = "$timestamp - INFO : Bug Check detection script completed"
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}
