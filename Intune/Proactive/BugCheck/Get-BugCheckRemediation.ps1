<#
.SYNOPSIS
Collects comprehensive diagnostic information following a Bug Check event for analysis and troubleshooting.

.DESCRIPTION
This script serves as the remediation component for Bug Check detection in Microsoft Intune Proactive Remediations.
When triggered after a Bug Check detection, it automatically:

1. Detects existing WinDbg installations or automatically installs WinDbg if dump files are present
   - Uses Winget-AutoUpdate script (%ProgramData%\Winget-AutoUpdate\Winget-Install.ps1) if available
   - Falls back to direct Microsoft download if Winget-AutoUpdate is not available
2. Systematically collects diagnostic information including:
   - System and application event logs (last 15 days)
   - Minidump files from Windows crash dumps with automated analysis
   - Installed hotfixes and system patches
   - Running services and their states
   - Installed drivers and their versions
   - Active processes at collection time
   - Pending Windows updates
   - System uptime and boot information
   - Kernel and hardware-related event logs
3. Performs comprehensive dump analysis using WinDbg (automatically downloaded if needed)
4. Implements intelligent analysis caching to avoid re-analyzing dumps within the cache period
5. Automatically cleans up old dump files beyond the retention period
6. Logs analysis results directly to Intune for immediate visibility
7. Packages all collected data into a compressed ZIP file

The script is designed for autonomous execution in Intune Proactive Remediations without requiring
command-line parameters. It automatically detects system conditions and adapts its behavior accordingly.

Caching Behavior:
- Analysis results are saved as .analysis files alongside dump files
- Cached results are used if less than AnalysisCacheDays old (default: 14 days)
- Use -ForceReAnalysis to ignore cache and re-analyze all dumps

Cleanup Behavior:
- Dump files older than DumpRetentionDays (default: 90 days) are automatically deleted
- Associated analysis files are also removed during cleanup

.PARAMETER OutputPath
Optional custom path for the diagnostic collection folder. Defaults to C:\Windows\Temp\DMPLogsfolder.

.PARAMETER LogPath
Optional custom path for the remediation log file. Defaults to C:\Windows\Temp\$ComputerName-BugCheckRemediation.log.

.PARAMETER IncludeWinDbg
Switch to download and install WinDbg for local dump analysis. Requires internet connectivity.

.PARAMETER ArchitecturePreference
Architecture preference for WinDbg download when -IncludeWinDbg is specified.

.PARAMETER AnalysisCacheDays
Number of days to cache WinDbg analysis results. If analysis results exist and are newer than this threshold, 
they will be reused instead of re-running the analysis. Default is 14 days.

.PARAMETER ForceReAnalysis
Ignore cached analysis results and force re-analysis of all dump files, overwriting existing .analysis files.

.PARAMETER DumpRetentionDays
Number of days to retain dump files. Files older than this threshold will be automatically deleted along 
with their associated analysis files. Default is 90 days.

.EXAMPLE
.\Get-BugCheckRemediation.ps1
Runs autonomously with automatic WinDbg detection/download and comprehensive dump analysis.
This is the typical execution mode for Intune Proactive Remediations.

.EXAMPLE
.\Get-BugCheckRemediation.ps1 -ForceReAnalysis
Forces re-analysis of all dump files, ignoring any cached results.

.EXAMPLE
.\Get-BugCheckRemediation.ps1 -DumpRetentionDays 30 -AnalysisCacheDays 7
Keeps dump files for 30 days and analysis cache for 7 days.

.EXAMPLE
.\Get-BugCheckRemediation.ps1 -OutputPath "C:\Temp\BugCheck_Analysis"
Runs with custom output path while maintaining autonomous WinDbg handling.

.OUTPUTS
Creates a ZIP file containing all collected diagnostic information.
File naming convention: BugCheck_<ComputerName>.zip
Logs all activities to the specified log file.

.NOTES
Author: MEMAppFactory
Created: 2024
Purpose: Intune Proactive Remediation - Bug Check Data Collection
Requirements: Local Administrator rights for system file access and event log reading
Compatibility: Windows 10/11, Windows Server 2016+

.REQUIREMENTS
- PowerShell 5.1 or later
- Local Administrator privileges (required for dump file access and system logs)
- Sufficient disk space for diagnostic collection (typically 100-500MB)
- Write access to Windows\Temp and Windows\Debug directories

.LINK
https://docs.microsoft.com/en-us/mem/intune/fundamentals/remediations
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWinDbg,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$ArchitecturePreference = 'x64',
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$AnalysisCacheDays = 14,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForceReAnalysis,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$DumpRetentionDays = 90
)

# Set strict mode and error handling for better script reliability
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Set default paths if not provided
if (-not $OutputPath) {
    $OutputPath = Join-Path $env:SystemRoot "Temp\DMPLogs"
}
if (-not $LogPath) {
    $LogPath = "$env:SystemRoot\Temp\$($env:COMPUTERNAME)-BugCheckRemediation.log"
}

# Script-level variables
$script:LogFile = $LogPath
$script:TempFolder = "$env:SystemRoot\Temp"
$script:DMPLogsFolder = $OutputPath
$script:DMPLogsFolderZIP = "$script:TempFolder\$env:COMPUTERNAME-BugCheck.zip"
$script:ZIPName = "$env:COMPUTERNAME_BugCheck.zip"

function Write-LogEntry {
    <#
    .SYNOPSIS
    Writes timestamped log entries to both log file and console output.
    
    .DESCRIPTION
    Creates formatted log entries with timestamp, message type, and message content.
    Handles cases where log file creation failed gracefully.
    
    .PARAMETER MessageType
    Type of message (INFO, SUCCESS, WARNING, ERROR, etc.)
    
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
        if ($script:LogFile -and (Test-Path -Path (Split-Path -Path $script:LogFile -Parent))) {
            Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
        }
        
        # Always write to console
        Write-Output $logEntry
    }
    catch {
        Write-Warning "Failed to write log entry: $_"
    }
}

function Remove-OldDumpFiles {
    <#
    .SYNOPSIS
    Removes dump files and associated analysis files older than the specified retention period.
    
    .DESCRIPTION
    Cleans up old dump files from the minidump folder to prevent disk space issues.
    Also removes associated .analysis files to maintain consistency.
    
    .PARAMETER MinidumpPath
    Path to the minidump folder
    
    .PARAMETER RetentionDays
    Number of days to retain files
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MinidumpPath,
        
        [Parameter(Mandatory = $true)]
        [int]$RetentionDays
    )
    
    try {
        if (-not (Test-Path -Path $MinidumpPath)) {
            Write-LogEntry -MessageType 'INFO' -Message 'Minidump folder not found - no cleanup needed'
            return
        }
        
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        Write-LogEntry -MessageType 'INFO' -Message "Cleaning up dump files older than $RetentionDays days (before $cutoffDate)"
        
        # Find old dump files
        $oldDumpFiles = @(Get-ChildItem -Path $MinidumpPath -Filter '*.dmp' -ErrorAction SilentlyContinue | 
            Where-Object { $_.LastWriteTime -lt $cutoffDate })
        
        if ($oldDumpFiles) {
            foreach ($dumpFile in $oldDumpFiles) {
                try {
                    # Remove the dump file
                    Remove-Item -Path $dumpFile.FullName -Force -ErrorAction Stop
                    Write-LogEntry -MessageType 'INFO' -Message "Removed old dump file: $($dumpFile.Name)"
                    
                    # Remove associated analysis file if it exists
                    $analysisFile = Join-Path -Path $MinidumpPath -ChildPath "$($dumpFile.BaseName).analysis"
                    if (Test-Path -Path $analysisFile) {
                        Remove-Item -Path $analysisFile -Force -ErrorAction Stop
                        Write-LogEntry -MessageType 'INFO' -Message "Removed associated analysis file: $($dumpFile.BaseName).analysis"
                    }
                }
                catch {
                    Write-LogEntry -MessageType 'ERROR' -Message "Failed to remove $($dumpFile.Name): $($_.Exception.Message)"
                }
            }
            
            Write-LogEntry -MessageType 'SUCCESS' -Message "Cleanup completed - removed $($oldDumpFiles.Count) old dump file(s)"
        } else {
            Write-LogEntry -MessageType 'INFO' -Message 'No old dump files found for cleanup'
        }
        
        # Also clean up orphaned analysis files
        $analysisFiles = Get-ChildItem -Path $MinidumpPath -Filter '*.analysis' -ErrorAction SilentlyContinue
        foreach ($analysisFile in $analysisFiles) {
            $correspondingDump = Join-Path -Path $MinidumpPath -ChildPath "$($analysisFile.BaseName).dmp"
            if (-not (Test-Path -Path $correspondingDump)) {
                try {
                    Remove-Item -Path $analysisFile.FullName -Force -ErrorAction Stop
                    Write-LogEntry -MessageType 'INFO' -Message "Removed orphaned analysis file: $($analysisFile.Name)"
                }
                catch {
                    Write-LogEntry -MessageType 'ERROR' -Message "Failed to remove orphaned analysis file $($analysisFile.Name): $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Cleanup operation failed: $($_.Exception.Message)"
    }
}

function Get-CachedAnalysisResult {
    <#
    .SYNOPSIS
    Retrieves cached analysis results if they exist and are within the cache period.
    
    .DESCRIPTION
    Checks for existing .analysis files and validates their age against the cache threshold.
    Returns cached results if valid, otherwise returns null.
    
    .PARAMETER DumpFilePath
    Path to the dump file
    
    .PARAMETER CacheDays
    Number of days to consider cache valid
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DumpFilePath,
        
        [Parameter(Mandatory = $true)]
        [int]$CacheDays
    )
    
    $dumpFile = $null

    try {
        $dumpFile = Get-Item -Path $DumpFilePath
        $analysisFilePath = Join-Path -Path $dumpFile.Directory.FullName -ChildPath "$($dumpFile.BaseName).analysis"
        
        if (-not (Test-Path -Path $analysisFilePath)) {
            return $null
        }
        
        $analysisFile = Get-Item -Path $analysisFilePath
        $cacheAge = (Get-Date) - $analysisFile.LastWriteTime
        
        if ($cacheAge.Days -le $CacheDays) {
            Write-LogEntry -MessageType 'INFO' -Message "Using cached analysis for $($dumpFile.Name) (age: $($cacheAge.Days) days)"
            
            # Read and parse cached results
            $cachedContent = Get-Content -Path $analysisFilePath -Raw -ErrorAction Stop
            $cachedResult = $cachedContent | ConvertFrom-Json -ErrorAction Stop
            
            return $cachedResult
        } else {
            Write-LogEntry -MessageType 'INFO' -Message "Cached analysis for $($dumpFile.Name) is stale (age: $($cacheAge.Days) days)"
            return $null
        }
    }
    catch {
        Write-LogEntry -MessageType 'WARNING' -Message "Failed to read cached analysis for $($dumpFile.Name): $($_.Exception.Message)"
        return $null
    }
}

function Save-AnalysisResult {
    <#
    .SYNOPSIS
    Saves analysis results to a cache file alongside the dump file.
    
    .DESCRIPTION
    Serializes analysis results to JSON and saves as .analysis file in the minidump folder.
    
    .PARAMETER DumpFilePath
    Path to the dump file
    
    .PARAMETER AnalysisResult
    Analysis result object to save
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DumpFilePath,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AnalysisResult,

        [Parameter(Mandatory = $false)]
        [string[]]$AdditionalDirectories
    )
    
    try {
        $dumpFile = Get-Item -Path $DumpFilePath
        $analysisFilePath = Join-Path -Path $dumpFile.Directory.FullName -ChildPath "$($dumpFile.BaseName).analysis"
        
        # Add metadata to the analysis result
        $analysisResult | Add-Member -NotePropertyName 'AnalysisDate' -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Force
        $analysisResult | Add-Member -NotePropertyName 'DumpFileDate' -NotePropertyValue $dumpFile.LastWriteTime -Force
        $analysisResult | Add-Member -NotePropertyName 'DumpFileSize' -NotePropertyValue $dumpFile.Length -Force
        
        # Serialize once for reuse across multiple cache locations
        $analysisJson = $analysisResult | ConvertTo-Json -Depth 10
        $analysisJson | Out-File -FilePath $analysisFilePath -Encoding UTF8 -ErrorAction Stop
        Write-LogEntry -MessageType 'SUCCESS' -Message "Analysis results cached: $($dumpFile.BaseName).analysis"

        if ($AdditionalDirectories) {
            foreach ($targetDirectory in $AdditionalDirectories) {
                if ([string]::IsNullOrWhiteSpace($targetDirectory)) { continue }

                try {
                    if (-not (Test-Path -Path $targetDirectory)) {
                        New-Item -Path $targetDirectory -ItemType Directory -Force | Out-Null
                    }

                    $replicaPath = Join-Path -Path $targetDirectory -ChildPath "$($dumpFile.BaseName).analysis"
                    $analysisJson | Out-File -FilePath $replicaPath -Encoding UTF8 -ErrorAction Stop
                    Write-LogEntry -MessageType 'INFO' -Message "Analysis cache replicated to: $replicaPath"
                }
                catch {
                    Write-LogEntry -MessageType 'WARNING' -Message ("Failed to write analysis replica to {0}: {1}" -f $targetDirectory, $_.Exception.Message)
                }
            }
        }
        
    }
    catch {
        $dumpIdentifier = if ($dumpFile) { $dumpFile.Name } else { [System.IO.Path]::GetFileName($DumpFilePath) }
        Write-LogEntry -MessageType 'ERROR' -Message ("Failed to cache analysis results for {0}: {1}" -f $dumpIdentifier, $_.Exception.Message)
    }
}

function Get-AnalysisFieldValue {
    <#
    .SYNOPSIS
    Retrieves a property value from a dump analysis result while handling missing members.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$AnalysisObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        [object]$DefaultValue = 'Unknown'
    )

    if ($null -eq $AnalysisObject) {
        return $DefaultValue
    }

    $resolvedValue = $null

    if ($AnalysisObject -is [System.Collections.IDictionary]) {
        if ($AnalysisObject.Contains($PropertyName)) {
            $resolvedValue = $AnalysisObject[$PropertyName]
        }
    }
    else {
        $property = $AnalysisObject.PSObject.Properties[$PropertyName]
        if ($property) {
            $resolvedValue = $property.Value
        }
    }

    if ($null -eq $resolvedValue) {
        return $DefaultValue
    }

    if ($resolvedValue -is [string]) {
        if ([string]::IsNullOrWhiteSpace($resolvedValue)) {
            return $DefaultValue
        }
        return $resolvedValue
    }

    if ($resolvedValue -is [System.Array]) {
        if ($resolvedValue.Count -gt 0) {
            return $resolvedValue
        }
        return $DefaultValue
    }

    return $resolvedValue
}

function Find-ExistingWinDbg {
    <#
    .SYNOPSIS
    Searches for existing WinDbg installations on the system.
    
    .DESCRIPTION
    Checks common installation paths and Windows SDK locations for WinDbg tools.
    Returns the path to WinDbg if found, otherwise returns null.
    #>
    [CmdletBinding()]
    param()
    
    $possiblePaths = @(
        # Windows SDK locations
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\x64",
        "${env:ProgramFiles(x86)}\Windows Kits\8.1\Debuggers\x64",
        "$env:ProgramFiles\Windows Kits\8.1\Debuggers\x64",
        
        # Standalone WinDbg installations
        "$env:ProgramFiles\WindowsApps\Microsoft.WinDbg_*",
        "${env:ProgramFiles(x86)}\Windows Kits\*\Debuggers\x64",
        
        # Custom locations in temp folders (from previous downloads)
        "$script:TempFolder\WinDbg\windbg",
        "$script:DMPLogsFolder\WinDbg\windbg"
    )
    
    foreach ($path in $possiblePaths) {
        if ($path -like '*`**') {
            # Handle wildcard paths
            $expandedPaths = Get-ChildItem -Path ($path -replace '\\\*.*$', '') -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -like ($path -replace '.*\\', '') }
            
            foreach ($expandedPath in $expandedPaths) {
                $testPath = if ($path -like '*WindowsApps*') { 
                    Join-Path -Path $expandedPath.FullName -ChildPath 'DbgX.Shell.exe' 
                } else { 
                    Join-Path -Path $expandedPath.FullName -ChildPath 'Debuggers\x64\cdb.exe' 
                }
                
                if (Test-Path -Path $testPath) {
                    Write-LogEntry -MessageType 'INFO' -Message "Found existing WinDbg at: $($expandedPath.FullName)" | Out-Null
                    return $expandedPath.FullName
                }
            }
        } else {
            # Handle direct paths
            if (-not (Test-Path -Path $path)) { continue }
            $candidate = Get-WinDbgExecutable -BasePath $path
            if ($candidate) {
                Write-LogEntry -MessageType 'INFO' -Message "Found existing WinDbg tools at: $path" | Out-Null
                return $path
            }
        }
    }
    
    Write-LogEntry -MessageType 'INFO' -Message 'No existing WinDbg installation found' | Out-Null
    return $null
}

function Install-WinDbgViaWinget {
    <#
    .SYNOPSIS
    Installs WinDbg using the Winget-AutoUpdate script if available.
    
    .DESCRIPTION
    Attempts to install WinDbg using the Winget-AutoUpdate infrastructure commonly found
    in enterprise environments. Falls back gracefully if the script is not available.
    #>
    [CmdletBinding()]
    param()
    
    try {
        $wingetAutoUpdateScript = "$env:ProgramData\Winget-AutoUpdate\Winget-Install.ps1"
        
        if (Test-Path -Path $wingetAutoUpdateScript) {
            Write-LogEntry -MessageType 'INFO' -Message 'Found Winget-AutoUpdate script - attempting WinDbg installation' | Out-Null
            
            # Execute the Winget-AutoUpdate script to install WinDbg
            $installArgs = @(
                '-AppIDs', 'Microsoft.WinDbg'
            )
            
            Write-LogEntry -MessageType 'INFO' -Message "Executing: $wingetAutoUpdateScript -AppIDs Microsoft.WinDbg" | Out-Null
            
            $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
                '-ExecutionPolicy', 'Bypass',
                '-File', $wingetAutoUpdateScript
            ) + $installArgs -Wait -PassThru -WindowStyle Hidden
            
            if ($process.ExitCode -eq 0) {
                Write-LogEntry -MessageType 'SUCCESS' -Message 'WinDbg installation via Winget-AutoUpdate completed successfully' | Out-Null
                
                # Give the installation time to complete and refresh environment
                Start-Sleep -Seconds 5
                
                # Try to find the newly installed WinDbg
                $newWinDbgPath = Find-ExistingWinDbg
                if ($newWinDbgPath) {
                    Write-LogEntry -MessageType 'SUCCESS' -Message "WinDbg successfully installed and located at: $newWinDbgPath" | Out-Null
                    return $newWinDbgPath
                } else {
                    Write-LogEntry -MessageType 'WARNING' -Message 'WinDbg installation completed but could not locate installation path' | Out-Null
                    return $null
                }
            } else {
                Write-LogEntry -MessageType 'ERROR' -Message "Winget-AutoUpdate installation failed with exit code: $($process.ExitCode)" | Out-Null
                return $null
            }
        } else {
            Write-LogEntry -MessageType 'INFO' -Message 'Winget-AutoUpdate script not found - skipping automated installation' | Out-Null
            return $null
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to install WinDbg via Winget-AutoUpdate: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Get-WinDbgExecutable {
    <#
    .SYNOPSIS
    Attempts to locate a usable debugger executable (cdb.exe, windbg.exe, kd.exe) under a base WinDbg path.

    .DESCRIPTION
    Handles traditional SDK layouts, manually extracted MSIX bundles, and WindowsApps MSIX installed paths.
    Performs a targeted recursive search if direct candidates aren't found at the root.
    Returns the full path to the first matching executable or $null if none found.

    .PARAMETER BasePath
    Root directory returned by WinDbg discovery/installation logic.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    try {
        if (-not (Test-Path -Path $BasePath)) { return $null }

        # If the provided path is already an executable, return it
        if ($BasePath.ToLower().EndsWith('.exe')) {
            if (Test-Path -Path $BasePath -PathType Leaf) {
                return $BasePath
            }
            return $null
        }

        $candidateNames = 'cdb.exe','windbg.exe','kd.exe'

        foreach ($name in $candidateNames) {
            $direct = Join-Path -Path $BasePath -ChildPath $name
            if (Test-Path -Path $direct -PathType Leaf) { return $direct }
        }

        # If only the WinDbgX GUI is present, attempt to locate the CLI debugger next to it
        $guiCandidates = 'DbgX.Shell.exe','DbgX.ShellHost.exe'
        foreach ($gui in $guiCandidates) {
            $guiPath = Join-Path -Path $BasePath -ChildPath $gui
            if (Test-Path -Path $guiPath -PathType Leaf) {
                $relativeCliPaths = @(
                    'amd64\cdb.exe',
                    'Debuggers\x64\cdb.exe',
                    'x64\cdb.exe',
                    'cdb.exe'
                )
                foreach ($relativeCli in $relativeCliPaths) {
                    $cliCandidate = Join-Path -Path $BasePath -ChildPath $relativeCli
                    if (Test-Path -Path $cliCandidate -PathType Leaf) {
                        Write-LogEntry -MessageType 'INFO' -Message "Mapped WinDbgX shell to CLI debugger at: $cliCandidate" | Out-Null
                        return $cliCandidate
                    }
                }

                # No usable CLI companion found alongside the shell
                Write-LogEntry -MessageType 'WARNING' -Message "WinDbgX shell located at $guiPath but no cdb/kd executable found in installation" | Out-Null
                return $null
            }
        }

        # Handle common nested folders (e.g., extracted MSIX structure)
        $nestedCandidates = @(
            'Debuggers\x64\cdb.exe',
            'amd64\cdb.exe',
            'x64\cdb.exe',
            'cdb.exe'
        )
        foreach ($sub in $nestedCandidates) {
            $candidatePath = Join-Path -Path $BasePath -ChildPath $sub
            if (Test-Path -Path $candidatePath -PathType Leaf) { return $candidatePath }
        }

        # Recursive search as a last resort (limit depth for performance)
        $found = Get-ChildItem -Path $BasePath -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $candidateNames -contains $_.Name } |
            Select-Object -First 1
        if ($found) { return $found.FullName }

        return $null
    }
    catch {
        Write-LogEntry -MessageType 'WARNING' -Message "WinDbg executable search failed under $($BasePath): $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Get-WinDbg {
    <#
    .SYNOPSIS
    Downloads and extracts the latest Windows Debugging Tools (WinDbg) from Microsoft.
    
    .DESCRIPTION
    Automatically downloads the current version of WinDbg from Microsoft's distribution endpoint.
    Extracts the debugging tools to a local directory for immediate use in dump analysis.
    
    .PARAMETER OutputDirectory
    Directory where WinDbg should be extracted. Creates directory if it doesn't exist.
    
    .PARAMETER Architecture
    Target architecture for the debugging tools (x64, x86, arm64).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = '.',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('x64', 'x86', 'arm64')]
        [string]$Architecture = 'x64'
    )
    
    try {
        Write-LogEntry -MessageType 'INFO' -Message "Starting WinDbg download for $Architecture architecture"
        
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }

        # Download the app installer to find the current URI for the msixbundle
        $appInstallerPath = Join-Path -Path $OutputDirectory -ChildPath 'windbg.appinstaller'
        Write-LogEntry -MessageType 'INFO' -Message 'Downloading WinDbg app installer manifest'
        Invoke-WebRequest -Uri 'https://aka.ms/windbg/download' -OutFile $appInstallerPath -ErrorAction Stop

        # Extract the msixbundle URI from the app installer
        $msixBundleUri = ([xml](Get-Content -Path $appInstallerPath)).AppInstaller.MainBundle.Uri
        Write-LogEntry -MessageType 'INFO' -Message "Found WinDbg bundle URI: $msixBundleUri"

        # Performance optimization for older PowerShell versions
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            $ProgressPreference = 'SilentlyContinue'
        }

        # Download the msixbundle (renamed as ZIP for compatibility)
        $bundleZipPath = Join-Path -Path $OutputDirectory -ChildPath 'windbg.zip'
        Write-LogEntry -MessageType 'INFO' -Message 'Downloading WinDbg bundle package'
        Invoke-WebRequest -Uri $msixBundleUri -OutFile $bundleZipPath -ErrorAction Stop

        # Extract the bundle contents
        $unzipPath = Join-Path -Path $OutputDirectory -ChildPath 'UnzippedBundle'
        Write-LogEntry -MessageType 'INFO' -Message 'Extracting WinDbg bundle'
        Expand-Archive -Path $bundleZipPath -DestinationPath $unzipPath -Force

        # Rename and extract the architecture-specific debugger package
        $msixPath = Join-Path -Path $unzipPath -ChildPath "windbgwin-$Architecture.msix"
        $msixZipPath = Join-Path -Path $unzipPath -ChildPath "windbgwin-$Architecture.zip"
        $windbgPath = Join-Path -Path $OutputDirectory -ChildPath 'windbg'
        
        Move-Item -Path $msixPath -Destination $msixZipPath -Force
        Expand-Archive -Path $msixZipPath -DestinationPath $windbgPath -Force

        Write-LogEntry -MessageType 'SUCCESS' -Message "WinDbg successfully installed to: $windbgPath" | Out-Null
        Write-LogEntry -MessageType 'INFO' -Message "Launch debugger with: $windbgPath\DbgX.Shell.exe" | Out-Null
        
        return $windbgPath
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to download WinDbg: $($_.Exception.Message)"
        throw
    }
}



function Write-ApplicationEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information',

        [Parameter(Mandatory = $false)]
        [int]$EventId = 100
    )

    $source = 'BugCheckRemediation'
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            try { New-EventLog -LogName 'Application' -Source $source } catch { }
        }

        $maxLength = 30000
        $safeMessage = if ($Message.Length -gt $maxLength) { $Message.Substring(0, $maxLength) } else { $Message }

        Write-EventLog -LogName 'Application' -Source $source -EventId $EventId -EntryType $EntryType -Message $safeMessage
    }
    catch {
        Write-LogEntry -MessageType 'WARNING' -Message "Failed to write Application event log entry: $($_.Exception.Message)"
    }
}

function Format-CommandLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $false)]
        [object[]]$Arguments
    )

    $escape = {
        param([object]$Token)

        if ($null -eq $Token) { return '""' }
        $tokenString = [string]$Token
        if ([string]::IsNullOrWhiteSpace($tokenString)) { return '""' }
        if ($tokenString -match "[\s`"`]") {
            $escaped = $tokenString.Replace('"', '""')
            return '"' + $escaped + '"'
        }
        return $tokenString
    }

    $formattedExe = & $escape $Executable
    $formattedArgs = @()
    if ($Arguments) {
        foreach ($arg in $Arguments) { $formattedArgs += (& $escape $arg) }
    }

    if ($formattedArgs.Count -gt 0) {
        return "$formattedExe $([string]::Join(' ', $formattedArgs))"
    }
    return $formattedExe
}

function Export-EventLogs {
    <#
    .SYNOPSIS
    Exports Windows Event Logs from the last 15 days to EVTX files.
    
    .DESCRIPTION
    Uses WEVTUtil to export event logs with time-based filtering.
    Exports events from the last 15 days (1296000000 microseconds = 15 days).
    
    .PARAMETER LogName
    Name of the Windows Event Log to export
    
    .PARAMETER OutputFileName
    Base filename for the exported EVTX file (extension added automatically)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogName,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFileName
    )
    
    Write-LogEntry -MessageType 'INFO' -Message "Collecting event logs from: $LogName"
    
    try {
        $outputPath = Join-Path -Path $script:DMPLogsFolder -ChildPath "$OutputFileName.evtx"
        
        # Export events from last 15 days using WEVTUtil
        $arguments = @(
            'export-log'
            $LogName
            $outputPath
            '/ow:true'
            '/q:*[System[TimeCreated[timediff(@SystemTime) <= 1296000000]]]'
        )
        
        & wevtutil.exe @arguments | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogEntry -MessageType 'SUCCESS' -Message "Event log $OutputFileName.evtx exported successfully"
        } else {
            Write-LogEntry -MessageType 'WARNING' -Message "Event log export returned exit code: $LASTEXITCODE"
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to export event log $OutputFileName.evtx : $($_.Exception.Message)"
    }
}

function Invoke-DumpAnalysis {
    <#
    .SYNOPSIS
    Analyzes Windows dump files using WinDbg and extracts crash information.
    
    .DESCRIPTION
    Uses WinDbg command-line interface to analyze dump files and extract key crash information
    including bug check codes, faulting modules, stack traces, and driver information.
    Results are formatted for inclusion in Intune remediation logs and cached for future use.
    
    .PARAMETER WinDbgPath
    Path to the WinDbg installation directory
    
    .PARAMETER DumpFilePath
    Path to the dump file to analyze
    
    .PARAMETER OutputDirectory
    Directory where analysis results should be saved
    
    .PARAMETER CacheDays
    Number of days to consider cached results valid
    
    .PARAMETER ForceReAnalysis
    Ignore cached results and force fresh analysis
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [string]$WinDbgPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [string]$DumpFilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [string]$OutputDirectory,
        
        [Parameter(Mandatory = $false)]
        [int]$CacheDays = 14,
        
        [Parameter(Mandatory = $false)]
        [switch]$ForceReAnalysis,

        [Parameter(Mandatory = $false)]
        [string]$OriginalMinidumpDirectory
    )
    
    try {
        $dumpFileName = [System.IO.Path]::GetFileNameWithoutExtension($DumpFilePath)
        $analysisDurationSeconds = $null
        $fallbackDurationSeconds = $null
        $usedMinimalFallback = $false
        $fallbackExitCode = $null
        $commandScriptPath = $null
        $fallbackCommandScriptPath = $null
        
        # Check for cached results first (unless forced)
        if (-not $ForceReAnalysis) {
            $cachedResult = Get-CachedAnalysisResult -DumpFilePath $DumpFilePath -CacheDays $CacheDays
            if ($cachedResult) {
                $requiredProps = 'WinDbgExitCode','AnalysisDurationSeconds','BugCheckCode','FaultingModule','ProbableCause','CommandLine'
                $missingProps = @()
                foreach ($prop in $requiredProps) {
                    $propInfo = $cachedResult.PSObject.Properties[$prop]
                    if (-not $propInfo -or [string]::IsNullOrEmpty([string]$propInfo.Value)) { $missingProps += $prop }
                }

                if ($missingProps.Count -gt 0) {
                    Write-LogEntry -MessageType 'INFO' -Message "Cached analysis missing fields ($($missingProps -join ', ')) - performing fresh analysis"
                } else {
                    $cachedResult | Add-Member -NotePropertyName 'IsCachedResult' -NotePropertyValue $true -Force
                    Write-LogEntry -MessageType 'INFO' -Message "Using cached analysis for: $dumpFileName"
                    if ($cachedResult.PSObject.Properties['CommandLine'] -and $cachedResult.CommandLine) {
                        Write-LogEntry -MessageType 'INFO' -Message "Cached analysis command line: $($cachedResult.CommandLine)"
                        Write-ApplicationEvent -Message "Bug check cached command line:\n$($cachedResult.CommandLine)" -EntryType 'Information' -EventId 208
                    }
                    if ($cachedResult.PSObject.Properties['FallbackCommandLine'] -and $cachedResult.FallbackCommandLine) {
                        Write-LogEntry -MessageType 'INFO' -Message "Cached fallback command line: $($cachedResult.FallbackCommandLine)"
                        Write-ApplicationEvent -Message "Bug check cached fallback command line:\n$($cachedResult.FallbackCommandLine)" -EntryType 'Information' -EventId 214
                    }
                    return $cachedResult
                }
            }
        }
        
        $analysisOutputFile = Join-Path -Path $OutputDirectory -ChildPath "$dumpFileName`_Analysis.txt"
        $winDbgExe = Get-WinDbgExecutable -BasePath $WinDbgPath
        if (-not $winDbgExe) {
            Write-LogEntry -MessageType 'WARNING' -Message "No debugger executable found directly under $WinDbgPath - attempting direct download fallback"
            try {
                # Attempt direct download/extract as a fallback
                $fallbackRoot = Join-Path -Path $OutputDirectory -ChildPath 'WinDbg_Fallback'
                if (-not (Test-Path -Path $fallbackRoot)) { New-Item -Path $fallbackRoot -ItemType Directory -Force | Out-Null }
                $downloadedPath = Get-WinDbg -OutputDirectory $fallbackRoot -Architecture 'x64'
                $winDbgExe = Get-WinDbgExecutable -BasePath $downloadedPath
            }
            catch {
                Write-LogEntry -MessageType 'ERROR' -Message "Fallback WinDbg download failed: $($_.Exception.Message)"
            }
        }
        if (-not $winDbgExe) { throw "WinDbg executable not found in $WinDbgPath (after fallback)" }
        Write-LogEntry -MessageType 'INFO' -Message "Using debugger executable: $winDbgExe"
        
        Write-LogEntry -MessageType 'INFO' -Message "Starting fresh analysis of dump file: $dumpFileName"
        
        # Ensure a local symbol cache directory exists
        $localSymbolCache = 'C:\Windows\Debug\Symbols'
        if (-not (Test-Path -Path $localSymbolCache)) {
            try { New-Item -Path $localSymbolCache -ItemType Directory -Force | Out-Null } catch { }
        }

        # Write debugger commands to a temporary script file for reliable execution ordering
        $commandScriptPath = Join-Path -Path $OutputDirectory -ChildPath "$dumpFileName`_Commands.txt"
        $commandList = @(
            ".echo BugCheck analysis for $dumpFileName",
            '!analyze -v',
            '!process 0 0',
            '!vm',
            '!drivers',
            '!irql',
            '!thread',
            '!running',
            'k',
            'lm',
            'q'
        )
        $commandList | Set-Content -Path $commandScriptPath -Encoding ASCII

        # Build argument list including the command script and symbol path directive
        $arguments = @(
            '-z', $DumpFilePath,
            '-cf', $commandScriptPath,
            '-y', "cache*$($localSymbolCache)*https://msdl.microsoft.com/download/symbols",
            '-logo', $analysisOutputFile
        )

        [Environment]::SetEnvironmentVariable('__NT_DEBUGGER_ACCEPT_LICENSE', 'YES', 'Process')

        $commandLine = Format-CommandLine -Executable $winDbgExe -Arguments $arguments
        Write-LogEntry -MessageType 'INFO' -Message "Executing WinDbg analysis with command: $commandLine"
        Write-ApplicationEvent -Message "Bug check analysis command line:\n$commandLine" -EntryType 'Information' -EventId 209
        $analysisStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $process = Start-Process -FilePath $winDbgExe -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        $analysisStopwatch.Stop()
        $analysisDurationSeconds = [math]::Round($analysisStopwatch.Elapsed.TotalSeconds, 2)
        Write-LogEntry -MessageType 'INFO' -Message "WinDbg exit code: $($process.ExitCode); primary analysis duration: ${analysisDurationSeconds}s"
        
        if ($process.ExitCode -eq 0 -and (Test-Path -Path $analysisOutputFile)) {
            $fileInfo = Get-Item -Path $analysisOutputFile -ErrorAction SilentlyContinue
            $fileSize = if ($fileInfo) { $fileInfo.Length } else { 0 }

            # If output seems too small, attempt a minimal re-run for just !analyze -v
            if ($fileSize -lt 500) {
                Write-LogEntry -MessageType 'WARNING' -Message "Analysis output appears very small (${fileSize} bytes) - attempting minimal fallback run"
                $minimalOutput = Join-Path -Path $OutputDirectory -ChildPath "$dumpFileName`_Minimal.txt"
                $fallbackCommandScriptPath = Join-Path -Path $OutputDirectory -ChildPath "$dumpFileName`_MinimalCommands.txt"
                $minimalCommands = @(
                    '!analyze -v',
                    'q'
                )
                $minimalCommands | Set-Content -Path $fallbackCommandScriptPath -Encoding ASCII
                $minimalArgs = @(
                    '-z', $DumpFilePath,
                    '-cf', $fallbackCommandScriptPath,
                    '-y', "cache*$($localSymbolCache)*https://msdl.microsoft.com/download/symbols",
                    '-logo', $minimalOutput
                )
                $minimalCmdLine = Format-CommandLine -Executable $winDbgExe -Arguments $minimalArgs
                Write-LogEntry -MessageType 'INFO' -Message "Executing fallback WinDbg command: $minimalCmdLine"
                Write-ApplicationEvent -Message "Bug check fallback command line:\n$minimalCmdLine" -EntryType 'Information' -EventId 213
                $fallbackStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $miniProc = Start-Process -FilePath $winDbgExe -ArgumentList $minimalArgs -Wait -PassThru -WindowStyle Hidden
                $fallbackStopwatch.Stop()
                $fallbackDurationSeconds = [math]::Round($fallbackStopwatch.Elapsed.TotalSeconds, 2)
                $fallbackExitCode = $miniProc.ExitCode
                Write-LogEntry -MessageType 'INFO' -Message "Fallback analysis exit code: $fallbackExitCode; duration: ${fallbackDurationSeconds}s"
                if ($miniProc.ExitCode -eq 0 -and (Test-Path -Path $minimalOutput)) {
                    $fallbackContent = Get-Content -Path $minimalOutput -Raw -ErrorAction SilentlyContinue
                    if ($fallbackContent -and ($fallbackContent.Length -gt $fileSize)) {
                        Write-LogEntry -MessageType 'INFO' -Message 'Using fallback minimal analysis output (larger than initial)'
                        Copy-Item -Path $minimalOutput -Destination $analysisOutputFile -Force -ErrorAction SilentlyContinue
                        $usedMinimalFallback = $true
                    }
                }
            }

            # Parse analysis results for key information
            $analysisContent = Get-Content -Path $analysisOutputFile -Raw -ErrorAction SilentlyContinue
            if (-not $analysisContent) {
                Write-LogEntry -MessageType 'ERROR' -Message 'WinDbg produced no output content for parsing'
                return $null
            }

            # Log first few lines for diagnostics
            $previewLines = ($analysisContent -split "`r?`n") | Select-Object -First 12
            Write-LogEntry -MessageType 'INFO' -Message "Analysis preview:\n$([string]::Join("`n", $previewLines))"

            $summary = Convert-DumpAnalysis -AnalysisContent $analysisContent -DumpFileName $dumpFileName

            if ($summary) {
                $summary | Add-Member -NotePropertyName 'WinDbgExitCode' -NotePropertyValue $process.ExitCode -Force
                $summary | Add-Member -NotePropertyName 'AnalysisDurationSeconds' -NotePropertyValue $analysisDurationSeconds -Force
                $summary | Add-Member -NotePropertyName 'FallbackRunUsed' -NotePropertyValue $usedMinimalFallback -Force
                $summary | Add-Member -NotePropertyName 'FallbackExitCode' -NotePropertyValue $fallbackExitCode -Force
                $summary | Add-Member -NotePropertyName 'FallbackDurationSeconds' -NotePropertyValue $fallbackDurationSeconds -Force
                $summary | Add-Member -NotePropertyName 'CommandLine' -NotePropertyValue $commandLine -Force
                if ($usedMinimalFallback) {
                    $summary | Add-Member -NotePropertyName 'FallbackCommandLine' -NotePropertyValue $minimalCmdLine -Force
                }
                $summary | Add-Member -NotePropertyName 'IsCachedResult' -NotePropertyValue $false -Force
            }

            # Cache the results
            if ($summary) {
                $replicaTargets = @()
                if ($OriginalMinidumpDirectory -and (Test-Path -Path $OriginalMinidumpDirectory -PathType Container)) {
                    $replicaTargets += $OriginalMinidumpDirectory
                }

                Save-AnalysisResult -DumpFilePath $DumpFilePath -AnalysisResult $summary -AdditionalDirectories $replicaTargets
            }

            Write-LogEntry -MessageType 'SUCCESS' -Message "Dump analysis completed: $dumpFileName"
            Write-LogEntry -MessageType 'INFO' -Message "Bug Check Code: $($summary.BugCheckCode)"
            Write-LogEntry -MessageType 'INFO' -Message "Faulting Module: $($summary.FaultingModule)"
            Write-LogEntry -MessageType 'INFO' -Message "Crash Reason: $($summary.CrashReason)"

            return $summary
        } else {
            throw "WinDbg analysis failed with exit code: $($process.ExitCode)"
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to analyze dump file $dumpFileName : $($_.Exception.Message)"
        return $null
    }
    finally {
        # Clean up script file if it was created
        if ($commandScriptPath -and (Test-Path -Path $commandScriptPath)) {
            Remove-Item -Path $commandScriptPath -Force -ErrorAction SilentlyContinue
        }
        if ($fallbackCommandScriptPath -and (Test-Path -Path $fallbackCommandScriptPath)) {
            Remove-Item -Path $fallbackCommandScriptPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Convert-DumpAnalysis {
    <#
    .SYNOPSIS
    Parses WinDbg analysis output to extract key crash information.
    
    .DESCRIPTION
    Extracts bug check codes, faulting modules, and crash reasons from WinDbg output.
    
    .PARAMETER AnalysisContent
    Raw content from WinDbg analysis output
    
    .PARAMETER DumpFileName
    Name of the analyzed dump file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AnalysisContent,
        
        [Parameter(Mandatory = $true)]
        [string]$DumpFileName
    )
    
    try {
        $summary = [PSCustomObject]@{
            DumpFile = $DumpFileName
            BugCheckCode = 'Unknown'
            BugCheckParameters = @()
            FaultingModule = 'Unknown'
            ModuleName = 'Unknown'
            ImageName = 'Unknown'
            ImageVersion = 'Unknown'
            CrashReason = 'Unknown'
            ProbableCause = 'Unknown'
            StackTrace = @()
            Analysis = 'Completed'
        }
        
        $addParameter = {
            param(
                [string]$label,
                [string]$value
            )

            if ([string]::IsNullOrWhiteSpace($label) -or [string]::IsNullOrWhiteSpace($value)) { return }
            $normalized = $value.Trim()
            if ($normalized -notmatch '^0x') { $normalized = "0x$normalized" }
            $entry = "$($label): $normalized"
            if (-not ($summary.BugCheckParameters -contains $entry)) {
                $summary.BugCheckParameters += $entry
            }
        }

        # Extract Bug Check Code
        if ($AnalysisContent -match 'Bug Check Code:\s*0x([0-9A-Fa-f]+)') {
            $summary.BugCheckCode = "0x$($matches[1])"
        } elseif ($AnalysisContent -match 'BUGCHECK_CODE:\s*([0-9A-Fa-f]+)') {
            $summary.BugCheckCode = "0x$($matches[1])"
        } elseif ($AnalysisContent -match 'BugCheck\s+0x?([0-9A-Fa-f]+)\s*,\s*\{([^}]*)\}') {
            $codeValue = $matches[1]
            if ($codeValue -notmatch '^0x') { $codeValue = "0x$codeValue" }
            $summary.BugCheckCode = $codeValue

            $rawParams = $matches[2] -split ','
            for ($idx = 0; $idx -lt $rawParams.Count; $idx++) {
                $paramValue = $rawParams[$idx].Trim()
                if ($paramValue) { &$addParameter "P$($idx + 1)" $paramValue }
            }
        }

        # Extract Bug Check Parameters (extended patterns)
        if ($AnalysisContent -match 'BUGCHECK_P1:\s*([0-9A-Fa-f]+)') {
            &$addParameter 'P1' $matches[1]
        }
        if ($AnalysisContent -match 'BUGCHECK_P2:\s*([0-9A-Fa-f]+)') {
            &$addParameter 'P2' $matches[1]
        }
        if ($AnalysisContent -match 'BUGCHECK_P3:\s*([0-9A-Fa-f]+)') {
            &$addParameter 'P3' $matches[1]
        }
        if ($AnalysisContent -match 'BUGCHECK_P4:\s*([0-9A-Fa-f]+)') {
            &$addParameter 'P4' $matches[1]
        }
        if ($AnalysisContent -match 'Arg1:?\s*0x?([0-9A-Fa-f]+)') {
            &$addParameter 'P1' $matches[1]
        }
        if ($AnalysisContent -match 'Arg2:?\s*0x?([0-9A-Fa-f]+)') {
            &$addParameter 'P2' $matches[1]
        }
        if ($AnalysisContent -match 'Arg3:?\s*0x?([0-9A-Fa-f]+)') {
            &$addParameter 'P3' $matches[1]
        }
        if ($AnalysisContent -match 'Arg4:?\s*0x?([0-9A-Fa-f]+)') {
            &$addParameter 'P4' $matches[1]
        }
        
        # Extract Faulting Module
        if ($AnalysisContent -match 'FAULTING_MODULE:\s*[0-9A-Fa-f]+\s+(.+)') {
            $summary.FaultingModule = $matches[1].Trim()
        } elseif ($AnalysisContent -match 'Probably caused by\s*:\s*(.+)') {
            $summary.FaultingModule = $matches[1].Trim()
        }

        # Extract module identification
        if ($AnalysisContent -match 'MODULE_NAME:\s*(\S+)') {
            $summary.ModuleName = $matches[1].Trim()
            if ($summary.FaultingModule -eq 'Unknown') {
                $summary.FaultingModule = $summary.ModuleName
            }
        }
        if ($AnalysisContent -match 'IMAGE_NAME:\s*(\S+)') {
            $summary.ImageName = $matches[1].Trim()
        }
        if ($AnalysisContent -match 'IMAGE_VERSION:\s*([^\r\n]+)') {
            $summary.ImageVersion = $matches[1].Trim()
        }
        
        # Extract Crash Reason
        if ($AnalysisContent -match 'PROCESS_NAME:\s*(.+)') {
            $processName = $matches[1].Trim()
            $summary.CrashReason = "Process: $processName"
        }
        
        # Extract Probable Cause
        if ($AnalysisContent -match 'PROBABLE_CAUSE:\s*(.+)') {
            $summary.ProbableCause = $matches[1].Trim()
        }
        
        # Extract key stack frames
        $stackMatches = [regex]::Matches($AnalysisContent, '(?m)^\s*[0-9a-f]+\s+[0-9a-f]+\s+(.+)$')
        $summary.StackTrace = @($stackMatches | Select-Object -First 5 | ForEach-Object { $_.Groups[1].Value.Trim() })
        
        return $summary
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to parse dump analysis: $($_.Exception.Message)"
        return [PSCustomObject]@{
            DumpFile = $DumpFileName
            BugCheckCode = 'Parse Error'
            Analysis = 'Failed'
        }
    }
}

function Get-DeviceUpTime {
    <#
    .SYNOPSIS
    Calculates accurate device uptime considering Fast Boot scenarios.
    
    .DESCRIPTION
    Determines the actual boot time by analyzing both OS boot time and kernel boot events.
    Accounts for Windows Fast Boot (hibernation-based boot) vs. cold boot scenarios.
    
    .PARAMETER ShowDays
    Return uptime as number of days since boot
    
    .PARAMETER ShowUptime
    Return the actual boot datetime
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ShowDays,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowUptime
    )
    
    try {
        # Get OS reported last boot time
        $lastReboot = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
        
        # Check Fast Boot configuration
        $checkFastBoot = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue).HiberbootEnabled
        
        $lastBoot = $null
        
        if (($null -eq $checkFastBoot) -or ($checkFastBoot -eq 0)) {
            # Fast Boot disabled - look for cold boot events
            $bootEvent = Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot' -ErrorAction SilentlyContinue | 
                Where-Object { $_.ID -eq 27 -and $_.Message -like '*0x0*' }
            if ($bootEvent) {
                $lastBoot = $bootEvent[0].TimeCreated
            }
        }
        elseif ($checkFastBoot -eq 1) {
            # Fast Boot enabled - look for fast boot events  
            $bootEvent = Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot' -ErrorAction SilentlyContinue | 
                Where-Object { $_.ID -eq 27 -and $_.Message -like '*0x1*' }
            if ($bootEvent) {
                $lastBoot = $bootEvent[0].TimeCreated
            }
        }
        
        # Determine most accurate boot time
        if ($null -eq $lastBoot) {
            $uptime = $lastReboot
        }
        else {
            $uptime = if ($lastReboot -ge $lastBoot) { $lastReboot } else { $lastBoot }
        }
        
        # Return requested format
        if ($ShowDays) {
            $currentDate = Get-Date
            $timeDifference = $currentDate - $uptime
            return $timeDifference.Days
        }
        elseif ($ShowUptime) {
            return $uptime
        }
        else {
            return $uptime
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to calculate uptime: $($_.Exception.Message)"
        return $null
    }
}

# Main script execution
try {
    Write-LogEntry -MessageType 'INFO' -Message 'Starting autonomous Bug Check diagnostic collection and analysis'
    Write-LogEntry -MessageType 'INFO' -Message 'Running in Intune Proactive Remediation mode - no user interaction required'
    Write-LogEntry -MessageType 'INFO' -Message "Analysis cache period: $AnalysisCacheDays days, Dump retention: $DumpRetentionDays days"
    if ($ForceReAnalysis) {
        Write-LogEntry -MessageType 'INFO' -Message 'Force re-analysis enabled - ignoring cached results'
    }
    
    # Initialize log file
    if (-not (Test-Path -Path $script:LogFile)) { 
        try {
            New-Item -Path $script:LogFile -ItemType File -Force | Out-Null 
        }
        catch {
            Write-Warning "Failed to create log file: $_"
        }
    }
    
    # Clean and prepare collection directory
    if (Test-Path -Path $script:DMPLogsFolder) { 
        Remove-Item -Path $script:DMPLogsFolder -Force -Recurse -ErrorAction SilentlyContinue
    }
    New-Item -Path $script:DMPLogsFolder -ItemType Directory -Force | Out-Null
    
    # Remove existing ZIP if present
    if (Test-Path -Path $script:DMPLogsFolderZIP) { 
        Remove-Item -Path $script:DMPLogsFolderZIP -Force -ErrorAction SilentlyContinue
    }
    
    Write-LogEntry -MessageType 'INFO' -Message 'Bug Check diagnostic collection initiated'
    Write-LogEntry -MessageType 'INFO' -Message "Collection directory: $script:DMPLogsFolder"
    
    # Perform dump file cleanup before collection
    Write-LogEntry -MessageType 'INFO' -Message "Performing dump file cleanup (retention: $DumpRetentionDays days)"
    $minidumpFolder = "$env:SystemRoot\Minidump"
    Remove-OldDumpFiles -MinidumpPath $minidumpFolder -RetentionDays $DumpRetentionDays
    
    # Automatic WinDbg detection and download for dump analysis
    $windbgPath = $null
    $dumpAnalysisResults = @()
    
    Write-LogEntry -MessageType 'INFO' -Message 'Checking for WinDbg installation for dump analysis'
    
    # First, check if WinDbg is already installed
    $existingWinDbg = Find-ExistingWinDbg
    
    if ($existingWinDbg) {
        $windbgPath = $existingWinDbg
        Write-LogEntry -MessageType 'SUCCESS' -Message "Using existing WinDbg installation: $windbgPath"
    } else {
        # Check if we have minidump files to analyze
        $minidumpFolder = "$env:SystemRoot\Minidump"
        $hasDumpFiles = (Test-Path -Path $minidumpFolder) -and 
                       (@(Get-ChildItem -Path $minidumpFolder -Filter "*.dmp" -ErrorAction SilentlyContinue).Count -gt 0)
        
        if ($hasDumpFiles) {
            Write-LogEntry -MessageType 'INFO' -Message 'Dump files detected - attempting WinDbg installation'
            
            # First, try to install via Winget-AutoUpdate if available
            $wingetInstalledPath = Install-WinDbgViaWinget
            if ($wingetInstalledPath) {
                $windbgPath = $wingetInstalledPath
                Write-LogEntry -MessageType 'SUCCESS' -Message "WinDbg installed via Winget-AutoUpdate: $windbgPath"
            } else {
                # Fall back to direct download method
                Write-LogEntry -MessageType 'INFO' -Message 'Winget installation failed or unavailable - falling back to direct download'
                try {
                    $windbgPath = Get-WinDbg -OutputDirectory (Join-Path -Path $script:DMPLogsFolder -ChildPath 'WinDbg') -Architecture $ArchitecturePreference
                    Write-LogEntry -MessageType 'SUCCESS' -Message "WinDbg downloaded and installed to: $windbgPath"
                }
                catch {
                    Write-LogEntry -MessageType 'ERROR' -Message "WinDbg download failed: $($_.Exception.Message)"
                    Write-LogEntry -MessageType 'WARNING' -Message 'Continuing without dump analysis'
                    $windbgPath = $null
                }
            }
        } else {
            Write-LogEntry -MessageType 'INFO' -Message 'No dump files found - skipping WinDbg installation'
            $windbgPath = $null
        }
    }
    
    # Collect system information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting system hotfix information'
    try {
        $hotfixCsvPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'HotfixList.csv'
        Get-CimInstance -ClassName Win32_QuickFixEngineering | 
            Select-Object HotFixID, Description, Caption, InstalledOn | 
            Sort-Object InstalledOn | 
            Export-Csv -Path $hotfixCsvPath -Delimiter ';' -NoTypeInformation
        Write-LogEntry -MessageType 'SUCCESS' -Message 'Hotfix list exported successfully'
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect hotfix information: $($_.Exception.Message)"
    }
    
    # Collect services information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting system services information'
    try {
        $servicesCsvPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'ServicesList.csv'
        Get-CimInstance -ClassName Win32_Service | 
            Select-Object Name, Caption, State, StartMode | 
            Export-Csv -Path $servicesCsvPath -Delimiter ';' -NoTypeInformation
        Write-LogEntry -MessageType 'SUCCESS' -Message 'Services list exported successfully'
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect services information: $($_.Exception.Message)"
    }
    
    # Collect driver information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting system drivers information'
    try {
        $driversCsvPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'DriversList.csv'
        Get-CimInstance -ClassName Win32_PnPSignedDriver | 
            Select-Object DeviceName, Manufacturer, DriverVersion, InfName, 
                @{Label = 'DriverDate'; Expression = { 
                    if ($_.DriverDate) { 
                        try { 
                            [Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate).ToString('MM-dd-yyyy') 
                        } catch { 
                            $_.DriverDate 
                        } 
                    } else { 
                        'Unknown' 
                    } 
                }}, 
                Description, IsSigned, ClassGuid, HardwareID, DeviceID | 
            Where-Object { $_.DeviceName -and $_.InfName } | 
            Sort-Object DeviceName -Unique | 
            Export-Csv -Path $driversCsvPath -Delimiter ';' -NoTypeInformation
        Write-LogEntry -MessageType 'SUCCESS' -Message 'Drivers list exported successfully'
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect drivers information: $($_.Exception.Message)"
    }
    
    # Collect process information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting running processes information'
    try {
        $processCsvPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'ProcessList.csv'
        Get-CimInstance -ClassName Win32_Process | 
            Select-Object ProcessName, Caption, CommandLine, Path, CreationDate, Description, ExecutablePath, Name, ProcessId, SessionId | 
            Export-Csv -Path $processCsvPath -Delimiter ';' -NoTypeInformation
        Write-LogEntry -MessageType 'SUCCESS' -Message 'Process list exported successfully'
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect process information: $($_.Exception.Message)"
    }
    
    # Collect pending updates information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting pending Windows updates information'
    try {
        $pendingUpdatesCsvPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'PendingUpdates.csv'
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $updates = @($updateSearcher.Search("IsHidden=0 and IsInstalled=0 and Type='Software'").Updates)
        $pendingUpdates = @($updates | Select-Object Title, Description, LastDeploymentChangeTime, SupportUrl, Type, RebootRequired)
        $pendingUpdates | Export-Csv -Path $pendingUpdatesCsvPath -Delimiter ';' -NoTypeInformation
        Write-LogEntry -MessageType 'SUCCESS' -Message "Found $($pendingUpdates.Count) pending updates"
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect pending updates: $($_.Exception.Message)"
    }
    
    # Export device uptime information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting system uptime information'
    try {
        $uptimeInfo = Get-DeviceUpTime
        $uptimeFilePath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'LastRebootDate.txt'
        $uptimeInfo | Out-File -FilePath $uptimeFilePath -Encoding UTF8
        Write-LogEntry -MessageType 'SUCCESS' -Message "System uptime: $uptimeInfo"
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect uptime information: $($_.Exception.Message)"
    }
    
    # Export event logs from last 15 days
    Write-LogEntry -MessageType 'INFO' -Message 'Starting event log collection (last 15 days)'
    $eventLogs = @(
        @{Name = 'System'; FileName = 'System'},
        @{Name = 'Application'; FileName = 'Applications'},
        @{Name = 'Security'; FileName = 'Security'},
        @{Name = 'Microsoft-Windows-Kernel-Power/Thermal-Operational'; FileName = 'KernelPower'},
        @{Name = 'Microsoft-Windows-Kernel-PnP/Driver Watchdog'; FileName = 'KernelPnPWatchdog'},
        @{Name = 'Microsoft-Windows-Kernel-PnP/Configuration'; FileName = 'KernelPnpConf'},
        @{Name = 'Microsoft-Windows-Kernel-LiveDump/Operational'; FileName = 'KernelLiveDump'},
        @{Name = 'Microsoft-Windows-Kernel-ShimEngine/Operational'; FileName = 'KernelShimEngine'},
        @{Name = 'Microsoft-Windows-Kernel-Boot/Operational'; FileName = 'KernelBoot'},
        @{Name = 'Microsoft-Windows-Kernel-IO/Operational'; FileName = 'KernelIO'}
    )
    
    foreach ($log in $eventLogs) {
        Export-EventLogs -LogName $log.Name -OutputFileName $log.FileName
    }
    
    # Copy minidump files and perform analysis if WinDbg is available
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting minidump files'
    try {
        $minidumpFolder = "$env:SystemRoot\Minidump"
        if (Test-Path -Path $minidumpFolder) {
            $destinationPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'Minidump'
            Copy-Item -Path $minidumpFolder -Destination $destinationPath -Recurse -Force
            
            $dumpFiles = @(Get-ChildItem -Path $destinationPath -Filter "*.dmp" -ErrorAction SilentlyContinue)
            $dumpCount = (@($dumpFiles)).Count
            Write-LogEntry -MessageType 'SUCCESS' -Message "Copied $dumpCount minidump file(s)"
            
            # Convert windbgPath to string for consistent usage throughout the analysis section
            $windbgPathString = [string]$windbgPath
            Write-LogEntry -MessageType 'INFO' -Message "WinDbg path for analysis: '$windbgPathString'"
            
            # Analyze dump files if WinDbg is available
            if ($dumpFiles -and $windbgPathString -and (-not [string]::IsNullOrEmpty($windbgPathString)) -and (Test-Path -Path $windbgPathString -PathType Container)) {
                Write-LogEntry -MessageType 'INFO' -Message "Starting analysis of $dumpCount dump file(s) using WinDbg"
                
                $analysisFolder = Join-Path -Path $script:DMPLogsFolder -ChildPath 'DumpAnalysis'
                New-Item -Path $analysisFolder -ItemType Directory -Force | Out-Null
                
                foreach ($dumpFile in $dumpFiles) {
                    Write-LogEntry -MessageType 'INFO' -Message "Analyzing dump file: $($dumpFile.Name)"
                    Write-LogEntry -MessageType 'INFO' -Message "Running bug check analysis for $($dumpFile.FullName)"
                    Write-ApplicationEvent -Message "Starting bug check analysis for $($dumpFile.FullName)" -EntryType 'Information' -EventId 210
                    
                    # Validate WinDbg path before calling Invoke-DumpAnalysis
                    if ([string]::IsNullOrEmpty($windbgPathString)) {
                        Write-LogEntry -MessageType 'ERROR' -Message "WinDbg path is null or empty - skipping analysis of $($dumpFile.Name)"
                        continue
                    }
                    
                    if (-not (Test-Path -Path $windbgPathString -PathType Container)) {
                        Write-LogEntry -MessageType 'ERROR' -Message "WinDbg path does not exist or is not a directory: $windbgPathString - skipping analysis of $($dumpFile.Name)"
                        continue
                    }
                    
                    # Capture only the PSCustomObject output from Invoke-DumpAnalysis (exclude log lines)
                    $rawResult = Invoke-DumpAnalysis -WinDbgPath $windbgPathString -DumpFilePath $dumpFile.FullName -OutputDirectory $analysisFolder -CacheDays $AnalysisCacheDays -ForceReAnalysis:$ForceReAnalysis -OriginalMinidumpDirectory $minidumpFolder
                    $analysisResult = $rawResult | Where-Object {
                        $typeName = $_.GetType().FullName
                        $typeName -like '*PSCustomObject'
                    } | Select-Object -Last 1
                    
                    if ($analysisResult) {
                        $dumpAnalysisResults += $analysisResult
                        
                        # Log key findings for Intune visibility with structured format
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "=== Bug Check ANALYSIS RESULT ==="
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "Dump File: $($dumpFile.Name)"
                        $analysisStatus   = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'Analysis' -DefaultValue 'Completed'
                        $bugCode         = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'BugCheckCode'
                        $faultModule     = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'FaultingModule'
                        $probable        = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'ProbableCause'
                        $exitCodeValue   = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'WinDbgExitCode'
                        $durationValue   = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'AnalysisDurationSeconds'
                        $imageNameValue  = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'ImageName'
                        $imageVersionVal = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'ImageVersion'
                        $fallbackUsed    = [bool](Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'FallbackRunUsed' -DefaultValue $false)
                        $fallbackExit    = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'FallbackExitCode' -DefaultValue $null
                        $fallbackDur     = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'FallbackDurationSeconds' -DefaultValue $null
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "Analysis Status: $analysisStatus"
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "Bug Check Code: $bugCode"
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "Faulting Module: $faultModule"
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "Probable Cause: $probable"
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "WinDbg Exit Code: $exitCodeValue"
                        Write-LogEntry -MessageType 'ANALYSIS' -Message "Analysis Duration (s): $durationValue"
                        if ($imageNameValue -and $imageNameValue -ne 'Unknown') {
                            $versionDisplay = if ($imageVersionVal -and $imageVersionVal -ne 'Unknown') { "$imageNameValue ($imageVersionVal)" } else { $imageNameValue }
                            Write-LogEntry -MessageType 'ANALYSIS' -Message "Module Version: $versionDisplay"
                        }
                        if ($fallbackUsed) {
                            $fallbackTelemetry = "Fallback run used"
                            if ($null -ne $fallbackExit) { $fallbackTelemetry += "; exit code: $fallbackExit" }
                            if ($null -ne $fallbackDur) { $fallbackTelemetry += "; duration: ${fallbackDur}s" }
                            Write-LogEntry -MessageType 'ANALYSIS' -Message $fallbackTelemetry
                        }
                        
                        $bugCheckParams = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'BugCheckParameters' -DefaultValue @()
                        if ($bugCheckParams -is [System.Array] -and $bugCheckParams.Count -gt 0) {
                            Write-LogEntry -MessageType 'ANALYSIS' -Message "Bug Check Parameters: $($bugCheckParams -join ', ')"
                        }
                        
                        $stackTraceSet = Get-AnalysisFieldValue -AnalysisObject $analysisResult -PropertyName 'StackTrace' -DefaultValue @()
                        if ($stackTraceSet -is [System.Array] -and $stackTraceSet.Count -gt 0) {
                            $topStack = $stackTraceSet | Select-Object -First 3
                            Write-LogEntry -MessageType 'ANALYSIS' -Message "Stack Trace (Top 3): $($topStack -join ' -> ')"
                        }
                        
                        # Add severity assessment for Intune alerting
                        $criticalBugChecks = @('0x00000050','0x0000001E','0x0000003B','0x000000D1','0x0000009F','0x00000124')
                        if ($bugCode -in $criticalBugChecks) {
                            Write-LogEntry -MessageType 'CRITICAL' -Message "WARNING: CRITICAL BUG CHECK DETECTED: $bugCode requires immediate attention"
                        }
                        
                                                Write-LogEntry -MessageType 'ANALYSIS' -Message "=== END ANALYSIS RESULT ==="

                                                $analysisEventMessage = @"
Bug check analysis completed for $($dumpFile.FullName)
  Status: $analysisStatus
  Bug Check Code: $bugCode
  Faulting Module: $faultModule
  Probable Cause: $probable
  Exit Code: $exitCodeValue
  Duration (s): $durationValue
"@
                        Write-ApplicationEvent -Message $analysisEventMessage -EntryType 'Information' -EventId 211
                    }
                    else {
                        Write-ApplicationEvent -Message "Bug check analysis produced no structured result for $($dumpFile.FullName)" -EntryType 'Warning' -EventId 212
                    }
                }
                
                # Filter to only PSCustomObject results (exclude any stray log strings)
                $typedAnalysisResults = $dumpAnalysisResults | Where-Object { $_ -is [pscustomobject] }

                # Create consolidated analysis summary
                if ($typedAnalysisResults) {
                    $summaryPath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'BugCheck_Analysis_Summary.txt'
                    $summaryContent = @"
Bug Check Analysis Summary
====================
Analysis Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total Dump Files Analyzed: $((@($typedAnalysisResults)).Count)

"@
                    
                    foreach ($result in $typedAnalysisResults) {
                        $dumpFile = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'DumpFile'
                        $bugCheckCode = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'BugCheckCode'
                        $faultingModule = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'FaultingModule'
                        $probableCause = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'ProbableCause'
                        $parametersRaw = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'BugCheckParameters' -DefaultValue @()
                        $parameters = if ($parametersRaw -is [System.Array] -and $parametersRaw.Count -gt 0) { $parametersRaw -join ', ' } else { 'None' }
                        $stackTraceRaw = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'StackTrace' -DefaultValue @()
                        $stackTrace = if ($stackTraceRaw -is [System.Array] -and $stackTraceRaw.Count -gt 0) { $stackTraceRaw -join ' -> ' } else { 'None' }
                        $exitCodeSummary = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'WinDbgExitCode'
                        $durationSummary = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'AnalysisDurationSeconds'
                        $fallbackSummary = if ([bool](Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'FallbackRunUsed' -DefaultValue $false)) { 'Yes' } else { 'No' }
                        $fallbackExitSummary = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'FallbackExitCode' -DefaultValue 'N/A'
                        $fallbackDurationSummary = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'FallbackDurationSeconds' -DefaultValue 'N/A'
                        $imageNameSummary = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'ImageName'
                        $imageVersionSummary = Get-AnalysisFieldValue -AnalysisObject $result -PropertyName 'ImageVersion'
                        
                        $summaryContent += @"
Dump File: $dumpFile
  Bug Check Code: $bugCheckCode
  Faulting Module: $faultingModule
  Probable Cause: $probableCause
  Parameters: $parameters
  Stack Trace: $stackTrace
    WinDbg Exit Code: $exitCodeSummary
    Analysis Duration (s): $durationSummary
    Fallback Run Used: $fallbackSummary
    Fallback Exit Code: $fallbackExitSummary
    Fallback Duration (s): $fallbackDurationSummary
    Module Version: $imageNameSummary ($imageVersionSummary)

"@
                    }
                    
                    $summaryContent | Out-File -FilePath $summaryPath -Encoding UTF8
                    Write-LogEntry -MessageType 'SUCCESS' -Message "Dump analysis summary created: BugCheck_Analysis_Summary.txt"
                    
                    # Log comprehensive summary for Intune console visibility
                    Write-LogEntry -MessageType 'SUMMARY' -Message "=== INTUNE Bug Check ANALYSIS SUMMARY ==="
                    $totalTyped = (@($typedAnalysisResults)).Count
                    Write-LogEntry -MessageType 'SUMMARY' -Message "Total Dumps Analyzed: $totalTyped"
                    
                    $uniqueBugChecks = $typedAnalysisResults | Where-Object { $_ | Get-Member -Name BugCheckCode -ErrorAction SilentlyContinue } | Group-Object BugCheckCode | ForEach-Object { "$($_.Name) ($($_.Count)x)" }
                    Write-LogEntry -MessageType 'SUMMARY' -Message "Bug Check Codes Found: $($uniqueBugChecks -join ', ')"
                    
                    $uniqueModules = $typedAnalysisResults | Where-Object { ($_ | Get-Member -Name FaultingModule -ErrorAction SilentlyContinue) -and $_.FaultingModule -ne 'Unknown' } | Group-Object FaultingModule | ForEach-Object { $_.Name }
                    if ($uniqueModules) {
                        Write-LogEntry -MessageType 'SUMMARY' -Message "Faulting Modules: $($uniqueModules -join ', ')"
                    }

                    $moduleVersionGroups = $typedAnalysisResults |
                        Where-Object { ($_ | Get-Member -Name ImageName -ErrorAction SilentlyContinue) -and $_.ImageName -ne 'Unknown' } |
                        Group-Object -Property {
                            $moduleName = $_.ImageName
                            $moduleVersion = if (($_ | Get-Member -Name ImageVersion -ErrorAction SilentlyContinue) -and $_.ImageVersion -and $_.ImageVersion -ne 'Unknown') { $_.ImageVersion } else { 'Unknown' }
                            "$moduleName|$moduleVersion"
                        }

                    if ($moduleVersionGroups) {
                        $moduleVersionSummary = $moduleVersionGroups | ForEach-Object {
                            $parts = $_.Name -split '\|', 2
                            $namePart = $parts[0]
                            $versionPart = if ($parts.Count -gt 1) { $parts[1] } else { 'Unknown' }
                            "$namePart ($versionPart) - $($_.Count)x"
                        }
                        Write-LogEntry -MessageType 'SUMMARY' -Message "Module Versions Observed: $($moduleVersionSummary -join '; ')"
                    }
                    
                    Write-LogEntry -MessageType 'SUMMARY' -Message "=== END INTUNE SUMMARY ==="
                }
            } elseif ($dumpFiles -and ([string]::IsNullOrEmpty($windbgPathString) -or (-not (Test-Path -Path $windbgPathString -PathType Container -ErrorAction SilentlyContinue)))) {
                Write-LogEntry -MessageType 'WARNING' -Message 'Dump files found but WinDbg could not be installed or is not accessible - analysis skipped'
                Write-LogEntry -MessageType 'INFO' -Message 'Manual analysis may be required or run script with administrator privileges'
            }
        } else {
            Write-LogEntry -MessageType 'WARNING' -Message 'No minidump folder found'
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to copy minidump files: $($_.Exception.Message)"
    }
    
    # Collect bugcheck event information
    Write-LogEntry -MessageType 'INFO' -Message 'Collecting bugcheck event information'
    try {
        # Use Get-WinEvent instead of deprecated Get-EventLog
        $bugCheckEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Id = 1001  # BugCheck event ID
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        
        if ($bugCheckEvents) {
            $lastBugCheckEvent = $bugCheckEvents[0]
            $lastBugCheckEventDate = $lastBugCheckEvent.TimeCreated
            $lastBugCheckEventMessage = $lastBugCheckEvent.Message
            
            $eventMessagePath = Join-Path -Path $script:DMPLogsFolder -ChildPath 'LastEventMessage.txt'
            @"
Last BugCheck Event Information
===============================
Event ID: $($lastBugCheckEvent.Id)
Time Created: $lastBugCheckEventDate
Level: $($lastBugCheckEvent.LevelDisplayName)
Source: $($lastBugCheckEvent.ProviderName)
Message:
$lastBugCheckEventMessage
"@ | Out-File -FilePath $eventMessagePath -Encoding UTF8
            
            Write-LogEntry -MessageType 'SUCCESS' -Message "Bugcheck event collected: $lastBugCheckEventDate"
        } else {
            Write-LogEntry -MessageType 'INFO' -Message 'No recent bugcheck events found'
        }
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to collect bugcheck events: $($_.Exception.Message)"
    }
    
    # Create diagnostic ZIP package
    Write-LogEntry -MessageType 'INFO' -Message 'Creating diagnostic ZIP package'
    try {
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
        [System.IO.Compression.ZipFile]::CreateFromDirectory($script:DMPLogsFolder, $script:DMPLogsFolderZIP)
        
        $zipFileInfo = Get-Item -Path $script:DMPLogsFolderZIP
        $zipSizeMB = [math]::Round($zipFileInfo.Length / 1MB, 2)
        
        Write-LogEntry -MessageType 'SUCCESS' -Message "Diagnostic ZIP created successfully"
        Write-LogEntry -MessageType 'INFO' -Message "ZIP file location: $script:DMPLogsFolderZIP"
        Write-LogEntry -MessageType 'INFO' -Message "ZIP file size: $zipSizeMB MB"
        
        # Create comprehensive final summary for Intune output with WinDbg analysis
        $finalOutput = "Bug Check Remediation Completed Successfully`n"
        $finalOutput += "=========================================`n"
        $finalOutput += "Collection Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
        $finalOutput += "Computer: $env:COMPUTERNAME`n"
        $finalOutput += "ZIP Package: $script:ZIPName ($zipSizeMB MB)`n`n"
        
        if ($dumpAnalysisResults -and (@($dumpAnalysisResults)).Count -gt 0) {
            $finalOutput += "CRITICAL: WinDbg Analysis Results Found`n"
            $finalOutput += "=========================================`n"
            $finalOutput += "Total Dump Files Analyzed: $((@($dumpAnalysisResults)).Count)`n`n"
            
            $typedAnalysisResults = $dumpAnalysisResults | Where-Object { $_ -is [pscustomobject] }
            foreach ($result in $typedAnalysisResults) {
                $dumpFile = if ($result | Get-Member -Name DumpFile -ErrorAction SilentlyContinue) { $result.DumpFile } else { 'Unknown' }
                $bugCheckCode = if ($result | Get-Member -Name BugCheckCode -ErrorAction SilentlyContinue) { $result.BugCheckCode } else { 'Unknown' }
                $faultingModule = if ($result | Get-Member -Name FaultingModule -ErrorAction SilentlyContinue) { $result.FaultingModule } else { 'Unknown' }
                $probableCause = if ($result | Get-Member -Name ProbableCause -ErrorAction SilentlyContinue) { $result.ProbableCause } else { 'Unknown' }
                $imageName = if ($result | Get-Member -Name ImageName -ErrorAction SilentlyContinue) { $result.ImageName } else { 'Unknown' }
                $imageVersion = if ($result | Get-Member -Name ImageVersion -ErrorAction SilentlyContinue) { $result.ImageVersion } else { 'Unknown' }
                $exitCode = if ($result | Get-Member -Name WinDbgExitCode -ErrorAction SilentlyContinue) { $result.WinDbgExitCode } else { 'Unknown' }
                $durationSeconds = if ($result | Get-Member -Name AnalysisDurationSeconds -ErrorAction SilentlyContinue) { $result.AnalysisDurationSeconds } else { 'Unknown' }
                $fallbackUsed = if (($result | Get-Member -Name FallbackRunUsed -ErrorAction SilentlyContinue) -and $result.FallbackRunUsed) { 'Yes' } else { 'No' }
                $fallbackExitCode = if ($result | Get-Member -Name FallbackExitCode -ErrorAction SilentlyContinue) { if ($null -ne $result.FallbackExitCode) { $result.FallbackExitCode } else { 'N/A' } } else { 'N/A' }
                $fallbackDurationSeconds = if ($result | Get-Member -Name FallbackDurationSeconds -ErrorAction SilentlyContinue) { if ($result.FallbackDurationSeconds) { $result.FallbackDurationSeconds } else { 'N/A' } } else { 'N/A' }
                
                $finalOutput += "File: $dumpFile`n"
                $finalOutput += "  -> Bug Check Code: $bugCheckCode`n"
                $finalOutput += "  -> Faulting Module: $faultingModule`n"
                $finalOutput += "  -> Probable Cause: $probableCause`n"
                $finalOutput += "  -> Module Version: $imageName ($imageVersion)`n"
                
                if (($result | Get-Member -Name BugCheckParameters -ErrorAction SilentlyContinue) -and $result.BugCheckParameters -and (@($result.BugCheckParameters)).Count -gt 0) {
                    $finalOutput += "  -> Parameters: $($result.BugCheckParameters -join ', ')`n"
                }
                
                if (($result | Get-Member -Name StackTrace -ErrorAction SilentlyContinue) -and $result.StackTrace -and (@($result.StackTrace)).Count -gt 0) {
                    $topStackFrames = $result.StackTrace | Select-Object -First 3
                    $finalOutput += "  -> Stack Trace: $($topStackFrames -join ' -> ')`n"
                }

                $finalOutput += "  -> WinDbg Exit Code: $exitCode`n"
                $finalOutput += "  -> Analysis Duration (s): $durationSeconds`n"
                $finalOutput += "  -> Fallback Run Used: $fallbackUsed`n"
                $finalOutput += "  -> Fallback Exit Code: $fallbackExitCode`n"
                $finalOutput += "  -> Fallback Duration (s): $fallbackDurationSeconds`n"
                
                $finalOutput += "`n"
            }
            
            # Add actionable insights based on common bug check codes
            $criticalBugChecks = @('0x00000050', '0x0000001E', '0x0000003B', '0x000000D1', '0x0000009F')
            $foundCritical = $typedAnalysisResults | Where-Object { ($_ | Get-Member -Name BugCheckCode -ErrorAction SilentlyContinue) -and $_.BugCheckCode -in $criticalBugChecks }
            
            if ($foundCritical) {
                $finalOutput += "CRITICAL ISSUES DETECTED:`n"
                foreach ($critical in $foundCritical) {
                    $criticalBugCheck = if ($critical.PSObject.Properties['BugCheckCode']) { $critical.BugCheckCode } else { 'Unknown' }
                    $criticalDumpFile = if ($critical.PSObject.Properties['DumpFile']) { $critical.DumpFile } else { 'Unknown' }
                    $finalOutput += "   * $criticalBugCheck in $criticalDumpFile - Requires immediate attention`n"
                }
                $finalOutput += "`n"
            }
            
            $finalOutput += "Analysis Details: Review BugCheck_Analysis_Summary.txt in ZIP package`n"
            $finalOutput += "Next Steps: Investigate faulting modules and update drivers if necessary`n`n"

            $moduleVersionGroups = $typedAnalysisResults |
                Where-Object { ($_ | Get-Member -Name ImageName -ErrorAction SilentlyContinue) -and $_.ImageName -ne 'Unknown' } |
                Group-Object -Property {
                    $modName = $_.ImageName
                    $modVersion = if (($_ | Get-Member -Name ImageVersion -ErrorAction SilentlyContinue) -and $_.ImageVersion -and $_.ImageVersion -ne 'Unknown') { $_.ImageVersion } else { 'Unknown' }
                    "$modName|$modVersion"
                }

            if ($moduleVersionGroups) {
                $finalOutput += "Module Version Summary:`n"
                foreach ($group in $moduleVersionGroups) {
                    $parts = $group.Name -split '\|', 2
                    $moduleNamePart = $parts[0]
                    $moduleVersionPart = if ($parts.Count -gt 1) { $parts[1] } else { 'Unknown' }
                    $finalOutput += "   * $moduleNamePart ($moduleVersionPart) - $($group.Count)x`n"
                }
                $finalOutput += "`n"
            }
        } else {
            $finalOutput += "INFO: No recent dump files found or analysis not performed`n`n"
        }
        
        $finalOutput += "Complete diagnostic package created: $script:DMPLogsFolderZIP`n"
        $finalOutput += "Package includes: Event logs, drivers, services, processes, and dump analysis`n"
        
        Write-ApplicationEvent -Message $finalOutput -EntryType 'Information' -EventId 100
        Write-Output $finalOutput
        exit 0
    }
    catch {
        Write-LogEntry -MessageType 'ERROR' -Message "Failed to create ZIP file: $($_.Exception.Message)"
        $zipErrorMessage = "Bug Check diagnostic collection failed during ZIP creation: $($_.Exception.Message)"
        Write-ApplicationEvent -Message $zipErrorMessage -EntryType 'Error' -EventId 901
        Write-Output $zipErrorMessage
        exit 1
    }
}
catch {
    $errorMessage = "Critical error during diagnostic collection: $($_.Exception.Message)"
    Write-LogEntry -MessageType 'ERROR' -Message $errorMessage
    Write-ApplicationEvent -Message $errorMessage -EntryType 'Error' -EventId 900
    Write-Output $errorMessage
    exit 1
}
finally {
    # Only log to file, not console, to avoid interfering with Intune output
    if ($script:LogFile -and (Test-Path -Path (Split-Path -Path $script:LogFile -Parent))) {
        $timestamp = '[{0:MM/dd/yy} {0:HH:mm:ss}]' -f (Get-Date)
        $logEntry = "$timestamp - INFO : Bug Check remediation script completed"
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}	
