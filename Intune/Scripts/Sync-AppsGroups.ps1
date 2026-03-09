<#
.SYNOPSIS
Creates (or updates) per-application, per-platform Entra ID security groups for devices where Intune has reported a discovered application installed.

 .DESCRIPTION
The script queries Intune discovered applications (Detected Apps) via Microsoft Graph and builds / updates device security groups
following this naming convention:

    Intune_<Platform>_<NormalizedAppName>_InstalledDevice

Platform is taken directly from the managed device OperatingSystem property for each device reporting the detected application.
No secondary heuristics, directory device lookups, or fallbacks are performed in this simplified version. If the OS value does
not map cleanly to a known label (Windows, macOS, iOS, iPadOS, Android, Linux) it is categorized as 'Other'.

NormalizedAppName is a condensed, alphanumeric PascalCase token derived from the discovered app DisplayName (architecture tokens,
trailing version numbers, years, punctuation, and the word 'Edition' are stripped).

Key behaviors:
 - Single app mode (default): specify -AppDisplayName "Exact Discovered Name".
 - Bulk mode: -AllApps processes every distinct detected app display name.
 - Confirmation: If a needed group does not exist you are prompted once per app (for all its platforms) unless -CreateAllGroups is used.
 - Skip list: Declining creation adds the app's raw display name to a persistent text file (SyncAppsGroups.SkipList.txt) so future runs auto-skip it.
 - Safe simulation: Supports -WhatIf / -Confirm because of ShouldProcess. Use -Verbose for detailed trace; uses Write-Verbose and Write-Warning.
 - Membership add reliability: Each device membership addition retries up to 3 times on transient 404 (eventual consistency) with a 10s delay.
 - Summary: Run results (Created/Updated/Skipped, counts, unresolved devices) are displayed in a final table.
 - Graph connection auto-check: If not connected (or required scopes missing) you will be prompted to sign in and required scopes are requested.
 - App-only auth: Use -UseAppOnly with ClientId/TenantId and either CertificateThumbprint or ClientSecret for non-interactive service principal authentication (application permissions required).

Troubleshooting quick reference:
 1. No groups created: Ensure the detected app name matches Intune exactly OR check if the app is in the skip list file.
 2. 404 adding members: This is usually directory replication delay. The script already retries; repeated failures suggest the device object was removed.
 3. Large 'Other' platform bucket: Devices reported an OperatingSystem value that did not match the standard mapping list; verify the raw OS strings on managed devices.
 4. Permissions errors: Confirm Graph delegated/app permissions: DeviceManagementManagedDevices.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All, Directory.ReadWrite.All.
 5. Module missing errors: Install Microsoft.Graph.Beta.* modules or re-run with -AutoInstallModules (if you kept that logic enabled externally).
 6. App skipped silently: Check SyncAppsGroups.SkipList.txt for the app name; remove it and rerun.
 7. Want dry run: Add -WhatIf to any invocation.

.PARAMETER PruneStaleMembers
When specified, remove existing group members that are NOT currently reporting the target application for the platform bucket.
CAUTION: This will remove any non-device or manually added members whose object IDs are not in the discovered device list.
Use -WhatIf first to review planned removals. Members are removed individually with ShouldProcess safeguards.

.PARAMETER AppDisplayName
Exact discovered application DisplayName (case-insensitive match) to target. Mutually exclusive with -AllApps.

.PARAMETER AllApps
Process every distinct discovered application (aggregate of DisplayName). Mutually exclusive with -AppDisplayName.

.PARAMETER AutoInstallModules
Attempt to install missing Microsoft.Graph.Beta.* dependencies for current user scope before executing logic.
If omitted and modules are missing the script should stop (implementation dependent if retained).

.PARAMETER CreateAllGroups
Automatically create all required groups (suppresses interactive Y/N prompt). Combine with -WhatIf to preview without changes.

.PARAMETER Platform
Optional list of platform labels to include (case-insensitive). If specified, only these platform buckets will be created/updated.
Valid values: Windows, macOS, iOS, iPadOS, Android, Linux, Other. If omitted, all detected platforms are considered.

.PARAMETER UseAppOnly
Use application (client credential) authentication instead of delegated interactive sign-in. Requires application permissions granted in Entra ID for all required resources and Admin Consent.

.PARAMETER ClientId
App (client) ID of the registered application when using -UseAppOnly.

.PARAMETER TenantId
Tenant ID (GUID or domain) for the application when using -UseAppOnly.

.PARAMETER CertificateThumbprint
Thumbprint of a local certificate (CurrentUser\My) used for app-only authentication. Mutually exclusive with -ClientSecret.

.PARAMETER ClientSecret
Client secret string for app-only authentication. Mutually exclusive with -CertificateThumbprint. Prefer certificates for security.

.PARAMETER DeviceCode
Use device code authentication flow for delegated (interactive) sign-in instead of launching a system web browser. Ignored when -UseAppOnly is specified (they are mutually exclusive). Useful for headless / remote sessions where a local browser is unavailable.

.EXAMPLE
PS> .\Sync-AppsGroups.ps1 -AppDisplayName "7-Zip 24.00 (x64 edition)"
Creates/updates platform group(s) for 7-Zip if devices report it (e.g. Intune_Windows_7Zip_InstalledDevice).

.EXAMPLE
PS> .\Sync-AppsGroups.ps1 -AllApps -CreateAllGroups -Verbose
Processes the entire discovered app catalog, auto-creating any missing groups, with verbose tracing.

.EXAMPLE
PS> .\Sync-AppsGroups.ps1 -AppDisplayName "Google Chrome" -WhatIf -Verbose
Simulates actions and shows which groups would be created/updated without persisting changes.

.EXAMPLE
PS> .\Sync-AppsGroups.ps1 -AppDisplayName "Google Chrome" -DeviceCode
Prompts using device code flow instead of opening a browser for delegated authentication, then creates/updates platform groups for Google Chrome.

.OUTPUTS
Writes a summary table of group actions to the host; detailed progress through Verbose stream.

.REQUIREMENTS
Microsoft.Graph Beta modules (DeviceManagement*, Groups, Directory) + Graph permissions:
  DeviceManagementConfiguration.ReadWrite.All
  DeviceManagementManagedDevices.ReadWrite.All
  Directory.ReadWrite.All
  Group.ReadWrite.All
  GroupMember.ReadWrite.All
  Device.ReadWrite.All

.NOTES
Author: MEMAppFactory Automation
Updated: $(Get-Date -Format 'yyyy-MM-dd')
File:   Sync-AppsGroups.ps1
Skip List File: SyncAppsGroups.SkipList.txt (created in working directory)
Versioning: Increment this header when functional logic changes; comment-only edits do not require version bump.
#>
[CmdletBinding(DefaultParameterSetName = 'SingleApp', SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'SingleApp')]
    [ValidateNotNullOrEmpty()]
    [Alias('Name')]
    [string]$AppDisplayName,

    [Parameter(Mandatory = $true, ParameterSetName = 'AllApps')]
    [switch]$AllApps,

    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [switch]$AutoInstallModules,

    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [switch]$CreateAllGroups
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [switch]$PruneStaleMembers
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [ValidateSet('Windows','macOS','iOS','iPadOS','Android','Linux','Other')]
    [string[]]$Platform
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [switch]$UseAppOnly
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [string]$ClientId
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [string]$TenantId
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [string]$CertificateThumbprint
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [string]$ClientSecret
    ,
    [Parameter(ParameterSetName = 'SingleApp')]
    [Parameter(ParameterSetName = 'AllApps')]
    [switch]$DeviceCode
)

# Enforce stricter scripting discipline early
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Required Graph delegated scopes for this script
$script:RequiredGraphScopes = @(
    'DeviceManagementConfiguration.ReadWrite.All'
    'DeviceManagementManagedDevices.ReadWrite.All'
    'Directory.ReadWrite.All'
    'Group.ReadWrite.All'
    'GroupMember.ReadWrite.All'
    'Device.ReadWrite.All'
)

# Summary tracking
$script:GroupResults = @()

# Persistent skip list file (apps previously declined for group creation)
$script:SkipListPath = Join-Path -Path (Get-Location) -ChildPath 'SyncAppsGroups.SkipList.txt'
$script:SkipApps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path $script:SkipListPath) {
    try {
        (Get-Content -Path $script:SkipListPath -ErrorAction Stop | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_.Trim() }) | ForEach-Object { [void]$script:SkipApps.Add($_) }
        Write-Information "Loaded $($script:SkipApps.Count) previously skipped app name(s) from '$($script:SkipListPath)'."
    }
    catch { Write-Warning "Failed to read skip list file: $_" }
}
$script:SkipListModified = $false

# Cache for mapping Azure AD deviceId (managed device AzureADDeviceId) -> directory object Id
$script:DeviceObjectIdCache = @{}

function Confirm-YesNo {
    param(
        [Parameter(Mandatory)][string]$Message,
        [int]$TimeoutSeconds = 20
    )
    Write-Information "$Message (Y/N) (auto-cancel in $TimeoutSeconds s)"
    $stopAt = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $stopAt) {
        if ($Host.UI.RawUI.KeyAvailable) {
            $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            switch ($key.Character) {
                'Y' { Write-Information 'Y'; return $true }
                'y' { Write-Information 'y'; return $true }
                'N' { Write-Information 'N'; return $false }
                'n' { Write-Information 'n'; return $false }
                default { Write-Information $key.Character; return $false }
            }
        }
        Start-Sleep -Milliseconds 150
    }
    Write-Information 'Prompt timeout (treated as No)'
    return $false
}

function Ensure-GraphConnection {
    <#
    .SYNOPSIS
    Verify an active Microsoft Graph connection with required scopes; prompt and connect if absent or insufficient.
    .DESCRIPTION
    Uses Get-MgContext. If not connected or any required scope missing, prompts the user. Aborts if user declines.
    If -AutoInstallModules was specified, attempts to install Microsoft.Graph.Beta meta module if missing.
    #>
    [CmdletBinding()]
    param()

    # Optional module auto-install
    if ($AutoInstallModules) {
        $neededModule = 'Microsoft.Graph.Beta'
        $hasModule = Get-Module -ListAvailable -Name $neededModule -ErrorAction SilentlyContinue
        if (-not $hasModule) {
            Write-Information "Attempting to install missing module $neededModule ..."
            try { Install-Module -Name $neededModule -Scope CurrentUser -Force -ErrorAction Stop -AllowClobber } catch { Write-Warning "Module install failed: $($_.Exception.Message)" }
        }
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue | Out-Null

    if ($UseAppOnly) {
        # Validate required parameters
        if (-not $ClientId -or -not $TenantId) { throw "-UseAppOnly requires -ClientId and -TenantId." }
        $usingCert = [string]::IsNullOrWhiteSpace($ClientSecret)
        if ($usingCert -and -not $CertificateThumbprint) { throw "Provide -CertificateThumbprint or -ClientSecret with -UseAppOnly." }
        if (-not $usingCert -and $CertificateThumbprint) { throw "Specify only one of -CertificateThumbprint or -ClientSecret." }
        if ($DeviceCode) { throw "-DeviceCode cannot be combined with -UseAppOnly (device code is only for delegated interactive auth)." }

        Write-Information "Establishing app-only (client credential) Graph connection..."
        try {
            if ($usingCert) {
                Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop | Out-Null
            } else {
                $secure = (ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)
                Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -ClientSecret $secure -NoWelcome -ErrorAction Stop | Out-Null
            }
            $ctx = Get-MgContext
            Write-Information "Connected (App-Only) as AppId $ClientId Tenant $TenantId."            
        }
        catch {
            throw "Failed app-only Graph connection: $($_.Exception.Message)"
        }
        return
    }

    $ctx = $null
    try { $ctx = Get-MgContext -ErrorAction Stop } catch { }
    $needConnect = $false
    $missingScopes = @()
    if (-not $ctx -or -not $ctx.Account) { $needConnect = $true } else {
        $current = @(); if ($ctx.Scopes) { $current = $ctx.Scopes }
        foreach ($s in $script:RequiredGraphScopes) { if ($current -notcontains $s) { $missingScopes += $s } }
        if ($missingScopes.Count -gt 0) { $needConnect = $true }
    }

    if (-not $needConnect) { Write-Verbose "Graph already connected as $($ctx.Account) with required scopes."; return }
    if ($missingScopes.Count -gt 0 -and $ctx.Account) { Write-Information "Existing Graph session missing required scopes: $($missingScopes -join ', ')" }

    $scopeDisplay = ($script:RequiredGraphScopes -join ', ')
    if (-not (Confirm-YesNo -Message "Microsoft Graph connection (scopes: $scopeDisplay) required. Connect now?" -TimeoutSeconds 25)) { throw "User declined Microsoft Graph connection. Aborting." }

    try {
        if ($DeviceCode) {
            Write-Information "Connecting to Graph using device code flow..."
            Connect-MgGraph -Scopes $script:RequiredGraphScopes -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Null
        }
        else {
            Connect-MgGraph -Scopes $script:RequiredGraphScopes -NoWelcome -ErrorAction Stop | Out-Null
        }
        $ctx = Get-MgContext
        Write-Information "Connected to Graph as $($ctx.Account) (Tenant: $($ctx.TenantId))."
    }
    catch { throw "Failed to establish Microsoft Graph connection: $($_.Exception.Message)" }

    $postScopes = @(); if ($ctx.Scopes) { $postScopes = $ctx.Scopes }
    $stillMissing = @(); foreach ($s in $script:RequiredGraphScopes) { if ($postScopes -notcontains $s) { $stillMissing += $s } }
    if ($stillMissing.Count -gt 0) { Write-Warning "Connected but still missing scopes: $($stillMissing -join ', ')" }
}

# Ensure we have a valid Graph connection before proceeding to any queries
Ensure-GraphConnection

function Resolve-DirectoryDeviceObjectId {
    <#
    .SYNOPSIS
    Resolve the Entra ID (directory) object Id for a given Azure AD deviceId (AzureADDeviceId on managed device).
    .DESCRIPTION
    Uses a simple in-memory cache to avoid repeated Graph lookups. Falls back to per-device filter query.
    .OUTPUTS
    [string] directory object Id or $null if not found.
    #>
    param([Parameter(Mandatory)][string]$AzureDeviceId)
    if ($script:DeviceObjectIdCache.ContainsKey($AzureDeviceId)) { return $script:DeviceObjectIdCache[$AzureDeviceId] }
    try {
        $escaped = $AzureDeviceId.Replace("'", "''")
        $dirDevice = Get-MgBetaDevice -Filter "deviceId eq '$escaped'" -All -ErrorAction Stop | Select-Object -First 1
        if ($dirDevice -and $dirDevice.Id) {
            $script:DeviceObjectIdCache[$AzureDeviceId] = $dirDevice.Id
            return $dirDevice.Id
        }
        else {
            $script:DeviceObjectIdCache[$AzureDeviceId] = $null
            return $null
        }
    }
    catch {
        Write-Verbose "Directory lookup failed for deviceId $AzureDeviceId : $($_.Exception.Message)"
        $script:DeviceObjectIdCache[$AzureDeviceId] = $null
        return $null
    }
}

function Convert-AppName {
    <#
    .SYNOPSIS
    Normalize a discovered app DisplayName into a compact PascalCase token safe for group names.
    .DESCRIPTION
    Removes architecture keywords, the word 'Edition', trailing versions / years, punctuation; capitalizes remaining fragments.
    .PARAMETER Name
    Raw discovered application display name.
    .OUTPUTS
    [string] Normalized name (may be empty string if nothing left after sanitation).
    #>
    param([string]$Name)
    if (-not $Name) { return '' }
    # Sanitation steps:
    # 1. Remove architecture tokens (x64, x86, arm64)
    # 2. Remove the word 'Edition'
    # 3. Remove trailing version strings (v1.2.3, 1.2, 2024, etc.) appearing at end
    # 4. Remove punctuation, condense spaces
    $sanitized = $Name -replace '(?i)\b(x64|x86|arm64)\b', ' ' -replace '(?i)\bEdition\b', ' '
    $sanitized = $sanitized -replace '(?i)\b(v?\d+(?:[\.-]\d+){0,3})$', ' ' -replace '(?i)\b(20\d{2}|19\d{2})$', ' '
    $clean = ($sanitized -replace '[^a-zA-Z0-9 ]', ' ') -replace '\s+', ' ' # keep spaces to split
    $parts = $clean.Trim().Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -eq 0) { return '' }
    ($parts | ForEach-Object { $_.Substring(0, 1).ToUpper() + $_.Substring(1).ToLower() }) -join ''
}

function Confirm-CreateGroup {
    <#
    .SYNOPSIS
    Interactive Y/N prompt (with timeout) for creating a new group unless -CreateAllGroups was specified.
    .DESCRIPTION
    Waits up to TimeoutSeconds; any non Y/y/N/n key is treated as No. Timeout also counts as No.
    .OUTPUTS
    [bool] True if creation approved.
    #>
    param(
        [string]$GroupName,
        [int]$TimeoutSeconds = 15
    )
    if ($CreateAllGroups) { return $true }
    Write-Information "Group '$GroupName' does not exist. Create? (Y/N) (auto-skip in $TimeoutSeconds s)"
    $stopAt = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $stopAt) {
        if ($Host.UI.RawUI.KeyAvailable) {
            $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            switch ($key.Character) {
                'Y' { Write-Information 'Y'; return $true }
                'y' { Write-Information 'y'; return $true }
                'N' { Write-Information 'N'; return $false }
                'n' { Write-Information 'n'; return $false }
                default { Write-Information $key.Character; return $false }
            }
        }
        Start-Sleep -Milliseconds 150
    }
    Write-Information "Prompt timeout reached (treated as No)"
    return $false
}

function Add-GroupResult {
    <#
    .SYNOPSIS
    Append a structured row to the in-memory results summary collection.
    .DESCRIPTION
    Central place to ensure consistent object shape for final reporting.
    #>
    param([string]$GroupName, [string]$Action, [int]$Added = 0, [int]$Existing = 0, [int]$Skipped = 0, [string]$Notes = '', [int]$Removed = 0)
    $script:GroupResults += [pscustomobject]@{Group = $GroupName; Action = $Action; Added = $Added; Existing = $Existing; Skipped = $Skipped; Removed = $Removed; Notes = $Notes }
}

function Get-PlatformLabel {
    <#
    .SYNOPSIS
    Map raw managed device OperatingSystem values to a normalized platform label used in group names.
    .DESCRIPTION
    Performs a light, case-insensitive normalization only; no directory or heuristic enrichment.
    #>
    param([string]$OperatingSystem)
    if (-not $OperatingSystem) { return 'Other' }
    switch -Regex ($OperatingSystem.Trim()) {
        '^(?i)windows' { return 'Windows' }
        '^(?i)mac ?os|macos' { return 'macOS' }
        '^(?i)ios$' { return 'iOS' }
        '^(?i)ipados' { return 'iPadOS' }
        '^(?i)android' { return 'Android' }
        '^(?i)linux' { return 'Linux' }
        default { return 'Other' }
    }
}

function Sync-AppGroup {
    <#
    .SYNOPSIS
    Core pipeline: for a given discovered app display name, compute platform buckets and ensure corresponding groups exist and are populated.
    .NOTES
    Uses retry logic for adds; writes progress via Verbose and warnings for skipped/unresolved devices.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('DisplayName')]
        [string]$AppDisplayName
    )
    begin { }
    process {
        $trimmed = $AppDisplayName.Trim()
        if (-not $trimmed) { return }

        # Auto-skip if previously declined (persistent skip list)
        if ($script:SkipApps.Contains($trimmed)) {
            Write-Verbose "Skipping previously declined app '$trimmed' (in skip list)."
            Add-GroupResult -GroupName "(Intune_*_$((Convert-AppName -Name $trimmed))_InstalledDevice)" -Action 'AutoSkipped'
            return
        }

        $normalizedApp = Convert-AppName -Name $trimmed
        if (-not $normalizedApp) { Write-Warning "Skipping app with no normalizable name: '$trimmed'"; return }

        Write-Verbose "[App:$trimmed] Querying detected apps..."
        Write-Information "Searching for devices with app: $trimmed ..."

        try {
            $escapedName = $trimmed.Replace("'", "''")
            $filter = "displayName eq '$escapedName'"
            $DetectedApps = Get-MgBetaDeviceManagementDetectedApp -Filter $filter -All -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed querying detected apps for '$trimmed' : $_"
            Add-GroupResult -GroupName "(Intune_*_$normalizedApp*)" -Action 'QueryFailed' -Notes ($_.Exception.Message)
            return
        }

        if (-not $DetectedApps) {
            Write-Verbose "No installs of '$trimmed' found (skipping)."
            Add-GroupResult -GroupName "(Intune_*_${normalizedApp}_InstalledDevice)" -Action 'NoInstalls'; return
        }

        $NotResolved = 0
        $OsDevices = @{} # Dictionary: Platform label -> HashSet[directory object Id]
        foreach ($App in $DetectedApps) {
            Write-Verbose "[App: $trimmed] Processing detected app record Id=$($App.Id)"
            $Devices = Get-MgBetaDeviceManagementDetectedAppManagedDevice -DetectedAppId $App.Id -All
            foreach ($Dev in $Devices) {
                $GraphDevice = Get-MgBetaDeviceManagementManagedDevice -ManagedDeviceId $Dev.Id -ErrorAction SilentlyContinue
                if (-not $GraphDevice) { continue }
                $plat = Get-PlatformLabel -OperatingSystem $GraphDevice.OperatingSystem
                $aadId = $GraphDevice.AzureADDeviceId
                if ($aadId) {
                    $dirId = Resolve-DirectoryDeviceObjectId -AzureDeviceId $aadId
                    if ($dirId) {
                        if (-not $OsDevices.ContainsKey($plat)) { $OsDevices[$plat] = [System.Collections.Generic.HashSet[string]]::new() }
                        [void]$OsDevices[$plat].Add($dirId)
                    }
                    else { $NotResolved++ }
                }
                else { $NotResolved++ }
            }
        }
        if ($NotResolved -gt 0) { Write-Warning "Skipped $NotResolved device(s) lacking resolvable directory object Id." }

        # Prompt once per app (after full discovery) if none of the target groups already exist and we are not in auto-create mode
        if (-not $CreateAllGroups) {
            $existingAny = $false
            $foundLabels = $OsDevices.Keys
            foreach ($osLabel in $foundLabels) {
                $probeName = "Intune_${osLabel}_${normalizedApp}_InstalledDevice"
                $probe = Get-MgBetaGroup -Filter "displayName eq '$probeName'" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($probe) { $existingAny = $true; break }
            }
            if (-not $existingAny -and $foundLabels.Count -gt 0) {
                $labelList = ($foundLabels -join ', ')
                Write-Output "Create groups for app '$trimmed' on platform(s): $labelList ? (Y/N)"
                # Precompute first label safely (avoid inline Select-Object in expandable string under StrictMode edge cases)
                $firstLabel = ($foundLabels | Select-Object -First 1)
                if (-not $firstLabel) { $firstLabel = 'Windows' }
                $confirmAll = Confirm-CreateGroup -GroupName "Intune_${firstLabel}_${normalizedApp}_InstalledDevice"
                if ($confirmAll) { $script:AppLevelApproved = $true } else {
                    if (-not $script:SkipApps.Contains($trimmed)) { [void]$script:SkipApps.Add($trimmed); $script:SkipListModified = $true }
                    Add-GroupResult -GroupName "(Intune_*_${normalizedApp}_InstalledDevice)" -Action 'AppLevelSkip'
                    return
                }
            }
        }

        # If user supplied -Platform filter, reduce platform keys
        $selectedPlatforms = $OsDevices.Keys
        if ($Platform) {
            $selectedPlatforms = @($selectedPlatforms | Where-Object { $_ -in $Platform })
        }

        if (-not $selectedPlatforms -or $selectedPlatforms.Count -eq 0) {
            Add-GroupResult -GroupName "(Intune_<Filtered>_${normalizedApp}_InstalledDevice)" -Action 'FilteredOut' -Notes 'No devices in selected platform(s)'
            return
        }

        foreach ($os in $selectedPlatforms) {
            $deviceSet = $OsDevices[$os]
            $groupName = "Intune_${os}_${normalizedApp}_InstalledDevice"
            $groupDesc = "Devices ($os) with [$trimmed] installed"

            $Group = Get-MgBetaGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue | Select-Object -First 1
            $creating = $false
            if (-not $Group) {
                $canCreate = $false
                if ($script:AppLevelApproved -or $CreateAllGroups) { $canCreate = $true } else { $canCreate = Confirm-CreateGroup -GroupName $groupName }
                if ($groupName -match '<OS>') { Write-Warning "Sanitizing unexpected placeholder token in group name: $groupName"; $groupName = $groupName -replace '<OS>', 'Windows' }
                if ($canCreate) {
                    if ($PSCmdlet.ShouldProcess($groupName, 'Create group and add members')) {
                        Write-Information "Creating group: $groupName"
                        $Group = New-MgBetaGroup -DisplayName $groupName -Description $groupDesc -MailEnabled:$false -MailNickname $groupName -SecurityEnabled:$true -GroupTypes @()
                        $creating = $true
                    }
                    else {
                        Add-GroupResult -GroupName $groupName -Action 'WhatIf-Skipped'
                        continue
                    }
                }
                else {
                    Write-Verbose "Skipping creation of $groupName (user declined)"
                    # Record explicit manual skip for this app (store original display name)
                    if (-not $script:SkipApps.Contains($trimmed)) { [void]$script:SkipApps.Add($trimmed); $script:SkipListModified = $true }
                    Add-GroupResult -GroupName $groupName -Action 'SkippedCreate' -Skipped $deviceSet.Count
                    continue
                }
            }
            else {
                Write-Verbose "Updating existing group: $groupName"
            }

            $ExistingMembers = @(Get-MgBetaGroupMember -GroupId $Group.Id -All | ForEach-Object { $_.Id })  # Current group membership IDs
            $ToAdd = @($deviceSet | Where-Object { $_ -notin $ExistingMembers })
            $addedCount = 0
            if ($ToAdd.Length -gt 0) {
                foreach ($DevId in $ToAdd) {
                    $attempt = 0
                    $maxAttempts = 3
                    $added = $false
                    while (-not $added -and $attempt -lt $maxAttempts) {
                        try {
                            if ($PSCmdlet.ShouldProcess("Member:$DevId", "Add to $groupName")) {
                                New-MgBetaGroupMemberByRef -GroupId $Group.Id -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$DevId" }
                                $addedCount++
                                $added = $true
                            }
                            else {
                                $added = $true # treat as logically skipped under WhatIf
                            }
                        }
                        catch {
                            $attempt++
                            $msg = $_.Exception.Message
                            if ($msg -match 'Request_ResourceNotFound' -and $attempt -lt $maxAttempts) {
                                Write-Warning "Add member retry $attempt/$maxAttempts for group $groupName (404). Waiting 10s..."
                                Start-Sleep -Seconds 10
                            }
                            elseif ($attempt -ge $maxAttempts) {
                                Write-Warning "Failed to add device object $DevId after $maxAttempts attempts: $msg"
                            }
                            else {
                                Write-Warning "Failed to add device object $DevId : $msg"
                                break
                            }
                        }
                    }
                }
            }
            $existingCount = $deviceSet.Count - $addedCount

            # Optional pruning of stale members (members present but no longer reporting app)
            $removedCount = 0
            if ($PruneStaleMembers) {
                $stale = @($ExistingMembers | Where-Object { $_ -notin $deviceSet })
                if ($stale.Length -gt 0) {
                    Write-Information "Pruning $($stale.Length) stale member(s) from $groupName" 
                    foreach ($staleId in $stale) {
                        try {
                            if ($PSCmdlet.ShouldProcess("Member:$staleId", "Remove from $groupName")) {
                                Remove-MgBetaGroupMemberByRef -GroupId $Group.Id -DirectoryObjectId $staleId -ErrorAction Stop
                                $removedCount++
                                Write-Verbose "Removed stale member $staleId from $groupName"
                            }
                        }
                        catch {
                            Write-Warning "Failed to remove stale member $staleId from $groupName : $($_.Exception.Message)"
                        }
                    }
                }
                else {
                    Write-Verbose "No stale members to prune for $groupName"
                }
            }
            # PowerShell 5.1 compatibility: replace ternary operator with standard if/else assignments
            if ($creating) { $action = 'Created' } else { $action = 'Updated' }
            if ($NotResolved -gt 0) { $notes = "$NotResolved unresolved" } else { $notes = '' }
            if ($removedCount -gt 0) { if ($notes) { $notes += '; ' }; $notes += "Removed $removedCount stale" }
            Add-GroupResult -GroupName $groupName -Action $action -Added $addedCount -Existing $existingCount -Removed $removedCount -Notes $notes
            Write-Information "Group '$groupName' population complete. Added: $addedCount Existing: $existingCount Removed: $removedCount"
        }
    }
}

if ($PSCmdlet.ParameterSetName -eq 'AllApps') {
    Write-Information "Enumerating all discovered applications..."
    # Get all distinct discovered apps and related data (case-insensitive unique)
    $AllDetectedAppNames = @(Get-MgBetaDeviceManagementDetectedApp -All | Sort-Object DisplayName -Unique)
    $appTotal = if ($AllDetectedAppNames) { $AllDetectedAppNames.Count } else { 0 }
    Write-Information "Processing $appTotal application name(s)."
    if ($appTotal -eq 0) {
        Write-Warning "No discovered applications returned."
    }
    else {
        # Pass the list of app names and platform labels  down the pipeline
        foreach ($appName in $AllDetectedAppNames) { $appName | Sync-AppGroup }
    }
}
else {
    Sync-AppGroup -AppDisplayName $AppDisplayName
}

Write-Information "Group synchronization process complete."

if ($GroupResults.Count -gt 0) {
    Write-Information 'Summary:'
    $GroupResults | Sort-Object Group | Format-Table -AutoSize | Out-String | Write-Information
}
else { Write-Information "No group actions performed." }

# Persist updated skip list if changed
if ($script:SkipListModified) {
    try {
        $script:SkipApps | Sort-Object | Set-Content -Path $script:SkipListPath -Encoding UTF8
        Write-Information "Updated skip list saved to '$($script:SkipListPath)' ($($script:SkipApps.Count) entries)."
    }
    catch { Write-Warning "Failed to write skip list file: $_" }
}
