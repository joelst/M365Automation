<#
.SYNOPSIS
Reassigns Apple ADE devices from one enrollment profile/policy to another.

.DESCRIPTION
Moves serials on an Apple DEP/ADE token from a source enrollment profile to a target
profile or policy, using the Graph beta action:

    POST /deviceManagement/depOnboardingSettings/{tokenId}/enrollmentProfiles/{profileId}/updateDeviceProfileAssignment
    { "deviceIds": [ "<serial>", ... ] }

Built for the legacy-profile -> settings-catalog-policy migration, where the portal has
no select-all on the token's Devices tab.

IMPORTANT -- reassignment does NOT re-provision enrolled devices.
An ADE profile assignment only takes effect at erase-and-setup. Devices already enrolled
keep their current configuration until they are next wiped. Expect no visible change on
already-enrolled devices after running this.

Both profiles are resolved by display name rather than by a constructed id, because the new
settings-catalog policies project through this endpoint with an "ECV2_" prefixed id that
should not be assembled by hand.

.PARAMETER TargetProfileName
Display name of the enrollment profile/policy to move devices TO.

.PARAMETER SerialNumber
One or more device serial numbers to move. Named devices are moved regardless of which
profile they are currently on, so this is the way to pull a single test device onto the new
policy without touching the rest of the fleet. Serials not present on the token, or whose
platform does not match -Platform, are reported and skipped.

.PARAMETER SourceProfileName
Display name of the enrollment profile to move devices FROM. Omit to consider every device
on the token that is not already on the target. Not used with -SerialNumber.

.PARAMETER Platform
Device platform to act on. Defaults to ios.

.PARAMETER BatchSize
Serials per Graph call. Defaults to 100.

.PARAMETER First
Only process the first N devices. Use this to prove the path on a handful of serials
before moving the whole fleet. Not used with -SerialNumber.

.PARAMETER SkipVerify
Send the batches and return immediately without waiting for convergence. Use for large moves,
then queue a -VerifyOnly run (backgrounded) to confirm and report. The command to run is
printed on exit.

.PARAMETER VerifyOnly
Send nothing; poll until every selected device reports the target profile, or the timeout
expires. This is the queued half of a -SkipVerify move, and is safe to run repeatedly.

.PARAMETER VerifyTimeoutMinutes
How long to poll for convergence. Defaults to 10.

.PARAMETER VerifyIntervalSeconds
Seconds between polls. Defaults to 15.

.EXAMPLE
.\Set-AdeDeviceProfileAssignment.ps1 -TargetProfileName 'iOS: ADE Setup Assistant modern auth (TEST)' -First 5 -WhatIf

.EXAMPLE
.\Set-AdeDeviceProfileAssignment.ps1 -TargetProfileName 'iOS: ADE Setup Assistant modern auth (TEST)' `
    -SourceProfileName 'Default iPhone enrollment for a user' -First 5

.EXAMPLE
# Pull one named test device onto the new policy, then wipe it to exercise the path.
.\Set-AdeDeviceProfileAssignment.ps1 -TargetProfileName 'iOS: ADE Setup Assistant modern auth (TEST)' `
    -SerialNumber F2LX1234ABCD

.EXAMPLE
# Large move: send now, confirm later. Step 2 is safe to background.
.\Set-AdeDeviceProfileAssignment.ps1 -TargetProfileName 'iOS: ADE Setup Assistant modern auth (TEST)' `
    -SourceProfileName 'Default iPhone enrollment for a user' -SkipVerify -Confirm:$false

.\Set-AdeDeviceProfileAssignment.ps1 -TargetProfileName 'iOS: ADE Setup Assistant modern auth (TEST)' `
    -SourceProfileName 'Default iPhone enrollment for a user' -VerifyOnly

.NOTES
Serial numbers are held in memory only -- nothing is written to disk.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Bulk')]
param(
    [Parameter(Mandatory)]
    [string] $TargetProfileName,

    [Parameter(Mandatory, ParameterSetName = 'Serial')]
    [ValidateNotNullOrEmpty()]
    [string[]] $SerialNumber,

    [Parameter(ParameterSetName = 'Bulk')]
    [string] $SourceProfileName,

    [ValidateSet('ios', 'macOS')]
    [string] $Platform = 'ios',

    [ValidateRange(1, 100)]
    [int] $BatchSize = 100,

    [Parameter(ParameterSetName = 'Bulk')]
    [int] $First,

    # Send the batches and return immediately, leaving convergence to a separate -VerifyOnly run.
    [switch] $SkipVerify,

    # Do not send anything; only poll until the selected devices show the target profile.
    [switch] $VerifyOnly,

    [ValidateRange(1, 120)]
    [int] $VerifyTimeoutMinutes = 10,

    [ValidateRange(5, 300)]
    [int] $VerifyIntervalSeconds = 15
)

if ($SkipVerify -and $VerifyOnly) {
    throw 'Use -SkipVerify or -VerifyOnly, not both.'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementServiceConfig.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome | Out-Null

# --- token ---------------------------------------------------------------------------
$tokens = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/depOnboardingSettings" -OutputType PSObject).value)
if ($tokens.Count -ne 1) {
    throw "Expected exactly one DEP token, found $($tokens.Count). Specify the token explicitly before running."
}
$tokenId = $tokens[0].id
Write-Host "Token : $($tokens[0].tokenName)  ($tokenId)"

# --- resolve profiles by NAME, never by a constructed id -----------------------------
$profiles = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/depOnboardingSettings/$tokenId/enrollmentProfiles" -OutputType PSObject).value)

$target = $profiles | Where-Object { $_.displayName -eq $TargetProfileName }
if (-not $target) {
    throw "Target profile '$TargetProfileName' not found. Available: $(($profiles.displayName) -join ' | ')"
}
# The device records carry only the trailing GUID, not the full (possibly ECV2_-prefixed) id.
$targetShortId = ($target.id -split '_')[-1]
Write-Host "Target: $($target.displayName)"
Write-Host "        id    = $($target.id)"
Write-Host "        short = $targetShortId"

$sourceShortId = $null
if ($SourceProfileName) {
    $source = $profiles | Where-Object { $_.displayName -eq $SourceProfileName }
    if (-not $source) {
        throw "Source profile '$SourceProfileName' not found. Available: $(($profiles.displayName) -join ' | ')"
    }
    $sourceShortId = ($source.id -split '_')[-1]
    Write-Host "Source: $($source.displayName)  (short = $sourceShortId)"
}

# --- devices -------------------------------------------------------------------------
$uri = "$graph/deviceManagement/depOnboardingSettings/$tokenId/importedAppleDeviceIdentities?`$top=500"
$devices = @()
while ($uri) {
    $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $devices += $page.value
    $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
}

Write-Host ""
Write-Host "Devices on token           : $($devices.Count)"

if ($PSCmdlet.ParameterSetName -eq 'Serial') {
    # Named devices move regardless of which profile they are currently on.
    $wantedSerials = @($SerialNumber | ForEach-Object { "$_".Trim().ToUpperInvariant() } | Where-Object { $_ })
    $index = @{}
    foreach ($d in $devices) { $index["$($d.serialNumber)".ToUpperInvariant()] = $d }

    $candidates = @()
    $notFound = @()
    $wrongPlatform = @()
    $alreadyOnTarget = @()

    foreach ($s in $wantedSerials) {
        $d = if ($index.ContainsKey($s)) { $index[$s] } else { $null }
        if (-not $d) { $notFound += $s; continue }
        if ($d.platform -ne $Platform) { $wrongPlatform += "$s (platform=$($d.platform))"; continue }
        if ($d.requestedEnrollmentProfileId -eq $targetShortId) { $alreadyOnTarget += $s; continue }
        $candidates += $d
    }

    Write-Host "Serials requested          : $($wantedSerials.Count)"
    Write-Host "Already on target          : $($alreadyOnTarget.Count)"
    Write-Host "To move                    : $($candidates.Count)"
    foreach ($s in $notFound) { Write-Warning "Serial not found on this token: $s" }
    foreach ($s in $wrongPlatform) { Write-Warning "Skipped, platform does not match -Platform '$Platform': $s" }
}
else {
    $candidates = @($devices | Where-Object {
            $_.platform -eq $Platform -and
            $_.requestedEnrollmentProfileId -ne $targetShortId -and
            (-not $sourceShortId -or $_.requestedEnrollmentProfileId -eq $sourceShortId)
        })

    Write-Host "Platform '$Platform'       : $(@($devices | Where-Object platform -eq $Platform).Count)"
    Write-Host "Already on target          : $(@($devices | Where-Object { $_.platform -eq $Platform -and $_.requestedEnrollmentProfileId -eq $targetShortId }).Count)"
    Write-Host "To move                    : $($candidates.Count)"

    if ($First -and $candidates.Count -gt $First) {
        $candidates = @($candidates | Select-Object -First $First)
        Write-Host "Limited by -First          : $($candidates.Count)"
    }
}

if (-not $candidates.Count) {
    Write-Host "`nNothing to do."
    return
}

# Enrolled devices will not re-provision until wiped -- make that visible up front.
$byState = $candidates | Group-Object enrollmentState | Sort-Object Name
Write-Host ""
Write-Host "Enrollment state of devices to move:"
foreach ($s in $byState) {
    $note = if ($s.Name -eq 'enrolled') { '  <- no change until erase-and-setup' } else { '' }
    Write-Host ("  {0,-16} {1}{2}" -f $s.Name, $s.Count, $note)
}

$wanted = @($candidates | ForEach-Object { $_.serialNumber })
$sent = 0
$failed = 0

# --- reassign ------------------------------------------------------------------------
if (-not $VerifyOnly) {
    $actionUri = "$graph/deviceManagement/depOnboardingSettings/$tokenId/enrollmentProfiles/$($target.id)/updateDeviceProfileAssignment"
    $batches = [Math]::Ceiling($candidates.Count / $BatchSize)

    Write-Host ""
    for ($i = 0; $i -lt $candidates.Count; $i += $BatchSize) {
        $batch = @($candidates[$i..([Math]::Min($i + $BatchSize - 1, $candidates.Count - 1))])
        $serials = @($batch | ForEach-Object { $_.serialNumber })
        $n = [int]($i / $BatchSize) + 1

        if (-not $PSCmdlet.ShouldProcess("$($serials.Count) $Platform device(s)", "Assign to '$($target.displayName)'")) {
            Write-Host ("  batch {0}/{1}: {2} device(s)  [WhatIf]" -f $n, $batches, $serials.Count)
            continue
        }

        try {
            Invoke-MgGraphRequest -Method POST -Uri $actionUri `
                -Body (@{ deviceIds = $serials } | ConvertTo-Json -Depth 3) `
                -ContentType 'application/json' | Out-Null
            $sent += $serials.Count
            Write-Host ("  batch {0}/{1}: {2} device(s)  sent" -f $n, $batches, $serials.Count) -ForegroundColor Green
        }
        catch {
            $failed += $serials.Count
            Write-Host ("  batch {0}/{1}: {2} device(s)  FAILED -- {3}" -f $n, $batches, $serials.Count, $_.Exception.Message) -ForegroundColor Red
        }
    }

    if (-not $PSCmdlet.ShouldProcess('tenant', 'verify')) {
        Write-Host "`nDry run -- nothing was changed."
        return
    }

    if ($SkipVerify) {
        # Sends are done; hand convergence off to a separate (often backgrounded) poller so a
        # large move does not hold the console for minutes.
        Write-Host ""
        Write-Host "Sent    : $sent"
        Write-Host "Failed  : $failed"
        Write-Host "Verification skipped. Poll for convergence with:"
        Write-Host "  .\Set-AdeDeviceProfileAssignment.ps1 -TargetProfileName '$($target.displayName)'" -NoNewline
        if ($SourceProfileName) { Write-Host " -SourceProfileName '$SourceProfileName'" -NoNewline }
        Write-Host " -Platform $Platform -VerifyOnly"
        return
    }
}

# --- verify by fresh read: HTTP 204 is not proof the binding moved -------------------
# This list endpoint is eventually consistent -- an immediate read routinely still shows the
# old profile even though the action succeeded. Poll rather than judging on one read.
$deadline = (Get-Date).AddMinutes($VerifyTimeoutMinutes)
$moved = 0
$attempt = 0

Write-Host "`nVerifying against a fresh read (eventually consistent, polling up to $VerifyTimeoutMinutes min)..."
while ($true) {
    $attempt++
    Start-Sleep -Seconds $VerifyIntervalSeconds

    $uri = "$graph/deviceManagement/depOnboardingSettings/$tokenId/importedAppleDeviceIdentities?`$top=500"
    $after = @()
    while ($uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
        $after += $page.value
        $uri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
    }

    $moved = @($after | Where-Object { $_.serialNumber -in $wanted -and $_.requestedEnrollmentProfileId -eq $targetShortId }).Count
    Write-Host ("  [{0}] attempt {1}: {2} of {3} reflected" -f (Get-Date -Format 'HH:mm:ss'), $attempt, $moved, $candidates.Count)

    if ($moved -ge $candidates.Count) { break }
    if ((Get-Date) -ge $deadline) { break }
}

Write-Host ""
if (-not $VerifyOnly) {
    Write-Host "Sent    : $sent"
    Write-Host "Failed  : $failed"
}
Write-Host "Moved   : $moved of $($candidates.Count) confirmed on '$($target.displayName)'"

if ($moved -ge $candidates.Count) {
    Write-Host "All devices confirmed." -ForegroundColor Green
}
else {
    Write-Host "Not all devices reflected within $VerifyTimeoutMinutes min. This endpoint lags, so re-read" -ForegroundColor Yellow
    Write-Host "before assuming failure -- re-running is safe and skips devices already on the target." -ForegroundColor Yellow
}
