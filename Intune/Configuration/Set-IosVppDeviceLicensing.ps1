<#
.SYNOPSIS
Switches iOS VPP app assignments from user licensing to device licensing.

.DESCRIPTION
User-licensed VPP apps require the end user to sign in to the App Store with a personal Apple
Account. Managed Apple IDs -- including ones provisioned by Apple Business Manager federation
with Microsoft Entra ID -- cannot acquire apps, so user licensing does not work on ADE devices.
Device licensing requires no App Store sign-in at all.

Microsoft also documents that mixing the two is unsupported:
  "Don't assign both device licenses and user licenses to the same device or user. This
   scenario isn't supported and can result in issues with app installation and updates."

Only REQUIRED assignments are changed. Microsoft's guidance is that apps migrate silently from
user to device licences only for the Required intent -- Available assignments are left alone so
nothing breaks for users who already installed on demand.

Assignments are rewritten with the /assign action, which replaces the whole set atomically. The
script preserves every existing assignment (intent, target, filter, settings) and changes only
useDeviceLicensing on required ones, so there is no window with missing coverage.

.PARAMETER AppName
Exact display name(s) of the iOS VPP app(s) to fix.

.EXAMPLE
.\Set-IosVppDeviceLicensing.ps1 -AppName 'Contoso Field App' -WhatIf

.EXAMPLE
.\Set-IosVppDeviceLicensing.ps1 -AppName 'Contoso Field App','Contoso HR'

.NOTES
Check licence headroom first -- device licensing consumes one licence per device rather than
one per user across up to five devices, so consumption can rise.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [string[]] $AppName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'Group.Read.All' -NoWelcome | Out-Null

$groupCache = @{}
function Get-GroupName {
    param([string] $Id)
    if (-not $groupCache.ContainsKey($Id)) {
        try { $groupCache[$Id] = (Invoke-MgGraphRequest -Method GET -Uri "$graph/groups/$Id`?`$select=displayName" -OutputType PSObject).displayName }
        catch { $groupCache[$Id] = "(group $Id)" }
    }
    $groupCache[$Id]
}

function ConvertTo-Hashtable {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    $h = @{}
    foreach ($p in $InputObject.PSObject.Properties) {
        if ($p.Name -in @('id', 'source', 'sourceId')) { continue }   # server-owned, not accepted on write
        $h[$p.Name] = $p.Value
    }
    $h
}

$all = (Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps?`$select=id,displayName" -OutputType PSObject).value

foreach ($name in $AppName) {
    $match = @()
    foreach ($a in $all) {
        if ($a.displayName -ne $name) { continue }
        $f = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)" -OutputType PSObject
        if ($f.'@odata.type' -ne '#microsoft.graph.iosVppApp') { continue }
        $match += $f
    }

    if (-not $match.Count) { Write-Warning "No iOS VPP app named '$name' found."; continue }
    if ($match.Count -gt 1) { Write-Warning "'$name' matched $($match.Count) iOS VPP records; processing all."; }

    foreach ($app in $match) {
        Write-Host ""
        Write-Host "=== $($app.displayName) ===  licences $($app.usedLicenseCount)/$($app.totalLicenseCount)"

        $asg = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($app.id)/assignments" -OutputType PSObject).value)
        if (-not $asg.Count) { Write-Host "  no assignments; nothing to do."; continue }

        $rebuilt = @()
        $changes = 0
        foreach ($x in $asg) {
            $target = ConvertTo-Hashtable $x.target
            $settings = ConvertTo-Hashtable $x.settings

            $label = "$($x.target.'@odata.type')" -replace '#microsoft.graph.|AssignmentTarget', ''
            if ($x.target.PSObject.Properties['groupId'] -and $x.target.groupId) { $label = "group:$(Get-GroupName $x.target.groupId)" }

            $current = if ($settings -and $settings.ContainsKey('useDeviceLicensing')) { $settings['useDeviceLicensing'] } else { $null }

            if ($x.intent -eq 'required' -and $current -eq $false) {
                $settings['useDeviceLicensing'] = $true
                $changes++
                Write-Host ("  CHANGE  required -> {0,-34} useDeviceLicensing False -> True" -f $label) -ForegroundColor Yellow
            }
            elseif ($current -eq $false) {
                Write-Host ("  keep    {0,-9} -> {1,-34} user-licensed (intent not Required; silent migration unsupported)" -f $x.intent, $label) -ForegroundColor DarkYellow
            }
            else {
                Write-Host ("  keep    {0,-9} -> {1,-34} useDeviceLicensing={2}" -f $x.intent, $label, $current)
            }

            $rebuilt += @{
                '@odata.type' = '#microsoft.graph.mobileAppAssignment'
                intent        = $x.intent
                target        = $target
                settings      = $settings
            }
        }

        if (-not $changes) { Write-Host "  nothing to change."; continue }

        if (-not $PSCmdlet.ShouldProcess($app.displayName, "Rewrite $($rebuilt.Count) assignment(s); $changes -> device licensing")) { continue }

        $body = @{ mobileAppAssignments = $rebuilt } | ConvertTo-Json -Depth 10
        try {
            Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/mobileApps/$($app.id)/assign" -Body $body -ContentType 'application/json' | Out-Null
            Write-Host "  applied." -ForegroundColor Green
        }
        catch {
            Write-Host "  FAILED -- $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        # verify by fresh read
        $after = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($app.id)/assignments" -OutputType PSObject).value)
        $stillUser = @($after | Where-Object { $_.intent -eq 'required' -and $_.settings -and $_.settings.PSObject.Properties['useDeviceLicensing'] -and $_.settings.useDeviceLicensing -eq $false })
        Write-Host ("  verified: {0} assignment(s); required still user-licensed: {1} (expect 0)" -f $after.Count, $stillUser.Count)
    }
}
