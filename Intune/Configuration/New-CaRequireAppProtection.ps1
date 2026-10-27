<#
.SYNOPSIS
Creates the Conditional Access policy that routes personal iOS/Android devices down the
App Protection (MAM) path, in report-only mode.

.DESCRIPTION
Without a CA policy granting 'compliantApplication' (Require app protection policy), MAM is
voluntary: a user can add their mailbox to native iOS Mail, or fully enroll their personal
phone, and never touch a protected app. This policy is what makes the MAM-only BYOD model real.

Created in report-only state. Review the impact in Entra > Conditional Access > Insights and
reporting before switching to enabled.

Scope decisions baked in, and why:

  clientAppTypes = mobileAppsAndDesktopClients
      Browser sessions are deliberately NOT included. 'Require app protection policy' can only
      be satisfied in a browser by Microsoft Edge, so including browsers would block Safari
      outright. Handle browser access separately if you want it restricted.

  platforms = iOS + Android only
      macOS and Windows are corporate-managed here and have no App Protection equivalent.

  includeApplications = Office365
      Covers Exchange Online, SharePoint/OneDrive and Teams as one unit, which is what
      "mail and Teams" actually depends on. Targeting Exchange alone leaves Teams half-covered.

.PARAMETER DisplayName
Name for the new policy.

.PARAMETER ExcludeGroupNames
Display names of the break-glass / CA exemption groups to exclude. Required: every one must resolve.

.PARAMETER Enable
Create the policy enabled instead of report-only. Not recommended for the first run.

.EXAMPLE
.\New-CaRequireAppProtection.ps1 -ExcludeGroupNames 'CA-BreakGlass' -WhatIf

.NOTES
Break-glass exclusions are resolved by name and the script refuses to run if it cannot find
them -- never create a tenant-wide CA policy without an exclusion path.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]   $DisplayName = 'Require app protection policy for iOS and Android',
    [Parameter(Mandatory)]
    [string[]] $ExcludeGroupNames,
    [switch]   $Enable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication
# Creating a CA policy needs Policy.ReadWrite.ConditionalAccess, which may not be consented yet
# and would force an interactive prompt. For a dry run, fall back to read scopes so the plan can
# still be previewed without granting write access.
try {
    Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Group.Read.All' -NoWelcome -ErrorAction Stop | Out-Null
}
catch {
    if ($WhatIfPreference) {
        Write-Warning 'Could not acquire Policy.ReadWrite.ConditionalAccess; continuing read-only for the preview.'
        Connect-MgGraph -Scopes 'Policy.Read.All', 'Group.Read.All' -NoWelcome | Out-Null
    }
    else { throw }
}
if (-not $WhatIfPreference -and (Get-MgContext).Scopes -notcontains 'Policy.ReadWrite.ConditionalAccess') {
    throw 'Policy.ReadWrite.ConditionalAccess was not granted. Run: Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess'
}

# --- resolve break-glass exclusions (refuse to proceed without them) -----------------
$excludeIds = @()
foreach ($n in $ExcludeGroupNames) {
    $grp = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups?`$filter=displayName eq '$n'&`$select=id,displayName" -OutputType PSObject).value)
    if ($grp.Count -ne 1) { throw "Expected exactly one group named '$n', found $($grp.Count). Refusing to create a tenant-wide CA policy without its exclusion path." }
    $excludeIds += $grp[0].id
    Write-Host "Exclude : $($grp[0].displayName)  id=$($grp[0].id)"
}

# --- refuse to create a duplicate ----------------------------------------------------
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/identity/conditionalAccess/policies?`$select=id,displayName,state" -OutputType PSObject).value)
if ($existing | Where-Object { $_.displayName -eq $DisplayName }) { throw "A policy named '$DisplayName' already exists." }

$alreadyMam = @()
foreach ($c in $existing) {
    $full = Invoke-MgGraphRequest -Method GET -Uri "$graph/identity/conditionalAccess/policies/$($c.id)" -OutputType PSObject
    if (@($full.grantControls.builtInControls) -contains 'compliantApplication') { $alreadyMam += $full.displayName }
}
if ($alreadyMam.Count) { Write-Warning "Existing policies already grant compliantApplication: $($alreadyMam -join ', ')" }

$state = if ($Enable) { 'enabled' } else { 'enabledForReportingButNotEnforced' }

$body = @{
    displayName = $DisplayName
    state       = $state
    conditions  = @{
        users          = @{
            includeUsers  = @('All')
            excludeGroups = $excludeIds
        }
        applications   = @{
            includeApplications = @('Office365')
        }
        platforms      = @{
            includePlatforms = @('iOS', 'android')
        }
        clientAppTypes = @('mobileAppsAndDesktopClients')
    }
    grantControls = @{
        operator        = 'OR'
        builtInControls = @('compliantApplication')
    }
}

Write-Host ""
Write-Host "Policy to create:"
Write-Host "  name       : $DisplayName"
Write-Host "  state      : $state"
Write-Host "  users      : All, excluding $($ExcludeGroupNames -join ', ')"
Write-Host "  apps       : Office365 (Exchange Online + SharePoint/OneDrive + Teams)"
Write-Host "  platforms  : iOS, Android"
Write-Host "  clientApps : mobileAppsAndDesktopClients  (browsers deliberately excluded)"
Write-Host "  grant      : compliantApplication (Require app protection policy)"
Write-Host ""

if (-not $PSCmdlet.ShouldProcess($DisplayName, "Create CA policy ($state)")) { Write-Host 'Dry run -- nothing was created.'; return }

$new = Invoke-MgGraphRequest -Method POST -Uri "$graph/identity/conditionalAccess/policies" `
    -Body ($body | ConvertTo-Json -Depth 10) -ContentType 'application/json' -OutputType PSObject
Write-Host "Created. id=$($new.id)" -ForegroundColor Green

# --- verify by fresh read ------------------------------------------------------------
# Directory writes are eventually consistent: an immediate GET on a just-created policy
# routinely returns 404 even though the create succeeded. Poll rather than judging on one read.
$chk = $null
for ($attempt = 1; $attempt -le 10; $attempt++) {
    Start-Sleep -Seconds 3
    try { $chk = Invoke-MgGraphRequest -Method GET -Uri "$graph/identity/conditionalAccess/policies/$($new.id)" -OutputType PSObject; break }
    catch { Write-Host ("  attempt {0}/10: not visible yet" -f $attempt) }
}
if (-not $chk) {
    Write-Host "Policy did not become readable within 30s. It was almost certainly created -- check the portal before re-running," -ForegroundColor Yellow
    Write-Host "because re-running would create a duplicate." -ForegroundColor Yellow
    return
}
Write-Host ""
Write-Host "Verified on fresh read:"
Write-Host ("  state      : {0}" -f $chk.state)
Write-Host ("  grant      : {0}" -f (@($chk.grantControls.builtInControls) -join '+'))
Write-Host ("  apps       : {0}" -f (@($chk.conditions.applications.includeApplications) -join ','))
Write-Host ("  platforms  : {0}" -f (@($chk.conditions.platforms.includePlatforms) -join ','))
Write-Host ("  clientApps : {0}" -f (@($chk.conditions.clientAppTypes) -join ','))
Write-Host ("  excluded   : {0} group(s)" -f @($chk.conditions.users.excludeGroups).Count)
Write-Host ""
Write-Host "NEXT: leave in report-only for a few days, review Entra > Conditional Access > Insights and reporting," -ForegroundColor Yellow
Write-Host "      then re-run with -Enable or flip the state in the portal." -ForegroundColor Yellow
