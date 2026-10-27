<#
.SYNOPSIS
Creates iOS app configuration policies that deliver IntuneMAMUPN / IntuneMAMOID, so managed
apps can detect that they are running on an Intune-enrolled device.

.DESCRIPTION
App protection policy settings that say "on enrolled devices" are silently inert unless the app
can tell it is managed. Intune signals that with the IntuneMAMUPN and IntuneMAMOID app
configuration values. Without them every app is treated as unmanaged, so for example
'App PIN when device PIN is set = Disable' never fires and corporate devices get an app PIN.

Two things shape what this builds:

  * Since Intune 2409, IntuneMAMUPN/OID/DeviceID are sent AUTOMATICALLY on enrolled iOS devices
    for Outlook, Teams, Word, Excel and PowerPoint. Those are skipped -- configuring them by
    hand adds objects for no benefit.

  * IntuneMAMUPN must be configured per app; a Managed Devices app configuration policy targets
    a single app. So this creates one policy per remaining app.

Each policy targets the app record that is actually DEPLOYED (has assignments). A config
pointing at an unassigned record delivers nothing -- exactly how the Defender supervised-mode
config was orphaned.

.PARAMETER AssignmentGroupName
Group to assign each policy to. Should match the app protection policy's assignment.

.PARAMETER BundleId
Limit to specific bundle ids. Default: every bundle in the iOS app protection policy that is
deployed via Intune and not auto-covered.

.PARAMETER NamePrefix
Prefix for created policy names.

.EXAMPLE
.\New-IosMamUpnAppConfigs.ps1 -WhatIf

.EXAMPLE
.\New-IosMamUpnAppConfigs.ps1 -BundleId com.microsoft.skydrive,com.microsoft.msedge
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]   $AssignmentGroupName = 'All Users',
    [string[]] $BundleId,
    [string]   $NamePrefix = 'iOS: MAM-UPN'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

# Auto-configured by Intune since the 2409 service release -- do not create policies for these.
$AutoCovered = @(
    'com.microsoft.office.outlook', 'com.microsoft.skype.teams',
    'com.microsoft.office.word', 'com.microsoft.office.excel', 'com.microsoft.office.powerpoint'
)

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'Group.Read.All' -NoWelcome | Out-Null

# --- assignment group -----------------------------------------------------------------
$grp = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups?`$filter=displayName eq '$AssignmentGroupName'&`$select=id,displayName" -OutputType PSObject).value)
if ($grp.Count -ne 1) { throw "Expected exactly one group named '$AssignmentGroupName', found $($grp.Count)." }
$grp = $grp[0]
Write-Host "Assign to: $($grp.displayName)  id=$($grp.id)"

# --- which bundles does the app protection policy cover? ------------------------------
$app = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections?`$select=id,displayName" -OutputType PSObject).value)
if ($app.Count -ne 1) { throw "Expected exactly one iOS app protection policy, found $($app.Count)." }
$appFull = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/iosManagedAppProtections/$($app[0].id)?`$expand=apps" -OutputType PSObject
$mamBundles = @($appFull.apps | ForEach-Object { "$($_.mobileAppIdentifier.bundleId)" } | Where-Object { $_ })
Write-Host "App protection policy '$($appFull.displayName)' covers $($mamBundles.Count) bundle(s)"

# --- index DEPLOYED iOS app records ---------------------------------------------------
$deployed = @{}
foreach ($a in (Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps?`$select=id,displayName" -OutputType PSObject).value) {
    $f = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)" -OutputType PSObject
    if ("$($f.'@odata.type')" -notmatch 'ios') { continue }
    $b = if ($f.PSObject.Properties['bundleId']) { "$($f.bundleId)" } else { '' }
    if (-not $b) { continue }
    $n = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileApps/$($a.id)/assignments" -OutputType PSObject).value).Count
    if ($n -le 0) { continue }
    if (-not $deployed.ContainsKey($b) -or $deployed[$b].Asg -lt $n) {
        $deployed[$b] = [pscustomobject]@{ Id = $a.id; Name = $f.displayName; Asg = $n }
    }
}

# --- existing configs, so this is re-runnable ------------------------------------------
$existingFor = @{}
foreach ($c in @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations" -OutputType PSObject).value)) {
    $f = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)" -OutputType PSObject
    $raw = "$($f | ConvertTo-Json -Depth 20 -Compress)"
    if ($f.PSObject.Properties['encodedSettingXml'] -and $f.encodedSettingXml) {
        try { $raw += [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($f.encodedSettingXml)) } catch { }
    }
    if ($raw -notmatch '(?i)IntuneMAMUPN') { continue }
    foreach ($aid in @($f.targetedMobileApps)) { $existingFor[$aid] = $f.displayName }
}

# --- build the work list ---------------------------------------------------------------
$targets = if ($BundleId) { @($BundleId) } else { @($mamBundles | Sort-Object -Unique) }
$plan = @()
foreach ($b in $targets) {
    if ($b -in $AutoCovered) { Write-Host ("  skip  {0,-40} auto-configured since Intune 2409" -f $b) -ForegroundColor DarkGray; continue }
    if (-not $deployed.ContainsKey($b)) { Write-Host ("  skip  {0,-40} not deployed via Intune" -f $b) -ForegroundColor DarkGray; continue }
    $d = $deployed[$b]
    if ($existingFor.ContainsKey($d.Id)) { Write-Host ("  skip  {0,-40} already covered by '{1}'" -f $b, $existingFor[$d.Id]) -ForegroundColor DarkGray; continue }
    $plan += [pscustomobject]@{ Bundle = $b; AppId = $d.Id; AppName = $d.Name }
}

Write-Host ""
if (-not $plan.Count) { Write-Host 'Nothing to create.'; return }
Write-Host "=== policies to create: $($plan.Count) ==="
$plan | ForEach-Object { Write-Host ("   {0,-34} {1}" -f $_.AppName, $_.Bundle) }
Write-Host ""

$created = 0; $failed = 0
foreach ($p in $plan) {
    $name = "$NamePrefix - $($p.AppName)"
    if (-not $PSCmdlet.ShouldProcess($name, 'Create app config policy + assign')) { continue }

    $body = @{
        '@odata.type'      = '#microsoft.graph.iosMobileAppConfiguration'
        displayName        = $name
        description        = 'Delivers IntuneMAMUPN/IntuneMAMOID so the app can detect Intune enrollment. Required for app protection settings that apply only to enrolled devices.'
        targetedMobileApps = @($p.AppId)
        settings           = @(
            @{ appConfigKey = 'IntuneMAMUPN'; appConfigKeyType = 'stringType'; appConfigKeyValue = '{{userprincipalname}}' },
            @{ appConfigKey = 'IntuneMAMOID'; appConfigKeyType = 'stringType'; appConfigKeyValue = '{{userid}}' }
        )
    }

    try {
        $new = Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/mobileAppConfigurations" `
            -Body ($body | ConvertTo-Json -Depth 8) -ContentType 'application/json' -OutputType PSObject

        $asgBody = @{ assignments = @(@{
                    '@odata.type' = '#microsoft.graph.managedDeviceMobileAppConfigurationAssignment'
                    target        = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $grp.id }
                }) } | ConvertTo-Json -Depth 8
        Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($new.id)/assign" -Body $asgBody -ContentType 'application/json' | Out-Null

        $created++
        Write-Host ("  created + assigned: {0}" -f $name) -ForegroundColor Green
    }
    catch {
        $failed++
        Write-Host ("  FAILED: {0} -- {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
    }
}

if (-not $PSCmdlet.ShouldProcess('tenant', 'verify')) { Write-Host "`nDry run -- nothing was created."; return }

Write-Host "`nVerifying against a fresh read..."
$ok = 0
foreach ($c in @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations" -OutputType PSObject).value)) {
    $f = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)" -OutputType PSObject
    if ($f.displayName -notlike "$NamePrefix*") { continue }
    $n = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/mobileAppConfigurations/$($c.id)/assignments" -OutputType PSObject).value).Count
    if ($n -gt 0) { $ok++ }
    Write-Host ("  {0,-52} assignments={1}" -f $f.displayName, $n)
}
Write-Host ""
Write-Host "Created: $created   Failed: $failed   Assigned policies now present: $ok"
