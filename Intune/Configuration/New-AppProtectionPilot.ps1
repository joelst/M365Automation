<#
.SYNOPSIS
Creates piloted copies of the iOS and Android app protection policies, and excludes the pilot
groups from the production policies so the two do not conflict.

.DESCRIPTION
Two app protection policies targeting the same user conflict, and Intune resolves the conflict
by taking the most restrictive value -- which makes pilot results hard to reason about. So for
each platform this script:

  1. Clones the production policy, carrying every writable setting across from LIVE state
  2. Applies the pilot overrides (below)
  3. Copies the targeted app list, plus any extra apps for that platform
  4. Assigns the clone to the pilot group (iOS additionally through the unmanaged filter)
  5. Adds an EXCLUSION for the pilot group on the production policy

iOS overrides -- the app PIN, and stop org data reaching personal iCloud:
    pinRequired        False -> True
    minimumPinLength   4     -> 6
    simplePinBlocked   False -> True
    dataBackupBlocked  False -> True

  iOS also gets the Managed apps filter in include mode, so the policy only reaches unmanaged
  devices. That is what keeps the app PIN off corporate ADE iPhones, and it is why the
  IntuneMAMUPN app configuration policies are not needed.

Android overrides -- close the containment hole and protect the apps people actually use:
    allowedOutboundDataTransferDestinations  allApps -> managedApps
    dataBackupBlocked                        False   -> True
    plus six apps added to the policy

  Android gets no filter. This assumes Android Enterprise enrollment is blocked and no Android
  devices are enrolled, so every Android device is already unmanaged. If you enroll Android,
  add a Managed apps filter to the Android assignment as well.

  Android's PIN is deliberately left as-is (already required, 4 digits, simple allowed). Aligning
  it to the iOS standard of 6 digits is a separate decision -- pass -AlignAndroidPin to include it.

.PARAMETER Platform
ios, android, or both (default).

.PARAMETER IosPilotGroup
Display name of the iOS pilot group. Required when Platform is ios or both.

.PARAMETER AndroidPilotGroup
Display name of the Android pilot group. Required when Platform is android or both.

.PARAMETER IosFilterName
Display name of the Managed apps assignment filter that matches unmanaged iOS devices.

.PARAMETER AlignAndroidPin
Also set Android minimumPinLength=6 and simplePinBlocked=True to match iOS.

.EXAMPLE
.\New-AppProtectionPilot.ps1 -IosPilotGroup 'MAM Pilot iOS' -AndroidPilotGroup 'MAM Pilot Android' -WhatIf

.EXAMPLE
.\New-AppProtectionPilot.ps1 -Platform ios -IosPilotGroup 'MAM Pilot iOS' -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('ios', 'android', 'both')]
    [string] $Platform = 'both',

    [string] $IosPilotGroup,
    [string] $AndroidPilotGroup,
    [string] $IosFilterName = 'iOS unmanaged apps',
    [string] $PilotSuffix = '(PILOT)',

    [switch] $AlignAndroidPin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/beta'

# Fail before connecting: each platform built needs its own pilot group.
if ($Platform -in @('ios', 'both') -and -not $IosPilotGroup) { throw '-IosPilotGroup is required when Platform is ios or both.' }
if ($Platform -in @('android', 'both') -and -not $AndroidPilotGroup) { throw '-AndroidPilotGroup is required when Platform is android or both.' }

# Server-owned; sending these back on a create is rejected or ignored.
$ReadOnly = @(
    'id', 'createdDateTime', 'lastModifiedDateTime', 'version', 'deployedAppCount',
    'isAssigned', 'apps', 'assignments', 'deploymentSummary'
)

# Android packages to add to the pilot policy. All six integrate the Intune App SDK, so they
# honour the policy as soon as it applies.
$AndroidExtraApps = @(
    'com.microsoft.office.officehubrow',  # Microsoft 365 hub
    'com.microsoft.emmx',                 # Edge
    'com.adobe.reader',                   # Adobe Acrobat Reader  <- non-Microsoft; key pilot subject
    'com.microsoft.office.onenote',
    'com.microsoft.loop',
    'com.microsoft.msapps'                # Power Apps
)

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'DeviceManagementConfiguration.Read.All', 'Group.Read.All' -NoWelcome | Out-Null

function Resolve-Group {
    param([string] $Name)
    $g = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/groups?`$filter=displayName eq '$Name'&`$select=id,displayName,groupTypes" -OutputType PSObject).value)
    if ($g.Count -ne 1) { throw "Expected exactly one group named '$Name', found $($g.Count)." }
    if (($g[0].groupTypes -join ',') -match 'DynamicMembership') { throw "'$Name' is dynamic; a pilot group must be Assigned (static)." }
    $g[0]
}

function Copy-Writable {
    param($Source, [hashtable] $Override)
    $h = @{}
    foreach ($p in $Source.PSObject.Properties) {
        if ($p.Name -in $ReadOnly -or $p.Name -like '@odata*') { continue }
        $h[$p.Name] = $p.Value
    }
    foreach ($k in $Override.Keys) { $h[$k] = $Override[$k] }
    $h
}

function Invoke-PilotBuild {
    param(
        [string] $Endpoint,          # iosManagedAppProtections | androidManagedAppProtections
        [string] $OdataType,
        [hashtable] $Override,
        $PilotGroup,
        $Filter,                     # $null for Android
        [string[]] $ExtraApps,
        [string] $IdentifierType     # iosMobileAppIdentifier | androidMobileAppIdentifier
    )

    $all = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/$Endpoint`?`$select=id,displayName" -OutputType PSObject).value)
    $src = @($all | Where-Object { $_.displayName -notlike "*$PilotSuffix*" })
    if ($src.Count -ne 1) { throw "Expected exactly one production policy in $Endpoint, found $($src.Count)." }
    $full = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/$Endpoint/$($src[0].id)?`$expand=apps,assignments" -OutputType PSObject

    $pilotName = "$($full.displayName) $PilotSuffix"
    Write-Host ""
    Write-Host "=============================================================="
    Write-Host "Source : $($full.displayName)   ($(@($full.apps).Count) apps)"
    Write-Host "Pilot  : $pilotName"
    Write-Host "Group  : $($PilotGroup.displayName)"
    if ($Filter) { Write-Host "Filter : $($Filter.displayName)  [include]" }

    if (@($all | Where-Object { $_.displayName -eq $pilotName }).Count) { throw "A policy named '$pilotName' already exists." }

    Write-Host ""
    Write-Host "Overrides:"
    foreach ($k in ($Override.Keys | Sort-Object)) {
        $cur = if ($full.PSObject.Properties[$k]) { "$($full.$k)" } else { '(unset)' }
        Write-Host ("   {0,-46} {1}  ->  {2}" -f $k, $cur, $Override[$k])
    }

    $srcApps = @($full.apps | ForEach-Object {
            if ($IdentifierType -eq 'iosMobileAppIdentifier') { "$($_.mobileAppIdentifier.bundleId)" } else { "$($_.mobileAppIdentifier.packageId)" }
        } | Where-Object { $_ })
    $newApps = @($ExtraApps | Where-Object { $_ -notin $srcApps })
    $finalApps = @($srcApps + $newApps | Sort-Object -Unique)
    if ($newApps.Count) {
        Write-Host ""
        Write-Host ("Apps added ({0}):" -f $newApps.Count)
        foreach ($a in $newApps) { Write-Host "   + $a" }
    }
    Write-Host ""
    Write-Host ("Pilot policy will target {0} app(s)" -f $finalApps.Count)

    if (-not $PSCmdlet.ShouldProcess($pilotName, "Create pilot policy, target $($finalApps.Count) apps, assign to $($PilotGroup.displayName)")) { return }

    # 1. create
    $body = Copy-Writable -Source $full -Override $Override
    $body['displayName'] = $pilotName
    $body['description'] = "PILOT copy of '$($full.displayName)'. Delete once the settings are folded into the production policy."
    $body['@odata.type'] = "#microsoft.graph.$OdataType"
    $new = Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/$Endpoint" -Body ($body | ConvertTo-Json -Depth 12) -ContentType 'application/json' -OutputType PSObject
    Write-Host "  created. id=$($new.id)" -ForegroundColor Green

    # 2. target apps
    $appPayload = @{ apps = @($finalApps | ForEach-Object {
                if ($IdentifierType -eq 'iosMobileAppIdentifier') { @{ mobileAppIdentifier = @{ '@odata.type' = "#microsoft.graph.$IdentifierType"; bundleId = $_ } } }
                else { @{ mobileAppIdentifier = @{ '@odata.type' = "#microsoft.graph.$IdentifierType"; packageId = $_ } } }
            }) }
    Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/$Endpoint/$($new.id)/targetApps" -Body ($appPayload | ConvertTo-Json -Depth 8) -ContentType 'application/json' | Out-Null
    Write-Host "  targeted $($finalApps.Count) app(s)." -ForegroundColor Green

    # 3. assign pilot group (with filter on iOS)
    $target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $PilotGroup.id }
    if ($Filter) {
        $target['deviceAndAppManagementAssignmentFilterId'] = $Filter.id
        $target['deviceAndAppManagementAssignmentFilterType'] = 'include'
    }
    Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/$Endpoint/$($new.id)/assign" `
        -Body (@{ assignments = @(@{ target = $target }) } | ConvertTo-Json -Depth 8) -ContentType 'application/json' | Out-Null
    Write-Host "  assigned to $($PilotGroup.displayName)." -ForegroundColor Green

    # 4. exclude the pilot group from the production policy, preserving its existing assignments
    $prodAssignments = @()
    foreach ($a in @($full.assignments)) {
        $t = @{ '@odata.type' = "$($a.target.'@odata.type')" }
        if ($a.target.PSObject.Properties['groupId'] -and $a.target.groupId) { $t['groupId'] = $a.target.groupId }
        if ($a.target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId'] -and $a.target.deviceAndAppManagementAssignmentFilterId) {
            $t['deviceAndAppManagementAssignmentFilterId'] = $a.target.deviceAndAppManagementAssignmentFilterId
            $t['deviceAndAppManagementAssignmentFilterType'] = $a.target.deviceAndAppManagementAssignmentFilterType
        }
        $prodAssignments += @{ target = $t }
    }
    $prodAssignments += @{ target = @{ '@odata.type' = '#microsoft.graph.exclusionGroupAssignmentTarget'; groupId = $PilotGroup.id } }
    Invoke-MgGraphRequest -Method POST -Uri "$graph/deviceAppManagement/$Endpoint/$($full.id)/assign" `
        -Body (@{ assignments = $prodAssignments } | ConvertTo-Json -Depth 8) -ContentType 'application/json' | Out-Null
    Write-Host "  excluded $($PilotGroup.displayName) from '$($full.displayName)'." -ForegroundColor Green

    # 5. verify
    Write-Host "  verifying..."
    $chk = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/$Endpoint/$($new.id)?`$expand=apps,assignments" -OutputType PSObject
    Write-Host ("     pilot apps={0}  assignments={1}" -f @($chk.apps).Count, @($chk.assignments).Count)
    foreach ($k in $Override.Keys | Sort-Object) {
        $v = if ($chk.PSObject.Properties[$k]) { "$($chk.$k)" } else { '(unset)' }
        $ok = ("$v" -eq "$($Override[$k])")
        Write-Host ("     {0,-46} = {1} {2}" -f $k, $v, $(if ($ok) { 'OK' } else { '<<< MISMATCH' }))
    }
    $prodChk = Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceAppManagement/$Endpoint/$($full.id)?`$expand=assignments" -OutputType PSObject
    $exc = @($prodChk.assignments | Where-Object { "$($_.target.'@odata.type')" -match 'exclusionGroup' })
    Write-Host ("     production policy assignments={0}  exclusions={1}" -f @($prodChk.assignments).Count, $exc.Count)
}

# --- iOS --------------------------------------------------------------------------------
if ($Platform -in @('ios', 'both')) {
    $grp = Resolve-Group $IosPilotGroup
    $filters = @((Invoke-MgGraphRequest -Method GET -Uri "$graph/deviceManagement/assignmentFilters" -OutputType PSObject).value)
    $flt = @($filters | Where-Object { $_.displayName -eq $IosFilterName })
    if ($flt.Count -ne 1) { throw "Expected exactly one assignment filter named '$IosFilterName', found $($flt.Count)." }
    if ("$($flt[0].assignmentFilterManagementType)" -ne 'apps') { throw "Filter '$IosFilterName' is not a Managed apps filter; it will not apply to an app protection policy." }

    Invoke-PilotBuild -Endpoint 'iosManagedAppProtections' -OdataType 'iosManagedAppProtection' `
        -Override @{ pinRequired = $true; minimumPinLength = 6; simplePinBlocked = $true; dataBackupBlocked = $true } `
        -PilotGroup $grp -Filter $flt[0] -ExtraApps @() -IdentifierType 'iosMobileAppIdentifier'
}

# --- Android ----------------------------------------------------------------------------
if ($Platform -in @('android', 'both')) {
    $grp = Resolve-Group $AndroidPilotGroup
    $ov = @{ allowedOutboundDataTransferDestinations = 'managedApps'; dataBackupBlocked = $true }
    if ($AlignAndroidPin) { $ov['minimumPinLength'] = 6; $ov['simplePinBlocked'] = $true }

    Invoke-PilotBuild -Endpoint 'androidManagedAppProtections' -OdataType 'androidManagedAppProtection' `
        -Override $ov -PilotGroup $grp -Filter $null -ExtraApps $AndroidExtraApps -IdentifierType 'androidMobileAppIdentifier'
}

Write-Host ""
Write-Host "Done. Remember the pilot policies are temporary -- fold the settings into production and delete them." -ForegroundColor Yellow
