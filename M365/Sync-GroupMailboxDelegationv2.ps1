#Requires -Module ExchangeOnlineManagement, Microsoft.Graph
<#
    .SYNOPSIS
    You can assign a group as a mailbox delegate to allow all users delegate access to the mailbox. However, when a group is assigned,
    Outlook for Windows users will not get these delegate mailboxes automapped. The user must manually add the mailbox to their Outlook profile.
    If users are accessing mail using Outlook for web or Mac, automapping is not supported, so you can simply assign a group delegated permissions.

    .DESCRIPTION
    This script will add and remove delegates to an Exchange Online mailbox. Specify the group name and the mailbox for which to provide access.

    .PARAMETER Group
    The Azure AD Group or Distribution group members to apply permissions

    .PARAMETER DelegateMailbox
    Mailbox to delegate access to

    .PARAMETER LeaveExistingDelegates
    Do not remove any of the existing delegates

    .PARAMETER Permissions
    Provide list of permissions to delegate. Default includes FullAccess and SendAs
#>

[CmdletBinding()]
param (
    # Parameter help description
    [Parameter()]
    [string]
    $Group,
    # Parameter help description

    [string]
    $DelegateMailbox,
    # Parameter help description

    [switch]
    $LeaveExistingDelegates,
    # Parameter help description

    [string[]]
    $Permissions = @("FullAccess", "SendAs"),
    [Parameter()]
    [string]
    $AADCertificateThumbprint = (Get-Item -Path Env:AAD_CERT_THUMBPRINT -ErrorAction SilentlyContinue).Value,
    [parameter()]
    [string]
    $ExchangeClientAppId = (Get-Item -Path Env:EXO_CLIENT_APP_ID -ErrorAction SilentlyContinue).Value,
    #$ExchangeClientAppId = "7f9edc5bd1054104898653542a4e87de",

    [Parameter()]
    [string]
    $TenantId = (Get-Item -Path Env:TENANT_ID -ErrorAction SilentlyContinue).Value
)

if (-not $ExchangeClientAppId) {
    $ExchangeClientAppId = [Environment]::GetEnvironmentVariable('EXCHANGE_CLIENT_APP_ID')
}
if (-not $AADCertificateThumbprint) {
    $AADCertificateThumbprint = [Environment]::GetEnvironmentVariable('AAD_CERTIFICATE_THUMBPRINT')
}
if (-not $TenantId) {
    $TenantId = [Environment]::GetEnvironmentVariable('TENANT_ID')
}
function Get-MgGroupMemberRecursively {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupId,

        [Parameter()]
        [string]
        $GroupDisplayName
    )

    if ([string]::IsNullOrWhiteSpace($GroupId)) {
        $GroupId = (Get-MgGroup -Filter "DisplayName eq '$GroupDisplayName'" -ErrorAction SilentlyContinue).Id
    }

    #Write-Output $GroupDisplayName $GroupId
    $output = @()
    if ($GroupId) {
        Get-MgGroupMember -GroupId $GroupId -All | ForEach-Object {
            if ($_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.user") {
                $output += $_
            }
            elseif ($_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.group") {
                $output += @(Get-MgGroupMemberRecursively -GroupId $_.Id)
            }
        }
    }

    return $output
}

Connect-MgGraph -TenantId $TenantID -CertificateThumbprint $AADCertificateThumbprint -ClientId $ExchangeClientAppId

Connect-ExchangeOnline -CertificateThumbprint $AADCertificateThumbprint -AppId $ExchangeClientAppId -Organization $TenantId -ShowBanner:$false
        $mObj = Get-ExoMailbox -anr $DelegateMailbox
        #$gObj = Get-AzAdGroup -DisplayName $group
        $gMembers = Get-MgGroupMemberRecursively -GroupDisplayName $Group | Sort-Object -Property Id -Unique
        Write-Output " members in group: $($gMembers.Count)"

        if ($Permissions -contains "FullAccess") {

            $existingFullAccessPermissions = Get-MailboxPermission -Identity $mObj.identity | Sort-Object -Property User -Unique | Where-Object { $_.User -notlike "*SELF" } | Sort-Object -Unique -Property User | Foreach-object { Get-MgUser -UserId $_.User }
            $cPermissions = Compare-Object -ReferenceObject $existingFullAccessPermissions -DifferenceObject $gMembers -Property Id
            $missingPermissions = $cPermissions | Where-Object -Property SideIndicator -EQ "=>"
            Write-Verbose " Missing perms: $($missingPermissions.Count + 0)"
            $extraPermissions = $cPermissions | Where-Object -Property SideIndicator -EQ "<="
            Write-Verbose " Extra perms: $($extraPermissions.Count +0)"
            # if need to add FullAccess
            #$gMembers | ForEach-Object { Add-MailboxPermission -Identity $mObj.Id -User $_.Id -AccessRights ‘FullAccess’ -Automapping:$true –inheritancetype All }
            if (($missingPermissions.Count + 0) -gt 0) {
                Write-Output "Adding $($missingPermissions.Count) missing permission(s) based on group membership"

                foreach ($missing in $missingPermissions) {
                    $u = Get-mgUser -UserId $missing.id
                    Write-Output "`t$($u.DisplayName) does not currently have permissions to $DelegateMailbox, adding now..."
                    Add-MailboxPermission -Identity $mObj.Id -User $missing.Id -AccessRights ‘FullAccess’ -Automapping:$true –inheritancetype All | Out-Null
                }
            }
            else {
                Write-Output "No Full Access permissions added to $DelegateMailbox"
            }

            if (($LeaveExistingDelegates.IsPresent -eq $false) -and (($extraPermissions.Count + 0) -gt 0)) {

                Write-Output "Removing $($extraPermissions.Count) extra permission(s) based on group membership"
                foreach ($extra in $extraPermissions) {
                    $u = Get-MgUser -UserId $extra.id
                    Write-Output "`t$($u.DisplayName) has permissions to $DelegateMailbox, removing now..."
                    Remove-MailboxPermission -Identity $mObj.identity -User $extra.Id -Confirm:$false -AccessRights "FullAccess" | Out-Null
                }
            }
            else {
                Write-Output "No Full Access permissions removed from $DelegateMailbox."
            }

        }

        if ($Permissions -contains "SendAs") {
            # If need to add SendAs
            #$gMembers | ForEach-Object { Add-RecipientPermission -Identity $DelegateMailbox -AccessRights SendAs -Trustee $_.Id -Confirm:$false }

            $existingSendAsPermissions = (Get-RecipientPermission -Identity $mObj.identity | Sort-Object -Property Trustee -Unique).Trustee | Foreach-object { Get-AzAdUser -UserPrincipalName $_ }
            $cPermissions = Compare-Object -ReferenceObject $existingSendAsPermissions -DifferenceObject $gMembers -Property Id
            $missingPermissions = $cPermissions | Where-Object -Property SideIndicator -EQ "=>"
            $extraPermissions = $cPermissions | Where-Object -Property SideIndicator -EQ "<="
            if (($missingPermissions.Count + 0) -gt 0) {
                Write-Output "Adding $($missingPermissions.Count) missing permission(s) based on group membership"

                foreach ($missing in $missingPermissions) {
                    $u = Get-MgUser -UserId $missing.id
                    Write-Output "`t$($u.DisplayName) does not currently have SendAs permissions to $DelegateMailbox, adding now..."
                    Add-RecipientPermission -Identity $mObj.Id -Trustee $missing.Id -AccessRights 'SendAs' -Confirm:$false | Out-Null
                }
            }
            else {
                Write-Output "No Send As permissions added to $DelegateMailbox"
            }

            if (($LeaveExistingDelegates.IsPresent -eq $false) -and (($extraPermissions.Count + 0) -gt 0)) {

                Write-Output "Removing $($extraPermissions.Count) extra permission(s) based on group membership"
                foreach ($extra in $extraPermissions) {
                    $u = Get-MgUser -UserId $extra.id
                    Write-Output "`t$($u.DisplayName) has permissions to $DelegateMailbox, removing now..."
                    Remove-RecipientPermission -Identity $mObj.identity -Trustee $extra.Id -Confirm:$false -AccessRights "SendAs" | Out-Null
                }
            }
            else {
                Write-Output "No Send As permissions removed from $DelegateMailbox."
            }
        }

