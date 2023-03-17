#Requires -Module ExchangeOnlineManagement, Microsoft.Graph.Groups
<#
    .SYNOPSIS
        Updates delegates based on group membership. Group can be AAD or a Distribution group.
 
    .DESCRIPTION
    

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
    $Permissions = @("FullAccess", "SendAs")
)

function Get-AzADGroupMemberRecursive {
    <#
.SYNOPSIS
Get-AzADGroupMemberRecursive - Retrieve Azure AD group memberships recursively using the Az PowerShell module
.DESCRIPTION 
Given that there's no native recursive group membership retrieval functionality
in Az PowerShell, this module can be used to recursively list Azure AD group memberships
.PARAMETER GroupDisplayName
The display name of the Azure AD group
.INPUTS
System.String.
.OUTPUTS Microsoft.Azure.Commands.ActiveDirectory.PSADUser, Microsoft.Azure.Commands.ActiveDirectory.PSADGroup, Microsoft.Azure.Commands.ActiveDirectory.PSADServicePrincipal
.LINK
https://github.com/dstreefkerk/PowerShell/blob/master/Azure%20AD/Get-AzADGroupMemberRecursive.ps1
.NOTES
Written By: Daniel Streefkerk
Change Log
v1.0, 16/02/2021 - Initial version
#>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $True, ValueFromPipeline = $true)]
        $GroupDisplayName)
    
    begin {
        try {
            if ((Get-AzAccessToken) -eq $null) {
                Write-Host "Log in with Connect-AzAccount first"
                Connect-AzAccount
            }
        }
        catch {
            throw "An error occurred while accessing Azure via PowerShell"
        }
    
    }
        
    process {
        $members = Get-AzADGroupMember -groupDisplayName $GroupDisplayName
    
        # If group contains no members, return null
        if ($null -eq $members) {
            return
        }
    
        # Return all members that aren't groups
        $members | Where-Object { $_.OdataType -ne '#microsoft.graph.group' }
    
        # Get sub-groups, and fetch their memberships recursively
        $groupMembers = $members | Where-Object { $_.OdataType -eq '#microsoft.graph.group' }
        if ($groupMembers) {
            $groupMembers | ForEach-Object { Get-AzADGroupMemberRecursive -GroupDisplayName $_.DisplayName }
        }
    }
    
}

$mObj = Get-ExoMailbox -anr $DelegateMailbox
#$gObj = Get-AzAdGroup -DisplayName $group
$gMembers = Get-AzADGroupMemberRecursive -GroupDisplayName $Group | Sort-Object -Property Id -Unique

if ($Permissions -contains "FullAccess") {
    $existingFullAccessPermissions = (Get-MailboxPermission -Identity $mObj.identity | Sort-Object -Property User -Unique).User | Foreach-object { Get-AzAdUser -UserPrincipalName $_ }
    $cPermissions = Compare-Object -ReferenceObject $existingFullAccessPermissions -DifferenceObject $gMembers -Property Id
    $missingPermissions = $cPermissions | Where-Object -Property SideIndicator -EQ "=>"
    $extraPermissions = $cPermissions | Where-Object -Property SideIndicator -EQ "<="
    # if need to add FullAccess
    #$gMembers | ForEach-Object { Add-MailboxPermission -Identity $mObj.Id -User $_.Id -AccessRights ‘FullAccess’ -Automapping:$true –inheritancetype All }
    if (($missingPermissions.Count + 0) -gt 0) {
        Write-Output "Adding $($missingPermissions.Count) missing permission(s) based on group membership"
        
        foreach ($missing in $missingPermissions) {
            $u = Get-AzAdUser -ObjectId $missing.id
            Write-Output "`t$($u.DisplayName) does not currently have permissions to $DelegateMailbox, adding now..."
            Add-MailboxPermission -Identity $mObj.Id -User $missing.Id -AccessRights ‘FullAccess’ -Automapping:$true –inheritancetype All | Out-Null
        }
    }
    else {
        Write-Output "No FullAccess permissions added to $DelegateMailbox"
    }
    
    if (($LeaveExistingDelegates.IsPresent -eq $false) -and (($extraPermissions.Count + 0) -gt 0)) {
        
        Write-Output "Removing $($extraPermissions.Count) extra permission(s) based on group membership"
        foreach ($extra in $extraPermissions) {
            $u = Get-AzAdUser -ObjectId $extra.id
            Write-Output "`t$($u.DisplayName) has permissions to $DelegateMailbox, removing now..."
            Remove-MailboxPermission -Identity $mObj.identity -User $extra.Id -Confirm:$false -AccessRights "FullAccess" | Out-Null
        } 
    }
    else {
        Write-Output "No FullAccess permissions removed from $DelegateMailbox."
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
            $u = Get-AzAdUser -ObjectId $missing.id
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
            $u = Get-AzAdUser -ObjectId $extra.id
            Write-Output "`t$($u.DisplayName) has permissions to $DelegateMailbox, removing now..."
            Remove-RecipientPermission -Identity $mObj.identity -Trustee $extra.Id -Confirm:$false -AccessRights "SendAs" | Out-Null
        } 
    }
    else {
        Write-Output "No Send As permissions removed from $DelegateMailbox."
    }
}

