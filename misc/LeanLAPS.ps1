<#
    .DESCRIPTION
    Local Admin Password Rotation and Account Management
    Set configuration values, and follow rollout instructions at https://www.lieben.nu/liebensraum/?p=3605
      
    .NOTES
    Copyright/License:     https://www.lieben.nu/liebensraum/commercial-use/ (Commercial (re)use not allowed without prior written consent by the author, otherwise free to use/modify as long as header kept intact)
    filename:               LeanLAPS.ps1
    author:                 Jos Lieben (Lieben Consultancy)
    created:                09/06/2021
    last updated:           see https://gitlab.com/Lieben/assortedFunctions/-/tree/master/leanLAPS
    
    inspired by:            Rudy Ooms; https://call4cloud.nl/2021/05/the-laps-reloaded/
    
    Customization by:   Joel Stidley https://github.com/joelst/
        - Updated password generator to remove commonly confused characters, like i,l,1,0, and O
        - Added Set-LocalUser try/catch if there are errors using ADSI password set option.
#>
[CmdletBinding()]
param (
    $minimumPasswordLength = 21,
    $publicEncryptionKey = "", # If you supply a public encryption key, LeanLAPS will use this to encrypt the password, ensuring it will only be in encrypted form in Proactive Remediations
    $localAdminName = "LocalAdmin",
    $removeOtherLocalAdmins = $true, # if set to True, will remove ALL other local admins, including those set through AzureAD device settings
    $disableBuiltinAdminAccount = $false, #Disables the built in admin account (which cannot be removed). Usually not needed as most OOBE setups have already done this
    $doNotRunOnServers = $true, # Built-in protection in case an admin accidentally assigns this script to e.g. a domain controller
    # Specify SIDs for Azure groups such as Global Admins and Device Administrators or for local or domain users to not remove from local admins. These are specific to your tenant, you can get them on a device by running: 
    # ([ADSI]::new("WinNT://$($env:COMPUTERNAME)/$((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]),Group")).Invoke('Members') | % {"$((New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value) <--- a.k.a: $(([ADSI]$_).Path.Split("/")[-1])"}
    $approvedAdmins = @( 

    )
)

$markerFile = Join-Path $Env:TEMP -ChildPath "LeanLAPS.marker"

function Get-NewPassword {
    <#
    .DESCRIPTION
        Generate a random password with the configured number of characters and special characters. 
        Does not return characters that are commonly confused like 0 and O and 1 and l. Also removes characters that cause issues in PowerShell scripts.
    
    .EXAMPLE
        Get-NewPassword -PasswordLength 13 -SpecialChars 4
        
        Returns a password that is 13 characters long and includes 4 special characters.
    
    .NOTES
        Very loosely based on: http://blog.oddbit.com/2012/11/04/powershell-random-passwords/
    
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [int]$PasswordLength = 20,
        # (REQUIRED)
        #
        # Specifies the total length of password to generate
    
        [int]$SpecialChars = 4
        # (REQUIRED)
        #
        # Specifies the number of special characters to include in the generated password.
    ) 
    $password = ""
    
    # punctuation options but doesn't include &,',",`,$,{,},[,],(),),|,;,, and a few others can break Vagrant/PowerShell or are difficult to read.
    $special = 43..46 + 94..95 + 126 + 33 + 35 + 61 + 63
    # Remove 0 and 1 because they can be confused with o,O,I,i,l
    $digits = 50..57
    # Remove O,o,i,I,l as these can be confused with other characters
    $letters = 65..72 + 74..78 + 80..90 + 97..104 + 106..107 + 109..110 + 112..122  
    # Pick total minus the number of special chars of random letters and digits 
    $chars = Get-Random -Count ($PasswordLength - $SpecialChars) -InputObject ($digits + $letters) 
    # Pick the specified number of special characters 
    $chars += Get-Random -Count $SpecialChars -InputObject ($special)        
    # Mix up the chars so that the special char aren't just at the end and then convert each char number to the char and put in a string
    $password = Get-Random -Count $PasswordLength -InputObject ($chars) | ForEach-Object -Begin { $aa = $null } -Process { $aa += [char]$_ } -End { $aa }
        
    return $password
}

function Convert-AzureAdObjectIdToSid {
    <#
.SYNOPSIS
Convert an Azure AD Object ID to SID
 
.DESCRIPTION
Converts an Azure AD Object ID to a SID.
Author: Oliver Kieselbach (oliverkieselbach.com)
The script is provided "AS IS" with no warranties.
 
.PARAMETER ObjectID
The Object ID to convert
#>

    param([String] $ObjectId)

    $bytes = [Guid]::Parse($ObjectId).ToByteArray()
    $array = New-Object 'UInt32[]' 4

    [Buffer]::BlockCopy($bytes, 0, $array, 0, 16)
    $sid = "S-1-12-1-$array".Replace(' ', '-')

    return $sid
}

function Convert-AzureAdSidToObjectId {
    <#
.SYNOPSIS
Convert a Azure AD SID to Object ID
 
.DESCRIPTION
Converts an Azure AD SID to Object ID.
Author: Oliver Kieselbach (oliverkieselbach.com)
The script is provided "AS IS" with no warranties.
 
.PARAMETER ObjectID
The SID to convert
#>
    param([String] $Sid)

    $text = $sid.Replace('S-1-12-1-', '')
    $array = [UInt32[]]$text.Split('-')

    $bytes = New-Object 'Byte[]' 16
    [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
    [Guid]$guid = $bytes

    return $guid
}

function Write-CustomEventLog {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Message
    )

    $EventSource = "LeanLAPS"
    if ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
        $null = New-EventLog -LogName Application -Source $EventSource | Out-Null
    }

    $null = Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1985 -Message $Message
}

Write-CustomEventLog "LeanLAPS starting on $($ENV:COMPUTERNAME) as $($MyInvocation.MyCommand.Name)"

if ($doNotRunOnServers -and (Get-CimInstance -Class Win32_OperatingSystem).ProductType -ne 1) {
    Write-CustomEventLog "Unsupported OS!"
    Write-Error "Unsupported OS!"
    Exit 0
}

$mode = $MyInvocation.MyCommand.Name.Split(".")[0]
$pwdSet = $false

# When in remediation mode, always exit successfully as we remediated during the detection phase
if ($mode -ne "detect") {
    Exit 0
}
else {
    # If the marker file is found this in not the first detection run, so only new password should be posted to Microsoft Endpoint Manager
    if (Test-Path $markerFile) {
        $pwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-Content $markerFile | ConvertTo-SecureString)))
        Remove-Item -Path $markerFile -Force -Confirm:$false
        
        if ($publicEncryptionKey.Length -gt 5) {
            $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
            $rsa.ImportCspBlob([byte[]]($publicEncryptionKey -split ","))
            $pwd = $rsa.Encrypt([System.Text.Encoding]::UTF8.GetBytes($pwd), $false )
        }
        else {
            # Ensure the plain text password is removed from Microsoft Endpoint Manager log files and registry (which are written after a delay):
            $triggers = @((New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(5) -Once), (New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(10) -Once), (New-ScheduledTaskTrigger -At (Get-Date).AddMinutes(30) -Once))
            $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -EncodedCommand RnVuY3Rpb24gV3JpdGUtQ3VzdG9tRXZlbnRMb2coJE1lc3NhZ2UpewogICAgJEV2ZW50U291cmNlPSJMZWFuTEFQUyIKICAgIGlmIChbU3lzdGVtLkRpYWdub3N0aWNzLkV2ZW50TG9nXTo6RXhpc3RzKCdBcHBsaWNhdGlvbicpIC1lcSAkRmFsc2UgLW9yIFtTeXN0ZW0uRGlhZ25vc3RpY3MuRXZlbnRMb2ddOjpTb3VyY2VFeGlzdHMoJEV2ZW50U291cmNlKSAtZXEgJEZhbHNlKXsKICAgICAgICAkcmVzID0gTmV3LUV2ZW50TG9nIC1Mb2dOYW1lIEFwcGxpY2F0aW9uIC1Tb3VyY2UgJEV2ZW50U291cmNlICB8IE91dC1OdWxsCiAgICB9CiAgICAkcmVzID0gV3JpdGUtRXZlbnRMb2cgLUxvZ05hbWUgQXBwbGljYXRpb24gLVNvdXJjZSAkRXZlbnRTb3VyY2UgLUVudHJ5VHlwZSBJbmZvcm1hdGlvbiAtRXZlbnRJZCAxOTg1IC1NZXNzYWdlICRNZXNzYWdlCn0KCiN3aXBlIHBhc3N3b3JkIGZyb20gbG9nZmlsZXMKdHJ5ewogICAgJGludHVuZUxvZzEgPSBKb2luLVBhdGggJEVudjpQcm9ncmFtRGF0YSAtY2hpbGRwYXRoICJNaWNyb3NvZnRcSW50dW5lTWFuYWdlbWVudEV4dGVuc2lvblxMb2dzXEFnZW50RXhlY3V0b3IubG9nIgogICAgJGludHVuZUxvZzIgPSBKb2luLVBhdGggJEVudjpQcm9ncmFtRGF0YSAtY2hpbGRwYXRoICJNaWNyb3NvZnRcSW50dW5lTWFuYWdlbWVudEV4dGVuc2lvblxMb2dzXEludHVuZU1hbmFnZW1lbnRFeHRlbnNpb24ubG9nIgogICAgU2V0LUNvbnRlbnQgLUZvcmNlIC1Db25maXJtOiRGYWxzZSAtUGF0aCAkaW50dW5lTG9nMSAtVmFsdWUgKEdldC1Db250ZW50IC1QYXRoICRpbnR1bmVMb2cxIHwgU2VsZWN0LVN0cmluZyAtUGF0dGVybiAiUGFzc3dvcmQiIC1Ob3RNYXRjaCkKICAgIFNldC1Db250ZW50IC1Gb3JjZSAtQ29uZmlybTokRmFsc2UgLVBhdGggJGludHVuZUxvZzIgLVZhbHVlIChHZXQtQ29udGVudCAtUGF0aCAkaW50dW5lTG9nMiB8IFNlbGVjdC1TdHJpbmcgLVBhdHRlcm4gIlBhc3N3b3JkIiAtTm90TWF0Y2gpCn1jYXRjaHskTnVsbH0KCiNvbmx5IHdpcGUgcmVnaXN0cnkgZGF0YSBhZnRlciBkYXRhIGhhcyBiZWVuIHNlbnQgdG8gTXNmdAppZigoR2V0LUNvbnRlbnQgLVBhdGggJGludHVuZUxvZzIgfCBTZWxlY3QtU3RyaW5nIC1QYXR0ZXJuICJQb2xpY3kgcmVzdWx0cyBhcmUgc3VjY2Vzc2Z1bGx5IHNlbnQuIikpewogICAgV3JpdGUtQ3VzdG9tRXZlbnRMb2cgIk1pY3Jvc29mdCBFbmRwb2ludCBNYW5hZ2VyIGxvZ2ZpbGUgaW5kaWNhdGVzIHNjcmlwdCByZXN1bHRzIGhhdmUgYmVlbiByZXBvcnRlZCB0byBNaWNyb3NvZnQiCiAgICBTZXQtQ29udGVudCAtRm9yY2UgLUNvbmZpcm06JEZhbHNlIC1QYXRoICRpbnR1bmVMb2cyIC1WYWx1ZSAoR2V0LUNvbnRlbnQgLVBhdGggJGludHVuZUxvZzIgfCBTZWxlY3QtU3RyaW5nIC1QYXR0ZXJuICJQb2xpY3kgcmVzdWx0cyBhcmUgc3VjY2Vzc2Z1bGx5IHNlbnQuIiAtTm90TWF0Y2gpCiAgICBTdGFydC1TbGVlcCAtcyA5MAogICAgdHJ5ewogICAgICAgIGZvcmVhY2goJFRlbmFudCBpbiAoR2V0LUNoaWxkSXRlbSAiSEtMTTpcU29mdHdhcmVcTWljcm9zb2Z0XEludHVuZU1hbmFnZW1lbnRFeHRlbnNpb25cU2lkZUNhclBvbGljaWVzXFNjcmlwdHNcUmVwb3J0cyIpKXsKICAgICAgICAgICAgZm9yZWFjaCgkc2NyaXB0IGluIChHZXQtQ2hpbGRJdGVtICRUZW5hbnQuUFNQYXRoKSl7CiAgICAgICAgICAgICAgICAkanNvbiA9ICgoR2V0LUl0ZW1Qcm9wZXJ0eSAtUGF0aCAoSm9pbi1QYXRoICRzY3JpcHQuUFNQYXRoIC1DaGlsZFBhdGggIlJlc3VsdCIpIC1OYW1lICJSZXN1bHQiKS5SZXN1bHQgfCBDb252ZXJ0ZnJvbS1Kc29uKQogICAgICAgICAgICAgICAgaWYoJGpzb24uUG9zdFJlbWVkaWF0aW9uRGV0ZWN0U2NyaXB0T3V0cHV0LlN0YXJ0c1dpdGgoIkxlYW5MQVBTIikpewogICAgICAgICAgICAgICAgICAgICRqc29uLlBvc3RSZW1lZGlhdGlvbkRldGVjdFNjcmlwdE91dHB1dCA9ICJSRURBQ1RFRCIKICAgICAgICAgICAgICAgICAgICBTZXQtSXRlbVByb3BlcnR5IC1QYXRoIChKb2luLVBhdGggJHNjcmlwdC5QU1BhdGggLUNoaWxkUGF0aCAiUmVzdWx0IikgLU5hbWUgIlJlc3VsdCIgLVZhbHVlICgkanNvbiB8IENvbnZlcnRUby1Kc29uIC1EZXB0aCAxMCAtQ29tcHJlc3MpIC1Gb3JjZSAtQ29uZmlybTokRmFsc2UKICAgICAgICAgICAgICAgICAgICBXcml0ZS1DdXN0b21FdmVudExvZyAicmVkYWN0ZWQgYWxsIGxvY2FsIGRhdGEiCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICB9Y2F0Y2h7JE51bGx9Cn0=" #base64 UTF16-LE encoded command https://www.base64encode.org/
            $Null = Register-ScheduledTask -TaskName "LeanLAPS_WL" -Trigger $triggers -User "SYSTEM" -Action $Action -Force
        }
        
        Write-Host "LeanLAPS current password: $pwd for $($localAdminName), last changed on $(Get-Date)"
        Exit 0
    }
}

try {
    $localAdmin = $null
    $localAdmin = Get-LocalUser -Name $localAdminName -ErrorAction Stop
    if (!$localAdmin) { Throw }
}
catch {
    Write-CustomEventLog "$localAdminName doesn't exist, creating..."
    try {
        $newPwd = Get-NewPassword -Passwordlength $minimumPasswordLength
        $newPwdSecStr = $newPwd | ConvertTo-SecureString -AsPlainText -Force
        $pwdSet = $true
        $localAdmin = New-LocalUser -PasswordNeverExpires -AccountNeverExpires -Name $localAdminName -Password $newPwdSecStr -Description "DO NOT MODIFY! LeanLAPS managed user"
        Write-CustomEventLog "$localAdminName created"
    }
    catch {
        Write-CustomEventLog "Something went wrong while provisioning $localAdminName $($_)"
        Write-Host "Something went wrong while provisioning $localAdminName $($_)"
        Exit 0
    }
}

try {
    $administratorsGroupName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]
    Write-CustomEventLog "Local administrators group is named $administratorsGroupName"
    $group = [ADSI]::new("WinNT://$($env:COMPUTERNAME)/$($administratorsGroupName),Group")
    $administrators = $group.Invoke('Members') | ForEach-Object { (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value }
    
    Write-CustomEventLog "There are $($administrators.count) readable accounts in $administratorsGroupName"

    if (!$administrators -or $administrators -notcontains $localAdmin.SID.Value) {
        Write-CustomEventLog "$localAdminName is not a local administrator, adding..."
        $res = Add-LocalGroupMember -Group $administratorsGroupName -Member $localAdminName -Confirm:$False -ErrorAction Stop
        Write-CustomEventLog "Added $localAdminName to the local administrators group"
    }
    
    # Disable built in admin account if specified
    foreach ($administrator in $administrators) {
        if ($administrator.EndsWith("-500")) {
            if ($disableBuiltinAdminAccount) {
                if ((Get-LocalUser -SID $administrator).Enabled) {
                    $res = Disable-LocalUser -SID $administrator -Confirm:$False
                    Write-CustomEventLog "Disabled $($administrator) because it is a built-in account and `$disableBuiltinAdminAccount is set to `$True"
                }
            }
        }
    }
    
    # Remove other local admins if specified, only executes if adding the new local admin succeeded
    if ($removeOtherLocalAdmins) {
        foreach ($administrator in $administrators) {
            if ($administrator.EndsWith("-500")) {
                Write-CustomEventLog "Not removing $($administrator) because it is a built-in account and cannot be removed"
                continue
            }
            if ($administrator -ne $localAdmin.SID.Value -and $approvedAdmins -notcontains $administrator) {
                Write-CustomEventLog "removeOtherLocalAdmins set to True, removing $($administrator) from Local Administrators"
                $res = Remove-LocalGroupMember -Group $administratorsGroupName -Member $administrator -Confirm:$False
                Write-CustomEventLog "Removed $administrator from Local Administrators"
            } 
            else {
                Write-CustomEventLog "$($administrator) whitelisted and not removed"
            }
        }
    }
    else {
        Write-CustomEventLog "removeOtherLocalAdmins set to False, will not remove any administrator permissions"
    }
}
catch {
    Write-CustomEventLog "Something went wrong while processing the local administrators group $($_)"
    Write-Host "Something went wrong while processing the local administrators group $($_)"
    Exit 0
}

if (!$pwdSet) {
    try {
        Write-CustomEventLog "Setting password for $localAdminName ..."
        $newPwd = Get-NewPassword $minimumPasswordLength
        $newPwdSecStr = ConvertTo-SecureString $newPwd -AsPlainText -Force
        $pwdSet = $true
              
        $localAdmin | Set-LocalUser -Password $newPwdSecStr -Confirm:$false -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $true -ErrorAction SilentlyContinue
        # Temporary: If Set-LocalUser fails, set password using ADSI, this should also ensure that Set-LocalUser works next time.
        $LocalDirectory = [ADSI]::new(('WinNT://{0}' -f $env:COMPUTERNAME))
        $LocalDirectory.'Children'.Find($LocalAdminName).Invoke('SetPassword', $NewPwd)

        Write-CustomEventLog "Password for $localAdminName set to a new value, see MEM"
    }
    catch {
        Write-CustomEventLog "Failed to set new password for $localAdminName"
        Write-Host "Failed to set password for $localAdminName because of $($_)"
        Exit 0
    }
}

Write-Host "LeanLAPS ran successfully for $($localAdminName)"
$res = Set-Content -Path $markerFile -Value (ConvertFrom-SecureString $newPwdSecStr) -Force -Confirm:$false
exit 1