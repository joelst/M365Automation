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
        - Updated 11/30/2022
#>
[CmdletBinding()]
param (
    $minimumPasswordLength = 21,
    $publicEncryptionKey = "", # If you supply a public encryption key, LeanLAPS will use this to encrypt the password, ensuring it will only be in encrypted in Proactive Remediation
    $localAdminName = "LocalAdmin",
    $autoEnableLocalAdmin = $false, #if for some reason the admin account this script creates becomes disabled, leanLAPS will re-enable it
    $removeOtherLocalAdmins = $true, # Removes ALL other local admins, including those set through AzureAD device settings
    $disableBuiltinAdminAccount = $true, # Disables the built in admin account (which cannot be removed). Usually not needed as most OOBE setups have already done this
    $doNotRunOnServers = $true, # Built-in protection in case an admin accidentally assigns this script to e.g. a domain controller
    # Specify SIDs for Azure groups such as Global Admins and Device Administrators or for local or domain users to not remove from local admins. These are specific to your tenant, you can get them on a device by running:
    # ([ADSI]::new("WinNT://$($env:COMPUTERNAME)/$((New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")).Translate([System.Security.Principal.NTAccount]).Value.Split("\")[1]),Group")).Invoke('Members') | % {"$((New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @([Byte[]](([ADSI]$_).properties.objectSid).Value, 0)).Value) <--- a.k.a: $(([ADSI]$_).Path.Split("/")[-1])"}
    $approvedAdmins = @(

    )

)

$markerFile = Join-Path $Env:TEMP -ChildPath "LeanLAPS.marker"
$markerFileExists = (Test-Path $markerFile)

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
    if ([System.Diagnostics.EventLog]::Exists('Application') -eq $false -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $false) {
        $null = New-EventLog -LogName Application -Source $EventSource | Out-Null
    }

    $null = Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1985 -Message $Message
}

Write-CustomEventLog "LeanLAPS starting on $($ENV:COMPUTERNAME) as $($MyInvocation.MyCommand.Name)"

if ($doNotRunOnServers -and (Get-CimInstance -Class Win32_OperatingSystem).ProductType -ne 1) {
    Write-CustomEventLog "Unsupported OS!"
    Write-Warning "Unsupported OS!"
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
            $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -EncodedCommand RgB1AG4AYwB0AGkAbwBuACAAVwByAGkAdABlAC0AQwB1AHMAdABvAG0ARQB2AGUAbgB0AEwAbwBnACgAJABNAGUAcwBzAGEAZwBlACkAewAKACAAIAAgACAAJABFAHYAZQBuAHQAUwBvAHUAcgBjAGUAPQAiAC4ATABpAGUAYgBlAG4AQwBvAG4AcwB1AGwAdABhAG4AYwB5ACIACgAgACAAIAAgAGkAZgAgACgAWwBTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAEUAdgBlAG4AdABMAG8AZwBdADoAOgBFAHgAaQBzAHQAcwAoACcAQQBwAHAAbABpAGMAYQB0AGkAbwBuACcAKQAgAC0AZQBxACAAJABGAGEAbABzAGUAIAAtAG8AcgAgAFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBFAHYAZQBuAHQATABvAGcAXQA6ADoAUwBvAHUAcgBjAGUARQB4AGkAcwB0AHMAKAAkAEUAdgBlAG4AdABTAG8AdQByAGMAZQApACAALQBlAHEAIAAkAEYAYQBsAHMAZQApAHsACgAgACAAIAAgACAAIAAgACAAJAByAGUAcwAgAD0AIABOAGUAdwAtAEUAdgBlAG4AdABMAG8AZwAgAC0ATABvAGcATgBhAG0AZQAgAEEAcABwAGwAaQBjAGEAdABpAG8AbgAgAC0AUwBvAHUAcgBjAGUAIAAkAEUAdgBlAG4AdABTAG8AdQByAGMAZQAgACAAfAAgAE8AdQB0AC0ATgB1AGwAbAAKACAAIAAgACAAfQAKACAAIAAgACAAJAByAGUAcwAgAD0AIABXAHIAaQB0AGUALQBFAHYAZQBuAHQATABvAGcAIAAtAEwAbwBnAE4AYQBtAGUAIABBAHAAcABsAGkAYwBhAHQAaQBvAG4AIAAtAFMAbwB1AHIAYwBlACAAJABFAHYAZQBuAHQAUwBvAHUAcgBjAGUAIAAtAEUAbgB0AHIAeQBUAHkAcABlACAASQBuAGYAbwByAG0AYQB0AGkAbwBuACAALQBFAHYAZQBuAHQASQBkACAAMQA5ADgANQAgAC0ATQBlAHMAcwBhAGcAZQAgACQATQBlAHMAcwBhAGcAZQAKAH0ACgAKACMAdwBpAHAAZQAgAHAAYQBzAHMAdwBvAHIAZAAgAGYAcgBvAG0AIABsAG8AZwBmAGkAbABlAHMACgB0AHIAeQB7AAoAIAAgACAAIAAkAGkAbgB0AHUAbgBlAEwAbwBnADEAIAA9ACAASgBvAGkAbgAtAFAAYQB0AGgAIAAkAEUAbgB2ADoAUAByAG8AZwByAGEAbQBEAGEAdABhACAALQBjAGgAaQBsAGQAcABhAHQAaAAgACIATQBpAGMAcgBvAHMAbwBmAHQAXABJAG4AdAB1AG4AZQBNAGEAbgBhAGcAZQBtAGUAbgB0AEUAeAB0AGUAbgBzAGkAbwBuAFwATABvAGcAcwBcAEEAZwBlAG4AdABFAHgAZQBjAHUAdABvAHIALgBsAG8AZwAiAAoAIAAgACAAIAAkAGkAbgB0AHUAbgBlAEwAbwBnADIAIAA9ACAASgBvAGkAbgAtAFAAYQB0AGgAIAAkAEUAbgB2ADoAUAByAG8AZwByAGEAbQBEAGEAdABhACAALQBjAGgAaQBsAGQAcABhAHQAaAAgACIATQBpAGMAcgBvAHMAbwBmAHQAXABJAG4AdAB1AG4AZQBNAGEAbgBhAGcAZQBtAGUAbgB0AEUAeAB0AGUAbgBzAGkAbwBuAFwATABvAGcAcwBcAEkAbgB0AHUAbgBlAE0AYQBuAGEAZwBlAG0AZQBuAHQARQB4AHQAZQBuAHMAaQBvAG4ALgBsAG8AZwAiAAoAIAAgACAAIABTAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAEYAbwByAGMAZQAgAC0AQwBvAG4AZgBpAHIAbQA6ACQARgBhAGwAcwBlACAALQBQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAxACAALQBWAGEAbAB1AGUAIAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgAC0AUABhAHQAaAAgACQAaQBuAHQAdQBuAGUATABvAGcAMQAgAHwAIABTAGUAbABlAGMAdAAtAFMAdAByAGkAbgBnACAALQBQAGEAdAB0AGUAcgBuACAAIgBQAGEAcwBzAHcAbwByAGQAIgAgAC0ATgBvAHQATQBhAHQAYwBoACkACgAgACAAIAAgAFMAZQB0AC0AQwBvAG4AdABlAG4AdAAgAC0ARgBvAHIAYwBlACAALQBDAG8AbgBmAGkAcgBtADoAJABGAGEAbABzAGUAIAAtAFAAYQB0AGgAIAAkAGkAbgB0AHUAbgBlAEwAbwBnADIAIAAtAFYAYQBsAHUAZQAgACgARwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAyACAAfAAgAFMAZQBsAGUAYwB0AC0AUwB0AHIAaQBuAGcAIAAtAFAAYQB0AHQAZQByAG4AIAAiAFAAYQBzAHMAdwBvAHIAZAAiACAALQBOAG8AdABNAGEAdABjAGgAKQAKAH0AYwBhAHQAYwBoAHsAJABOAHUAbABsAH0ACgAKACMAbwBuAGwAeQAgAHcAaQBwAGUAIAByAGUAZwBpAHMAdAByAHkAIABkAGEAdABhACAAYQBmAHQAZQByACAAZABhAHQAYQAgAGgAYQBzACAAYgBlAGUAbgAgAHMAZQBuAHQAIAB0AG8AIABNAHMAZgB0AAoAaQBmACgAKABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAFAAYQB0AGgAIAAkAGkAbgB0AHUAbgBlAEwAbwBnADIAIAB8ACAAUwBlAGwAZQBjAHQALQBTAHQAcgBpAG4AZwAgAC0AUABhAHQAdABlAHIAbgAgACIAUABvAGwAaQBjAHkAIAByAGUAcwB1AGwAdABzACAAYQByAGUAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAHMAZQBuAHQALgAiACkAKQB7AAoAIAAgACAAIABXAHIAaQB0AGUALQBDAHUAcwB0AG8AbQBFAHYAZQBuAHQATABvAGcAIAAiAEkAbgB0AHUAbgBlACAAbABvAGcAZgBpAGwAZQAgAGkAbgBkAGkAYwBhAHQAZQBzACAAcwBjAHIAaQBwAHQAIAByAGUAcwB1AGwAdABzACAAaABhAHYAZQAgAGIAZQBlAG4AIAByAGUAcABvAHIAdABlAGQAIAB0AG8AIABNAGkAYwByAG8AcwBvAGYAdAAiAAoAIAAgACAAIABTAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAEYAbwByAGMAZQAgAC0AQwBvAG4AZgBpAHIAbQA6ACQARgBhAGwAcwBlACAALQBQAGEAdABoACAAJABpAG4AdAB1AG4AZQBMAG8AZwAyACAALQBWAGEAbAB1AGUAIAAoAEcAZQB0AC0AQwBvAG4AdABlAG4AdAAgAC0AUABhAHQAaAAgACQAaQBuAHQAdQBuAGUATABvAGcAMgAgAHwAIABTAGUAbABlAGMAdAAtAFMAdAByAGkAbgBnACAALQBQAGEAdAB0AGUAcgBuACAAIgBQAG8AbABpAGMAeQAgAHIAZQBzAHUAbAB0AHMAIABhAHIAZQAgAHMAdQBjAGMAZQBzAHMAZgB1AGwAbAB5ACAAcwBlAG4AdAAuACIAIAAtAE4AbwB0AE0AYQB0AGMAaAApAAoAIAAgACAAIABTAHQAYQByAHQALQBTAGwAZQBlAHAAIAAtAHMAIAA5ADAACgAgACAAIAAgAHQAcgB5AHsACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAoACQAVABlAG4AYQBuAHQAIABpAG4AIAAoAEcAZQB0AC0AQwBoAGkAbABkAEkAdABlAG0AIAAiAEgASwBMAE0AOgBcAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwASQBuAHQAdQBuAGUATQBhAG4AYQBnAGUAbQBlAG4AdABFAHgAdABlAG4AcwBpAG8AbgBcAFMAaQBkAGUAQwBhAHIAUABvAGwAaQBjAGkAZQBzAFwAUwBjAHIAaQBwAHQAcwBcAFIAZQBwAG8AcgB0AHMAIgApACkAewAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGYAbwByAGUAYQBjAGgAKAAkAHMAYwByAGkAcAB0ACAAaQBuACAAKABHAGUAdAAtAEMAaABpAGwAZABJAHQAZQBtACAAJABUAGUAbgBhAG4AdAAuAFAAUwBQAGEAdABoACkAKQB7AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAkAGoAcwBvAG4AIAA9ACAAKAAoAEcAZQB0AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAAoAEoAbwBpAG4ALQBQAGEAdABoACAAJABzAGMAcgBpAHAAdAAuAFAAUwBQAGEAdABoACAALQBDAGgAaQBsAGQAUABhAHQAaAAgACIAUgBlAHMAdQBsAHQAIgApACAALQBOAGEAbQBlACAAIgBSAGUAcwB1AGwAdAAiACkALgBSAGUAcwB1AGwAdAAgAHwAIABjAG8AbgB2AGUAcgB0AGYAcgBvAG0ALQBqAHMAbwBuACkACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGkAZgAoACQAagBzAG8AbgAuAFAAbwBzAHQAUgBlAG0AZQBkAGkAYQB0AGkAbwBuAEQAZQB0AGUAYwB0AFMAYwByAGkAcAB0AE8AdQB0AHAAdQB0AC4AUwB0AGEAcgB0AHMAVwBpAHQAaAAoACIATABlAGEAbgBMAEEAUABTACIAKQApAHsACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAJABqAHMAbwBuAC4AUABvAHMAdABSAGUAbQBlAGQAaQBhAHQAaQBvAG4ARABlAHQAZQBjAHQAUwBjAHIAaQBwAHQATwB1AHQAcAB1AHQAIAA9ACAAIgBSAEUARABBAEMAVABFAEQAIgAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABTAGUAdAAtAEkAdABlAG0AUAByAG8AcABlAHIAdAB5ACAALQBQAGEAdABoACAAKABKAG8AaQBuAC0AUABhAHQAaAAgACQAcwBjAHIAaQBwAHQALgBQAFMAUABhAHQAaAAgAC0AQwBoAGkAbABkAFAAYQB0AGgAIAAiAFIAZQBzAHUAbAB0ACIAKQAgAC0ATgBhAG0AZQAgACIAUgBlAHMAdQBsAHQAIgAgAC0AVgBhAGwAdQBlACAAKAAkAGoAcwBvAG4AIAB8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuACAALQBEAGUAcAB0AGgAIAAxADAAIAAtAEMAbwBtAHAAcgBlAHMAcwApACAALQBGAG8AcgBjAGUAIAAtAEMAbwBuAGYAaQByAG0AOgAkAEYAYQBsAHMAZQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABXAHIAaQB0AGUALQBDAHUAcwB0AG8AbQBFAHYAZQBuAHQATABvAGcAIAAiAHIAZQBkAGEAYwB0AGUAZAAgAGEAbABsACAAbABvAGMAYQBsACAAZABhAHQAYQAiAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQAKACAAIAAgACAAIAAgACAAIAB9AAoAIAAgACAAIAB9AGMAYQB0AGMAaAB7ACQATgB1AGwAbAB9AAoAfQA=" #base64 UTF16-LE encoded command https://www.base64encode.org/
            $null = Register-ScheduledTask -TaskName "leanLAPS_WL" -Trigger $triggers -User "SYSTEM" -Action $Action -Force
        }
        $JsonString = [PSCustomObject]@{
            Username       = $localAdminName
            SecurePassword = $pwd
            Date           = Get-Date
        } | ConvertTo-Json -Compress
        Write-Host $JsonString

        #Write-Output "LeanLAPS current password: $pwd for $($localAdminName), last changed on $(Get-Date)"
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
        Write-Output "Something went wrong while provisioning $localAdminName $($_)"
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
        $null = Add-LocalGroupMember -Group $administratorsGroupName -Member $localAdminName -Confirm:$False -ErrorAction Stop
        Write-CustomEventLog "Added $localAdminName to the local administrators group"
    }

    #Enable leanLAPS account if it is disabled
    if ($autoEnableLocalAdmin) {
        if (!(Get-LocalUser -SID $localAdmin.SID.Value).Enabled) {
            $null = Enable-LocalUser -SID $localAdmin.SID.Value -Confirm:$false
            Write-CustomEventLog "Enabled $($localAdminName) because it was disabled and `$autoEnableLocalAdmin is set to `$True"
        }
    }

    # Disable built in admin account if specified
    foreach ($administrator in $administrators) {
        if ($administrator.EndsWith("-500")) {
            if ($disableBuiltinAdminAccount) {
                if ((Get-LocalUser -SID $administrator).Enabled) {
                    $null = Disable-LocalUser -SID $administrator -Confirm:$false
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
                $null = Remove-LocalGroupMember -Group $administratorsGroupName -Member $administrator -Confirm:$False
                Write-CustomEventLog "Removed $administrator from Local Administrators"
            }
            else {
                Write-CustomEventLog "$($administrator) allowListed and not removed"
            }
        }
    }
    else {
        Write-CustomEventLog "removeOtherLocalAdmins set to False, will not remove any administrator permissions"
    }
}
catch {
    Write-CustomEventLog "Something went wrong while processing the local administrators group $($_)"
    Write-Output "Something went wrong while processing the local administrators group $($_)"
    Exit 0
}

if (!$pwdSet) {
    try {
        Write-CustomEventLog "Setting password for $localAdminName ..."
        $newPwd = Get-NewPassword $minimumPasswordLength
        $newPwdSecStr = ConvertTo-SecureString $newPwd -AsPlainText -Force
        $pwdSet = $true

        $null = $localAdmin | Set-LocalUser -Password $newPwdSecStr -Confirm:$false -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $true -ErrorAction SilentlyContinue
        # Temporary: If Set-LocalUser fails, set password using ADSI, this should also ensure that Set-LocalUser works next time.
        $LocalDirectory = [ADSI]::new(('WinNT://{0}' -f $env:COMPUTERNAME))
        $LocalDirectory.'Children'.Find($LocalAdminName).Invoke('SetPassword', $NewPwd)

        Write-CustomEventLog "Password for $localAdminName set to a new value, see MDE"
    }
    catch {
        Write-CustomEventLog "Failed to set new password for $localAdminName"
        Write-Host "Failed to set password for $localAdminName because of $($_)"
        Exit 0
    }
}

Write-Host "LeanLAPS ran successfully for $($localAdminName) on $(Get-Date)"
$null = Set-Content -Path $markerFile -Value (ConvertFrom-SecureString $newPwdSecStr) -Force -Confirm:$false
exit 1