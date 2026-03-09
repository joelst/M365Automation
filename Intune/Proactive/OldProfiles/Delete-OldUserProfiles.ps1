<#
Very well written script originally from Action1.com to clean up old user profiles
Adjusted for style, preferences, and allow it to be run outside of Action1.

#>
[CmdletBinding()]
    param (
    # Minimum number of days for a profile to be considered inactive
    [int]$InactiveDays = 30,
    # Set to true to remove profiles that do not have a last sign in date
    [bool]$RemoveStaleWithoutSignInDate = $false,
    # Array of Sids to exclude from removal
    $ExcludedSids = @()
    )

function Set-ScriptLog {
    try {
        $logDirectorypath = (Get-Item -Path $env:TEMP -ErrorAction Stop).FullName
        $logfilename = '\logs\RemoveInactiveUsrProfiles.txt'
        $script:logpath = Join-Path -Path $logDirectorypath -ChildPath $logfilename -ErrorAction Stop
        if (Test-Path -Path $logpath -PathType Leaf) {
            $logfile = Get-Item -Path $logpath -ErrorAction Stop
            $logsize = $logfile.Length
            if ($logsize -ge 5242880) {
                Remove-Item -Path $logpath -Force -ErrorAction Stop | Out-Null
                Out-File -FilePath $logpath -Encoding utf8 -ErrorAction Stop
                Write-Log -LogLevel INFO -Message 'The log file exceeded the 5 MB limit and has been deleted.' -Output Log
            }
        }
        else {
            New-Item -Path $logpath -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Log -LogLevel ERROR -Message "The Set-ScriptLog function has been failed to run, caught the exception, type: $($_.Exception.GetType().FullName), message: $($_.Exception.Message.Trim()), line: $($_.InvocationInfo.ScriptLineNumber)." -Output All
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet("INFO", "ERROR", "DBG")]
        [string]$LogLevel,
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter(Mandatory)]
        [ValidateSet("History", "Log", "All")]
        [string]$Output
    )
    try {
        switch ($Output) {
            'History' { $Host.UI.WriteLine($Message) }
            'Log' {
                if (-not([string]::IsNullOrEmpty($logpath))) {
                    $timestamp = ([datetime]::Now).ToString('yyyyMMdd HH:mm:sszzz')
                    $logMessage = $timestamp + ' - ' + $LogLevel + ' - ' + $Message
                    Add-Content -Path $logpath -Value $logMessage -Encoding UTF8 -ErrorAction Stop
                }
            }
            'All' {
                $Host.UI.WriteLine($Message)
                if (-not([string]::IsNullOrEmpty($logpath))) {
                    $timestamp = ([datetime]::Now).ToString('yyyyMMdd HH:mm:sszzz')
                    $logMessage = $timestamp + ' - ' + $LogLevel + ' - ' + $Message
                    Add-Content -Path $logpath -Value $logMessage -Encoding UTF8 -ErrorAction Stop
                }
            }
        }
    }
    catch {
        $Host.UI.WriteLine("The Write-Log function has been failed to run, caught the exception, type: $($_.Exception.GetType().FullName), message: $($_.Exception.Message.Trim()), line: $($_.InvocationInfo.ScriptLineNumber).")
    }
}

function Test-OSCompat {
    try {
        $osVersion = [System.Environment]::OSVersion.Version
        if (($osVersion.Major -lt 10) -or (($osVersion.Major -eq 10) -and ($osVersion.Build -lt 17763))) {
            Write-Log -LogLevel INFO -Message "The endpoint operating system version is $($osVersion -join '.'), the minimum supported operating system version is 10.0.17763." -Output All
            return $false
        }
        return $true
    }
    catch {
        return $false
    }
}

function Test-PSCompat {
    $psv = $PSVersionTable.PSVersion
    if (($psv.Major -lt 5) -or (($psv.Major -eq 5) -and ($psv.Minor -lt 1))) {
        Write-Log -LogLevel INFO -Message "The current version of PowerShell is $($psv.Major).$($psv.Minor), the minimum supported version of PowerShell is 5.1 and above." -Output All
        return $false
    }
    return $true
}

function Test-SID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Value
    )
    try {
        $object = New-Object System.Security.Principal.SecurityIdentifier($Value)
        $isAccountSid = $object.IsAccountSid()
        Write-Log -LogLevel INFO -Message "The SID $Value is valid account SID." -Output Log
        return $isAccountSid
    }
    catch {
        Write-Log -LogLevel ERROR -Message "The SID $Value cannot be checked for the valid account SID." -Output Log
        return $false
    }
}

function Get-SID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Username
    )
    try {
        $sid = (New-Object Security.Principal.NTAccount($Username)).Translate([Security.Principal.SecurityIdentifier]).Value
        Write-Log -LogLevel INFO -Message "Successfully translated the netbios username $Username to SID $sid." -Output Log
        return $sid
    }
    catch {
        Write-Log -LogLevel ERROR -Message "Unable to translate the netbios username $Username to SID." -Output Log
        return $false
    }
}

function Get-Username {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SID
    )
    try {
        $netbiosUsername = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount]).Value
        Write-Log -LogLevel INFO -Message "Successfully translated the SID $SID to the netbios username $netbiosUsername." -Output Log
        return $netbiosUsername
    }
    catch {
        Write-Log -LogLevel ERROR -Message "Unable to translate the SID $SID to the netbios username." -Output Log
        return $false
    }
}

function Remove-ProfileNative {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$SID,
        [Parameter(Mandatory)]
        [string]$ProfilePath
    )
    $memberDefinition = @'
[DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool DeleteProfile(string sidString, string profilePath, string computerName);
'@

    if (-not ([System.Management.Automation.PSTypeName]'Win32Functions.NativeDeleteProfile').Type) {
        Add-Type -MemberDefinition $memberDefinition -Name 'NativeRemoveProfile' -Namespace 'Win32Functions'
    }

    $returnValue = [Win32Functions.NativeRemoveProfile]::DeleteProfile($SID, $ProfilePath, [NullString]::Value)
    Write-Log -LogLevel DBG -Message "The Remove-ProfileNative function has returned $returnValue." -Output Log
    return $returnValue
}

function Move-ItemDelayed {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Destination
    )

    $flag = 0x00000004

    $memberDefinition = @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@

    if (-not ([System.Management.Automation.PSTypeName]'Win32Functions.MoveItemDelayed').Type) {
        Add-Type -MemberDefinition $memberDefinition -Name 'MoveItemDelayed' -Namespace 'Win32Functions'
    }

    $returnValue = [Win32Functions.MoveItemDelayed]::MoveFileEx($Path, $Destination, $flag)
    Write-Log -LogLevel DBG -Message "The Move-ItemDelayed function has returned $returnValue." -Output Log
    return $returnValue
}

function Set-ServiceStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet("Start", "Stop", "Status")]
        [string]$Action,
        [Parameter()]
        [PSCustomObject]$ServiceList
    )

    $runningStatus = 'Running'
    $stoppedStatus = 'Stopped'
    $waitTimespan = New-TimeSpan -Seconds 180 -ErrorAction SilentlyContinue
    switch ($Action) {
        'Status' {
            $stopServices = @('PcaSvc', 'DiagTrack')
            $serviceObj = Get-Service -Name $stopServices -ErrorAction SilentlyContinue | Select-Object Name, Status -ErrorAction SilentlyContinue
            if ($null -ne $serviceObj) {
                $serviceString = ($serviceObj | Out-String -ErrorAction SilentlyContinue).Trim()
                Write-Log -LogLevel INFO -Message "The current state of services: `r`n $serviceString" -Output Log
                return $serviceObj
            }
        }
        'Start' {
            foreach ($service in $ServiceList) {
                $serviceName = $service.Name
                $serviceStatus = $service.Status
                if ($serviceStatus -eq $runningStatus) {
                    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($null -ne $service) {
                        $service.WaitForStatus($runningStatus, $waitTimespan)
                        $serviceString = ($service | Select-Object Name, Status -ErrorAction SilentlyContinue | Out-String -ErrorAction SilentlyContinue).Trim()
                        Write-Log -LogLevel INFO -Message "The current state of service: `r`n $serviceString" -Output Log
                    }
                }
            }
        }
        'Stop' {
            foreach ($service in $ServiceList) {
                $serviceName = $service.Name
                $serviceStatus = $service.Status
                if ($serviceStatus -eq $runningStatus) {
                    Write-Log -LogLevel INFO -Message "Stopping the service." -Output Log
                    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($null -ne $service) {
                        $service.WaitForStatus($stoppedStatus, $waitTimespan)
                        $serviceString = ($service | Select-Object Name, Status -ErrorAction SilentlyContinue | Out-String -ErrorAction SilentlyContinue).Trim()
                        Write-Log -LogLevel INFO -Message "The current state of service: `r`n $serviceString" -Output Log
                    }
                }
            }
        }
    }
}

function Get-RegistryValue {
    param (
        [Parameter(Mandatory)]
        [string]$RegistryPath,
        [Parameter(Mandatory)]
        [string]$RegistryValue
    )
    try {
        Get-ItemPropertyValue -Path $RegistryPath -Name $RegistryValue -ErrorAction Stop
    }
    catch {}
}

function Main {
    begin {
        Set-ScriptLog
        Write-Log -LogLevel INFO -Message 'Logging started.' -Output Log
    }

    process {

        $limit = $InactiveDays
        if ($limit -isnot [int]) {
            Write-Log -LogLevel INFO -Message "The specified value $limit is not an integer, please specify an integer value of the 'Inactivity Period' parameter." -Output All
            return
        }
        if ($limit -le 6) {
            Write-Log -LogLevel INFO -Message "The specified value $limit is less than the minimum allowed 7 days, please specify a higher value of the 'Inactivity Period' parameter." -Output All
            return
        }
        Write-Log -LogLevel INFO -Message "The inactivity period is $limit." -Output Log

        Write-Log -LogLevel INFO -Message "Remove profile without sign in date is $RemoveStaleWithoutSignInDate" -Output Log

        $excludeSidArray = @()
        if (-not([string]::IsNullOrEmpty($ExcludedSids))) {
            Write-Log -LogLevel INFO -Message "The following profiles have been specified to be excluded: $ExcludedSids." -Output Log
            Write-Log -LogLevel INFO -Message "Resolving SID of excluded profiles." -Output Log
            $excludeUserProfileArray = $ExcludedSids -split ','
            foreach ($excludeUserProfile in $excludeUserProfileArray) {
                $value = $excludeUserProfile.Trim(' ', "'", '"')
                if ((Test-SID -Value $value) -ne $false) {
                    $excludeSidArray += $value
                }
                else {
                    $sid = Get-SID -Username $value
                    if ($sid -ne $false) {
                        $excludeSidArray += $sid
                    }
                }
            }
        }
        else {
            Write-Log -LogLevel INFO -Message "There no exclusions have been specified." -Output Log
        }

        $excludeSidArray = $excludeSidArray | Select-Object -Unique
        Write-Log -LogLevel INFO -Message "The SID list of excluded profiles after translation: $($excludeSidArray -join ', ')." -Output Log
        Write-Log -LogLevel INFO -Message "The search for the inactive user profiles older than $limit days has been started." -Output All
        Write-Log -LogLevel INFO -Message "The following user profiles have been excluded: $ExcludedSids." -Output History
        Write-Log -LogLevel INFO -Message "Remove stale profiles without sign in date: $RemoveStaleWithoutSignInDate." -Output History

        try {
            $userProfiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop
            $excludeService = $userProfiles | Where-Object { $_.Special -eq $true } -ErrorAction Stop
            $excludeServiceSid = $excludeService.SID
            Write-Log -LogLevel INFO -Message "The SID list of excluded system profiles: $($excludeServiceSid -join ', ')." -Output Log
            $excludeSidArray = $excludeServiceSid + $excludeSidArray

            $excludeNetbiosUsernameArray = @()
            foreach ($excludeSid in $excludeSidArray) {
                $netbiosUsername = Get-Username -SID $excludeSid
                if ($netbiosUsername -eq $false) {
                    $excludeNetbiosUsernameArray += $excludeSid
                    continue
                }
                $excludeNetbiosUsernameArray += $netbiosUsername
            }

            $excludeNetbiosUsernameArray = $excludeNetbiosUsernameArray | Select-Object -Unique
            $excludeNetbiosUsernameString = $excludeNetbiosUsernameArray -join ', '
            Write-Log -LogLevel INFO -Message "The following user profiles have been excluded: $excludeNetbiosUsernameString." -Output Log

            $profileRegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
            $profileList = Get-ChildItem -Path $profileRegistryPath -ErrorAction Stop
            $profileListExclusions = $profileList | Where-Object { $_.PSChildName -notin $excludesidarray } -ErrorAction Stop
        }
        catch {
            Write-Log -LogLevel ERROR -Message "The Main function has been failed to run, caught the exception, type: $($_.Exception.GetType().FullName), message: $($_.Exception.Message.Trim()), line: $($_.InvocationInfo.ScriptLineNumber)." -Output All
        }

        Write-Log -LogLevel INFO -Message "Collecting the user profiles from the registry." -Output Log

        $profilesToUnloadd = @()
        foreach ($profile in $profileListExclusions) {
            $profileObject = New-Object -TypeName psobject
            $sid = $profile.PSChildName
            $netbiosUsername = Get-Username -SID $sid
            if ($netbiosUsername -eq $false) {
                $netbiosUsername = $sid
            }
            $lplth = $null
            $lpltl = $null
            $lputh = $null
            $lputl = $null
            $loadTime = $null
            $unloadTime = $null

            $profilePath = Get-RegistryValue -RegistryPath $profile.PSPath -RegistryValue ProfileImagePath

            $lplth = Get-RegistryValue -RegistryPath $profile.PSPath -RegistryValue LocalProfileLoadTimeHigh
            if ($null -ne $lplth -and $lplth -ne 0) {
                $lplth = '{0:X8}' -f $lplth
            }
            else {
                $lplth = $false
            }
            $lpltl = Get-RegistryValue -RegistryPath $profile.PSPath -RegistryValue LocalProfileLoadTimeLow
            if ($null -ne $lpltl -and $lpltl -ne 0) {
                $lpltl = '{0:X8}' -f $lpltl
            }
            else {
                $lpltl = $false
            }
            $lputh = Get-RegistryValue -RegistryPath $profile.PSPath -RegistryValue LocalProfileUnloadTimeHigh
            if ($null -ne $lputh -and $lputh -ne 0) {
                $lputh = '{0:X8}' -f $lputh
            }
            else {
                $lputh = $false
            }
            $lputl = Get-RegistryValue -RegistryPath $profile.PSPath -RegistryValue LocalProfileUnloadTimeLow
            if ($null -ne $lputl -and $lputl -ne 0) {
                $lputl = '{0:X8}' -f $lputl
            }
            else {
                $lputl = $false
            }

            if ($lplth -ne $false -and $lpltl -ne $false) {
                $loadTime = [datetime]::FromFileTime([string]::Join('', '0x', $lplth, $lpltl))
            }
            else {
                $loadTime = $null
            }
            if ($lputh -ne $false -and $lputl -ne $false) {
                $unloadTime = [datetime]::FromFileTime([string]::Join('', '0x', $lputh, $lputl))
            }
            else {
                $unloadTime = $null
            }

            $profileObject | Add-Member NoteProperty Username -Value $netbiosUsername
            $profileObject | Add-Member NoteProperty SID -Value $sid
            $profileObject | Add-Member NoteProperty ProfilePath -Value $profilePath
            $profileObject | Add-Member NoteProperty LoadTime -Value $loadTime
            $profileObject | Add-Member NoteProperty UnloadTime -Value $unloadTime

            $profilesToUnloadd += $profileObject
        }

        if ($profilesToUnloadd.Count -eq 0) {
            Write-Log -LogLevel INFO -Message "No user profiles have been found." -Output All
            return
        }

        $profilesToRemove = @()
        foreach ($profile in $profilesToUnloadd) {
            try {
                $netbiosUsername = $profile.Username
                $sid = $profile.SID
                $profilePath = $profile.ProfilePath
                $loadTime = $profile.LoadTime
                $unloadTime = $profile.UnloadTime
                $currentDate = [datetime]::Now

                if([string]::IsNullOrEmpty($profilePath)) {
                    Write-Log -LogLevel INFO -Message "The Profile Path is null or empty, skipping it, the SID - $sid, the netbios username - $netbiosUsername, ." -Output Log
                    continue
                }

                $currentDateFormat = $currentDate.ToString('MM/dd/yyyy HH:mm:ss')
                Write-Log -LogLevel INFO -Message "Analyzing the load and unload time." -Output Log
                Write-Log -LogLevel INFO -Message "The SID - $sid, the netbios username - $netbiosUsername, the load time - $loadTime, the unload time - $unloadTime, the current date - $currentDateFormat." -Output Log

                if ($null -eq $unloadTime -and $null -eq $loadTime) {
                    if ($RemoveStaleWithoutSignInDate) {
                        $profilesToRemove += $profile
                        Write-Log -LogLevel INFO -Message "The SID - $sid, the netbios username - $netbiosUsername fits the search criteria." -Output Log
                        continue
                    }
                    Write-Log -LogLevel INFO -Message "No profile sign in and sign out date have been found for the account $netbiosUsername, $sid." -Output All
                    continue
                }
                if ($null -eq $loadTime) {
                    Write-Log -LogLevel INFO -Message "No profile sign in date has been found for the account $netbiosUsername, $sid." -Output All
                    continue
                }
                if ($null -eq $unloadTime) {
                    Write-Log -LogLevel INFO -Message "No profile sign out date has been found for the account $netbiosUsername, $sid." -Output All
                    continue
                }

                $unloadDelta = New-TimeSpan -Start $unloadTime -End $currentDate -ErrorAction Stop
                if ($unloadTime -gt $loadTime -and $unloadDelta.Days -ge $limit) {
                    $profilesToRemove += $profile
                    Write-Log -LogLevel INFO -Message "The SID - $sid, the netbios username - $netbiosUsername fits the search criteria." -Output Log
                }
                else {
                    Write-Log -LogLevel INFO -Message "The SID - $sid, the netbios username - $netbiosUsername does not fit the search criteria." -Output Log
                }
            }
            catch {
                Write-Log -LogLevel ERROR -Message "The Main function has failed to run, caught the exception, type: $($_.Exception.GetType().FullName), message: $($_.Exception.Message.Trim()), line: $($_.InvocationInfo.ScriptLineNumber)." -Output All
            }
        }

        if ($profilesToRemove.Count -eq 0) {
            Write-Log -LogLevel INFO -Message "No user profile matching the search criteria has been found." -Output All
            return
        }

        $serviceList = Set-ServiceStatus -Action Status
        Set-ServiceStatus -Action Stop -ServiceList $serviceList

        foreach ($profile in $profilesToRemove) {
            try {
                $netbiosUsername = $profile.Username
                $sid = $profile.SID
                $profilePath = $profile.ProfilePath

                $profileisloaded = Test-Path -Path "Registry::HKU\$sid" -ErrorAction Stop
                if ($profileisloaded -eq $true) {
                    Start-Process -FilePath REG -ArgumentList "UNLOAD HKU\$sid" -Wait -ErrorAction SilentlyContinue
                }

                $returnValue = Remove-ProfileNative -SID $sid -ProfilePath $profilePath
                if ($returnValue -eq $true) {
                    Write-Log -LogLevel INFO -Message "The $netbiosUsername, $sid profile and its directory have been successfully removed." -Output All
                }
                else {
                    $userprofile = $userProfiles | Where-Object { $_.SID -eq $sid } -ErrorAction Stop
                    if ($null -ne $userprofile) {
                        $userprofile | Remove-CimInstance -ErrorAction Stop
                        Write-Log -LogLevel INFO -Message "The $netbiosUsername, $sid profile and its directory have been successfully removed." -Output All
                    }
                    else {
                        Write-Log -LogLevel INFO -Message "The user profile record is missing from the WMI repository." -Output All
                    }
                }
            }
            catch [Microsoft.Management.Infrastructure.CimException] {
                Write-Log -LogLevel ERROR -Message "The Main function has failed to run, caught the exception, type: $($_.Exception.GetType().FullName), message: $($_.Exception.Message.Trim()), line: $($_.InvocationInfo.ScriptLineNumber)." -Output Log

                $sourcepath = $profilePath
                $destinationpath = $sourcepath + ([datetime]::Now).ToString('.yyyy_MM_dd_HH_mm_ss') + '.Action1_bak'
                $mid = Move-ItemDelayed -Path $sourcepath -Destination $destinationpath
                if ($mid -eq $true) {
                    Write-Log -LogLevel INFO -Message "Unable to delete the user profile directory because it is being used by another process." -Output All
                    Write-Log -LogLevel INFO -Message "The $netbiosUsername, $sid profile directory will be renamed to $destinationpath after restart of the endpoint." -Output All
                    $userprofile = $profileListExclusions | Where-Object { $_.PSChildName -eq $sid } -ErrorAction Stop
                    Remove-Item -Path $userProfile.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Log -LogLevel INFO -Message "The $netbiosUsername, $sid profile has been successfully removed." -Output All
                }
                else {
                    Write-Log -LogLevel INFO -Message "Unable to create pending rename operation of the $netbiosUsername profile directory." -Output All
                }
            }
            catch {
                Write-Log -LogLevel ERROR -Message "The Main function has failed to run, caught the exception, type: $($_.Exception.GetType().FullName), message: $($_.Exception.Message.Trim()), line: $($_.InvocationInfo.ScriptLineNumber)." -Output All
            }
        }
    }
    end {
        Set-ServiceStatus -Action Start -ServiceList $serviceList
        Write-Log -LogLevel INFO -Message "The search for the inactive user profiles has been completed." -Output All
        Write-Log -LogLevel INFO -Message 'Logging finished.' -Output Log
    }
}

if ($(Test-OSCompat) -and $(Test-PSCompat)) {
    Main
}
