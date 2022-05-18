<#

New-ProactiveGoogleChromeUpdate.ps1

Proactive Remediation for Google Chrome.

Adapted from https://github.com/richeaston/Intune-Proactive-Remediation/tree/main/Chrome-Forced-Update

This script should be run as the user if Chrome is installed per user.

#>

$ProcessName = "chrome"

function Show-Window {
    param(
        [Parameter(Mandatory)]
        [string] $ProcessName
    )
  
    # As a courtesy, strip '.exe' from the name, if present.
    $ProcessName = $ProcessName -replace '\.exe$'
  
    # Get the ID of the first instance of a process with the given name
    # that has a non-empty window title.
    # NOTE: If multiple instances have visible windows, it is undefined
    #       which one is returned.
    $procId = (Get-Process -ErrorAction Ignore $ProcessName).Where({ $_.MainWindowTitle }, 'First').Id
  
    
    # Note: 
    #  * This can still fail, because the window could have been closed since
    #    the title was obtained.
    #  * If the target window is currently minimized, it gets the *focus*, but is
    #    *not restored*.
    #  * The return value is $true only if the window still existed and was *not
    #    minimized*; this means that returning $false can mean EITHER that the
    #    window doesn't exist OR that it just happened to be minimized.
    $null = (New-Object -ComObject WScript.Shell).AppActivate($procId)
  
}

$mode = $MyInvocation.MyCommand.Name.Split(".")[0]

if ($mode -eq "detect") {

    try { 

        #check Chrome version installed    
        #$GCVersionInfo = (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction Ignore).'(Default)').VersionInfo
        #$GCVersion = $GCVersionInfo.ProductVersion
        $GCVersion = Get-ItemPropertyValue -Path 'HKCU:\Software\Google\Chrome\BLBeacon' -Name version
        
        Write-Output "Installed Chrome Version: $GCVersion" 

        #Get latest version of Chrome
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $j = Invoke-WebRequest 'https://omahaproxy.appspot.com/all.json' | ConvertFrom-Json

        foreach ($ver in $j) {
            if ($ver.os -like '*win') {
                $GCVer = $ver.versions.Current_Version
                foreach ($GCV in $GCVer[4]) {
                    if ($GCV -eq $GCVersion) {
                        # Installed version is latest
                        Write-Output "Latest: $($Ver.os) == Installed: $GCVersion, no update required $(Get-Date)"
                        Exit 0
                    }
                    else {
                        # Installed version is not latest
                        Write-Output "Latest: $($Ver.os) > Installed: $GCV, remediation required $(Get-Date)" 
                        Exit 1
                    }
                }
            }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errmsg -eq "Cannot bind argument to parameter 'Path' because it is null.") {
            Write-Output "Google Chrome version not found - $(Get-Date)"
            Exit 0
        }
        else {
            Write-Output $errMsg
            Exit 1
        }
    }

}
else {
 
    Write-Output " Running Google Chrome Update $(Get-Date)"

    if (Test-Path -Path "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" ) {
        
        if (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue) {
            Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
            & "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /ua /installsource scheduler
            & "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c
            Start-Process $ProcessName
        }
        else {
            & "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /ua /installsource scheduler
            & "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c
        }
    }

    Exit 0

}