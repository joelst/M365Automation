<#

New-ProactiveMicrosoftEdgeUpdate.ps1

Proactive Remediation for Edge.

Adapted from https://github.com/richeaston/Intune-Proactive-Remediation/tree/main/Chrome-Forced-Update

This script should be run as the user if Edge is installed per user.

#>

$ProcessName = "msedge"

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

function Get-EdgeVersion {
        #check MS EDGE version installed    
        $EdgeVersionInfo = (Get-AppxPackage -Name "Microsoft.MicrosoftEdge.Stable" -ErrorAction SilentlyContinue).Version 
        $edgeVer = Get-ItemPropertyValue -Path 'HKCU:\\SOFTWARE\Microsoft\Edge\BLBeacon' -Name version -ErrorAction SilentlyContinue
        
        if ("" -eq $edgeVer) {
            # If we aren't running as an admin lets take the latest package version.
            $edgeVer = $EdgeVersionInfo
        }
        return $edgeVer
    
}


$mode = $MyInvocation.MyCommand.Name.Split(".")[0]

if ($mode -eq "detect") {

    try { 
        
        $edgeRegistryVer = Get-EdgeVersion

        Write-Output "Installed Edge version: $edgeRegistryVer" 

        #Get latest version of MSEDGE
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $j = Invoke-WebRequest 'https://edgeupdates.microsoft.com/api/products?view=enterprise' | ConvertFrom-Json

        foreach ($ver in $j) {
            #$channel = $ver.Product 
            if ($ver.Product -eq 'Stable' ) {
                foreach ($v in $(($ver.Releases).ProductVersion[0])) {
                    if ($v -match $edgeRegistryVer ) {
                        #version installed is latest
                        Write-Output "Latest: $v == Installed: $edgeRegistryVer, no update required. $(Get-Date)"
                        Exit 0
                    }
                    else {
                        #version installed is not latest
                        Write-Output "Latest: $v > Installed: $edgeRegistryVer, remediation required $(Get-Date)" 
                        Exit 1
                    }
                }
            }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errmsg -eq "Cannot bind argument to parameter 'Path' because it is null.") {
            Write-Output "Edge version not found - $(Get-Date)"
            Exit 0
        }
        else {
            Write-Output $errMsg
            Exit 1
        }
    }
}
else {
 
    Write-Output " Running Edge update $(Get-Date)"

    if (Test-Path -Path "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" ) {

        if (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue) {
            Write-Output " Edge running, updating and restarting"
            Start-ScheduledTask MicrosoftEdgeUpdateTaskMachineCore -AsJob
            Start-ScheduledTask MicrosoftEdgeUpdateTaskMachineUA -AsJob
            & "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c
            & "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler
            Start-Sleep 15
            Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
            Start-Sleep 5
            Start-Process $ProcessName

        }
        else {
            Write-Output " Edge not running, updating"
            & "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c
            & "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler
        }
    }
    Exit 0

}