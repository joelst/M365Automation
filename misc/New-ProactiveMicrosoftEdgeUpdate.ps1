<#

New-GoogleChromeUpdate.ps1

Proactive Remediation for Google Chrome.

Adapted from https://github.com/richeaston/Intune-Proactive-Remediation/tree/main/Chrome-Forced-Update



#>

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
        clear
        #check MSEDGE version installed    
        #$EdgeVersionInfo = (Get-AppxPackage -Name "Microsoft.MicrosoftEdge.Stable").Version
        $edgeregistryver = Get-ItemPropertyValue -Path 'HKCU:\\SOFTWARE\Microsoft\Edge\BLBeacon' -Name version
        Write-Output "Installed MSEDGE Version: $edgeregistryver" 

        #Get latest version of MSEDGE
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $j = Invoke-WebRequest 'https://edgeupdates.microsoft.com/api/products?view=enterprise' | ConvertFrom-Json

        foreach ($ver in $j) {
            #$channel = $ver.Product 
            if ($ver.Product -eq 'Stable' ) {
                foreach ($v in $(($ver.Releases).ProductVersion[0])) {
                    if ($v -match $edgeregistryver ) {
                        #version installed is latest
                        Write-Output "Stable Version: $v,  MSEDGE Version $edgeregistryver is the latest stable release"
                        Exit 0
                    }
                    else {
                        #version installed is not latest
                        Write-Output "Stable Version:$v, Installed Version $edgeregistryver, Not safe, trigger alert" 
                        Exit 1
                    }
                }
            }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errmsg -eq "Cannot bind argument to parameter 'Path' because it is null.") {
            Write-Output "MSEDGE does not appear to be installed"
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

    if (Test-Path -Path "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" ) {

        Get-Process -Name "msedge" | Stop-Process

        & "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler
    
    }
    Exit 0

}