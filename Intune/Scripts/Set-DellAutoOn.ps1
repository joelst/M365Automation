#
#  This will install Dell Command | Configure using winget and then set the auto on settings.
#
Function Get-WingetCmd {

    #Get WinGet Path (if admin context)
    # Includes Workaround for ARM64 (removed X64 and replaces it with a wildcard)
    $ResolveWingetPath = Resolve-Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe" | Sort-Object { [version]($_.Path -replace '^[^\d]+_((\d+\.)*\d+)_.*', '$1') }

    if ($ResolveWingetPath) {
        #If multiple version, pick last one
        $WingetPath = $ResolveWingetPath[-1].Path
    }

    #Get Winget Location in User context
    $WingetCmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($WingetCmd) {
        $Script:Winget = $WingetCmd.Source
    }
    #Get Winget Location in System context
    elseif (Test-Path "$WingetPath\winget.exe") {
        $Script:Winget = "$WingetPath\winget.exe"
    }
    else {
        
        return $false
    }

    #Run winget to list apps and accept source agrements (necessary on first run)
    & $Script:Winget list --accept-source-agreements -s winget | Out-Null

    return $true

}

if ((Test-Path -Path "C:\program files (x86)\Dell\Command Configure\X86_64\cctk.exe") -eq $false) {

    try {

        Write-Output " Testing to see if Winget is available"
        if (Get-WingetCmd) {
            Write-Output " Checking to see if Dell Command Configure is installed."
            $appInfo = & $Script:Winget uninstall --id Dell.CommandConfigure --silent
            if ($appInfo -like "*Dell.CommandConfigure*") {

                $version = $appInfo.Split("Dell.CommandConfigure")[5].Trim().Split(" ")[0]
                Write-Output " Dell Command Configure Version $Version installed..."
                if ($Version -notlike "4.10*") {
                    Write-Output " Uninstalling Dell Command Configure $version"
                    & $Script:Winget uninstall --id Dell.CommandConfigure --silent
                    Start-Sleep 15
    
                }

            }
            Write-Output " Installing latest Dell Command Configure"
            & $Script:Winget install --id Dell.CommandConfigure --silent --accept-package-agreements --accept-source-agreements
            Start-Sleep 30
            Remove-Item -Path "C:\Users\Public\Desktop\Dell Command Configure Wizard.lnk" -Force -ErrorAction SilentlyContinue
        }    
    }
    catch {
        Write-Output " Could not use winget."
    }
}

Remove-Item -Path "C:\Users\Public\Desktop\Dell Command Configure Wizard.lnk" -Force -ErrorAction SilentlyContinue
Write-Output "$(Get-Date) Configuring auto start settings for computer."
Set-Location 'C:\program files (x86)\Dell\Command Configure\X86_64\'
& .\cctk.exe --AutoOn=everyday --AutoOnHr=19 --AutoOnMn=35 --AcPwrRcvry=On

exit 0
