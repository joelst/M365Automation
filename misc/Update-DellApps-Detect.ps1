<#
.SYNOPSIS
Updates  on DELL machines by finding latest version available in Dell Command Update XML, Downloading and installing, then triggers a CM Reboot (typically 90 minute countdown)

Big thanks to the original developer: Gary Blok | @gwblok | recastsoftware.com
https://github.com/gwblok/garytown/blob/master/Intune/

Minor adjustments by:   Joel Stidley https://github.com/joelst/
- Made many options as parameters
- Simplified proxy usage
- fixed issue when release has multiple dates assigned.
- streamlined logging

Usage: Create a proactive remediation script package and include Update-DellApps-Detect.ps1 as the detection script and 
  Update-DellApps-Remediate.ps1 as the remediate script. Assign the package to run on only Dell PCs.

#>
[CmdletBinding()]
param (
    $ScriptVersion = "21.6.14.1",
    $whoami = $env:USERNAME,
    $IntuneFolder = "$env:ProgramData\Intune",
    $LogFilePath = "$IntuneFolder\Logs",
    $LogFile = "$LogFilePath\Dell-Updates.log",
    $scriptName = "Dell DCU Update - From Cloud",
    $ProxyConnection,
    $ProxyConnectionPort = "8080",
    $Compliance = $true,
    $Remediate = $false,
    [bool]$UseProxy = $false,
    $ProxyServer,
    $BitsProxyList
)

$SystemSKUNumber = (Get-CimInstance -ClassName Win32_ComputerSystem).SystemSKUNumber
$Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer
$CabPath = "$env:temp\DellCabDownloads\DellSDPCatalogPC.cab"
$CabPathIndex = "$env:temp\DellCabDownloads\CatalogIndexPC.cab"
$CabPathIndexModel = "$env:temp\DellCabDownloads\CatalogIndexModel.cab"
$DellCabExtractPath = "$env:temp\DellCabDownloads\DellCabExtract"

if ($Remediate -eq $true)
{ $ComponentText = "DCU Apps - Remediation" }
else { $ComponentText = "DCU Apps - Detection" }

if (!(Test-Path -Path $LogFilePath)) { $NewFolder = New-Item -Path $LogFilePath -ItemType Directory -Force }

Function Get-InstalledApplication {
    [CmdletBinding()]
    Param(
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [String[]]$ComputerName = $ENV:COMPUTERNAME,

        [Parameter(Position = 1)]
        [String[]]$Properties,

        [Parameter(Position = 2)]
        [String]$IdentifyingNumber,

        [Parameter(Position = 3)]
        [String]$Name,

        [Parameter(Position = 4)]
        [String]$Publisher
    )
    Begin {
        function IsCpuX86 ([Microsoft.Win32.RegistryKey]$hklmHive) {
            $regPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
            $key = $hklmHive.OpenSubKey($regPath)

            $cpuArch = $key.GetValue('PROCESSOR_ARCHITECTURE')

            if ($cpuArch -eq 'x86') {
                return $true
            }
            else {
                return $false
            }
        }
    }
    Process {
        foreach ($computer in $computerName) {
            $regPath = @(
                'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )

            try {
                $hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine, 
                    $computer
                )
                if (!$hive) {
                    continue
                }
        
                # if CPU is x86 do not query for Wow6432Node
                if ($IsCpuX86) {
                    $regPath = $regPath[0]
                }

                foreach ($path in $regPath) {
                    $key = $hive.OpenSubKey($path)
                    if (!$key) {
                        continue
                    }
                    foreach ($subKey in $key.GetSubKeyNames()) {
                        $subKeyObj = $null
                        if ($PSBoundParameters.ContainsKey('IdentifyingNumber')) {
                            if ($subKey -ne $IdentifyingNumber -and 
                                $subkey.TrimStart('{').TrimEnd('}') -ne $IdentifyingNumber) {
                                continue
                            }
                        }
                        $subKeyObj = $key.OpenSubKey($subKey)
                        if (!$subKeyObj) {
                            continue
                        }
                        $outHash = New-Object -TypeName Collections.Hashtable
                        $appName = [String]::Empty
                        $appName = ($subKeyObj.GetValue('DisplayName'))
                        if ($PSBoundParameters.ContainsKey('Name')) {
                            if ($appName -notlike $name) {
                                continue
                            }
                        }
                        if ($appName) {
                            if ($PSBoundParameters.ContainsKey('Properties')) {
                                if ($Properties -eq '*') {
                                    foreach ($keyName in ($hive.OpenSubKey("$path\$subKey")).GetValueNames()) {
                                        Try {
                                            $value = $subKeyObj.GetValue($keyName)
                                            if ($value) {
                                                $outHash.$keyName = $value
                                            }
                                        }
                                        Catch {
                                            Write-Warning "Subkey: [$subkey]: $($_.Exception.Message)"
                                            continue
                                        }
                                    }
                                }
                                else {
                                    foreach ($prop in $Properties) {
                                        $outHash.$prop = ($hive.OpenSubKey("$path\$subKey")).GetValue($prop)
                                    }
                                }
                            }
                            $outHash.Name = $appName
                            $outHash.IdentifyingNumber = $subKey
                            $outHash.Publisher = $subKeyObj.GetValue('Publisher')
                            if ($PSBoundParameters.ContainsKey('Publisher')) {
                                if ($outHash.Publisher -notlike $Publisher) {
                                    continue
                                }
                            }
                            $outHash.ComputerName = $computer
                            $outHash.Version = $subKeyObj.GetValue('DisplayVersion')
                            $outHash.Path = $subKeyObj.ToString()
                            New-Object -TypeName PSObject -Property $outHash
                        }
                    }
                }
            }
            catch {
                Write-Error $_
            }
        }
    }
    End {}
}

function New-CMTraceLog {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
 
        [Parameter(Mandatory = $false)]
        $ErrorMessage,
 
        [Parameter(Mandatory = $false)]
        $Component = $ComponentText,
 
        [Parameter(Mandatory = $false)]
        [int]$Type,
		
        [Parameter(Mandatory = $true)]
        $LogFile = "$env:ProgramData\Intune\Logs\CMLog.log"
    )

    <#
        Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"
 
    if ($null -ne $ErrorMessage) { $Type = 3 }
    if ($null -eq $Component) { $Component = " " }
    if ($null -eq $Type) { $Type = 1 }
 
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile

    if ($Type -eq 1) {
        Write-Output $Message
    }
    elseif ($Type -eq 2) {
        Write-Warning $Message
    }
    elseif ($Type -eq 3) {
        Write-Error $Message
    }
    else {
        Write-Host $Message
    }
    
}
Function Restart-ByPassComputer {

    #Add Logic for Bitlocker
    #Add Toast Notification
    #Add Shutdown in 2 hours

    #Assuming if Process "Explorer" Exist, that a user is logged on.
    $Session = Get-Process -Name "Explorer" -ErrorAction SilentlyContinue
    CMTraceLog -Message "User Session: $Session" -Type 1 -LogFile $LogFile
    Suspend-BitLocker -MountPoint $env:SystemDrive
    If ($null -ne $Session) {
        New-CMTraceLog -Message "User Session: $Session, Restarting in 60 minutes" -Type 1 -LogFile $LogFile
        Start-Process shutdown.exe -ArgumentList '/r /f /t 3600 /c "System must be restarted to apply updates, please save your work now. Otherwise Computer will reboot in 60 minutes"'
 
    }
    else {
        New-CMTraceLog -Message "No User Session Found, Restarting in 60 seconds" -Type 1 -LogFile $LogFile
        Start-Process shutdown.exe -ArgumentList '/r /f /t 60 /c "Updating System, computer will restart in 60 seconds"'
    }

}  

New-CMTraceLog -Message "---------------------------------" -Type 1 -LogFile $LogFile
New-CMTraceLog -Message "Starting $ScriptName, $ScriptVersion | Remediation Mode $Remediate" -Type 1 -LogFile $LogFile
New-CMTraceLog -Message "Running as $whoami" -Type 1 -LogFile $LogFile

if ($Manufacturer -match "Dell") {

    $InstallApps = Get-InstalledApplication
    $InstalledDCM = $InstallApps | Where-Object { $_.Name -eq 'Dell Command | Monitor' }
    $InstalledDCU = $InstallApps | Where-Object { $_.Name -match 'Dell Command' -and $_.Name -match 'Update' }

    if ($InstalledDCM) { 
        [Version]$DCM_InstalledVersion = $InstalledDCM.Version 
    }
    if ($InstalledDCU) { 
        [Version]$DCU_InstalledVersion = $InstalledDCU.Version 
    }

    # Test if proxy is ok
    if ($UseProxy) {

        if (((Test-NetConnection $ProxyConnection -Port $ProxyConnectionPort -ErrorAction SilentlyContinue).PingSucceeded -eq $true)) {
            Write-Output "Proxy server verified"
            [system.net.webrequest]::DefaultWebProxy = New-Object system.net.webproxy("$ProxyServer")
        }
        else {
            $UseProxy = $false
            $ProxyServer = $null
            $BitsProxyList = $null
            Write-Output "Proxy server not found"
        }
    }

    # Download and parse Dell Command Update XML
    if (!(Test-Path $DellCabExtractPath)) { 
        $newfolder = New-Item -Path $DellCabExtractPath -ItemType Directory -Force 
    }

    Write-Host "Downloading Dell Cab" -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://downloads.dell.com/catalog/CatalogIndexPC.cab" -OutFile $CabPathIndex -UseBasicParsing -Proxy $ProxyServer
    [int32]$n = 1
    
    while (!(Test-Path $CabPathIndex) -and $n -lt '3') {
        Invoke-WebRequest -Uri "https://downloads.dell.com/catalog/CatalogIndexPC.cab" -OutFile $CabPathIndex -UseBasicParsing -Proxy $ProxyServer
        $n++
    }
    if (Test-Path "$DellCabExtractPath\DellSDPCatalogPC.xml") { 
        Remove-Item -Path "$DellCabExtractPath\DellSDPCatalogPC.xml" -Force 
    }
    Start-Sleep -Seconds 1
    if (Test-Path $DellCabExtractPath) { 
        Remove-Item -Path $DellCabExtractPath -Force -Recurse 
    }
    
    $NewFolder = New-Item -Path $DellCabExtractPath -ItemType Directory
    $Expand = expand $CabPathIndex $DellCabExtractPath\CatalogIndexPC.xml

    Write-Host "Loading Dell catalog..." -ForegroundColor Yellow
    [xml]$XMLIndex = Get-Content "$DellCabExtractPath\CatalogIndexPC.xml"

    # Find this computer model info in the file  (Based on System SKU)
    $XMLModel = $XMLIndex.ManifestIndex.GroupManifest | Where-Object { $_.SupportedSystems.Brand.Model.systemID -match $SystemSKUNumber }
    
    if ($XMLModel) {
        New-CMTraceLog -Message "Dell DCU XML downloaded, searching for updates..." -Type 1 -LogFile $LogFile
        Invoke-WebRequest -Uri "http://downloads.dell.com/$($XMLModel.ManifestInformation.path)" -OutFile $CabPathIndexModel -UseBasicParsing -Proxy $ProxyServer
        if (Test-Path $CabPathIndexModel) {
            $Expand = expand $CabPathIndexModel $DellCabExtractPath\CatalogIndexPCModel.xml
            [xml]$XMLIndexCAB = Get-Content "$DellCabExtractPath\CatalogIndexPCModel.xml"
            $DCUAvailable = $XMLIndexCAB.Manifest.SoftwareComponent | Where-Object { $_.ComponentType.value -eq "" }
            $DCUAppsAvailable = $XMLIndexCAB.Manifest.SoftwareComponent | Where-Object { $_.ComponentType.value -eq "APAC" }
            $AppNames = $DCUAppsAvailable.name.display.'#cdata-section' | Select-Object -Unique
            
            # This uses the x86 Windows version, not the UWP app.  You can change this if you like
            $AppDCUVersion = ( [System.Version[]]$Version = ($DCUAppsAvailable | Where-Object { $_.path -match 'command-update' -and $_.SupportedOperatingSystems.OperatingSystem.osArch -match "x64" -and $_.Description.Display.'#cdata-section' -notmatch "UWP" }).vendorVersion) | Sort-Object | Select-Object -Last 1
            $AppDCU = $DCUAppsAvailable | Where-Object { $_.path -match 'command-update' -and $_.SupportedOperatingSystems.OperatingSystem.osArch -match "x64" -and $_.Description.Display.'#cdata-section' -notmatch "UWP" -and $_.vendorVersion -eq $AppDCUVersion }
            $AppDCMVersion = ( [System.Version[]]$Version = ($DCUAppsAvailable | Where-Object { $_.path -match 'Command-Monitor' -and $_.SupportedOperatingSystems.OperatingSystem.osArch -match "x64" } | Select-Object -Property vendorVersion).vendorVersion) | Sort-Object | Select-Object -Last 1
            $AppDCM = $DCUAppsAvailable | Where-Object { $_.path -match 'Command-Monitor' -and $_.SupportedOperatingSystems.OperatingSystem.osArch -match "x64" -and $_.vendorVersion -eq $AppDCMVersion }
            
            $DCUDRIVERSAvailable = $XMLIndexCAB.Manifest.SoftwareComponent | Where-Object { $_.ComponentType.value -eq "DRVR" }
            $DCUFIRMWAREAvailable = $XMLIndexCAB.Manifest.SoftwareComponent | Where-Object { $_.ComponentType.value -eq "FRMW" }

            # Check DCU
            $DellItem = $AppDCU
            Write-Verbose "`$InstalledDCU.Version = $($InstalledDCU.Version)"
            if ("" -ne $InstalledDCU.Version) { 
                $CurrentVersion = $InstalledDCU.Version 
            } 
            else { 
                $CurrentVersion = $null 
            }
            
            $DCUVersion = $DellItem.vendorVersion
            Write-Verbose "`$DellItem.releaseDate: $($DellItem.releaseDate[0])"
            $DCUReleaseDate = $(Get-Date $DellItem.releaseDate[0] -Format 'yyyy-MM-dd')               
            $TargetLink = "http://downloads.dell.com/$($DellItem.path)"
            $TargetFileName = ($DellItem.path).Split("/") | Select-Object -Last 1
            
            if ($DCUVersion -gt $CurrentVersion) {
                if ($CurrentVersion -eq $null) { 
                    [String]$CurrentVersion = "Not installed" 
                }
                if ($Remediate -eq $true) {
                    New-CMTraceLog -Message "Update available: Installed = $CurrentVersion Available = $DCUVersion" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "  Title: $($DellItem.Name.Display.'#cdata-section')" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Severity: $($DellItem.Criticality.Display.'#cdata-section')" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   FileName: $TargetFileName" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Release Date: $DCUReleaseDate" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   KB: $($DellItem.releaseID)" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Link: $TargetLink" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Info: $($DellItem.ImportantInfo.URL)" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Version: $DCUVersion " -Type 1 -LogFile $LogFile

                    # Build info to download and Update CM Package
                    $TargetFilePathName = "$($DellCabExtractPath)\$($TargetFileName)"
                    New-CMTraceLog -Message "   Running Command: Invoke-WebRequest -Uri $TargetLink -OutFile $TargetFilePathName -UseBasicParsing -Proxy $ProxyServer " -Type 1 -LogFile $LogFile
                    Invoke-WebRequest -Uri $TargetLink -OutFile $TargetFilePathName -UseBasicParsing -Proxy $ProxyServer

                    #Confirm Download
                    if (Test-Path $TargetFilePathName) {
                        New-CMTraceLog -Message "   Download completed " -Type 1 -LogFile $LogFile
                        $LogFileName = $TargetFilePathName.replace(".exe", ".log")
                        $Arguments = "/s /l=$LogFileName"
                        Write-Output "Starting update"
                        Write-Output "Log file = $LogFileName"
                        New-CMTraceLog -Message " Running Command: Start-Process $TargetFilePathName $Arguments -Wait -PassThru " -Type 1 -LogFile $LogFile
                        $Process = Start-Process "$TargetFilePathName" $Arguments -Wait -PassThru
                        New-CMTraceLog -Message " Update completed with exitcode: $($Process.ExitCode)" -Type 1 -LogFile $LogFile

                        If ($Process -ne $null -and $Process.ExitCode -eq '2') {
                            $RestartComputer = $true
                        }
                    }
                    else {
                        New-CMTraceLog -Message " Update download failed" -Type 3 -LogFile $LogFile
                        $Compliance = $false
                    }
                }
                else {
                    #Needs Remediation
                    New-CMTraceLog -Message "Update $($DellItem.Name.Display.'#cdata-section'): Installed = $CurrentVersion | Available = $DCUVersion | Remediation Required" -Type 1 -LogFile $LogFile
                    $Compliance = $false
                }
            
            }
            else {
                #Compliant
                New-CMTraceLog -Message " Update $($DellItem.Name.Display.'#cdata-section') is already installed: $CurrentVersion" -Type 1 -LogFile $LogFile
            }

            # Check DCM Now
            $DellItem = $AppDCM
            if ("" -ne $InstalledDCM) { 
                [Version]$CurrentVersion = $InstalledDCM.Version 
            }
            else { $CurrentVersion = $null }

            [Version]$DCUVersion = $DellItem.vendorVersion
            $DCUReleaseDate = $(Get-Date $DellItem.releaseDate -Format 'yyyy-MM-dd')               
            $TargetLink = "http://downloads.dell.com/$($DellItem.path)"
            $TargetFileName = ($DellItem.path).Split("/") | Select-Object -Last 1

            if ($DCUVersion -gt $CurrentVersion) {
                if ($CurrentVersion -eq $null) { [String]$CurrentVersion = "Not Installed" }
                if ($Remediate -eq $true) {
                    New-CMTraceLog -Message "Update available: Installed = $CurrentVersion Available = $DCUVersion" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "  Title: $($DellItem.Name.Display.'#cdata-section')" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Severity: $($DellItem.Criticality.Display.'#cdata-section')" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   FileName: $TargetFileName" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Release Date: $DCUReleaseDate" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   KB: $($DellItem.releaseID)" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Link: $TargetLink" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Info: $($DellItem.ImportantInfo.URL)" -Type 1 -LogFile $LogFile
                    New-CMTraceLog -Message "   Version: $DCUVersion " -Type 1 -LogFile $LogFile

                    #Build Required Info to Download and Update CM Package
                    $TargetFilePathName = "$($DellCabExtractPath)\$($TargetFileName)"
                    New-CMTraceLog -Message "   Running Command: Invoke-WebRequest -Uri $TargetLink -OutFile $TargetFilePathName -UseBasicParsing -Proxy $ProxyServer " -Type 1 -LogFile $LogFile
                    Invoke-WebRequest -Uri $TargetLink -OutFile $TargetFilePathName -UseBasicParsing -Proxy $ProxyServer

                    #Confirm Download
                    if (Test-Path $TargetFilePathName) {
                        New-CMTraceLog -Message "   Download Complete " -Type 1 -LogFile $LogFile
                                     
                        $LogFileName = $TargetFilePathName.replace(".exe", ".log")
                        $Arguments = "/s /l=$LogFileName"
                        Write-Output "Starting update..."
                        New-CMTraceLog -Message " Running Command: Start-Process $TargetFilePathName $Arguments -Wait -PassThru " -Type 1 -LogFile $LogFile
                        $Process = Start-Process "$TargetFilePathName" $Arguments -Wait -PassThru
                        New-CMTraceLog -Message " Update complete with exitcode: $($Process.ExitCode)" -Type 1 -LogFile $LogFile
                    
                        If ($Process -ne $null -and $Process.ExitCode -eq '2') {
                            $RestartComputer = $true
                        }
                    }
                    else {
                        New-CMTraceLog -Message "Update download failed" -Type 3 -LogFile $LogFile
                        $Compliance = $false
                    }
                }
                else {
                    #Needs Remediation
                    #$DellItem.Name.Display.'#cdata-section'
                    New-CMTraceLog -Message "Update available for $($DellItem.Name.Display.'#cdata-section'): Installed = $CurrentVersion | Available = $DCUVersion | Remediation Required" -Type 1 -LogFile $LogFile
                    $Compliance = $false
                }
            
            }
            else {
                #Compliant
                New-CMTraceLog -Message " Update $($DellItem.Name.Display.'#cdata-section') is already installed: $CurrentVersion" -Type 1 -LogFile $LogFile
            }
        }
        else {
            #No Cab with XML was able to download
            New-CMTraceLog -Message "No cab file downloaded" -Type 2 -LogFile $LogFile
        }
    }
    else {
        #No Match in the DCU XML for this Model (SKUNumber)
        New-CMTraceLog -Message "No match for $SystemSKUNumber" -Type 2 -LogFile $LogFile
    }

    if ($Compliance -eq $false) {
        New-CMTraceLog -Message "Exit script as non-compliant" -Type 2 -LogFile $LogFile
        exit 1
    }
    if ($RestartComputer -eq $true) { Restart-ByPassComputer }
}
else {
    New-CMTraceLog -Message "This isn't a Dell computer exiting...`n     This script should only be run on Dell computers." -Type 2 -LogFile $LogFile
}