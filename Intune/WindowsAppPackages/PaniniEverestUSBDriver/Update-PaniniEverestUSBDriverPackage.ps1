#Requires -Modules IntuneWin32App
<#
    .SYNOPSIS
        Packages the Panini Everest USB Driver for MEM (Intune) deployment.
        Optionally uploads the new package into the target Intune tenant, unassigned.

    .DESCRIPTION
        Panini Everest USB Driver is not in winget, so the vendor installer is supplied with
        -InstallerPath. The package wraps the InstallScript setup with recorded response
        files (setup.iss / uninstall.iss) and the Install/Uninstall wrapper scripts from this
        folder. See Install-PaniniEverestUSBDriver.ps1 for why a wrapper is needed.

        If Panini changes the setup dialogs in a new version, re-record both response files:
          Install:   <setup>.exe /r /f1"C:\temp\setup.iss"
          Uninstall: "%ProgramFiles(x86)%\InstallShield Installation Information\{2B580190-33FA-40B9-92EA-C08B3466F45D}\setup.exe" -runfromtemp -l0x0409 -removeonly /r /f1"C:\temp\uninstall.iss"
        The original setup.exe ignores -removeonly, so the uninstall must be recorded with the cached setup.

    .NOTES
        For details on IntuneWin32App go here: https://github.com/MSEndpointMgr/IntuneWin32App/blob/master/README.md

    .PARAMETER InstallerPath
    Path to the Panini_Everest_USB_Driver_Setup_<version>.exe downloaded from Panini

    .PARAMETER Path
    Path to use for staging package source files

    .PARAMETER PackageOutputPath
    Path to export the created packages

    .PARAMETER TenantName
    Microsoft Endpoint Manager (Intune) Azure Active Directory Tenant. This should be in the format of Organization.onmicrosoft.com

    .PARAMETER ClientID
    Optional Entra app registration client ID passed to Connect-MSIntuneGraph

    .EXAMPLE
    .\Update-PaniniEverestUSBDriverPackage.ps1 -InstallerPath "D:\Downloads\Panini_Everest_USB_Driver_Setup_3.25.9.exe" -TenantName contoso.onmicrosoft.com -Upload
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $True)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [System.String] $InstallerPath,

    [Parameter(Mandatory = $False)]
    [System.String] $Path = "D:\MEMApp\",

    [Parameter(Mandatory = $False)]
    [System.String] $PackageOutputPath = "D:\MEMAppOut\",

    [Parameter(Mandatory = $False)]
    [System.String] $TenantName,

    [Parameter(Mandatory = $False)]
    [System.String] $ClientID,

    [Parameter(Mandatory = $False)]
    [System.Management.Automation.SwitchParameter] $Upload,

    [Parameter(Mandatory = $False)]
    $PackageName = "Panini Everest USB Driver",

    [Parameter(Mandatory = $False)]
    $PackageId = "Panini.EverestUSBDriver",

    [Parameter(Mandatory = $False)]
    $ProductCode = "{2B580190-33FA-40B9-92EA-C08B3466F45D}",

    [Parameter(Mandatory = $False)]
    $MinimumSupportedWindowsRelease = "W10_1809",

    [switch]$Force
)

$Win32Wrapper = "https://raw.githubusercontent.com/microsoft/Microsoft-Win32-Content-Prep-Tool/master/IntuneWinAppUtil.exe"
$ProgressPreference = "SilentlyContinue"

#Create subfolders for this package
$PackageOutputPath = Join-Path -Path $PackageOutputPath -ChildPath $PackageId
$Path = Join-Path -Path $Path -ChildPath $PackageId

#region Package metadata from the installer
$Installer = Get-Item -Path $InstallerPath
$Signature = Get-AuthenticodeSignature -FilePath $Installer.FullName
if ($Signature.Status -ne "Valid" -or $Signature.SignerCertificate.Subject -notmatch "O=Panini S\.p\.A\.") {
    Write-Error -Message "Installer signature is not a valid Panini S.p.A. signature: $($Signature.Status) $($Signature.SignerCertificate.Subject)"
    return
}
$PackageVersion = $Installer.VersionInfo.ProductVersion.Trim()
$Publisher = "Panini"
$Description = "Panini Everest check scanner USB (RNDIS) driver. Installs the panini-usbnet-ecm network driver and adds the Panini Certification Authority V2 certificate to the Local Machine Trusted Root store."
$InformationURL = "https://www.panini.com"
$PrivacyURL = "https://www.panini.com"
$DisplayName = $PackageName
$SetupFileName = "Panini_Everest_USB_Driver_Setup_$PackageVersion.exe"
Write-Host -ForegroundColor "Cyan" "Creating Package: $DisplayName $PackageVersion"

$InstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Install-PaniniEverestUSBDriver.ps1"
$UninstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\Uninstall-PaniniEverestUSBDriver.ps1"
#endregion

#region Stage the package source folder
$PackagePath = Join-Path -Path $Path -ChildPath "Package"
Write-Host -ForegroundColor "Cyan" "    Package path: $PackagePath"
If (Test-Path -Path $PackagePath) { Remove-Item -Path $PackagePath -Recurse -Force }
New-Item -Path $PackagePath -ItemType "Directory" -Force > $Null
If (!(Test-Path -Path $PackageOutputPath)) { New-Item -Path $PackageOutputPath -ItemType "Directory" -Force > $Null }

Copy-Item -Path $Installer.FullName -Destination (Join-Path -Path $PackagePath -ChildPath $SetupFileName)
foreach ($file in "Install-PaniniEverestUSBDriver.ps1", "Uninstall-PaniniEverestUSBDriver.ps1", "setup.iss", "uninstall.iss") {
    Copy-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath $file) -Destination $PackagePath
}
#endregion

#region Package the app
$wrapperBin = Join-Path -Path $Path -ChildPath (Split-Path -Path $Win32Wrapper -Leaf)
If (!(Test-Path -Path $wrapperBin)) {
    try {
        Invoke-WebRequest -Uri $Win32Wrapper -OutFile $wrapperBin -UseBasicParsing
    }
    catch [System.Exception] {
        Write-Error -Message "MEM Win32 Content Prep tool download failed with: $($_.Exception.Message)"
        return
    }
}

Get-ChildItem -Path $PackageOutputPath -Filter "*.intunewin" -ErrorAction "SilentlyContinue" | Remove-Item -Force
$params = @{
    SourceFolder         = $PackagePath
    SetupFile            = "Install-PaniniEverestUSBDriver.ps1"
    OutputFolder         = $PackageOutputPath
    IntuneWinAppUtilPath = $wrapperBin
    Force                = $true
}
$IntuneWinPackage = New-IntuneWin32AppPackage @params
$IntuneWinFile = Get-ChildItem -Path $PackageOutputPath -Filter "*.intunewin" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
If (-not $IntuneWinFile) {
    Write-Error -Message "Failed to find an Intunewin package in $PackageOutputPath."
    return
}
Write-Host -ForegroundColor "Cyan" "Found package: $($IntuneWinFile.FullName)."
#endregion

#region Detection and requirement rules
# The InstallScript ARP entry is written to the 32-bit (WOW6432Node) view
$params = @{
    VersionComparison         = $true
    KeyPath                   = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    ValueName                 = "DisplayVersion"
    Check32BitOn64System      = $true
    VersionComparisonOperator = "greaterThanOrEqual"
    VersionComparisonValue    = $PackageVersion
}
$DetectionRule = New-IntuneWin32AppDetectionRuleRegistry @params

# x64 only: the package has no ARM64 driver
$params = @{
    Architecture                   = "x64"
    MinimumSupportedWindowsRelease = $MinimumSupportedWindowsRelease
}
$RequirementRule = New-IntuneWin32AppRequirementRule @params
#endregion

#region Upload the Intune app, no assignment
If ($Upload.IsPresent) {
    if ([string]::IsNullOrWhiteSpace($TenantName)) {
        Write-Error -Message "TenantName is required with -Upload."
        return
    }

    Write-Host -ForegroundColor "Cyan" "Connecting to tenant: $TenantName."
    $connectParams = @{ TenantID = $TenantName }
    if ($ClientID) { $connectParams.ClientID = $ClientID }
    # IntuneWin32App 1.4.x sets $Global:AccessToken itself; assigning the return value would clear it
    Connect-MSIntuneGraph @connectParams | Out-Null
    if (-not $Global:AccessToken -or -not (Test-AccessToken)) {
        Write-Error -Message "Failed to authenticate to $TenantName. Supply -ClientID for an app registration with DeviceManagementApps.ReadWrite.All."
        return
    }

    Write-Host "    Checking to see if $PackageName $PackageVersion has already been created in MEM..."
    $existingPackage = Get-IntuneWin32App -DisplayName $PackageName -WarningAction SilentlyContinue | Where-Object { $_.displayVersion -eq $PackageVersion } | Select-Object -First 1
    if ($existingPackage -and -not $Force.IsPresent) {
        Write-Host "        Package already exists (id $($existingPackage.id)), exiting process!`n"
        return
    }

    try {
        $params = @{
            FilePath                 = $IntuneWinFile.FullName
            DisplayName              = $DisplayName
            Description              = $Description
            Publisher                = $Publisher
            AppVersion               = $PackageVersion
            InformationURL           = $InformationURL
            PrivacyURL               = $PrivacyURL
            CompanyPortalFeaturedApp = $false
            InstallExperience        = "system"
            RestartBehavior          = "basedOnReturnCode"
            DetectionRule            = $DetectionRule
            RequirementRule          = $RequirementRule
            InstallCommandLine       = $InstallCommandLine
            UninstallCommandLine     = $UninstallCommandLine
            Verbose                  = $true
        }
        $App = Add-IntuneWin32App @params

        # Requirement rule "x64" maps to allowedArchitectures "x64,arm64"; the x64 driver cannot load on ARM64
        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp"; allowedArchitectures = "x64" } | ConvertTo-Json
        Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($App.id)" -Headers $Global:AuthenticationHeader -Body $body -ContentType "application/json" | Out-Null

        Write-Host -ForegroundColor "Green" "Created $($App.displayName) $PackageVersion (id $($App.id)). No assignment was added."
        $App
    }
    catch [System.Exception] {
        Write-Error -Message "Failed to create application: $DisplayName with: $($_.Exception.Message)"
        return
    }
}
Else {
    Write-Warning -Message "Parameter -Upload not specified. Skipping upload to MEM."
}
#endregion
