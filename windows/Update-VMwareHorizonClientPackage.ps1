#Requires -Modules IntuneWin32App, PSIntuneAuth, AzureAD
<#
    .SYNOPSIS
        Packages the latest Adobe Acrobat Reader DC (US English) for Intune deployment.
        Uploads the mew package into the target Intune tenant.

    .NOTES
        For details on IntuneWin32App go here: https://github.com/MSEndpointMgr/IntuneWin32App/blob/master/README.md
        For details on Evergreen go here: https://stealthpuppy.com/Evergreen
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $False)]
    [System.String] $Path = "D:\MEMApp\VMware",

    [Parameter(Mandatory = $False)]
    [System.String] $PackageOutputPath = "D:\MEMAppOut\VMware",

    [Parameter(Mandatory = $False)]
    [System.String] $ScriptName = "Install-Package.ps1",

    [Parameter(Mandatory = $False)]
    [System.String] $TenantName = "placeholder.onmicrosoft.com",

    [Parameter(Mandatory = $False)]
    [System.Management.Automation.SwitchParameter] $Upload,
   
    [Parameter(Mandatory = $False)]
    [ValidateSet("System","User")]
    $InstallExperience = "System",
    
    [Parameter(Mandatory = $False)]
    $PackageName = "VMware Horizon Client",
    
    [Parameter(Mandatory = $False)]
    $PackageId = "Vmware.HorizonClient",
    
    [Parameter(Mandatory = $False)]
    $ProductCode = "{9F959D5E-DF9C-4AC4-88C3-261EB45A4C38}",
    
    [Parameter(Mandatory = $False)]
    $AppPath = "${env:ProgramFiles(x86)}\VMware\VMware Horizon View Client\",
    
    [Parameter(Mandatory = $False)]
    $AppExecutable = "vmware-view.exe",

    $IconSource = "https://images-na.ssl-images-amazon.com/images/I/51LHYlml%2BgL.png"

)

$Win32Wrapper = "https://raw.githubusercontent.com/microsoft/Microsoft-Win32-Content-Prep-Tool/master/IntuneWinAppUtil.exe"


#region Check if token has expired and if, request a new
Write-Host -ForegroundColor "Cyan" "Checking for existing authentication token for tenant: $TenantName."
If ($Null -ne $Global:AccessToken) {
    $UtcDateTime = (Get-Date).ToUniversalTime()
    [datetime]$Global:TokenExpires = [datetime]$Global:AccessToken.ExpiresOn.DateTime
    $TokenExpireMins = ($Global:TokenExpires - $UtcDateTime).Minutes
    Write-Warning -Message "Current authentication token expires in (minutes): $($TokenExpireMins)"

    If ($TokenExpireMins -le 1) {
        Write-Host -ForegroundColor "Cyan" "Existing token found but is or will soon expire, requesting a new token."
        
        $Global:AccessToken = Connect-MSIntuneGraph -TenantID $TenantName
        #$Global:AccessToken = Get-MSIntuneAuthToken -TenantName $TenantName
    }
    else {
        Write-Host -ForegroundColor "Cyan" "Existing authentication token has not expired, will not request a new token."
    }        
}
else {
    Write-Host -ForegroundColor "Cyan" "Authentication token does not exist, requesting a new token."
    $Global:AccessToken = Connect-MSIntuneGraph -TenantID $TenantName
    #$Global:AccessToken = Get-MSIntuneAuthToken -TenantName $TenantName -PromptBehavior "Auto"
    
}
#endregion

    #region Variables
    Write-Host -ForegroundColor "Cyan" "Getting $PackageName updates via Winget."
    $ProgressPreference = "SilentlyContinue"
    $InformationPreference = "Continue"
    

    $packageInfo = winget show $PackageId | ConvertFrom-String -Delimiter ": " -PropertyNames "Detail","Value"
    foreach ($info in $packageInfo)
    {
        if ($info.Detail.Trim() -eq "Version")
        {
            $PackageVersion = $info.Value.Trim()
            Write-Output "  PackageVersion = $PackageVersion"
        }
        if ($info.Detail.Trim() -eq "Publisher")
        {
            $Publisher = $info.Value.Trim()
            Write-Output "  Publisher = $Publisher"
        }
        if ($info.Detail.Trim() -eq "Publisher Url")
        {
            $PublisherUrl = $info.Value.Trim()
            Write-Output "  PublisherURL = $PublisherUrl"
        }
        if ($info.Detail.Trim() -eq "Description")
        {
            $Description = $info.Value.Trim()
            Write-Output "  Description = $Description"
        }
        if ($info.Detail.Trim() -eq "Privacy Url")
        {
            $PrivacyURL = $info.Value.Trim()
            Write-Output "  PrivacyUrl = $PrivacyUrl"
        }
        if ($info.Detail.Trim() -eq "Download Url")
        {
            $DownloadUrl = $info.Value.Trim()
            Write-Output "  DownloadUrl = $DownloadUrl"
        }
        if ($info.Detail.Trim() -eq "Homepage")
        {
            $InformationURL = $info.Value.Trim()
            Write-Output "  InfomationUrl = $InformationUrl"
        }
        if ($info.Detail.Trim() -eq "Homepage")
        {
            $InformationURL = $info.Value.Trim()
            Write-Output "  InfomationUrl = $InformationUrl"
        }
    }
    
    # Variables for the package
    $DisplayName = $PackageName ##+ " " + $PackageVersion

    Write-Output "`n  Creating Package: $DisplayName"
    $Executable = Split-Path -Path $DownloadUrl -Leaf

    $InstallCommandLine = ".\$Executable /silent /norestart VDM_SERVER=<VIEW.COMPANYNAME.COM>"
    $UninstallCommandLine = ".\$Executable /silent /norestart /uninstall"
    #To_Automate region

    #endregion
    Write-Host "    Checking to see if $PackageName $PackageVersion has already been created in MEM..."
    $existingPackages = Get-IntuneWin32App -DisplayName $PackageName | Where-Object {$_.DisplayVersion -eq $PackageVersion} | Select-Object -First 1

    if (-not $existingPackages -eq '')
    {
        Write-Host "        Package already exists, exiting process!"
        exit
    }
    else {
        Write-Host "        Package does not exist, creating package now!"
    }

    # Download installer with winget
    If ($PackageName) {
 
        # Test to make sure the paths we need are available.
        If ((Test-Path $path -ErrorAction SilentlyContinue) -ne $true)
        {
            $null = New-Item -Path $path -ErrorAction SilentlyContinue -ItemType Directory | Out-Null
        }

        If ((Test-Path $PackageOutputPath -ErrorAction SilentlyContinue) -ne $true)
        {
           $null =  New-Item -Path $PackageOutputPath -ErrorAction SilentlyContinue -ItemType Directory | Out-Null
        }

        # Create the package folder
        $PackagePath = Join-Path -Path $Path -ChildPath "Package"
        Write-Host -ForegroundColor "Cyan" "    Package path: $PackagePath"
        If (!(Test-Path -Path $PackagePath)) { New-Item -Path $PackagePath -ItemType "Directory" -Force -ErrorAction "SilentlyContinue" > $Null }
        $PackageOutputPath = Join-Path -Path $PackageOutputPath -ChildPath "Output"
        Write-Host -ForegroundColor "Cyan" "    Output path: $PackageOutputPath"

        #region Download files and setup the package
   
        #region Package the app
        # Download the Package
        # TODO - Check the hash to make sure the file is valid
        Write-Verbose "  Executing: Join-Path -Path $Path -ChildPath (Split-Path -Path $PackagePath -Leaf)"
        $packageFile = Join-Path -Path $Path -ChildPath (Split-Path -Path $DownloadUrl -Leaf)
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $packageFile -UseBasicParsing
        }
        catch [System.Exception] {
            Write-Error -Message "MEM Win32 Content Prep tool failed with: $($_.Exception.Message)"
            Break
        }

        #region Package the app
        # Download the Intune Win32 wrapper
        # TODO: Check if already available and skip download if it is.
        Write-Verbose "  Executing: Join-Path -Path $Path -ChildPath (Split-Path -Path $Win32Wrapper -Leaf)"
        $wrapperBin = Join-Path -Path $Path -ChildPath (Split-Path -Path $Win32Wrapper -Leaf)
        try {
            Invoke-WebRequest -Uri $Win32Wrapper -OutFile $wrapperBin -UseBasicParsing
        }
        catch [System.Exception] {
            Write-Error -Message "MEM Win32 Content Prep tool failed with: $($_.Exception.Message)"
            Break
        }

        # Create the package
        Write-Host -ForegroundColor "Cyan" " Package path: $(Split-Path -Path $packageFile -Parent)"
        Write-Host -ForegroundColor "Cyan" " Update path: $packageFile"
        $ArgList = "-c $(Split-Path -Path $packageFile -Parent) -s $packageFile -o $PackageOutputPath -q"
        Write-Host "  Argument list: $ArgList"

        try {
           
            $params = @{
                FilePath     = $wrapperBin
                ArgumentList = $ArgList
                Wait         = $True
                PassThru     = $True
                NoNewWindow  = $True
            }
            Write-Host " Executing: $process = Start-Process @params"
            $process = Start-Process @params
        }
        catch [System.Exception] {
            Write-Error -Message "Failed to create MEM package with: $($_.Exception.Message)"
            Break
        }
        try {
            $IntuneWinFile = Get-ChildItem -Path $PackageOutputPath -Filter "*.intunewin" -ErrorAction "SilentlyContinue" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        }
        catch {
            Write-Error -Message "Failed to find an Intunewin package in $PackageOutputPath with: $($_.Exception.Message)"
            Break
        }
        Write-Host -ForegroundColor "Cyan" "Found package: $($IntuneWinFile.FullName)."
        #endregion


        #region Upload intunewin file and create the Intune app
        # Convert image file to icon
        $ImageFile = (Join-Path -Path $Path -ChildPath (Split-Path -Path $IconSource -Leaf))
        try {
            Invoke-WebRequest -Uri $IconSource -OutFile $ImageFile -UseBasicParsing
        }
        catch [System.Exception] {
            Write-Error -Message "Failed to download: $IconSource with: $($_.Exception.Message)"
            Break
        }
        If (Test-Path -Path $ImageFile) {
            $Icon = New-IntuneWin32AppIcon -FilePath $ImageFile
        }
        Else {
            Write-Error -Message "Cannot find the icon file."
            Break
        }

        # Create detection rule using the en-US MSI product code (1033 in the GUID below correlates to the lcid)
        If ($ProductCode -and $PackageVersion) {
            $params = @{
                ProductCode = $ProductCode
                #ProductVersionOperator = "greaterThanOrEqual"
                #ProductVersion         = $PackageVersion
            }
            $DetectionRule1 = New-IntuneWin32AppDetectionRuleMSI @params
        }
        Else {
            Write-Host -ForegroundColor "Cyan" "ProductCode: $ProductCode."
            Write-Host -ForegroundColor "Cyan" "Version: $PackageVersion."
            Write-Error -Message "Cannot create the detection rule - check ProductCode and version number."
            Break
        }
        If ($AppPath -and $AppExecutable) {
            $params = @{
                Version              = $True
                Path                 = $AppPath
                FileOrFolder         = $AppExecutable
                Check32BitOn64System = $False 
                Operator             = "greaterThanOrEqual"
                VersionValue         = $PackageVersion
            }
            $DetectionRule2 = New-IntuneWin32AppDetectionRuleFile @params
        }
        Else {
            Write-Error -Message "Cannot create the detection rule - check application path and executable."
            Write-Host -ForegroundColor "Cyan" "Path: $AppPath."
            Write-Host -ForegroundColor "Cyan" "Exe: $AppExecutable."
            Break
        }
        If ($DetectionRule1 -and $DetectionRule2) {
            $DetectionRule = @($DetectionRule1, $DetectionRule2)
        }
        Else {
            Write-Error -Message "Failed to create the detection rule."
            Break
        }
    
        # Create custom requirement rule
        $params = @{
            Architecture                    = "All"
            MinimumSupportedOperatingSystem = "1607"
        }
        $RequirementRule = New-IntuneWin32AppRequirementRule @params

        # Add new EXE Win32 app
        # Requires a connection via Connect-MSIntuneGraph first
        If ($PSBoundParameters.Keys.Contains("Upload")) {
            try {
                $params = @{
                    FilePath                 = $IntuneWinFile.FullName
                    DisplayName              = $DisplayName
                    Description              = $Description
                    Publisher                = $Publisher
                    InformationURL           = $InformationURL
                    PrivacyURL               = $PrivacyURL
                    CompanyPortalFeaturedApp = $false
                    InstallExperience        = $InstallExperience
                    RestartBehavior          = "suppress"
                    DetectionRule            = $DetectionRule
                    RequirementRule          = $RequirementRule
                    InstallCommandLine       = $InstallCommandLine
                    UninstallCommandLine     = $UninstallCommandLine
                    AppVersion               = $PackageVersion
                    Icon                     = $Icon
                    Verbose                  = $true

                }
                $null = Add-IntuneWin32App @params
            }
            catch [System.Exception] {
                Write-Error -Message "Failed to create application: $DisplayName with: $($_.Exception.Message)"
                Break
            }

            # Create an available assignment for all users
            <#
            If ($Null -ne $App) {
                try {
                    $params = @{
                        Id                           = $App.Id
                        Intent                       = "available"
                        Notification                 = "showAll"
                        DeliveryOptimizationPriority = "foreground"
                        #AvailableTime                = ""
                        #DeadlineTime                 = ""
                        #UseLocalTime                 = $true
                        #EnableRestartGracePeriod     = $true
                        #RestartGracePeriod           = 360
                        #RestartCountDownDisplay      = 20
                        #RestartNotificationSnooze    = 60
                        Verbose                      = $true
                    }
                    Add-IntuneWin32AppAssignmentAllUsers @params
                }
                catch [System.Exception] {
                    Write-Warning -Message "Failed to add assignment to $($App.displayName) with: $($_.Exception.Message)"
                    Break
                }
            }
            #>
        }
        Else {
            Write-Warning -Message "Parameter -Upload not specified. Skipping upload to MEM."
        }
        #endregion
    }
    Else {
        Write-Error -Message "Failed to retrieve $Package update package via Evergreen."
    }
