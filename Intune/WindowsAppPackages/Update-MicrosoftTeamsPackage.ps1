#Requires -Modules IntuneWin32App, PSIntuneAuth, AzureAD
<#
    .SYNOPSIS
        Packages the latest Microsoft Teams for MEM (Intune) deployment.
        Uploads the mew package into the target Intune tenant.

    .NOTES
        For details on IntuneWin32App go here: https://github.com/MSEndpointMgr/IntuneWin32App/blob/master/README.md

    .PARAMETER Path
    Path to use for downloading and processing packages

    .PARAMETER PackageOutputPath
    Path to export the created packages

    .PARAMETER TenantName
    Microsoft Endpoint Manager (Intune) Azure Active Directory Tenant. This should be in the format of Organization.onmicrosoft.com
    
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $False)]
    [System.String] $Path = "D:\MEMApp\",

    [Parameter(Mandatory = $False)]
    [System.String] $PackageOutputPath = "D:\MEMAppOut\",

    [Parameter(Mandatory = $True)]
    [System.String] $TenantName,

    [Parameter(Mandatory = $False)]
    [System.Management.Automation.SwitchParameter] $Upload,

    [Parameter(Mandatory = $False)]
    $PackageName = "Microsoft Teams",
    
    [Parameter(Mandatory = $False)]
    $PackageId = "Microsoft.Teams",
    
    [Parameter(Mandatory = $False)]
    $ProductCode = "",
    
    [Parameter(Mandatory = $False)]
    [ValidateSet("System","User")]
    $InstallExperience = "User",

    [Parameter(Mandatory = $False)]
    [ValidateSet("Default","MSI","FileVersion","FileExists")]
    [string]$DetectionType = "FileExists",  

    [Parameter(Mandatory = $False)]
    $AppPath = "%LocalAppData%\Microsoft\Teams\",
    
    [Parameter(Mandatory = $False)]
    $AppExecutable = "Update.exe",

    $IconSource = "https://raw.githubusercontent.com/joelst/MEMAppFactory/main/logos/$($PackageId)-logo.png",

    [Parameter(Mandatory = $False)]
    $MinimumSupportedOperatingSystem = "21H1",

    [Parameter(Mandatory = $False)]
    $VersionOperator = "Equal",

    [switch]$Force

)
    
$Win32Wrapper = "https://raw.githubusercontent.com/microsoft/Microsoft-Win32-Content-Prep-Tool/master/IntuneWinAppUtil.exe"

#Create subfolders for this package
$PackageOutputPath = Join-Path $PackageOutputPath $PackageId
$Path = Join-Path $Path $PackageId

#region Check if token has expired and if, request a new
Write-Host -ForegroundColor "Cyan" "Checking for existing authentication token for tenant: $TenantName."
if ($Null -ne $Global:AccessToken) {
    $UtcDateTime = (Get-Date).ToUniversalTime()
    [datetime]$Global:TokenExpires = [datetime]$Global:AccessToken.ExpiresOn.DateTime
    $TokenExpireMins = ($Global:TokenExpires - $UtcDateTime).Minutes
    Write-Warning -Message "Current authentication token expires in (minutes): $($TokenExpireMins)"

    if ($TokenExpireMins -le 1) {
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

$packageInfo = winget show $PackageId 
    foreach ($info in $packageInfo)
    {
        try{ 
            $key = ($info -split ": ")[0].Trim()
            $value = ($info -split ": ")[1].Trim()
        }
        catch{
            # just ignore the error
        }
        
        if ($key -eq "Version")
        {
            $PackageVersion = $value
            Write-Verbose "  PackageVersion = $PackageVersion"
        }
        if ($key -eq "Publisher")
        {
            $Publisher = $value
            Write-Verbose "  Publisher = $Publisher"
        }
        if ($key -eq "Publisher Url")
        {
            $PublisherUrl = $value
            Write-Verbose "  PublisherURL = $PublisherUrl"
        }
        if ($key -eq "Description")
        {
            $Description = $value
            Write-Verbose "  Description = $Description"
        }
        if ($key -eq "Privacy Url")
        {
            $PrivacyURL = $value
            Write-Verbose "  PrivacyUrl = $PrivacyUrl"
        }
        if ($key -eq "Download Url")
        {
            $DownloadUrl = $value
            Write-Verbose "  DownloadUrl = $DownloadUrl"
        }
        if ($key -eq "Homepage")
        {
            $InformationURL = $value
            Write-Verbose "  InfomationUrl = $InformationUrl"
        }
        if ($key -eq "Installer Url") {
            $DownloadUrl = $value
            Write-Verbose "  DownloadUrl = $DownloadUrl"
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($InformationURL)){
        $InformationUrl = "https://bing.com/$packageName"
    }
    
    if ([string]::IsNullOrWhiteSpace($PublisherURL)){
        $PublisherUrl = "https://bing.com/$packageName"
    }

    if ([string]::IsNullOrWhiteSpace($PrivacyURL)){
        $PrivacyUrl = "https://bing.com/$packageName"
    }

    # Variables for the package
    $DisplayName = $PackageName ##+ " " + $PackageVersion

    Write-Output "`n  Creating Package: $DisplayName"
    $Executable = Split-Path -Path $DownloadUrl -Leaf

    $InstallCommandLine = ".\$Executable --silent"
    $UninstallCommandLine = "%LocalAppData%\Microsoft\Teams\Update.exe --uninstall -s"
    #To_Automate region

#endregion
    Write-Host "    Checking to see if $PackageName $PackageVersion has already been created in MEM..."
    $existingPackages = Get-IntuneWin32App -DisplayName $PackageName | Where-Object {$_.DisplayVersion -eq $PackageVersion} | Select-Object -First 1

    if (-not $existingPackages -eq '')
    {
        if ($Force.IsPresent -eq $false) {
            Write-Host "        Package already exists, exiting process!`n"
            #$global:createdPackage += "$PackageName $PackageVersion existing"
            exit
        }
        else{
            Write-Host "        Package already exists, Force parameter detected!`n"
            $global:createdPackage += "$PackageName $PackageVersion created"
        }
    }
    else {
        Write-Host "        Package does not exist, creating package now!`n"
        $global:createdPackage += "$PackageName $PackageVersion created"
    }

    # Download installer with winget
    if ($PackageName) {
 
        # Test to make sure the paths we need are available.
        if ((Test-Path $path -ErrorAction SilentlyContinue) -ne $true)
        {
            $null = New-Item -Path $path -ErrorAction SilentlyContinue -ItemType Directory | Out-Null
        }

        if ((Test-Path $PackageOutputPath -ErrorAction SilentlyContinue) -ne $true)
        {
           $null =  New-Item -Path $PackageOutputPath -ErrorAction SilentlyContinue -ItemType Directory | Out-Null
        }

        # Create the package folder
        $PackagePath = Join-Path -Path $Path -ChildPath "Package"
        Write-Host -ForegroundColor "Cyan" "    Package path: $PackagePath"
        if (!(Test-Path -Path $PackagePath)) { New-Item -Path $PackagePath -ItemType "Directory" -Force -ErrorAction "SilentlyContinue" > $Null }
        $PackageOutputPath = Join-Path -Path $PackageOutputPath -ChildPath "Output"
        Write-Host -ForegroundColor "Cyan" "    Output path: $PackageOutputPath"

        #region Download files and setup the package
   
        #region Package the app
        # Download the Package
        # TODO - Check the hash to make sure the file is valid
        Write-Verbose "  Executing: Join-Path -Path $Path -ChildPath (Split-Path -Path $DownloadUrl -Leaf)"
        $packageFile = Join-Path -Path $Path -ChildPath (Split-Path -Path $DownloadUrl -Leaf)
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $packageFile -UseBasicParsing
        }
        catch [System.Exception] {
            Write-Error -Message "Package download error: $($_.Exception.Message)"
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
        If ($ProductCode -and $PackageVersion -or ($DetectionRuleType -eq "Default")) {
            $params = @{
                ProductCode = $ProductCode
                #ProductVersionOperator = $VersionOperator
                #ProductVersion         = $PackageVersion
            }
            $DetectionRule1 = New-IntuneWin32AppDetectionRuleMSI @params
        }

        If ($AppPath -and $AppExecutable -and ($DetectionType -eq "FileVersion")) {
            $params = @{
                Version              = $True
                Path                 = $AppPath
                FileOrFolder         = $AppExecutable
                Check32BitOn64System = $False 
                Operator             = $VersionOperator
                VersionValue         = $PackageVersion
            }
            $DetectionRule2 = New-IntuneWin32AppDetectionRuleFile @params
        }
        ElseIf ($DetectionType -eq "FileExists"){
            $params = @{
                Existence            = $True
                Path                 = $AppPath
                FileOrFolder         = $AppExecutable
                Check32BitOn64System = $False 
                DetectionType        = "exists"
                
            }
            $DetectionRule2 = New-IntuneWin32AppDetectionRuleFile @params
        }
        
        $DetectionRule = @()

        If ($DetectionRule1){
            $DetectionRule += $DetectionRule1
        }
        
        If ($DetectionRule2) {
            $DetectionRule += $DetectionRule2
        }
        
        if ($DetectionRule.Count -le 0) {
            Write-Error -Message "Failed to create the detection rule."
            Break
        }
    
        # Create custom requirement rule
        $params = @{
            Architecture                    = "All"
            MinimumSupportedOperatingSystem = $MinimumSupportedOperatingSystem
        }
        $RequirementRule = New-IntuneWin32AppRequirementRule @params

        # Add new EXE Win32 app
        # Requires a connection via Connect-MSIntuneGraph first
        If ($PSBoundParameters.Keys.Contains("Upload")) {
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
            $params | Write-Output
            try {

                $app = Add-IntuneWin32App @params
            }
            catch [System.Exception] {
                
                Write-Error -Message "Failed to create application: $DisplayName with: $($_.Exception.Message)"
                Break
            }

            # Create an available assignment for all users
            if ($Null -ne $App) {
                try {
                    $params = @{
                        Id                           = $App.Id
                        Intent                       = "available"
                        Notification                 = "hideAll"
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

        }
        else {
            Write-Warning -Message "Parameter -Upload not specified. Skipping upload to MEM."
        }
        #endregion
    }
    else {
        Write-Error -Message "Failed to retrieve $Package update package."
    }
