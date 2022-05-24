#Requires -Modules IntuneWin32App, PSIntuneAuth, AzureAD
<#
    .SYNOPSIS
        Execute all Update-*.ps1 in the specified path to create an update factory. 

        IMPORTANT Some of the update scripts have "extra" parameters that are not included in this script, you can modify this script or the individual scripts to ensure
        the correct parameter values are included.

    .NOTES
        For details on IntuneWin32App go here: https://github.com/MSEndpointMgr/IntuneWin32App/blob/master/README.md
    
    .PARAMETER ScriptPath
    Path where all of the Update scripts exist

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

    [Parameter(Mandatory = $False)]
    [System.String] $ScriptPath = (Get-Location).Path,

    [Parameter(Mandatory = $True)]
    [System.String] $TenantName

)

$global:createdPackage = @()
## FIND ALL Update-*.ps1 files in $ScriptPath, using -filter and -include was not working so using this sloppy Get-ChildItem
$Scripts = (Get-ChildItem -Path $ScriptPath -Exclude "Update-AllPackages.ps1", "*.json", "New-*.ps1").FullName

Write-Output "`n Found $($scripts.Count) scripts to run"
Write-Verbose "The following scripts will be executed"

foreach ($script in $scripts) {
    Write-Verbose "  $script"
}

foreach ($script in $scripts) {
    if ($script -notcontains "Update-AllPackages.ps1") {
        Write-Output "`n Running: $script `n"

        # using this method because need to specify a switch so -ArgumentList is not straightforward
        $sb = {
            & $script -Path $path -PackageOutputPath $PackageOutputPath -TenantName $TenantName -Upload
        }
        
        Invoke-Command -ScriptBlock $sb
    }
    
}

if ($null -ne $global:createdPackage) {
    Write-Host "Created..."
    $global:createdPackage

}
else {
    Write-Host "No packages created..."
}