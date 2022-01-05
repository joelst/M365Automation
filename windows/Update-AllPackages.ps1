#Requires -Modules IntuneWin32App, PSIntuneAuth, AzureAD
<#
    .SYNOPSIS
        Packages the latest 7-Zip for MEM (Intune) deployment.
        Uploads the mew package into the target Intune tenant.

    .NOTES
        For details on IntuneWin32App go here: https://github.com/MSEndpointMgr/IntuneWin32App/blob/master/README.md
        For details on Evergreen go here: https://stealthpuppy.com/Evergreen
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $False)]
    [System.String] $Path = "D:\MEMApp\",

    [Parameter(Mandatory = $False)]
    [System.String] $PackageOutputPath = "D:\MEMAppOut\",

    [Parameter(Mandatory = $False)]
    [System.String] $ScriptPath = "D:\MemAppFactory",

    [Parameter(Mandatory = $False)]
    [System.String] $TenantName = "placeholder.onmicrosoft.com",
   
)

## WORK IN PROGRESS

## FIND ALL Update-*.ps1 files in $ScriptPath

## For each - Execute each found scripts with provided switches.

