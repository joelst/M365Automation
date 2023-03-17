
<#
    Description
    I needed a quick way to enforce the following settings when a configuration profile wasn't working. It's not the right way, but it worked.
#>
[CmdletBinding()]
param (
    [Parameter()]
    [int]
    $MinPwdLength = 12,
    [Parameter()]
    [int]
    $MinPwdAge = 1,
    [Parameter()]
    [int]
    $LockoutDuration =  15,
    [Parameter()]
    [int]
    $LockoutThreshold =  10,    
    [Parameter()]
    [int]
    $LockoutWindow =  15
)
function Set-RegInfo {
    [CmdletBinding()]
    param (
        $RegistryPath,
        $Name,
        $Value,
        $Type
    )

    # Clean up entries
    $Type = $Type.replace("REG_", "")
    $RegistryPath = $RegistryPath.Replace("HKLM\", "HKLM:\").Replace("HKCU\", "HKCU:\").Replace("HCU\", "HCU:\")
    # Create the key if it does not exist
    If (-NOT (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
    # Now set the value
    $null = New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $Type -Force
}

net accounts /minpwlen:$MinPwdLength /minpwage:$MinPwdAge /lockoutduration:$LockoutDuration /lockoutthreshold:$LockoutThreshold /lockoutwindow:$LockoutWindow
exit 0
