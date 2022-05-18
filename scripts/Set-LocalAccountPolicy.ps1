
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
        $Path,
        $Name,
        $Value,
        $PropertyType
    )
    
# Create the key if it does not exist
    if (-NOT (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
    }  
    # Now set the value
    $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Continue
}


Invoke-Command {net accounts /minpwlen:$MinPwdLength /minpwage:$MinPwdAge /lockoutduration:$LockoutDuration /lockoutthreshold:$LockoutThreshold /lockoutwindow:$LockoutWindow}
