#
# Despite many hours of trying to work through this process. It never worked reliably when running as SYSTEM
# Interim fix for https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/
# 5/31/2022

function Set-RegInfo {
    [CmdletBinding()]
    param (
        $RegistryPath,
        $Name,
        $Value,
        $Type
    )
    
# Create the key if it does not exist
    If (-NOT (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
    }  
    # Now set the value
    $null = New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType $Type -Force
}


Write-Output " Updating Registry directly"
$rPath = "Registry::HKCR\ms-msdt\"
Remove-Item -Path $rPath -Recurse -ErrorAction SilentlyContinue
 