<#
    .DESCRIPTION
    Generates keys for LeanLaps to use
    
    Find instructions at https://www.lieben.nu/liebensraum/?p=3605

#>

## Generate key pair
$RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)

$private = $rsa.ExportCspBlob(1)
Write-Host "Your private key is:"
$private = $private -join ","
Set-Clipboard $private
$private
Write-Host "Private key has been saved to your clipboard. Be sure to save it somewhere safe."
Read-Host "Press any key to continue"

$public = $rsa.ExportCspBlob(0)
Write-Host "Your public key is:"
$public = $public -join ","
Set-Clipboard $public
$public
Write-Host "Public key has been saved to your clipboard"
