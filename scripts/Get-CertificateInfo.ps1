[CmdletBinding()]
param (
    [Parameter()]
    # Password for PFX file
    [string]
    $CertificatePassword,
    [Parameter()]
    # Path to the pfx file
    [string]
    $CertificatePath
)

if ($null -eq (Get-Command openssl -ErrorAction SilentlyContinue)) { 
    if (Test-Path "C:\Program Files\OpenSSL-Win64\bin") {
        $env:path = "$env:path;C:\Program Files\OpenSSL-Win64\bin"
    }
    else {
        Write-Error " OpenSSL is not in path, please fix and start again"
        exit
    }
}
if (Test-Path $CertificatePath) {
    $CertificatePassword = "pass:$($CertificatePassword)"
    $pemPath = $CertificatePath.Replace(".pfx", "cert.pem")
    openssl pkcs12 -nodes -in $CertificatePath -clcerts -nomacver -nokeys -out $pemPath -passin $CertificatePassword
    Get-Content $pemPath | openssl x509 -text -noout
    Remove-Item $pemPath
}
else {
    Write-Output "Error: $CertificatePath does not exist!"
}