<#
    .SYNOPSIS
        Silently installs the Panini Everest USB Driver (InstallScript setup) for Intune Win32 deployment.

    .DESCRIPTION
        The Panini setup is a pure InstallScript project, so /s only works with a recorded
        response file (setup.iss) and setup.exe exits 0 even when the install fails. This
        wrapper runs setup with the response file, reads ResultCode from the /f2 log and
        returns a real exit code to Intune.

        Setup installs the panini-usbnet-ecm RNDIS driver, copies driver files to
        "Program Files (x86)\Panini" and adds "Panini Certification Authority V2" to the
        LocalMachine Root store.

    .NOTES
        Package contents (same folder as this script):
          Panini_Everest_USB_Driver_Setup_<version>.exe
          setup.iss
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $False)]
    [System.String] $LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
)

$ResponseFile = Join-Path -Path $PSScriptRoot -ChildPath "setup.iss"
$SetupLog = Join-Path -Path $LogPath -ChildPath "PaniniEverestUSBDriver-Install-Setup.log"
Start-Transcript -Path (Join-Path -Path $LogPath -ChildPath "PaniniEverestUSBDriver-Install.log") -Append | Out-Null

function Get-InstallShieldResultCode {
    param ([System.String] $Path)
    if (-not (Test-Path -Path $Path)) { return $null }
    $match = Select-String -Path $Path -Pattern '^\s*ResultCode\s*=\s*(-?\d+)' | Select-Object -First 1
    if ($match) { return [int]$match.Matches[0].Groups[1].Value }
    return $null
}

try {
    $Setup = Get-ChildItem -Path $PSScriptRoot -Filter "Panini_Everest_USB_Driver_Setup_*.exe" | Select-Object -First 1
    if (-not $Setup) { throw "Setup executable not found in $PSScriptRoot." }
    if (-not (Test-Path -Path $ResponseFile)) { throw "Response file not found: $ResponseFile." }

    Remove-Item -Path $SetupLog -Force -ErrorAction SilentlyContinue

    # /f1 and /f2 must be absolute paths
    $ArgList = "/s /f1`"$ResponseFile`" /f2`"$SetupLog`""
    Write-Host "Executing: $($Setup.FullName) $ArgList"
    $process = Start-Process -FilePath $Setup.FullName -ArgumentList $ArgList -Wait -PassThru -NoNewWindow
    Write-Host "Setup exit code: $($process.ExitCode)"

    $ResultCode = Get-InstallShieldResultCode -Path $SetupLog
    Write-Host "InstallShield ResultCode: $ResultCode"
    if ($null -eq $ResultCode) { throw "No ResultCode found in $SetupLog." }
    if ($ResultCode -ne 0) {
        # -3 = dialog sequence did not match setup.iss (e.g. product already installed)
        throw "Setup failed with InstallShield ResultCode $ResultCode."
    }

    if ((Get-Content -Path $SetupLog -Raw) -match '(?m)^\s*Reboot\s*=\s*1') {
        Write-Host "Setup reports a reboot is required."
        $ExitCode = 3010
    }
    else {
        $ExitCode = 0
    }
}
catch {
    Write-Error -Message $_.Exception.Message
    $ExitCode = 1
}
finally {
    Stop-Transcript | Out-Null
}
exit $ExitCode
