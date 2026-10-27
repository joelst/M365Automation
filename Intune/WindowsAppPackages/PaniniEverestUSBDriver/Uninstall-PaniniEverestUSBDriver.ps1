<#
    .SYNOPSIS
        Silently uninstalls the Panini Everest USB Driver for Intune Win32 deployment.

    .DESCRIPTION
        The original setup launcher ignores -removeonly and offers to reinstall, so removal
        runs the cached maintenance setup from the ARP UninstallString with a recorded
        response file (uninstall.iss). It removes the driver, the driver store entry, the
        program files, the registry key and the Panini root certificate.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $False)]
    [System.String] $LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs",

    [Parameter(Mandatory = $False)]
    [System.String] $ProductCode = "{2B580190-33FA-40B9-92EA-C08B3466F45D}"
)

$ResponseFile = Join-Path -Path $PSScriptRoot -ChildPath "uninstall.iss"
$SetupLog = Join-Path -Path $LogPath -ChildPath "PaniniEverestUSBDriver-Uninstall-Setup.log"
Start-Transcript -Path (Join-Path -Path $LogPath -ChildPath "PaniniEverestUSBDriver-Uninstall.log") -Append | Out-Null

function Get-InstallShieldResultCode {
    param ([System.String] $Path)
    if (-not (Test-Path -Path $Path)) { return $null }
    $match = Select-String -Path $Path -Pattern '^\s*ResultCode\s*=\s*(-?\d+)' | Select-Object -First 1
    if ($match) { return [int]$match.Matches[0].Groups[1].Value }
    return $null
}

try {
    $UninstallKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
    if (-not (Test-Path -Path $UninstallKey)) {
        Write-Host "Panini Everest USB Driver is not installed, nothing to do."
        $ExitCode = 0
    }
    else {
        $CachedSetup = "${env:ProgramFiles(x86)}\InstallShield Installation Information\$ProductCode\setup.exe"
        if (-not (Test-Path -Path $CachedSetup)) { throw "Cached maintenance setup not found: $CachedSetup." }
        if (-not (Test-Path -Path $ResponseFile)) { throw "Response file not found: $ResponseFile." }

        Remove-Item -Path $SetupLog -Force -ErrorAction SilentlyContinue

        $ArgList = "-runfromtemp -l0x0409 -removeonly /s /f1`"$ResponseFile`" /f2`"$SetupLog`""
        Write-Host "Executing: $CachedSetup $ArgList"
        $process = Start-Process -FilePath $CachedSetup -ArgumentList $ArgList -Wait -PassThru -NoNewWindow
        Write-Host "Setup exit code: $($process.ExitCode)"

        $ResultCode = Get-InstallShieldResultCode -Path $SetupLog
        Write-Host "InstallShield ResultCode: $ResultCode"
        if ($null -eq $ResultCode) { throw "No ResultCode found in $SetupLog." }
        if ($ResultCode -ne 0) { throw "Uninstall failed with InstallShield ResultCode $ResultCode." }

        if ((Get-Content -Path $SetupLog -Raw) -match '(?m)^\s*Reboot\s*=\s*1') {
            Write-Host "Setup reports a reboot is required."
            $ExitCode = 3010
        }
        else {
            $ExitCode = 0
        }
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
