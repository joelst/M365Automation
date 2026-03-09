[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$AppToDetect = 'Microsoft.RemoteHelp'
)

function Get-WingetCmd {
  [CmdletBinding()]
  param ()

  $wingetCmd = $null

  try {
    # In system context, winget lives under the WindowsApps package path.
    $wingetInfo = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe" -ErrorAction Stop |
      Sort-Object -Property { $_.VersionInfo.FileVersionRaw }

    if ($wingetInfo) {
      $wingetCmd = $wingetInfo[-1].FullName
    }
  }
  catch {
    if (Test-Path "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe") {
      $wingetCmd = "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe"
    }
  }

  return $wingetCmd
}

$winget = Get-WingetCmd
if (-not $winget) {
  Write-Output 'Not installed: WinGet executable was not found.'
  exit 1
}

$jsonFile = Join-Path -Path $env:TEMP -ChildPath ("InstalledApps-{0}.json" -f ([guid]::NewGuid().ToString('N')))

try {
  & $winget export -o $jsonFile --accept-source-agreements | Out-Null

  if (-not (Test-Path $jsonFile)) {
    Write-Output 'Not installed: Unable to enumerate installed apps.'
    exit 1
  }

  $json = Get-Content -Path $jsonFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

  $packages = @()
  foreach ($source in @($json.Sources)) {
    if ($source.Packages) {
      $packages += @($source.Packages)
    }
  }

  $app = $packages | Where-Object { $_.PackageIdentifier -eq $AppToDetect } | Select-Object -First 1
  if ($app) {
    Write-Output "Installed: $AppToDetect"
    exit 0
  }

  Write-Output "Not installed: $AppToDetect"
  exit 1
}
catch {
  Write-Output "Not installed: detection failed with error: $($_.Exception.Message)"
  exit 1
}
finally {
  if (Test-Path $jsonFile) {
    Remove-Item -Path $jsonFile -Force -ErrorAction SilentlyContinue
  }
}