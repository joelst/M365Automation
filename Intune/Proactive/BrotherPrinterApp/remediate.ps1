[CmdletBinding()]
param()

$appId = '9PG9S0WQV5WH'

function Get-WingetCmd {
  [CmdletBinding()]
  param ()

  try {
    $wingetCandidates = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe" -ErrorAction Stop |
      Sort-Object -Property { $_.VersionInfo.FileVersionRaw }

    if ($wingetCandidates) {
      return $wingetCandidates[-1].FullName
    }
  }
  catch {
  }

  $userWinget = "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe"
  if (Test-Path $userWinget) {
    return $userWinget
  }

  return $null
}

function Test-AppInstalled {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$WingetPath,

    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  $output = & $WingetPath list --id $PackageId --exact --accept-source-agreements --disable-interactivity 2>&1
  return [bool]($output | Select-String -SimpleMatch $PackageId)
}

$winget = Get-WingetCmd
if (-not $winget) {
  Write-Output 'Remediation failed: winget was not found.'
  exit 1
}

if (-not (Test-AppInstalled -WingetPath $winget -PackageId $appId)) {
  Write-Output "Remediation not required: package is already absent ($appId)."
  exit 0
}

& $winget uninstall --id $appId --exact --scope user --silent --accept-source-agreements --disable-interactivity 2>&1 | Out-Null

if (Test-AppInstalled -WingetPath $winget -PackageId $appId) {
  Write-Output "Remediation failed: package is still installed ($appId)."
  exit 1
}

Write-Output "Remediation succeeded: package removed ($appId)."
exit 0