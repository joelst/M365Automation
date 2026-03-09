# See Microsoft 365 Apps Version history https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date#version-history

$targetVersions = @{
    'CurrentChannel'                        = [System.Version]::Parse('16.0.17231.20236')
    'MonthlyEnterpriseChannel2'             = [System.Version]::Parse('16.0.17126.20190')
    'MonthlyEnterpriseChannel1'             = [System.Version]::Parse('16.0.17029.20178')
    'Semi-AnnualEnterpriseChannel(Preview)' = [System.Version]::Parse('16.0.16731.20550')
    'Semi-AnnualEnterpriseChannel1'         = [System.Version]::Parse('16.0.16130.20916')
    'Semi-AnnualEnterpriseChannel2'         = [System.Version]::Parse('16.0.15601.20870')
    'CurrentChannel(Preview)'               = [System.Version]::Parse('16.0.17231.20236')
}

$configuration = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction SilentlyContinue
$displayVersion = $null

if ($null -eq $configuration -or [string]::IsNullOrWhiteSpace($configuration.VersionToReport)) {
    throw "$(Get-Date) Unable to parse Office Version"
}

try {
    $displayVersion = [System.Version]::Parse($configuration.VersionToReport)
}
catch {
    throw "$(Get-Date) Unable to parse Office Version"
}

if ($displayVersion) {

    Write-Output ("$(Get-Date) Discovered VersionToReport {0}" -f $displayVersion.ToString())

    $targetVersion = $targetVersions.Values | Where-Object { $_.Build -eq $displayVersion.Build } | Select-Object -Unique -First 1

    $targetVersionText = if ($null -ne $targetVersion) { $targetVersion.ToString() } else { 'Unknown' }
    Write-Output ('Mapped minimum target version to {0}' -f $targetVersionText)

    if ($null -eq $targetVersion -or $displayVersion -lt $targetVersion) {
        Write-Output ('Current Office365 Version {0} is lower than specified target version {1}' -f $displayVersion.ToString(), $targetVersionText)
        Write-Output 'Triggering remediation...'
        exit 1
    }
    else {
        Write-Output ('Current Office365 Version {0} matches specified target version {1}' -f $displayVersion.ToString(), $targetVersionText)
        exit 0
    }
}
else {
    throw "$(Get-Date) Unable to parse Office Version"
}