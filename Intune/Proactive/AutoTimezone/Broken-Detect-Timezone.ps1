<#
.SYNOPSIS
Detection script for Intune Proactive Remediation.

.DESCRIPTION
Checks whether automatic time zone updates are enabled (tzautoupdate not disabled).
If the device has any IPv4 address in one of the configured subnets, the time zone must be Central.
If the device is not in those subnets, the time zone is not evaluated.

.NOTES
Exit 0 = healthy
Exit 1 = needs remediation
#>
[CmdletBinding()]
param()

function ConvertTo-IPv4UInt32 {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$IpAddress
  )

  $bytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
  if ($bytes.Count -ne 4) {
    throw "Not an IPv4 address: $IpAddress"
  }

  [Array]::Reverse($bytes)
  return [BitConverter]::ToUInt32($bytes, 0)
}

function Test-IPv4InCidr {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$IpAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Cidr
  )

  $parts = $Cidr.Split('/')
  if ($parts.Count -ne 2) {
    throw "Invalid CIDR: $Cidr"
  }

  $networkIp = $parts[0]
  $prefixLength = [int]$parts[1]
  if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
    throw "Invalid CIDR prefix length: $prefixLength"
  }

  $ipInt = ConvertTo-IPv4UInt32 -IpAddress $IpAddress
  $netInt = ConvertTo-IPv4UInt32 -IpAddress $networkIp

  $mask = if ($prefixLength -eq 0) {
    [uint32]0
  }
  else {
    # Windows PowerShell is strict when converting to [uint32]; keep the value in range.
    $mask32 = [uint64]([uint32]::MaxValue)
    [uint32](($mask32 -shl (32 - $prefixLength)) -band $mask32)
  }

  return (($ipInt -band $mask) -eq ($netInt -band $mask))
}

function Get-LocationReadiness {
  [CmdletBinding()]
  param()

  $locationService = Get-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
  $lfsvcStart = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc' -Name 'Start' -ErrorAction SilentlyContinue).Start

  $locationPolicies = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -ErrorAction SilentlyContinue
  $policyDisableLocation = $locationPolicies.DisableLocation
  $policyDisableWlp = $locationPolicies.DisableWindowsLocationProvider

  $consentValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -ErrorAction SilentlyContinue).Value

  $policyBlocksLocation = ($policyDisableLocation -eq 1) -or ($policyDisableWlp -eq 1)
  $consentAllowsLocation = ($null -eq $consentValue) -or ($consentValue -match 'Allow')
  $serviceNotDisabled = ($null -eq $lfsvcStart) -or ($lfsvcStart -ne 4)
  $serviceRunning = $locationService -and $locationService.Status -eq 'Running'

  $isReady = (-not $policyBlocksLocation) -and $consentAllowsLocation -and $serviceNotDisabled -and $serviceRunning

  [pscustomobject]@{
    IsReady                              = $isReady
    ServiceStatus                        = if ($locationService) { [string]$locationService.Status } else { 'NotFound' }
    ServiceStart                         = $lfsvcStart
    PolicyDisableLocation                = $policyDisableLocation
    PolicyDisableWindowsLocationProvider = $policyDisableWlp
    ConsentValue                         = $consentValue
  }
}

$tzAutoRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate'
$tzAutoStart = (Get-ItemProperty -Path $tzAutoRegPath -Name 'Start' -ErrorAction SilentlyContinue).Start
$currentTimeZoneId = (Get-TimeZone).Id

# "Set time zone automatically" generally maps to tzautoupdate not being disabled.
$isAutoTimeZoneEnabled = $tzAutoStart -in 2, 3
$isAutoTimeZoneDisabled = $tzAutoStart -eq 4

# Desired state:
# - If the device has any IPv4 address in any of these subnets, the time zone must be Central AND auto time zone must be OFF.
# - If the device is NOT in these subnets, do not enforce time zone or auto/manual state.
$targetCidrs = @(
  '10.35.20.0/23',
  '192.168.20.0/24',
  '192.168.60.0/24',
  '10.35.80.0/24',
  '192.168.80.0/24',
  '192.168.3.0/24'
)
$matchingIpDetails = @()
try {
  $ipv4Addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object {
      $_.IPAddress -and
      $_.IPAddress -ne '127.0.0.1' -and
      $_.IPAddress -notlike '169.254.*' -and
      $_.PrefixOrigin -ne 'WellKnown'
    } |
    Select-Object -ExpandProperty IPAddress
}
catch {
  $ipv4Addresses = @()
}

foreach ($ip in ($ipv4Addresses | Sort-Object -Unique)) {
  try {
    foreach ($cidr in $targetCidrs) {
      if (Test-IPv4InCidr -IpAddress $ip -Cidr $cidr) {
        $matchingIpDetails += "$ip($cidr)"
      }
    }
  }
  catch {
    # Ignore malformed addresses
  }
}

$isInTargetNetwork = $matchingIpDetails.Count -gt 0

$centralTimeZoneId = 'Central Standard Time'
$isCentralTimeZone = $currentTimeZoneId -eq $centralTimeZoneId

if ($isInTargetNetwork) {
  $ips = $matchingIpDetails -join ','

  if ($isCentralTimeZone -and $isAutoTimeZoneDisabled) {
    Write-Output "Healthy: TimeZoneId=$currentTimeZoneId | InTargetNetworks=Yes | MatchingIp=$ips | AutoTimeZone=Disabled (tzautoupdate Start=$tzAutoStart)"
    exit 0
  }

  $autoState = if ($isAutoTimeZoneDisabled) { 'Disabled' } elseif ($isAutoTimeZoneEnabled) { 'Enabled' } else { 'Unknown' }
  Write-Output "ISSUE DETECTED: TimeZoneId=$currentTimeZoneId | Expected=$centralTimeZoneId | InTargetNetworks=Yes | MatchingIp=$ips | AutoTimeZone=$autoState (tzautoupdate Start=$tzAutoStart)"
  exit 1
}

if (-not $isInTargetNetwork) {
  $autoState = if ($isAutoTimeZoneDisabled) { 'Disabled' } elseif ($isAutoTimeZoneEnabled) { 'Enabled' } else { 'Unknown' }
  Write-Output "Healthy: InTargetNetworks=No | TimeZoneId=$currentTimeZoneId | AutoTimeZone=$autoState (tzautoupdate Start=$tzAutoStart)"
  exit 0
}

# Fallback (should not be reached)
Write-Output 'ISSUE DETECTED: Unexpected state'
exit 1