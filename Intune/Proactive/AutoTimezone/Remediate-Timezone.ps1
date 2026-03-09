<#
.SYNOPSIS
Intune Proactive Remediation: force Central time zone on a specific network.

.DESCRIPTION
Verifies the same conditions as detection:
- Device has an IPv4 address within one of the configured subnets
- Current time zone is not Central

If the device is in a target subnet and not already Central:
- Sets time zone to "Central Standard Time"
- If tzautoupdate is currently Automatic/Manual (Start 2 or 3), disables tzautoupdate to prevent automatic changes

.NOTES
Exit 0 = remediation succeeded / not needed
Exit 1 = remediation failed
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function ConvertTo-IPv4UInt32 {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$ipAddress
	)

	# Avoid System.Net.IPAddress to stay compatible with Constrained Language Mode.
	$octets = $ipAddress -split '\.'
	if ($octets.Count -ne 4) {
		throw "Not an IPv4 address: $ipAddress"
	}

	$o0 = [int]$octets[0]
	$o1 = [int]$octets[1]
	$o2 = [int]$octets[2]
	$o3 = [int]$octets[3]
	foreach ($o in @($o0, $o1, $o2, $o3)) {
		if ($o -lt 0 -or $o -gt 255) {
			throw "Not an IPv4 address: $ipAddress"
		}
	}

	return ([uint32]$o0 -shl 24) -bor ([uint32]$o1 -shl 16) -bor ([uint32]$o2 -shl 8) -bor ([uint32]$o3)
}

function Test-IPv4InCidr {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$ipAddress,

		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$cidr
	)

	$parts = $cidr.Split('/')
	if ($parts.Count -ne 2) {
		throw "Invalid CIDR: $cidr"
	}

	$networkIp = $parts[0]
	$prefixLength = [int]$parts[1]
	if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
		throw "Invalid CIDR prefix length: $prefixLength"
	}

	$ipInt = ConvertTo-IPv4UInt32 -ipAddress $ipAddress
	$netInt = ConvertTo-IPv4UInt32 -ipAddress $networkIp

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

function Write-RemediationLog {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$message
	)

	$logDir = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\IntuneManagementExtension\Logs'
	if (-not (Test-Path -Path $logDir)) {
		New-Item -Path $logDir -ItemType Directory -Force | Out-Null
	}

	$logPath = Join-Path -Path $logDir -ChildPath 'TimeZoneFix.log'
	Add-Content -Path $logPath -Value "$(Get-Date -Format u) - $message"
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
		IsReady = $isReady
		ServiceStatus = if ($locationService) { [string]$locationService.Status } else { 'NotFound' }
		ServiceStart = $lfsvcStart
		PolicyDisableLocation = $policyDisableLocation
		PolicyDisableWindowsLocationProvider = $policyDisableWlp
		ConsentValue = $consentValue
	}
}

try {
	$tzAutoRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate'
	$tzAutoStart = (Get-ItemProperty -Path $tzAutoRegPath -Name 'Start' -ErrorAction SilentlyContinue).Start
	$isAutoTimeZoneEnabled = $tzAutoStart -in 2, 3

	$currentTimeZoneId = (Get-TimeZone).Id

	$targetCidrs = @(
		'192.168.30.0/24',
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
				if (Test-IPv4InCidr -ipAddress $ip -cidr $cidr) {
					$matchingIpDetails += "$ip($cidr)"
				}
			}
		}
		catch {
			# ignore parsing errors
		}
	}

	$isInTargetNetwork = $matchingIpDetails.Count -gt 0
	$targetTimeZoneId = 'Central Standard Time'
	$isCentralTimeZone = $currentTimeZoneId -eq $targetTimeZoneId

	if ($isInTargetNetwork) {
		$ips = if ($matchingIpDetails.Count -gt 0) { $matchingIpDetails -join ',' } else { '' }

		if ($isCentralTimeZone) {
			$msg = "No action: Already Central | TimeZoneId=$currentTimeZoneId | InTargetNetworks=Yes | AutoTimeZone=$isAutoTimeZoneEnabled (tzautoupdate Start=$tzAutoStart) | MatchingIp=$ips"
			Write-Output $msg
			Write-RemediationLog -message $msg
			exit 0
		}

		Write-Output "Remediating (Target Network): TimeZoneId=$currentTimeZoneId -> $targetTimeZoneId | InTargetNetworks=Yes | AutoTimeZone=$isAutoTimeZoneEnabled (tzautoupdate Start=$tzAutoStart) | MatchingIp=$ips"
		Set-TimeZone -Id $targetTimeZoneId

		# Auto time zone is wacky on these networks. If tzautoupdate is enabled, disable it.
		$disabledAutoTimeZone = $false
		if ($isAutoTimeZoneEnabled) {
			try {
				Stop-Service -Name tzautoupdate -Force -ErrorAction SilentlyContinue
				& sc.exe config tzautoupdate start= disabled | Out-Null
				Set-ItemProperty -Path $tzAutoRegPath -Name 'Start' -Value 4 -Force
				$disabledAutoTimeZone = $true
			}
			catch {
				$disabledAutoTimeZone = $false
			}
		}
	}
	else {
		# Off target networks: do not change auto/manual time zone settings or the current time zone.
		$msg = "No action (Off Target): InTargetNetworks=No | TimeZoneId=$currentTimeZoneId | AutoTimeZone=$isAutoTimeZoneEnabled (tzautoupdate Start=$tzAutoStart)"
		Write-Output $msg
		Write-RemediationLog -message $msg
		exit 0
	}

	# Optional time resync (best-effort)
	try {
		Start-Service -Name w32time -ErrorAction SilentlyContinue
		& w32tm.exe /resync /force | Out-Null
	}
	catch {
		# ignore resync failures
	}

	$finalTz = (Get-TimeZone).Id
	$finalTzAutoStart = (Get-ItemProperty -Path $tzAutoRegPath -Name 'Start' -ErrorAction SilentlyContinue).Start
	$msg = "Remediation complete: TimeZoneId=$finalTz | DisabledAutoTimeZone=$disabledAutoTimeZone | tzautoupdate Start=$finalTzAutoStart | MatchingIp=$($matchingIpDetails -join ',')"
	Write-Output $msg
	Write-RemediationLog -message $msg
	exit 0
}
catch {
	$err = "Remediation failed: $($_.Exception.Message)"
	Write-Output $err
	try { Write-RemediationLog -message $err } catch { }
	exit 1
}