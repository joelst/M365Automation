<#
.SYNOPSIS
    Configures Windows Defender ASR rules and security hardening aligned to CIS Windows 11 Enterprise v3.0.0.

.DESCRIPTION
    Applies comprehensive security hardening:
    - 19 Attack Surface Reduction rules (16 CIS + 3 organizational/preview)
    - Defender cloud protection, PUA, Network Protection, Controlled Folder Access
    - ~50 registry hardening settings (UAC, WinRM, Firewall, SMB, RDP, LDAP, etc.)
    - Local account policies (password length, lockout)
    - PowerShell v2 removal, DEP enforcement

    Works with Intune, standard CLI, or any deployment tool that runs .ps1 files.
    For Action1 RMM (no param block), use Set-CustomASRRules-Action1.ps1.

    CIS control IDs are annotated inline. (L1) = Level 1, (L2) = Level 2, Org = beyond CIS.

.PARAMETER ActionType
    Action for ASR rules: Enabled, Disabled, AuditMode, Warn. Default: Enabled.

.PARAMETER Overwrite
    Replace existing ASR rules instead of merging with current configuration.

.EXAMPLE
    .\Set-CustomASRRules.ps1
    .\Set-CustomASRRules.ps1 -ActionType AuditMode
    .\Set-CustomASRRules.ps1 -Overwrite

.NOTES
    Author: Joel Stidley
    Requirements: Admin privileges, Windows 10/11 or Server 2016+

.LINK
    https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
#>
[CmdletBinding()]
param(
    [ValidateSet('Enabled', 'Disabled', 'AuditMode', 'Warn')]
    [string]$ActionType = 'Enabled',

    [switch]$Overwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- Event log initialization (silently skipped on failure) ---
$script:_EvtSrc = 'Intune Security Script'
$script:_EvtOk = $false
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists($script:_EvtSrc)) {
        New-EventLog -LogName Application -Source $script:_EvtSrc -ErrorAction Stop
    }
    $script:_EvtOk = $true
} catch { $script:_EvtOk = $false }

$WriteLog = {
    param([string]$Type, [string]$Msg)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$ts] $Type : $Msg"
    if ($script:_EvtOk) {
        $et = switch ($Type) { 'ERROR' { 'Error' } 'WARNING' { 'Warning' } default { 'Information' } }
        Write-EventLog -LogName Application -Source $script:_EvtSrc -EventId 1000 -EntryType $et -Message $Msg -ErrorAction SilentlyContinue
    }
}

$SetReg = {
    param([string]$Path, [string]$Name, $Value, [string]$Type)
    $Type = $Type.Replace('REG_', '')
    if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    & $WriteLog -Type 'OK' -Msg "$Path\$Name = $Value"
}

& $WriteLog -Type 'INFO' -Msg "Starting security hardening (ActionType=$ActionType, Overwrite=$Overwrite)"

# SECTION 1: DEFENDER - ASR RULES & PROTECTION SETTINGS

$defenderAvailable = [bool]((Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue) -and (Get-Command -Name 'Set-MpPreference' -ErrorAction SilentlyContinue))

if ($defenderAvailable) {
    & $WriteLog -Type 'INFO' -Msg 'Defender cmdlets available - configuring ASR and protection settings'

    # ASR rule GUIDs - CIS 18.10.43.6.1.1 "Configure Attack Surface Reduction rules" (L1)
    # Individual rules: CIS 18.10.43.6.1.2 "Set the state for each ASR rule" (L1)
    $RuleIds = @(
        'e6db77e5-3df2-4cf1-b95a-636979351e5b'  # CIS 18.10.43.6.1.2 - Block persistence through WMI event subscription
        'd1e49aac-8f56-4280-b9ba-993a6d77406c'  # CIS 18.10.43.6.1.2 - Block process creations from PSExec and WMI
        '01443614-cd74-433a-b99e-2ecdc07bfc25'  # CIS 18.10.43.6.1.2 - Block executables unless prevalence/age/trust
        '56a863a9-875e-4185-98a7-b882c64b5ce5'  # CIS 18.10.43.6.1.2 - Block abuse of exploited vulnerable signed drivers
        'c1db55ab-c21a-4637-bb3f-a12568109d35'  # CIS 18.10.43.6.1.2 - Use advanced protection against ransomware
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a'  # CIS 18.10.43.6.1.2 - Block Office apps from creating child processes
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'  # CIS 18.10.43.6.1.2 - Block Adobe Reader from creating child processes
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'  # CIS 18.10.43.6.1.2 - Block credential stealing from LSASS
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'  # CIS 18.10.43.6.1.2 - Block executable content from email client/webmail
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc'  # CIS 18.10.43.6.1.2 - Block execution of potentially obfuscated scripts
        'd3e037e1-3eb8-44c8-a917-57927947596d'  # CIS 18.10.43.6.1.2 - Block JS/VBS from launching downloaded executables
        '3b576869-a4ec-4529-8536-b80a7769e899'  # CIS 18.10.43.6.1.2 - Block Office apps from creating executable content
        '26190899-1602-49e8-8b27-eb1d0a1ce869'  # CIS 18.10.43.6.1.2 - Block Office comms apps from creating child processes
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'  # CIS 18.10.43.6.1.2 - Block untrusted/unsigned processes from USB
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'  # CIS 18.10.43.6.1.2 - Block Win32 API calls from Office macros
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'  # CIS 18.10.43.6.1.2 - Block Office apps from injecting code into processes
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'  # Org - Block use of copied/impersonated system tools (beyond CIS)
        '33ddedf1-c6e0-47cb-833e-de6133960387'  # Org - Block rebooting machine in Safe Mode (preview, beyond CIS)
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6'  # Org - Block Webshell creation for Servers (server-specific, beyond CIS)
    )

    # Merge with existing rules unless overwriting
    if (-not $Overwrite) {
        try {
            $existingRules = (Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids
            if ($existingRules) {
                $existingRuleIds = $existingRules -split ',' | Where-Object { $_ -and $_.Trim() }
                $RuleIds += $existingRuleIds
            }
        }
        catch {
            & $WriteLog -Type 'WARNING' -Msg "Could not retrieve existing ASR rules: $($_.Exception.Message)"
        }
    }

    $RuleIds = $RuleIds | Sort-Object -Unique
    $actions = @($ActionType) * $RuleIds.Count

    # Apply ASR rules
    try {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $RuleIds -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
        & $WriteLog -Type 'OK' -Msg "$($RuleIds.Count) ASR rules applied"
    }
    catch {
        & $WriteLog -Type 'ERROR' -Msg "Failed to apply ASR rules: $($_.Exception.Message)"
    }

    # Verify
    try {
        $appliedCount = ((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids | Measure-Object).Count
        & $WriteLog -Type 'OK' -Msg "Verified $appliedCount ASR rules configured"
    }
    catch {
        & $WriteLog -Type 'WARNING' -Msg "Could not verify ASR rules: $($_.Exception.Message)"
    }

    # PUA protection - CIS 18.10.43.7.1 "Configure detection for potentially unwanted applications" (L1)
    try { Set-MpPreference -PUAProtection Enabled -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'PUA protection enabled' } catch { & $WriteLog -Type 'ERROR' -Msg "PUA: $($_.Exception.Message)" }

    # Network Protection - CIS 18.10.43.6.3.1 "Prevent users and apps from accessing dangerous websites" (L1)
    try { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Network Protection enabled' } catch { & $WriteLog -Type 'ERROR' -Msg "NetworkProtection: $($_.Exception.Message)" }

    # Controlled Folder Access - CIS 18.10.43.6.2.1 "Configure Controlled folder access" (L2 / Org)
    try { Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Controlled Folder Access enabled' } catch { & $WriteLog -Type 'ERROR' -Msg "CFA: $($_.Exception.Message)" }

    # Real-time protection - CIS 18.10.43.10.2 "Turn off real-time protection = Disabled" (L1)
    try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Real-time protection ensured enabled' } catch { & $WriteLog -Type 'ERROR' -Msg "RTP: $($_.Exception.Message)" }

    # Cloud-delivered protection - CIS 18.10.43.5.1 "Join Microsoft MAPS = Advanced MAPS" (L1)
    try { Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'MAPS reporting set to Advanced' } catch { & $WriteLog -Type 'ERROR' -Msg "MAPS: $($_.Exception.Message)" }

    # Sample submission - CIS 18.10.43.5.2 "Send file samples when further analysis is needed = Send safe samples" (L1)
    try { Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Sample submission set to SendSafeSamples' } catch { & $WriteLog -Type 'ERROR' -Msg "SampleSubmit: $($_.Exception.Message)" }

    # Cloud block level - Org hardening (sets aggressive cloud protection level)
    try { Set-MpPreference -CloudBlockLevel High -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Cloud block level set to High' } catch { & $WriteLog -Type 'ERROR' -Msg "CloudBlock: $($_.Exception.Message)" }

    # Cloud extended timeout - CIS 18.10.43.5.3 "Configure extended cloud check = 50 seconds" (L1)
    try { Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Cloud extended timeout set to 50s' } catch { & $WriteLog -Type 'ERROR' -Msg "CloudTimeout: $($_.Exception.Message)" }

    # Block at First Sight - Org hardening (complements CIS 18.10.43.5.1 cloud protection)
    try { Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'Block at First Sight ensured enabled' } catch { & $WriteLog -Type 'ERROR' -Msg "BAFS: $($_.Exception.Message)" }

    # AMSI script scanning - Org hardening (ensures AMSI integration is active for script inspection)
    try { Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop; & $WriteLog -Type 'OK' -Msg 'AMSI script scanning ensured enabled' } catch { & $WriteLog -Type 'ERROR' -Msg "ScriptScan: $($_.Exception.Message)" }
}
else {
    & $WriteLog -Type 'WARNING' -Msg 'Defender cmdlets not available - skipping ASR and protection settings'
}


# SECTION 2: REGISTRY HARDENING


& $WriteLog -Type 'INFO' -Msg 'Applying registry hardening settings...'

# Network security - CIS 18.6.14.1 "Prohibit installation and configuration of Network Bridge" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_AllowNetBridge_NLA' -Value 0 -Type 'DWORD'
# CIS 18.6.20.1 "Prohibit use of Internet Connection Sharing on your DNS domain network" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value 0 -Type 'DWORD'
# CIS 18.6.20.2 "Require domain users to elevate when setting a network's location" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_StdDomainUserSetLocation' -Value 1 -Type 'DWORD'
# Windows Installer - CIS 18.10.79.1 "Always install with elevated privileges = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Type 'DWORD'
# Adobe Reader - Org hardening (disable JavaScript in Adobe Acrobat, not a CIS Windows control)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -Name 'bDisableJavaScript' -Value 1 -Type 'DWORD'
# Autorun prevention - CIS 18.9.8.1 "Turn off Autoplay = All drives" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 -Type 'DWORD'
# CIS 18.9.8.2 "Set the default behavior for AutoRun = Do not execute" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutoRun' -Value 1 -Type 'DWORD'
# CIS 18.9.8.3 "Turn off Autoplay for non-volume devices = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Value 1 -Type 'DWORD'

# UAC settings
# CIS 18.9.16.2 "Do not display network selection UI = Enabled" / Enumerate admin accounts (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Value 0 -Type 'DWORD'
# CIS 2.3.17.2 "UAC: Apply UAC restrictions to local accounts on network logons" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0 -Type 'DWORD'
# CIS 2.3.17.3 "UAC: Behavior of the elevation prompt for standard users = Auto deny" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Value 0 -Type 'DWORD'
# CIS 2.3.17.1 "UAC: Behavior of the elevation prompt for administrators = Prompt for consent on secure desktop" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Type 'DWORD'
# CIS 2.3.17.7 "UAC: Run all administrators in Admin Approval Mode = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type 'DWORD'
# CIS 2.3.17.6 "UAC: Switch to the secure desktop when prompting for elevation = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1 -Type 'DWORD'

# Authentication and network security
# CIS 2.3.11.7 "Network security: LAN Manager authentication level = Send NTLMv2 only. Refuse LM & NTLM" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Type 'DWORD'
# CIS 2.3.10.7 "Network access: Restrict anonymous access to Named Pipes and Shares = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -Type 'DWORD'
# CIS 2.3.10.2 "Network access: Do not allow anonymous enumeration of SAM accounts = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Type 'DWORD'
# CIS 18.4.7 "Configure LSASS to run as a protected process = Enabled with UEFI Lock" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type 'DWORD'
# CIS 2.3.8.1 "Microsoft network client: Digitally sign communications (always) = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type 'DWORD'
# CIS 2.3.9.2 "Microsoft network server: Digitally sign communications (always) = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type 'DWORD'
# CIS 2.3.10.8 "Network access: Restrict anonymous access to Named Pipes and Shares = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Type 'DWORD'

# WinRM security
# CIS 18.10.89.1.3 "Allow Basic authentication (Client) = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Value 0 -Type 'DWORD'
# CIS 18.10.89.2.3 "Allow Basic authentication (Service) = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Value 0 -Type 'DWORD'
# CIS 18.10.89.1.4 "Allow unencrypted traffic (Client) = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Value 0 -Type 'DWORD'
# CIS 18.10.89.2.4 "Allow unencrypted traffic (Service) = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Value 0 -Type 'DWORD'
# CIS 18.10.89.1.2 "Allow Digest authentication = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Value 0 -Type 'DWORD'
# CIS 18.10.89.1.1 "Allow CredSSP authentication (Client) = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowCredSSP' -Value 0 -Type 'DWORD'
# CIS 18.10.89.2.1 "Allow CredSSP authentication (Service) = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowCredSSP' -Value 0 -Type 'DWORD'
# CIS 18.10.89.2.5 "Disallow WinRM from storing RunAs credentials = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Value 1 -Type 'DWORD'
# CIS 18.10.90.1 "Allow Remote Shell Access = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' -Name 'AllowRemoteShellAccess' -Value 0 -Type 'DWORD'

# Windows Firewall
# CIS 9.3.5 "Windows Firewall: Public: Settings: Apply local firewall rules = No" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'AllowLocalPolicyMerge' -Value 0 -Type 'DWORD'
# CIS 9.3.6 "Windows Firewall: Public: Settings: Apply local connection security rules = No" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'AllowLocalIPsecPolicyMerge' -Value 0 -Type 'DWORD'
# CIS 9.1.3 "Windows Firewall: Domain: Settings: Display a notification = No" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -Name 'DisableNotifications' -Value 1 -Type 'DWORD'
# CIS 9.2.3 "Windows Firewall: Private: Settings: Display a notification = No" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' -Name 'DisableNotifications' -Value 1 -Type 'DWORD'
# CIS 9.3.3 "Windows Firewall: Public: Settings: Display a notification = No" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -Name 'DisableNotifications' -Value 1 -Type 'DWORD'
# CIS 9.1.7 "Windows Firewall: Domain: Logging: Log dropped packets = Yes" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogDroppedPackets' -Value 1 -Type 'DWORD'
# CIS 9.1.8 "Windows Firewall: Domain: Logging: Size limit (KB) = 16384 or greater" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogFileSize' -Value 16384 -Type 'DWORD'
# CIS 9.2.7 "Windows Firewall: Private: Logging: Log dropped packets = Yes" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogDroppedPackets' -Value 1 -Type 'DWORD'
# CIS 9.2.8 "Windows Firewall: Private: Logging: Size limit (KB) = 16384 or greater" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging' -Name 'LogFileSize' -Value 16384 -Type 'DWORD'
# CIS 9.3.9 "Windows Firewall: Public: Logging: Log dropped packets = Yes" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' -Name 'LogDroppedPackets' -Value 1 -Type 'DWORD'
# CIS 9.3.10 "Windows Firewall: Public: Logging: Size limit (KB) = 16384 or greater" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging' -Name 'LogFileSize' -Value 16384 -Type 'DWORD'
# SMB security - CIS 18.4.8.1 "Configure SMB v1 client driver = Disable driver (Start=4)" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4 -Type 'DWORD'
# Remote assistance - CIS 18.10.56.1 "Configure Solicited Remote Assistance = Disabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Value 0 -Type 'DWORD'
# Internet Explorer - Org hardening (legacy browser security)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download' -Name 'RunInvalidSignatures' -Value 0 -Type 'DWORD'
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext' -Name 'VersionCheckEnabled' -Value 1 -Type 'DWORD'
# OneDrive - Org hardening (enable admin sync reports)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name 'EnableSyncAdminReports' -Value 1 -Type 'DWORD'
# Chrome - Org hardening (browser security, not a CIS Windows control)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'BackgroundModeEnabled' -Value 0 -Type 'DWORD'
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name 'BlockThirdPartyCookies' -Value 1 -Type 'DWORD'
# IP source routing - CIS 18.4.4 "MSS: (DisableIPSourceRouting IPv6) = Highest protection" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Type 'DWORD'
# CIS 18.4.3 "MSS: (DisableIPSourceRouting) = Highest protection" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Type 'DWORD'
# Spectre/Meltdown mitigations - CIS 18.4.1 speculation control (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverride' -Value 72 -Type 'DWORD'
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverrideMask' -Value 3 -Type 'DWORD'
# WDigest - CIS 18.4.9 "WDigest Authentication = Disabled" - prevent cleartext passwords in memory (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Type 'DWORD'
# RDP - CIS 18.10.57.3.9.5 "Require NLA for remote connections = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type 'DWORD'
# CIS 18.10.57.3.9.3 "Set client connection encryption level = High Level" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 3 -Type 'DWORD'
# CIS 18.10.57.3.9.2 "Require secure RPC communication = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Value 1 -Type 'DWORD'
# Disable Remote Registry service - CIS 5.27 "Remote Registry = Disabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' -Name 'Start' -Value 4 -Type 'DWORD'
# Disable Windows Script Host - Org hardening (mitigates wscript/cscript malware execution)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0 -Type 'DWORD'
# NetBIOS - CIS 18.4.6 "MSS: (NoNameReleaseOnDemand)" / P-node mitigates NBT-NS poisoning (L2)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Value 2 -Type 'DWORD'
# Disable LLMNR - CIS 18.6.4.1 "Turn off multicast name resolution = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Type 'DWORD'

# PrintNightmare mitigations
# CIS 18.7.7 "Point and Print Restrictions: NoWarningNoElevationOnInstall = Disabled (0)" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -Value 0 -Type 'DWORD'
# CIS 18.7.8 "Point and Print Restrictions: UpdatePromptSettings = 0 (Show warning and elevation prompt)" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'UpdatePromptSettings' -Value 0 -Type 'DWORD'
# CIS 18.7.5 "Limits print driver installation to Administrators = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Type 'DWORD'
# SEHOP - CIS 18.8.3 "Enable Structured Exception Handling Overwrite Protection (SEHOP) = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Value 0 -Type 'DWORD'
# LDAP encryption - CIS 2.3.11.6 "Network security: LDAP client signing requirements = Negotiate signing" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' -Name 'LDAPClientIntegrity' -Value 2 -Type 'DWORD'
# Value 2 = Require signing (exceeds CIS minimum of Negotiate signing)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' -Name 'LDAPClientSigning' -Value 2 -Type 'DWORD'
# Safe DLL search mode - CIS 2.3.1.1 "MSS: (SafeDllSearchMode) = Enabled" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Value 1 -Type 'DWORD'
# Include command line in process creation events - CIS 18.9.3.1 (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type 'DWORD'
# Disable password reveal button - CIS 18.9.16.1 "Do not display the password reveal button = Enabled" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Value 1 -Type 'DWORD'
# Early Launch Antimalware - CIS 18.9.13.1 "Boot-Start Driver Initialization Policy = Good and Unknown" (L1)
& $SetReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Value 8 -Type 'DWORD'

# Data Execution Prevention - CIS 18.3.1 DEP AlwaysOn (L1)
# NOTE: bcdedit changes alter BCD which can change TPM PCR measurements.
# If BitLocker is active, we must suspend protectors for one reboot to avoid a recovery key prompt.
try {
    $depStatus = & bcdedit.exe /enum '{current}' 2>&1 | Select-String -Pattern 'nx'
    if ($depStatus -and $depStatus -notmatch 'AlwaysOn') {
        $blVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($blVolume -and $blVolume.ProtectionStatus -eq 'On') {
            Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 -ErrorAction Stop | Out-Null
            & $WriteLog -Type 'OK' -Msg 'BitLocker suspended for 1 reboot (DEP change)'
        }
        & bcdedit.exe /set '{current}' nx AlwaysOn 2>&1 | Out-Null
        & $WriteLog -Type 'OK' -Msg 'DEP set to AlwaysOn'
    }
    else {
        & $WriteLog -Type 'OK' -Msg 'DEP already set to AlwaysOn'
    }
}
catch {
    & $WriteLog -Type 'WARNING' -Msg "Could not configure DEP: $($_.Exception.Message)"
}

# Screen lock inactivity timeout - CIS 18.8.1 "Machine inactivity limit = 600 seconds or fewer" (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 600 -Type 'DWORD'
# Screensaver policy - CIS 18.10.12.1 / 18.10.12.2 / 18.10.12.3 (enable, require password, 10-min timeout) (L1)
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '1' -Type 'String'
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Value '1' -Type 'String'
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Value '600' -Type 'String'
& $SetReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'BlockDomainPicturePassword' -Value '1' -Type 'DWORD'
& $WriteLog -Type 'OK' -Msg 'Registry hardening complete'

# SECTION 3: LOCAL ACCOUNT POLICY

# CIS 1.1.4 (minpwlen 12+), CIS 1.1.3 (minpwage 1+),
# CIS 1.2.1 (lockout duration 15+), CIS 1.2.2 (lockout threshold 5-10), CIS 1.2.3 (lockout window 15+) (L1)
& $WriteLog -Type 'INFO' -Msg 'Applying local account policies...'
& net.exe accounts /minpwlen:12 /minpwage:1 /lockoutduration:15 /lockoutthreshold:10 /lockoutwindow:15 | Out-Null
if ($LASTEXITCODE -eq 0) { & $WriteLog -Type 'OK' -Msg 'Local account policies applied' } else { & $WriteLog -Type 'ERROR' -Msg "net accounts failed with exit code $LASTEXITCODE" }

# SECTION 4: DISABLE POWERSHELL V2

# CIS 18.10.86.1 related; forces scripts through PS 5.1+ with AMSI and script block logging (L1)
try {
    $psV2 = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
    if ($psV2 -and $psV2.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction Stop
        & $WriteLog -Type 'OK' -Msg 'PowerShell v2 feature disabled'
    }
    else {
        & $WriteLog -Type 'OK' -Msg 'PowerShell v2 already disabled or not present'
    }
}
catch {
    & $WriteLog -Type 'WARNING' -Msg "Could not disable PowerShell v2: $($_.Exception.Message)"
}


& $WriteLog -Type 'SUCCESS' -Msg "All security hardening applied at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

exit 0
