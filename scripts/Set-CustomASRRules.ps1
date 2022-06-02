<#
    Set-CustomASRRules.ps1

    Applies all ASR Rule Ids provided in the RuleIds parameter
    As-is no warranties, please test before using in production. 
    Please provide suggestions and updates via GitHub.

Joel Stidley
https://github.com/joelst

Reference: https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
- Block Persistance through WMI event subscription GUID: e6db77e5-3df2-4cf1-b95a-636979351e5b
- Block abuse of exploited vulnerable signed drivers GUID: 56a863a9-875e-4185-98a7-b882c64b5ce5
- Block executable files from running unless they meet a prevalence, age, or trusted list criterion. GUID: 01443614-cd74-433a-b99e-2ecdc07bfc25
- Block abuse of exploited vulnerable signed drivers GUID: 56a863a9-875e-4185-98a7-b882c64b5ce5
- Use advanced protection against ransomware GUID: c1db55ab-c21a-4637-bb3f-a12568109d35
#>
[CmdletBinding()]
param (
    # string array of all rule Ids to apply
    [Parameter()]
    [array]$RuleIds = @("e6db77e5-3df2-4cf1-b95a-636979351e5b", "d1e49aac-8f56-4280-b9ba-993a6d77406c", "01443614-cd74-433a-b99e-2ecdc07bfc25", "56a863a9-875e-4185-98a7-b882c64b5ce5", "c1db55ab-c21a-4637-bb3f-a12568109d35"),
    # Type of action. Can be Enabled, AuditMode, Warn, Disabled
    [Parameter()]
    [string]
    [ValidateSet("Enabled", "Disabled", "AuditMode", "Warn")]
    $ActionType = "Enabled",
    # Switch to force overwriting existing rules with the rules provided in RuleIds
    [Parameter()]
    [switch]$Overwrite
)

[string]$rules = ""
[string]$actions = ""

if ($Overwrite.IsPresent -eq $false) {
    # Get the existing rules, so we don't overwrite any
    $existingRuleIds = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    $RuleIds = + $existingRuleIds

}

$RuleIds = $RuleIds | Sort-Object -Unique 

Foreach ($ruleId in $RuleIds) {
    $rules += ",$ruleId"
    $actions += ",$ActionType"
}

$rules = $rules.TrimStart(",")
$actions = $actions.TrimStart(",")

Add-MpPreference -AttackSurfaceReductionRules_Ids $rules -AttackSurfaceReductionRules_Actions $actions
# Enable Potentially unwanted application protection
Set-MpPreference -PUAProtection Enabled