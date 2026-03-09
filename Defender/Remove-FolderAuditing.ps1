<#
.SYNOPSIS
    Removes audit rules (SACL entries) from specified folders.

.DESCRIPTION
    Removes file system audit rules from one or more folders. By default removes
    all audit rules for the Everyone (S-1-1-0) principal, matching the rules set
    by Enable-CISAuditLogging.ps1. Use -RemoveAll to clear every audit rule
    regardless of principal.

    Run from an elevated PowerShell session.

.PARAMETER path
    One or more folder paths to remove auditing from.

.PARAMETER removeAll
    When specified, removes all SACL entries on the folder, not just Everyone.

.EXAMPLE
    .\Remove-FolderAuditing.ps1 -path 'C:\SensitiveData'

.EXAMPLE
    .\Remove-FolderAuditing.ps1 -path 'C:\Folder1', 'C:\Folder2' -removeAll
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string[]]$path,

  [Parameter()]
  [switch]$removeAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  [CmdletBinding()]
  param()

  try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  catch {
    return $false
  }
}

if (-not (Test-IsAdmin)) {
  Write-Error 'This script must be run as Administrator to modify audit rules.'
  exit 1
}

foreach ($folder in $path) {
  if (-not (Test-Path -Path $folder)) {
    Write-Warning "Folder not found, skipping: $folder"
    continue
  }

  try {
    $acl = Get-Acl -Path $folder -Audit

    $rules = $acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])
    if ($rules.Count -eq 0) {
      Write-Verbose "No audit rules found on: $folder"
      continue
    }

    $removed = 0
    foreach ($rule in $rules) {
      if ($removeAll -or $rule.IdentityReference.Value -eq 'S-1-1-0') {
        $acl.RemoveAuditRule($rule) | Out-Null
        $removed++
      }
    }

    if ($removed -gt 0) {
      Set-Acl -Path $folder -AclObject $acl
      Write-Output "Removed $removed audit rule(s) from: $folder"
    }
    else {
      Write-Verbose "No matching audit rules to remove on: $folder"
    }
  }
  catch {
    Write-Warning "Failed to process '$folder': $($_.Exception.Message)"
  }
}
