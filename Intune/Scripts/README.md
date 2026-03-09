# Intune Scripts

This folder contains utility and deployment scripts used with Intune, RMM workflows, and endpoint standardization tasks.

## Script index

- `Add-WingetPackage.ps1`
  - Ensures `winget` is present by downloading/installing the Microsoft package bundle when missing.

- `AddShortcuts.ps1`
  - Restores commonly used application shortcuts and includes telemetry/repair control options.

- `Detect-WingetInstalledApp.ps1`
  - Detects whether a specified winget package identifier is installed (default: `Microsoft.RemoteHelp`).

- `winget-detect.ps1`
  - Detect script variant for winget package presence with robust SYSTEM-context path handling and explicit detect exit behavior.

- `Enable-WindowsLapsEntraWithoutIntune.ps1`
  - Configures Windows LAPS policy via registry for Entra ID backup without requiring an Intune settings catalog policy.

- `Fix-BitlockerFVEConflict.ps1`
  - Reapplies BitLocker/FVE policy and prerequisite settings used to recover from policy conflict scenarios.

- `New-ItarianConfig.ps1`
  - Rebuilds and applies Itarian/Comodo client enrollment/configuration using a scheduled task workflow.

- `Set-AutomaticTimeZone.ps1`
  - Enables location consent and timezone auto-update service settings.

- `Set-CustomASRRules.ps1`
  - Applies Defender ASR and related hardening settings (supports parameterized action modes).

- `Set-CustomASRRules-Action1.ps1`
  - Action1-compatible variant of the ASR hardening script (no script-level parameter block).

- `Set-DellAutoOn.ps1`
  - Installs/updates Dell Command Configure (via winget when needed) and sets BIOS auto-on scheduling.

- `Set-DellCommandUpdateSettings.ps1`
  - Configures Dell Command Update preferences through registry values.

- `Set-NLA.ps1`
  - Enables Network Level Authentication for remote desktop sessions.

- `Sync-AppsGroups.ps1`
  - Syncs Intune discovered applications to Entra ID device groups per app/platform using Microsoft Graph.

- `Dell-SSDUpdate.pem`
  - Placeholder: PEM artifact retained for Dell update tooling workflows; exact consumption path should be documented.

## Usage notes

- Run as administrator or SYSTEM when required by the script.
- Review script parameters and defaults before deployment.
- Pilot in a test device group before broad rollout.
- Maintain script naming using `Verb-Noun.ps1` where practical.
