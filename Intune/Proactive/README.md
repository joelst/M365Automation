# Intune Proactive Remediations

This folder contains Intune Proactive Remediation packages and helper scripts used to detect and remediate endpoint configuration drift.

## How this folder is organized

- Most remediation packages are in subfolders (for example: `BitlockerHealth`, `AutoTimezone`, `M365-Apps`).
- Typical package pattern:
  - `detect.ps1` returns `0` when compliant and `1` when remediation is needed.
  - `remediate.ps1` applies the fix and returns `0` on success.
- A few top-level scripts are included for one-off or reusable remediation logic.

## Top-level scripts

- `New-DesktopShortcutCleanup.ps1`
  - Proactive detection/remediation script for duplicate desktop shortcuts (Edge/Teams) in user profile/OneDrive desktop paths.

- `New-ProactiveLSARunAs.ps1`
  - Detects and enforces `RunAsPPL` (LSA protection) in `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

- `Set-LocalAccountPolicy.ps1`
  - Applies local account policy settings using `net accounts` (minimum password length/age and lockout controls).

## Remediation package subfolders

- `AddWingetSystem`
  - Placeholder: package purpose not yet documented.
- `AutoTimezone`
  - Placeholder: package purpose not yet documented.
- `Bitlocker`
  - Placeholder: package purpose not yet documented.
- `BitlockerHealth`
  - Placeholder: package purpose not yet documented.
- `BrotherPrinterApp`
  - Placeholder: package purpose not yet documented.
- `BugCheck`
  - Placeholder: package purpose not yet documented.
- `Chrome`
  - Placeholder: package purpose not yet documented.
- `DellApps`
  - Placeholder: package purpose not yet documented.
- `DellBios`
  - Placeholder: package purpose not yet documented.
- `Disable-LocalPwdStorage`
  - Placeholder: package purpose not yet documented.
- `Edge`
  - Placeholder: package purpose not yet documented.
- `HKCU`
  - Placeholder: package purpose not yet documented.
- `LocalAdminAccount`
  - Placeholder: package purpose not yet documented.
- `M365-Apps`
  - Placeholder: package purpose not yet documented.
- `OldProfiles`
  - Placeholder: package purpose not yet documented.
- `PrinterApps`
  - Placeholder: package purpose not yet documented.
- `Uptime`
  - Placeholder: package purpose not yet documented.

## Authoring and usage notes

- Keep detection non-mutating whenever possible.
- Write clear output strings for Intune reporting and troubleshooting.
- Preserve explicit exit code contracts (`0` compliant/success, `1` non-compliant/failure-to-remediate).
- Test in SYSTEM context before broad assignment.
- Prefer pairing each package with consistent detect/remediate naming and a short internal header describing intent.
