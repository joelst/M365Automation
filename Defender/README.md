# Defender Scripts

This folder contains Defender hardening, incident response (DFIR), and related security utility scripts.

## Quick Notes

- Run scripts from an elevated PowerShell session unless your RMM tool already runs as SYSTEM.
- Some scripts modify audit policy, event log settings, registry values, or SACL entries.
- Test in a lab or pilot ring before broad deployment.

## Script Index

### Disable-MSDTUrlProtocol.ps1
Disables the `ms-msdt` URL protocol handler by removing `HKCR\ms-msdt`.

Use case:
- Mitigation/hardening for MSDT protocol abuse scenarios (historical CVE-2022-30190 response).

### Enable-CISAuditLogging.ps1
Applies CIS-style Windows logging/auditing baseline controls.

What it can configure:
- Advanced Audit Policy subcategories.
- PowerShell logging (script block, module, transcription).
- Event log sizing and retention.
- Optional folder SACL auditing.

### Remove-FolderAuditing.ps1
Removes folder audit rules (SACL entries) from one or more paths.

Behavior:
- By default removes `Everyone` (S-1-1-0) rules.
- `-removeAll` clears all SACL entries on the target folder(s).

### Get-DGDeviceReadiness.ps1
Legacy Device Guard readiness/compliance assessment utility.

Purpose:
- Evaluates system readiness posture for Device Guard-related controls.
- Includes logging output under `C:\DGLogs`.

Notes:
- This is an advanced script with embedded policy/test data and should be validated in a test environment before production use.

### Invoke-DFIRCollection.ps1
Primary Windows incident response initial collection script.

Highlights:
- Forensic-first, read-only collection approach.
- Captures broad host state and artifacts (volatile data, Defender/ASR posture, registry views, persistence evidence, etc.).
- Produces output under `C:\ProgramData\IR` with hash manifest and packaged artifacts.

### Invoke-DFIRCollection-Action1.ps1
Action1-compatible variant of the DFIR collection script.

Differences from the primary version:
- Designed for Action1 execution model.
- Avoids script-level constructs that can conflict with Action1 handling.
- Keeps the same collection intent and similar evidence output structure.

### Invoke-DFIRSearching.ps1
Post-collection/event-log search helper for selected Security event IDs over a defined date range.

Current behavior:
- Filters IDs such as `4688`, `4624`, `4625`, `4648`, `4657`, `4720`, and `4732`.
- Exports matching events to CSV.
- Requires you to set input/output paths in the script before running.

## Suggested Workflow

1. Apply baseline logging controls with `Enable-CISAuditLogging.ps1`.
2. During incident triage, run `Invoke-DFIRCollection.ps1` (or `Invoke-DFIRCollection-Action1.ps1` when using Action1).
3. Use `Invoke-DFIRSearching.ps1` for targeted event extraction.
4. If needed, clean up folder auditing with `Remove-FolderAuditing.ps1`.

## Safety and Validation

- Review script parameters and defaults before execution.
- Prefer pilot deployment and change tracking for hardening scripts.
- Preserve generated DFIR outputs as evidence and maintain chain-of-custody procedures where required.
