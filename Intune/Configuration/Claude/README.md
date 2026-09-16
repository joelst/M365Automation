# Claude Desktop - Intune Deployment (Chat + optional Cowork)

Two independent Intune concerns, aimed at **separate assignment groups** during pilot:

| Component | Who gets it | Purpose |
|-----------|-------------|---------|
| **Win32 app – Claude Desktop** | Broad "Claude chat" group (and Cowork users) | Machine-wide MSIX; **chat works without Hyper-V** |
| **Proactive Remediation – Cowork prereqs** | Narrow "Claude Cowork" pilot/production group only | Enables Virtual Machine Platform + HCS services |

## How Claude behaves if virtualization is not ready

Anthropic’s enterprise docs and real-world behavior:

- **Chat works** if Claude is installed without Virtual Machine Platform. Users without admin historically get Claude but not Cowork.
- **Cowork is unavailable** until Virtual Machine Platform is enabled, the device is **Restarted** (not just shut down — Fast Startup can leave virtualization services uninitialized), and HCS services (`vmcompute`, `hns`) are running.
- **No reinstall is required** after virtualization is enabled later. The same provisioned MSIX picks up Cowork once the OS stack is healthy (users may need to fully quit/relaunch Claude or sign out/in).
- Wrong install context (per-user `Add-AppxPackage` / LOB MSIX as user) is a separate failure mode: Claude may appear installed but Cowork’s machine service never registers. This repo uses `Add-AppxProvisionedPackage` in **System** context to avoid that.

So for pilot: ship **chat widely**, enable **Cowork prereqs only for the Cowork group**. Order does not have to be “prereqs first, then Claude.”

```
Chat group:     Win32 Claude ──────────────────────────► chat ready
Cowork group:   Win32 Claude  (same app)  ─────────────► chat ready
                + Remediation (VMP/HCS) ──► Restart ──► Cowork ready
```

---

## 1. Win32 app – Claude Desktop (all Claude users)

**Scripts:** `Install-ClaudeMSIX.ps1`, `Uninstall-ClaudeMSIX.ps1`, `Detect-ClaudeMSIX.ps1`

### Package contents (source folder before IntuneWinAppUtil)

```
Claude\
  Install-ClaudeMSIX.ps1
  Uninstall-ClaudeMSIX.ps1
  Detect-ClaudeMSIX.ps1
  Claude-x64.msix      # https://claude.ai/api/desktop/win32/x64/msix/latest/redirect
  Claude-arm64.msix    # https://claude.ai/api/desktop/win32/arm64/msix/latest/redirect
```

The install script selects **x64 vs arm64** from `PROCESSOR_ARCHITECTURE`. Legacy name `Claude-latest.msix` is accepted on AMD64 only if `Claude-x64.msix` is missing.

```
IntuneWinAppUtil.exe -c "C:\Source\Claude" -s Install-ClaudeMSIX.ps1 -o "C:\Output"
```

### How the MSIX gets to the device

There is **no runtime download** from Anthropic during install.

1. You download `Claude-x64.msix` / `Claude-arm64.msix` once (build machine or pipeline).
2. You wrap them **inside** the Win32 content folder and run IntuneWinAppUtil → `.intunewin`.
3. Intune stores that package; **Intune Management Extension** downloads/extracts it to a local IME cache on the device.
4. `Install-ClaudeMSIX.ps1` runs as SYSTEM and calls `Add-AppxProvisionedPackage -PackagePath` against the **extracted local path** next to the script.

So delivery channel = **Intune Win32 app content**, not winget and not a live URL at install time. Keep both architectures in the package so one app works on AMD64 and ARM64.

### Program tab

| Field | Value |
|-------|--------|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-ClaudeMSIX.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-ClaudeMSIX.ps1` |
| Install behavior | **System** (required) |
| Device restart behavior | No specific action |

**Optional Cowork-gated install** (only if you want a *second* app that refuses to install until prereqs exist — usually unnecessary for pilot):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-ClaudeMSIX.ps1 -RequireCoworkPrereqs
```

Default install **does not** hard-fail on missing virtualization: it logs Cowork status and still provisions Claude for chat.

### Requirements tab

- OS architecture: 64-bit (covers AMD64; assign arm64 devices to the same app — the script picks the correct MSIX)
- Minimum OS: Windows 10 2004+ (prefer Windows 11 for Cowork pilots)
- **Do not** add the Cowork flag as a requirement on the general chat app

If you create a separate Cowork-gated Win32 app using `-RequireCoworkPrereqs`, then add:

| Rule | Value |
|------|--------|
| File exists | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude\ClaudeCoworkPrereqsReady.flag` |

### Detection rules

- Custom detection script: `Detect-ClaudeMSIX.ps1`
- Run as 32-bit: **No**
- Detects **only** `Get-AppxProvisionedPackage` (machine-wide). Winget / per-user AppX alone = **not installed**.

### Migrating devices that already have winget Claude

| Situation | What happens |
|-----------|----------------|
| Claude only via `winget install Anthropic.Claude` (SYSTEM or user) | Detection = not installed → install runs **once** |
| Install cleanup | Stops Claude, removes Squirrel if any, best-effort `winget uninstall Anthropic.Claude`, removes per-user AppX, then provisions bundled MSIX |
| After success | Detection finds provisioned package → exit 0 every check-in → **no loop** |
| Already provisioned by this app | Install exits 0 immediately (idempotent); no remove/re-add |

**Required to avoid fighting loops:** unassign/retire any **other** Intune app or remediation that still runs `winget install` / `winget upgrade` for `Anthropic.Claude`. Two owners (winget app + this Win32 app) will reinstall over each other.

For a version bump of **this** Win32 app where you need to replace the staged MSIX, either use supersedence so install re-runs, or set install command to:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-ClaudeMSIX.ps1 -ForceReprovision
```

### Return codes (important for soft retries)

| Code | Code type |
|------|-----------|
| 0 | Success |
| 1 | **Retry** (missing MSIX, provision failure) |
| 2 | **Retry** (only when `-RequireCoworkPrereqs` and prereqs missing) |

Without mapping 1/2 to Retry, early failures show as permanent **Failed** in Intune.

### Assignment

- **Required** → Entra ID / Intune group for **Claude chat** users (pilot or production)
- Include Cowork users in this group (or nest groups) so they get the same MSIX
- Exclude VDI without nested virtualization only if those devices should not get Claude at all; otherwise they still get chat

---

## 2. Proactive Remediation – Cowork prerequisites only

**Scripts:** `Detect-CoworkPrereqs.ps1` + `Remediate-CoworkPrereqs.ps1`

Assign **only** to the **Claude Cowork** group (pilot first). Chat-only devices should not get Hyper-V/VMP forced on.

| Field | Value |
|-------|--------|
| Detection script | `Detect-CoworkPrereqs.ps1` |
| Remediation script | `Remediate-CoworkPrereqs.ps1` |
| Run as logged-on credentials | **No** (SYSTEM) |
| Enforce signature check | No (unless you sign scripts) |
| **Run script in 64-bit PowerShell** | **Yes** |
| Schedule | **Hourly** during pilot → daily later |

### What it does

1. Enables `VirtualMachinePlatform` if needed  
2. Treats `EnablePending` as “wait for reboot” (does **not** re-enable every hour)  
3. Starts **`vmcompute`** and **`hns`** (Anthropic HCS stack; not full Hyper-V `vmms`)  
4. Writes `ClaudeCoworkPrereqsReady.flag` when healthy; **removes** the flag if services drift  

### Reboot guidance

- After feature enable, devices need a **Restart** (Start → Restart).  
- **Shutdown + power on** with Fast Startup can leave virtualization half-initialized.  
- Budget ~2 remediation cycles + at least one Restart before Cowork is ready.  
- This script does not force reboot; use Intune restart notifications or user comms if you need a controlled window.

### Logs (Collect diagnostics picks these up)

| Path | Source |
|------|--------|
| `...\Logs\Claude\ClaudeCowork-Detection.log` | Detection |
| `...\Logs\Claude\ClaudeCowork-Remediation.log` | Remediation |
| `...\Logs\Claude\Install-ClaudeMSIX.log` | Install |
| `...\Logs\Claude\Uninstall-ClaudeMSIX.log` | Uninstall |
| `...\Logs\Claude\ClaudeCoworkPrereqsReady.flag` | Ready marker |
| Application event log source `ClaudeCoworkMSIX` | Best-effort |

Full path prefix: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Claude\`

---

## 3. Recommended pilot group model

| Group | Win32 Claude | Cowork Remediation |
|-------|--------------|--------------------|
| `SG-Claude-Chat-Pilot` | Required | No |
| `SG-Claude-Cowork-Pilot` | Required (member of chat or direct assign) | Required |
| VDI / no nested virt | Optional chat only | **Exclude** |
| Production chat | Expand chat assignment | Still no |
| Production Cowork | Same MSIX | Expand remediation |

Cowork users who already have Claude from the chat app only need remediation + Restart; **do not** build a second MSIX just for Cowork.

---

## 4. AppLocker / WDAC

Confirm packaged apps / MSIX are allowed, or allowlist Claude. Otherwise Intune reports success but users cannot launch Claude.

---

## 5. Update ownership

Decide before rollout:

| Mode | Action |
|------|--------|
| **MDM-managed** (recommended for change control) | Set `disableAutoUpdates` via ADMX/config profile (`HKLM` policy — confirm current Anthropic path on pilot: often under `SOFTWARE\Policies\...`). Ship new MSIX versions through this Win32 app (version bump / supersedence). |
| **Self-managed** | Leave auto-update on; detection may need to follow Anthropic’s guidance (`Get-AppxPackage` version floor) so IME stays Installed after self-update. |

Install script does **not** write update policy — use a configuration profile so chat and Cowork share one policy.

---

## 6. Known pitfalls

- **Do not** “just elevate once as admin” on a standard user’s device to force Cowork. That can register services under the wrong context. Use SYSTEM provisioning + this remediation.  
- **Winget + this Win32 app together:** retire the winget deployment; leave only one installer.  
- **Squirrel + MSIX:** install/uninstall stop Claude/Update processes and remove `%LocalAppData%\AnthropicClaude` (including `Update.exe --uninstall` when present).  
- **VDI without nested virt:** Cowork cannot work; exclude from Cowork remediation group.  
- **hypervisorlaunchtype:** if VMware/VirtualBox is installed and Cowork still fails, check `bcdedit` for `hypervisorlaunchtype Auto`.  
- **Logged-on users** after first provision may need logoff/logon or a Restart before Start menu shows Claude for already-signed-in sessions.

---

## 7. Official references

- [Deploy Claude Desktop for Windows](https://support.claude.com/en/articles/12622703-deploy-claude-desktop-for-windows)  
- [Enterprise configuration](https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop)  

MSIX downloads:

- x64: https://claude.ai/api/desktop/win32/x64/msix/latest/redirect  
- arm64: https://claude.ai/api/desktop/win32/arm64/msix/latest/redirect  
