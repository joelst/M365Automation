#!/bin/zsh
set -euo pipefail

# Ensure audit_control exists
if [[ ! -e /etc/security/audit_control ]] && [[ -e /etc/security/audit_control.example ]]; then
  /bin/cp /etc/security/audit_control.example /etc/security/audit_control
fi

# Enable + start auditd (launchd)
# (Commands are consistent with published Sequoia/Tahoe STIG-style guidance)
/bin/launchctl enable system/com.apple.auditd
/bin/launchctl bootstrap system /System/Library/LaunchDaemons/com.apple.auditd.plist || true

# Initialize audit subsystem
/usr/sbin/audit -i

# Basic status check (non-fatal output)
LAUNCHD_RUNNING=$(/bin/launchctl print system | /usr/bin/grep -c -E '\tcom.apple.auditd' || true)
AUDITD_RUNNING=$(/usr/sbin/audit -c | /usr/bin/grep -c "AUC_AUDITING" || true)

echo "auditd_launchd_running=${LAUNCHD_RUNNING}"
echo "audit_status_AUC_AUDITING=${AUDITD_RUNNING}"
