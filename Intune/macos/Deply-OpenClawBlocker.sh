#!/bin/bash
# OpenClaw/Clawdbot/Moltbot Blocker Deployment for Intune
# Handles: npm, Homebrew, manual installs

set -uo pipefail

LOG='/var/log/openclaw_blocker.log'
DAEMON_LABEL='com.company.block.openclaw'
DAEMON_PLIST='/Library/LaunchDaemons/com.company.block.openclaw.plist'
BLOCKER_SCRIPT='/Library/Scripts/block_openclaw.sh'
BLOCK_INTERVAL_SECONDS='300'

FAILURES=0
CRITICAL_FAILURE=0

log() {
    local MESSAGE="$1"
    printf '%s: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$MESSAGE" | tee -a "$LOG" >/dev/null
}

record_failure() {
    local SEVERITY="$1"
    local MESSAGE="$2"
    FAILURES=$((FAILURES + 1))
    if [ "$SEVERITY" = 'critical' ]; then
        CRITICAL_FAILURE=1
        log "ERROR: $MESSAGE"
    else
        log "WARN: $MESSAGE"
    fi
}

safe_rm() {
    local TARGET="$1"
    if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
        rm -rf "$TARGET" || record_failure 'warning' "Failed to remove $TARGET"
    fi
}

safe_kill_pattern() {
    local PATTERN="$1"
    local LINE
    local PID
    local CMD

    while IFS= read -r LINE; do
        PID="${LINE%% *}"
        CMD="${LINE#* }"

        case "$CMD" in
            *'/Library/Scripts/block_openclaw.sh'*)
                continue
                ;;
        esac

        if kill -TERM "$PID" 2>/dev/null; then
            sleep 1
            kill -0 "$PID" 2>/dev/null && kill -KILL "$PID" 2>/dev/null
        fi
    done < <(pgrep -fl "$PATTERN" 2>/dev/null)
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log 'ERROR: This script must run as root.'
    exit 1
fi

log 'Starting deployment'

CURRENT_USER="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
USER_UID=''
USER_HOME=''
HAS_LOGGED_IN_USER=0

if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != 'root' ] && [ "$CURRENT_USER" != 'loginwindow' ]; then
    USER_UID="$(id -u "$CURRENT_USER" 2>/dev/null || true)"
    USER_HOME="$(dscl . -read "/Users/$CURRENT_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
    if [ -n "$USER_UID" ] && [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
        HAS_LOGGED_IN_USER=1
        log "Active user detected: $CURRENT_USER ($USER_UID)"
    else
        log "No valid home directory found for detected user: $CURRENT_USER"
    fi
else
    log 'No active GUI user detected; skipping user-scoped cleanup.'
fi

# Stop target processes without matching this blocker script itself.
safe_kill_pattern 'openclaw|clawdbot|moltbot'
killall 'OpenClaw' 2>/dev/null || true

if [ "$HAS_LOGGED_IN_USER" -eq 1 ]; then
    safe_rm "$USER_HOME/.openclaw"
    safe_rm "$USER_HOME/.clawdbot"
    safe_rm "$USER_HOME/.moltbot"

    if command -v npm >/dev/null 2>&1; then
        sudo -u "$CURRENT_USER" npm uninstall -g openclaw clawdbot moltbot >/dev/null 2>&1 || \
            record_failure 'warning' 'npm uninstall returned a non-zero exit code.'
    else
        log 'npm not found; skipping npm uninstall.'
    fi

    if [ -x '/opt/homebrew/bin/brew' ]; then
        sudo -u "$CURRENT_USER" /opt/homebrew/bin/brew uninstall openclaw clawdbot moltbot >/dev/null 2>&1 || \
            record_failure 'warning' 'Homebrew uninstall (/opt/homebrew) returned a non-zero exit code.'
    fi

    if [ -x '/usr/local/bin/brew' ]; then
        sudo -u "$CURRENT_USER" /usr/local/bin/brew uninstall openclaw clawdbot moltbot >/dev/null 2>&1 || \
            record_failure 'warning' 'Homebrew uninstall (/usr/local) returned a non-zero exit code.'
    fi
fi

safe_rm '/usr/local/bin/openclaw'
safe_rm '/usr/local/bin/clawdbot'
safe_rm '/usr/local/bin/moltbot'
safe_rm '/opt/homebrew/bin/openclaw'
safe_rm '/opt/homebrew/bin/clawdbot'
safe_rm '/opt/homebrew/bin/moltbot'
safe_rm '/Applications/OpenClaw.app'

if [ "$HAS_LOGGED_IN_USER" -eq 1 ]; then
    safe_rm "$USER_HOME/Applications/OpenClaw.app"
    shopt -s nullglob
    for PLIST in "$USER_HOME"/Library/LaunchAgents/*openclaw* \
                 "$USER_HOME"/Library/LaunchAgents/*clawdbot* \
                 "$USER_HOME"/Library/LaunchAgents/*moltbot*; do
        if [ -f "$PLIST" ]; then
            launchctl bootout "gui/$USER_UID" "$PLIST" >/dev/null 2>&1 || true
            rm -f "$PLIST" || record_failure 'warning' "Failed to remove LaunchAgent: $PLIST"
        fi
    done
    shopt -u nullglob
fi

mkdir -p '/Library/Scripts' || record_failure 'critical' 'Failed to create /Library/Scripts.'

cat > "$BLOCKER_SCRIPT" << 'SCRIPT'
#!/bin/bash
set -uo pipefail

SLEEP_SECONDS="${1:-300}"
if ! [[ "$SLEEP_SECONDS" =~ ^[0-9]+$ ]]; then
    SLEEP_SECONDS='300'
fi

kill_targets() {
    local LINE
    local PID
    local CMD

    while IFS= read -r LINE; do
        PID="${LINE%% *}"
        CMD="${LINE#* }"

        case "$CMD" in
            *'/Library/Scripts/block_openclaw.sh'*)
                continue
                ;;
        esac

        if kill -TERM "$PID" 2>/dev/null; then
            sleep 1
            kill -0 "$PID" 2>/dev/null && kill -KILL "$PID" 2>/dev/null
        fi
    done < <(pgrep -fl 'openclaw|clawdbot|moltbot' 2>/dev/null)
}

while true; do
    kill_targets
    killall 'OpenClaw' 2>/dev/null || true
    rm -f /usr/local/bin/openclaw /usr/local/bin/clawdbot /usr/local/bin/moltbot
    rm -f /opt/homebrew/bin/openclaw /opt/homebrew/bin/clawdbot /opt/homebrew/bin/moltbot
    sleep "$SLEEP_SECONDS"
done
SCRIPT

if [ $? -ne 0 ]; then
    record_failure 'critical' 'Failed to write blocker script.'
fi

chmod 755 "$BLOCKER_SCRIPT" || record_failure 'critical' 'Failed to set blocker script permissions.'
chown root:wheel "$BLOCKER_SCRIPT" || record_failure 'critical' 'Failed to set blocker script ownership.'

cat > "$DAEMON_PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.block.openclaw</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/Library/Scripts/block_openclaw.sh</string>
        <string>$BLOCK_INTERVAL_SECONDS</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/var/log/openclaw_blocker_daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/openclaw_blocker_daemon.log</string>
</dict>
</plist>
PLIST

if [ $? -ne 0 ]; then
    record_failure 'critical' 'Failed to write LaunchDaemon plist.'
fi

chmod 644 "$DAEMON_PLIST" || record_failure 'critical' 'Failed to set LaunchDaemon plist permissions.'
chown root:wheel "$DAEMON_PLIST" || record_failure 'critical' 'Failed to set LaunchDaemon plist ownership.'

launchctl bootout system/$DAEMON_LABEL >/dev/null 2>&1 || true
launchctl bootstrap system "$DAEMON_PLIST" >/dev/null 2>&1 || record_failure 'critical' 'Failed to bootstrap LaunchDaemon.'
launchctl enable system/$DAEMON_LABEL >/dev/null 2>&1 || record_failure 'warning' 'Failed to enable LaunchDaemon.'
launchctl kickstart -k system/$DAEMON_LABEL >/dev/null 2>&1 || record_failure 'warning' 'Failed to kickstart LaunchDaemon.'

if [ "$CRITICAL_FAILURE" -eq 1 ]; then
    log "Deployment finished with critical failures. total_failures=$FAILURES"
    exit 1
fi

if [ "$FAILURES" -gt 0 ]; then
    log "Deployment finished with warnings. total_failures=$FAILURES"
else
    log 'Deployment complete'
fi

exit 0