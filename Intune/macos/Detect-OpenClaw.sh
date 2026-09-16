#!/bin/bash
# OpenClaw/Clawdbot/Moltbot Detection - Custom Attribute
# Multi-signal detection for inventory visibility; always exits 0 for Intune custom attributes.

set -uo pipefail

INDICATOR_COUNT=0
SIGNALS=''

PROCESS_HIT=0
PERSISTENCE_HIT=0
ARTIFACT_HIT=0
PORT_HIT=0
PACKAGE_HIT=0

add_signal() {
    local NAME="$1"
    INDICATOR_COUNT=$((INDICATOR_COUNT + 1))
    if [ -z "$SIGNALS" ]; then
        SIGNALS="$NAME"
    else
        SIGNALS="$SIGNALS,$NAME"
    fi
}

# Running process indicators (primary signal requested).
if pgrep -if 'openclaw|clawdbot|moltbot|clawd' >/dev/null 2>&1; then
    PROCESS_HIT=1
    add_signal 'process'
fi

# Persistence indicators: launchd labels/files across system and user contexts.
if launchctl list 2>/dev/null | grep -Eiq 'ai\.openclaw|com\.clawdbot|bot\.molt|openclaw|clawdbot|moltbot'; then
    PERSISTENCE_HIT=1
fi

if compgen -G '/Library/LaunchDaemons/*openclaw*' >/dev/null || \
   compgen -G '/Library/LaunchDaemons/*clawdbot*' >/dev/null || \
   compgen -G '/Library/LaunchDaemons/*moltbot*' >/dev/null; then
    PERSISTENCE_HIT=1
fi

# Artifact indicators: binaries/apps/config and credential/session traces.
if [ -f '/usr/local/bin/openclaw' ] || [ -f '/usr/local/bin/clawdbot' ] || [ -f '/usr/local/bin/moltbot' ] || \
   [ -f '/opt/homebrew/bin/openclaw' ] || [ -f '/opt/homebrew/bin/clawdbot' ] || [ -f '/opt/homebrew/bin/moltbot' ] || \
   [ -d '/Applications/OpenClaw.app' ]; then
    ARTIFACT_HIT=1
fi

# Port indicators associated with gateway/UI listeners.
if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:18789 -sTCP:LISTEN >/dev/null 2>&1 || \
       lsof -nP -iTCP:18793 -sTCP:LISTEN >/dev/null 2>&1; then
        PORT_HIT=1
    fi
fi

# Package indicators from npm/Homebrew installs.
if command -v npm >/dev/null 2>&1; then
    if npm list -g --depth=0 2>/dev/null | grep -Eiq 'openclaw|clawdbot|moltbot'; then
        PACKAGE_HIT=1
    fi
fi

if command -v brew >/dev/null 2>&1; then
    if brew list --formula 2>/dev/null | grep -Eiq 'openclaw|clawdbot|moltbot' || \
       brew list --cask 2>/dev/null | grep -Eiq 'openclaw|clawdbot|moltbot'; then
        PACKAGE_HIT=1
    fi
fi

# Check all user home directories for user-scoped traces.
for USER_HOME in /Users/*; do
    [ ! -d "$USER_HOME" ] && continue
    [ "$USER_HOME" = '/Users/Shared' ] && continue

    if [ -d "$USER_HOME/.openclaw" ] || [ -d "$USER_HOME/.clawdbot" ] || [ -d "$USER_HOME/.moltbot" ] || \
       [ -f "$USER_HOME/.openclaw/.env" ] || [ -f "$USER_HOME/.clawdbot/.env" ] || \
       compgen -G "$USER_HOME/.openclaw/credentials/*.json" >/dev/null || \
       compgen -G "$USER_HOME/.clawdbot/credentials/*.json" >/dev/null || \
       compgen -G "$USER_HOME/.openclaw/agents/*/sessions/*.jsonl" >/dev/null || \
       compgen -G "$USER_HOME/.clawdbot/agents/*/sessions/*.jsonl" >/dev/null || \
       [ -d "$USER_HOME/Applications/OpenClaw.app" ]; then
        ARTIFACT_HIT=1
    fi

    if compgen -G "$USER_HOME/Library/LaunchAgents/*openclaw*" >/dev/null || \
       compgen -G "$USER_HOME/Library/LaunchAgents/*clawdbot*" >/dev/null || \
       compgen -G "$USER_HOME/Library/LaunchAgents/*moltbot*" >/dev/null; then
        PERSISTENCE_HIT=1
    fi
done

if [ "$PERSISTENCE_HIT" -eq 1 ]; then
    add_signal 'persistence'
fi
if [ "$ARTIFACT_HIT" -eq 1 ]; then
    add_signal 'artifacts'
fi
if [ "$PORT_HIT" -eq 1 ]; then
    add_signal 'ports'
fi
if [ "$PACKAGE_HIT" -eq 1 ]; then
    add_signal 'packages'
fi

# Detection policy:
# - Any process hit is considered detected.
# - Otherwise require at least 2 independent indicators to reduce false positives.
if [ "$PROCESS_HIT" -eq 1 ] || [ "$INDICATOR_COUNT" -ge 2 ]; then
    echo "Detected (score=$INDICATOR_COUNT; signals=$SIGNALS)"
else
    echo "Not Detected (score=$INDICATOR_COUNT${SIGNALS:+; signals=$SIGNALS})"
fi

exit 0
