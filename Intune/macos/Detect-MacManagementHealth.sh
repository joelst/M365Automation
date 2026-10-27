#!/bin/bash
# Report the macOS management signals that fail SILENTLY.
#
# Each of these breaks something important while leaving the Mac looking healthy in Intune:
#
#   Platform SSO not registered  -> user keeps signing in manually; Company Portal shows
#   "Registration required" and nothing escalates it.
#   Bootstrap token not escrowed -> on Apple silicon, MDM-initiated OS updates download,
#   reboot, fail to get authorization and revert. The device
#   reports the update as offered and applied. This is the one
#   that makes declarative update enforcement a no-op.
#   FileVault off                -> fails 'macOS: Base compliance', which gates Conditional
#                                   Access, which is what actually stops the user working.
#   Clock drift                  -> Entra token validation fails while TLS keeps working, so
#                                   MDM check-in succeeds and sign-in does not.
#
# Run as SYSTEM. Platform SSO registration is per-user state, so the PSSO check is executed as
# the console user via launchctl asuser rather than as root, which would report nothing.
#
# Detection only. It nudges but never remediates: PSSO registration requires the user to
# authenticate, so no script can complete it, and a script that pretended to would just hide
# the problem. Set NUDGE_USER=0 to suppress the prompt entirely.
#
# Exit 0 = healthy, or state could not be determined.
# Exit 1 = at least one signal is broken.

set -uo pipefail

NUDGE_USER=1
NUDGE_STAMP='/var/db/.gg_psso_nudge'
NUDGE_INTERVAL_HOURS=24

PROBLEMS=''
UNCERTAIN=''

add_problem() {
    if [ -z "$PROBLEMS" ]; then PROBLEMS="$1"; else PROBLEMS="$PROBLEMS,$1"; fi
}
add_unknown() {
    if [ -z "$UNCERTAIN" ]; then UNCERTAIN="$1"; else UNCERTAIN="$UNCERTAIN,$1"; fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "UNKNOWN (must run as system; set the Intune script to run as root)"
    exit 0
fi

OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo '0')"
ARCH="$(uname -m 2>/dev/null || echo 'unknown')"

# The console user, excluding the login window and root. Without a real console user there is
# no per-user state to inspect, so the PSSO check is skipped rather than reported as failed.
CONSOLE_USER="$(stat -f '%Su' /dev/console 2>/dev/null)"
case "$CONSOLE_USER" in
    ''|root|_mbsetupuser|loginwindow) CONSOLE_USER='' ;;
esac

# ---------------------------------------------------------------------------
# Platform SSO
# ---------------------------------------------------------------------------
PSSO_STATE='skipped'

if [ -z "$CONSOLE_USER" ]; then
    PSSO_STATE='no-console-user'
elif ! command -v app-sso >/dev/null 2>&1; then
    PSSO_STATE='app-sso-missing'
    add_unknown 'psso'
else
    CONSOLE_UID="$(id -u "$CONSOLE_USER" 2>/dev/null)"
    PSSO_OUT="$(launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" app-sso platform -s 2>/dev/null)"

    if [ -z "$PSSO_OUT" ]; then
        PSSO_STATE='no-output'
        add_unknown 'psso'
    else
        # Match on the field rather than parsing the whole structure: the output is a nested
        # dump whose shape is not documented and has changed between releases, but
        # registrationCompleted is the documented signal.
        REG_LINE="$(echo "$PSSO_OUT" | grep -i 'registrationCompleted' | head -n 1)"
        if [ -z "$REG_LINE" ]; then
            PSSO_STATE='not-configured'
            add_problem 'psso_not_configured'
        elif echo "$REG_LINE" | grep -Eiq 'true|= *1|: *1'; then
            PSSO_STATE='registered'
        else
            PSSO_STATE='not-registered'
            add_problem 'psso_not_registered'
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Bootstrap token -- only meaningful on Apple silicon
# ---------------------------------------------------------------------------
BOOTSTRAP='n/a'

if [ "$ARCH" = 'arm64' ]; then
    BT_OUT="$(profiles status -type bootstraptoken 2>/dev/null)"
    if [ -z "$BT_OUT" ]; then
        BOOTSTRAP='unknown'
        add_unknown 'bootstrap_token'
    elif echo "$BT_OUT" | grep -iq 'escrowed to server: YES'; then
        BOOTSTRAP='escrowed'
    else
        BOOTSTRAP='not-escrowed'
        add_problem 'bootstrap_token_not_escrowed'
    fi
fi

# ---------------------------------------------------------------------------
# FileVault -- required by macOS: Base compliance
# ---------------------------------------------------------------------------
FV_OUT="$(fdesetup status 2>/dev/null)"
if [ -z "$FV_OUT" ]; then
    FILEVAULT='unknown'
    add_unknown 'filevault'
elif echo "$FV_OUT" | grep -iq 'FileVault is On'; then
    FILEVAULT='on'
else
    FILEVAULT='off'
    add_problem 'filevault_off'
fi

# ---------------------------------------------------------------------------
# Clock drift -- the failure that looks like everything else
# ---------------------------------------------------------------------------
NETWORK_TIME="$(/usr/sbin/systemsetup -getusingnetworktime 2>/dev/null | sed -n 's/^Network Time: //p')"
if [ -z "$NETWORK_TIME" ]; then
    add_unknown 'network_time'
elif [ "$NETWORK_TIME" != 'On' ]; then
    add_problem 'network_time_off'
fi

# ---------------------------------------------------------------------------
# Nudge, not remediate
# ---------------------------------------------------------------------------
# Opening Company Portal re-presents the registration prompt a user may have dismissed. Rate
# limited, because a prompt that appears on every scheduled run trains people to close it
# without reading -- which is how the original notification got dismissed in the first place.
if [ "$NUDGE_USER" -eq 1 ] && [ "$PSSO_STATE" = 'not-registered' ] && [ -n "$CONSOLE_USER" ]; then
    SHOULD_NUDGE=1
    if [ -f "$NUDGE_STAMP" ]; then
        STAMP_AGE_HOURS=$(( ( $(date +%s) - $(stat -f '%m' "$NUDGE_STAMP" 2>/dev/null || echo 0) ) / 3600 ))
        [ "$STAMP_AGE_HOURS" -lt "$NUDGE_INTERVAL_HOURS" ] && SHOULD_NUDGE=0
    fi
    if [ "$SHOULD_NUDGE" -eq 1 ]; then
        CONSOLE_UID="$(id -u "$CONSOLE_USER" 2>/dev/null)"
        launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" \
            open -a 'Company Portal' >/dev/null 2>&1 && touch "$NUDGE_STAMP"
    fi
fi

DETAIL="psso=$PSSO_STATE bootstrap=$BOOTSTRAP filevault=$FILEVAULT time=${NETWORK_TIME:-unknown} arch=$ARCH macOS=$OS_VERSION"

if [ -n "$PROBLEMS" ]; then
    echo "UNHEALTHY ($PROBLEMS${UNCERTAIN:+; undetermined: $UNCERTAIN}) [$DETAIL]"
    exit 1
fi

if [ -n "$UNCERTAIN" ]; then
    echo "OK so far (undetermined: $UNCERTAIN) [$DETAIL]"
    exit 0
fi

echo "OK [$DETAIL]"
exit 0
