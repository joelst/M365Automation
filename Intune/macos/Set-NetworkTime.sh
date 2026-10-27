#!/bin/bash
# Enforce network time synchronisation.
#
# Why this exists: a Mac that has been powered off for a long stretch comes back with a clock
# that has drifted, and Entra token validation is the first thing to break. JWT nbf/exp
# windows are minutes to hours, so even a modest skew makes every token exchange fail while
# TLS and MDM check-in keep working normally -- the Mac looks healthy, enrols, receives
# profiles, and simply cannot sign in. Platform SSO registration is the usual casualty, and it
# fails with a message that points nowhere near the clock.
#
# Nothing in the tenant configured network time before this, so a drifted Mac had no way back
# except someone noticing by hand.
#
# Idempotent and safe to run on a schedule: it only writes a setting that is not already
# correct, and stepping the clock to the right time is not a destructive act.
#
# Exit 0 = network time is enabled (whether or not this run had to change anything).
# Exit 1 = network time could not be enabled.

set -uo pipefail

TIME_SERVER='time.apple.com'
SYSTEMSETUP='/usr/sbin/systemsetup'
CHANGES=''

add_change() {
    if [ -z "$CHANGES" ]; then CHANGES="$1"; else CHANGES="$CHANGES,$1"; fi
}

if [ ! -x "$SYSTEMSETUP" ]; then
    echo "FAILED (systemsetup not found at $SYSTEMSETUP)"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "FAILED (must run as root; Intune shell scripts should be set to run as system)"
    exit 1
fi

BEFORE_DATE="$(date '+%Y-%m-%d %H:%M:%S %Z')"

# Set the time server only when it differs. systemsetup reports it as
# "Network Time Server: time.apple.com".
CURRENT_SERVER="$("$SYSTEMSETUP" -getnetworktimeserver 2>/dev/null | sed -n 's/^Network Time Server: //p')"
if [ "$CURRENT_SERVER" != "$TIME_SERVER" ]; then
    if "$SYSTEMSETUP" -setnetworktimeserver "$TIME_SERVER" >/dev/null 2>&1; then
        add_change "server=$TIME_SERVER"
    fi
fi

# Enable automatic time. Reported as "Network Time: On" / "Network Time: Off".
USING_NETWORK_TIME="$("$SYSTEMSETUP" -getusingnetworktime 2>/dev/null | sed -n 's/^Network Time: //p')"
if [ "$USING_NETWORK_TIME" != 'On' ]; then
    if "$SYSTEMSETUP" -setusingnetworktime on >/dev/null 2>&1; then
        add_change 'networktime=on'
    fi
fi

# Force an immediate step. timed corrects small drift on its own schedule but is deliberately
# unhurried about large offsets, and a large offset is exactly the case this script exists
# for -- leaving it to settle on its own can mean days more of failed sign-ins. sntp -sS sets
# the clock outright rather than slewing it.
if command -v sntp >/dev/null 2>&1; then
    EPOCH_BEFORE="$(date +%s)"
    if sntp -sS "$TIME_SERVER" >/dev/null 2>&1; then
        EPOCH_AFTER="$(date +%s)"
        DELTA=$(( EPOCH_AFTER - EPOCH_BEFORE ))
        [ "$DELTA" -lt 0 ] && DELTA=$(( 0 - DELTA ))
        # Only call it a correction if the clock actually moved. The step runs on every pass
        # because it is harmless and idempotent, but a Mac whose time was already right must
        # not report CORRECTED daily -- a status that is always the same is a status nobody
        # reads, and this script's whole value is being noticed when it matters.
        if [ "$DELTA" -gt 5 ]; then
            add_change "stepped=${DELTA}s"
        fi
    fi
fi

# Re-read rather than trusting the writes above: on recent macOS these calls can fail silently
# when the calling process lacks Full Disk Access, and reporting success we did not verify is
# worse than reporting nothing.
FINAL_STATE="$("$SYSTEMSETUP" -getusingnetworktime 2>/dev/null | sed -n 's/^Network Time: //p')"
AFTER_DATE="$(date '+%Y-%m-%d %H:%M:%S %Z')"

if [ "$FINAL_STATE" != 'On' ]; then
    echo "FAILED (network time still '$FINAL_STATE'; check Full Disk Access for the management agent)"
    exit 1
fi

if [ -n "$CHANGES" ]; then
    echo "CORRECTED ($CHANGES; was '$BEFORE_DATE', now '$AFTER_DATE')"
else
    echo "OK (network time on, server '$CURRENT_SERVER', clock '$AFTER_DATE')"
fi

exit 0
