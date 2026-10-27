#!/bin/bash
# Report whether Defender / Purview still hold the permissions they need.
#
# Why this asks mdatp rather than the privacy database:
#
#   Defender's own permissions come from mdatp, not from the privacy database. mdatp is
#   documented, supported, works identically on every macOS version, and answers the question
#   that actually matters -- does Defender have what it needs -- rather than inferring it from
#   an OS-internal table. macOS 27 also blocks direct reads of the local TCC database, so the
#   sqlite approach an earlier version of this script used cannot work there at all.
#
# The DLP browser-visibility permission IS covered, on macOS 27 and later, via `tccutil list`.
# Two things about that are worth writing down, because both contradict what the documentation
# implies:
#
#   - The TCC service is still called Accessibility on macOS 27. Microsoft's guidance says the
#     permission "moved" to Device Control and Data Access; that is the System Settings LABEL.
#     The underlying identifier did not change.
#   - `tccutil list` exists on macOS 27 but is absent from the man page and from `--info`,
#     which prints only the reset usage. Its syntax is `-s SERVICE` / `-b BUNDLE_ID`, and the
#     kTCCService prefix may be omitted. Output is bare service names, one per line.
#
# Purview also reports this permission centrally (Device Onboarding -> device details ->
# Installed / Not updated). This check exists so the same signal shows up in Intune next to
# everything else, not to replace that.
#
# Exit 0 = permissions present, or state could not be determined.
# Exit 1 = a required permission is missing.

set -uo pipefail

MDATP='/usr/local/bin/mdatp'
[ -x "$MDATP" ] || MDATP="$(command -v mdatp 2>/dev/null || true)"

if [ -z "$MDATP" ] || [ ! -x "$MDATP" ]; then
    echo "UNKNOWN (mdatp not installed or not on PATH)"
    exit 0
fi

read_field() {
    # --field prints a bare value, sometimes quoted depending on version. Normalise both.
    "$MDATP" health --field "$1" 2>/dev/null | tr -d '"' | tr -d '[:space:]'
}

FULL_DISK="$(read_field full_disk_access_enabled)"
REAL_TIME="$(read_field real_time_protection_enabled)"
HEALTHY="$(read_field healthy)"

PROBLEMS=''
UNCERTAIN=''

add_problem() {
    if [ -z "$PROBLEMS" ]; then PROBLEMS="$1"; else PROBLEMS="$PROBLEMS,$1"; fi
}

# Kept separate from PROBLEMS on purpose: "we could not tell" and "it is revoked" are different
# findings, and collapsing them produces false alarms at fleet scale.
add_unknown() {
    if [ -z "$UNCERTAIN" ]; then UNCERTAIN="$1"; else UNCERTAIN="$UNCERTAIN,$1"; fi
}

# An empty read means mdatp did not answer -- a different condition from answering "false",
# and it must not be reported as a revoked permission. Crying wolf across the fleet is how a
# detection script gets ignored.
if [ -z "$FULL_DISK" ] && [ -z "$REAL_TIME" ] && [ -z "$HEALTHY" ]; then
    echo "UNKNOWN (mdatp present but returned no health fields)"
    exit 0
fi

case "$FULL_DISK" in
    false|False|FALSE) add_problem 'full_disk_access' ;;
esac

case "$REAL_TIME" in
    false|False|FALSE|unavailable) add_problem "real_time_protection=$REAL_TIME" ;;
esac

# DLP browser visibility. This is the grant a user can revoke on macOS 27, and revoking it is
# what causes Safari, Chrome and Firefox to start being treated as restricted destinations.
# Only checkable from 27 onward: `tccutil list` does not exist before it, and macOS 27 blocks
# reading the TCC database directly, so there is no equivalent check for 26 and below.
OS_MAJOR="$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)"
DLP_BUNDLE='com.microsoft.dlp.daemon'
DLP_CHECKED='no'

if [ "${OS_MAJOR:-0}" -ge 27 ] 2>/dev/null && command -v tccutil >/dev/null 2>&1; then
    TCC_OUT="$(tccutil list -b "$DLP_BUNDLE" 2>/dev/null)"

    if [ -n "$TCC_OUT" ]; then DLP_CHECKED='yes'; fi

    if [ -z "$TCC_OUT" ]; then
        # No output at all is ambiguous -- the command may have been refused rather than the
        # bundle having no grants -- so this is not treated as a revocation.
        add_unknown 'dlp_browser_visibility'
    elif ! echo "$TCC_OUT" | grep -qx 'Accessibility'; then
        # ASSUMPTION, still unvalidated: that a revoked service drops out of this list rather
        # than being listed with a denied marker. The observed output carries no status column,
        # which is consistent with it listing only live authorisations, but that was seen on a
        # Mac where the permission was granted. Confirm by revoking Accessibility for Microsoft
        # Purview on one Mac and re-running `tccutil list -b com.microsoft.dlp.daemon`: if
        # Accessibility still appears, this check needs to read a status instead of presence.
        add_problem 'dlp_browser_visibility'
    fi
fi

if [ -n "$PROBLEMS" ]; then
    echo "MISSING ($PROBLEMS${UNCERTAIN:+; undetermined: $UNCERTAIN}; macOS $(sw_vers -productVersion 2>/dev/null))"
    exit 1
fi

# Healthy is reported separately from the individual permissions: Defender can hold every
# permission and still be unhealthy for unrelated reasons. Surface it without failing on it,
# so this script keeps meaning exactly one thing.
if [ "$HEALTHY" = 'false' ] || [ "$HEALTHY" = 'False' ]; then
    ISSUES="$("$MDATP" health --field health_issues 2>/dev/null | tr -d '\n' | tr -s ' ')"
    echo "OK but UNHEALTHY (permissions present; health_issues: ${ISSUES:-unreported})"
    exit 0
fi

# Say only what was actually established. Claiming "DLP permissions present" on a Mac where the
# DLP grant was never checked -- macOS 26, or tccutil unavailable -- would be a clean bill of
# health for something this script did not look at.
if [ "$DLP_CHECKED" = 'yes' ]; then
    SCOPE='Defender permissions and DLP browser visibility present'
else
    SCOPE='Defender permissions present; DLP browser visibility not checkable here, see Purview device details'
fi

echo "OK ($SCOPE${UNCERTAIN:+; undetermined: $UNCERTAIN}; macOS $(sw_vers -productVersion 2>/dev/null))"
exit 0
