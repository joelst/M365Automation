#!/bin/bash
# Report the Microsoft Defender / Endpoint DLP client version against the macOS 27 floor.
#
# Why this exists: the macOS 27 DLP protection modes (unallowedBrowserMode,
# pasteToBrowserMode) are only honoured by Endpoint DLP client 101.26072 or later. An older
# client ignores the configuration silently -- the profile installs, the keys are present, and
# nothing enforces them. That is the worst kind of gap, because every dashboard says the
# policy is applied.
#
# Reports rather than remediates: upgrading the client is an app deployment, not something a
# detection script should attempt behind the administrator's back.
#
# Exit 0 = at or above the floor, or version could not be determined.
# Exit 1 = below the floor and needs upgrading.

set -uo pipefail

# Endpoint DLP client floor for the macOS 27 protection modes.
REQUIRED_MAJOR=101
REQUIRED_BUILD=26072

MDATP='/usr/local/bin/mdatp'
[ -x "$MDATP" ] || MDATP="$(command -v mdatp 2>/dev/null || true)"

if [ -z "$MDATP" ] || [ ! -x "$MDATP" ]; then
    echo "UNKNOWN (mdatp not installed or not on PATH)"
    exit 0
fi

VERSION="$("$MDATP" health --field app_version 2>/dev/null | tr -d '"' | tr -d '[:space:]')"

if [ -z "$VERSION" ]; then
    echo "UNKNOWN (mdatp present but did not report app_version)"
    exit 0
fi

MAJOR="$(echo "$VERSION" | cut -d. -f1)"
BUILD="$(echo "$VERSION" | cut -d. -f2)"

# Guard against a version string that is not the expected numeric shape rather than letting
# an arithmetic comparison fail open and report a healthy result.
case "$MAJOR$BUILD" in
    ''|*[!0-9]*)
        echo "UNKNOWN (unrecognised version string '$VERSION')"
        exit 0
        ;;
esac

if [ "$MAJOR" -gt "$REQUIRED_MAJOR" ] 2>/dev/null; then
    echo "OK ($VERSION)"
    exit 0
fi

if [ "$MAJOR" -eq "$REQUIRED_MAJOR" ] 2>/dev/null && [ "$BUILD" -ge "$REQUIRED_BUILD" ] 2>/dev/null; then
    echo "OK ($VERSION)"
    exit 0
fi

echo "OUTDATED ($VERSION; macOS 27 DLP protection modes need $REQUIRED_MAJOR.$REQUIRED_BUILD or later)"
exit 1
