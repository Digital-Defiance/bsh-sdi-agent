#!/usr/bin/env bash
# One-time setup: store Apple notarytool credentials in Keychain.
# Run this once per machine before using release.sh.
#
# You need an app-specific password (not your Apple ID password):
#   https://appleid.apple.com → Sign-In and Security → App-Specific Passwords
set -euo pipefail

TEAM_ID="J6887N729S"
KEYCHAIN_PROFILE="BSH-SDIAgent-notarytool"

echo "==> Storing notarytool credentials in Keychain"
echo "    Profile name: ${KEYCHAIN_PROFILE}"
echo
echo "You will be prompted for:"
echo "  • Apple ID (e.g. you@example.com)"
echo "  • App-specific password (generate at https://appleid.apple.com)"
echo

xcrun notarytool store-credentials "${KEYCHAIN_PROFILE}" \
  --team-id "${TEAM_ID}"

echo
echo "Done. Credentials stored under profile '${KEYCHAIN_PROFILE}'."
echo "release.sh will use this profile automatically."
