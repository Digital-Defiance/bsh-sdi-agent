#!/usr/bin/env bash
# Build, sign, notarize, staple, and package BSH SDIAgent for distribution.
#
# Prerequisites:
#   • Xcode + command-line tools installed
#   • Developer ID Application certificate in Keychain
#   • Notarytool credentials stored: run scripts/setup-notarytool.sh once first
#   • Optional: brew install create-dmg  (for .dmg output)
#
# Usage:
#   ./scripts/release.sh [version]
#
#   version  — optional; defaults to MARKETING_VERSION from the Xcode project
#
# Output (in ./dist/):
#   BSH-SDIAgent-<version>.zip       — stapled, ready for direct download
#   BSH-SDIAgent-<version>.dmg       — if create-dmg is available
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROJECT="${REPO_DIR}/BSH SDIAgent.xcodeproj"
SCHEME="BSH SDIAgent"
EXPORT_OPTIONS="${REPO_DIR}/ExportOptions.plist"
KEYCHAIN_PROFILE="BSH-SDIAgent-notarytool"
TEAM_ID="J6887N729S"
BUNDLE_ID="org.digitaldefiance.bsh.sdi-agent"
DIST_DIR="${REPO_DIR}/dist"
WORK_DIR="${REPO_DIR}/.build"

# ── Version ───────────────────────────────────────────────────────────────────
if [[ $# -ge 1 ]]; then
  VERSION="$1"
else
  VERSION=$(grep -m1 'MARKETING_VERSION' "${PROJECT}/project.pbxproj" \
    | sed 's/.*= //; s/;//; s/ //')
fi
echo "==> Building BSH SDIAgent ${VERSION}"

# ── Prepare directories ───────────────────────────────────────────────────────
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/archive" "${DIST_DIR}"

ARCHIVE="${WORK_DIR}/archive/BSHSDIAgent.xcarchive"
EXPORT_DIR="${WORK_DIR}/export"

# ── Archive ───────────────────────────────────────────────────────────────────
echo "==> Archiving (Release)…"
xcrun xcodebuild archive \
  -project "${PROJECT}" \
  -scheme "${SCHEME}" \
  -configuration Release \
  -archivePath "${ARCHIVE}" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="Developer ID Application" \
  DEVELOPMENT_TEAM="${TEAM_ID}" \
  ENABLE_HARDENED_RUNTIME=YES \
  -quiet
echo "    Archive: ${ARCHIVE}"

# ── Export (Developer ID signed) ─────────────────────────────────────────────
echo "==> Exporting…"
xcrun xcodebuild -exportArchive \
  -archivePath "${ARCHIVE}" \
  -exportPath "${EXPORT_DIR}" \
  -exportOptionsPlist "${EXPORT_OPTIONS}" \
  -quiet
APP="${EXPORT_DIR}/BSH SDIAgent.app"
echo "    Exported: ${APP}"

# ── Notarize ──────────────────────────────────────────────────────────────────
echo "==> Zipping for notarization…"
NOTARIZE_ZIP="${WORK_DIR}/BSHSDIAgent-notarize.zip"
ditto -c -k --keepParent "${APP}" "${NOTARIZE_ZIP}"

echo "==> Submitting to Apple notary service (this may take a few minutes)…"
NOTARIZE_OUT=$(xcrun notarytool submit "${NOTARIZE_ZIP}" \
  --keychain-profile "${KEYCHAIN_PROFILE}" \
  --wait \
  --timeout 1800 2>&1) || true
echo "${NOTARIZE_OUT}"

SUBMISSION_ID=$(echo "${NOTARIZE_OUT}" | grep -E '^\s+id:' | head -1 | awk '{print $2}')
STATUS=$(echo "${NOTARIZE_OUT}" | grep -E '^\s+status:' | awk '{print $2}')

if [[ "${STATUS}" != "Accepted" ]]; then
  echo
  echo "==> Notarization FAILED (status: '${STATUS}'). Fetching rejection log…"
  [[ -n "${SUBMISSION_ID}" ]] && \
    xcrun notarytool log "${SUBMISSION_ID}" --keychain-profile "${KEYCHAIN_PROFILE}"
  exit 1
fi
echo "    Notarization accepted."

# ── Staple ────────────────────────────────────────────────────────────────────
echo "==> Stapling ticket to app bundle…"
xcrun stapler staple "${APP}"

# ── Verify ────────────────────────────────────────────────────────────────────
echo "==> Verifying Gatekeeper…"
spctl --assess --type exec --verbose "${APP}" 2>&1

# ── Package: ZIP ─────────────────────────────────────────────────────────────
DIST_ZIP="${DIST_DIR}/BSH-SDIAgent-${VERSION}.zip"
echo "==> Creating ${DIST_ZIP}…"
ditto -c -k --keepParent "${APP}" "${DIST_ZIP}"
echo "    SHA-256: $(shasum -a 256 "${DIST_ZIP}" | awk '{print $1}')"

# ── Package: DMG (optional) ──────────────────────────────────────────────────
if command -v create-dmg &>/dev/null; then
  DIST_DMG="${DIST_DIR}/BSH-SDIAgent-${VERSION}.dmg"
  echo "==> Creating ${DIST_DMG}…"
  create-dmg \
    --volname "BSH SDIAgent ${VERSION}" \
    --window-pos 200 120 \
    --window-size 540 380 \
    --icon-size 128 \
    --icon "BSH SDIAgent.app" 135 190 \
    --hide-extension "BSH SDIAgent.app" \
    --app-drop-link 405 190 \
    "${DIST_DMG}" \
    "${APP}"
  echo "    SHA-256: $(shasum -a 256 "${DIST_DMG}" | awk '{print $1}')"
else
  echo "    (Skipping .dmg — install create-dmg: brew install create-dmg)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "==> Done. Distribution files in ${DIST_DIR}/"
ls -lh "${DIST_DIR}"/BSH-SDIAgent-"${VERSION}".*
echo
echo "Next steps:"
echo "  1. Create a GitHub release tagged v${VERSION}"
echo "  2. Upload the zip (and dmg if present) as release assets"
echo "  3. Update your Homebrew cask with the new URL + sha256"
