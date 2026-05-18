#!/usr/bin/env bash
# Update the Homebrew cask at homebrew-tap/Casks/bsh-sdiagent.rb with a new
# version, zip URL, and SHA-256.
#
# Usage:
#   ./scripts/update-cask.sh --version <version>
#
#   --version   Version string (e.g. 1.0.1). Looks for dist/BSH-SDIAgent-<version>.zip
#
# The cask file is expected at:
#   /Volumes/Code/homebrew-tap/Casks/bsh-sdiagent.rb
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CASK_FILE="/Volumes/Code/homebrew-tap/Casks/bsh-sdiagent.rb"
GITHUB_REPO="Digital-Defiance/bsh-sdi-agent"

# ── Parse args ────────────────────────────────────────────────────────────────
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  echo "Error: --version is required" >&2
  exit 1
fi

# ── Locate zip ────────────────────────────────────────────────────────────────
ZIPFILE="${REPO_DIR}/dist/BSH-SDIAgent-${VERSION}.zip"

if [[ ! -f "${ZIPFILE}" ]]; then
  echo "Error: zip not found: ${ZIPFILE}" >&2
  exit 1
fi

# ── Compute SHA-256 ───────────────────────────────────────────────────────────
SHA256=$(shasum -a 256 "${ZIPFILE}" | awk '{print $1}')
echo "==> SHA-256: ${SHA256}"

# ── Derive URL ────────────────────────────────────────────────────────────────
URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/BSH-SDIAgent-${VERSION}.zip"
echo "==> URL: ${URL}"

# ── Verify cask exists ────────────────────────────────────────────────────────
if [[ ! -f "${CASK_FILE}" ]]; then
  echo "Error: cask file not found: ${CASK_FILE}" >&2
  exit 1
fi

# ── Update cask ───────────────────────────────────────────────────────────────
echo "==> Updating ${CASK_FILE}…"

# Capture old values for the summary
OLD_VERSION=$(grep -E '^\s+version ' "${CASK_FILE}" | sed 's/.*version "//; s/"//')
OLD_SHA256=$(grep -E '^\s+sha256 ' "${CASK_FILE}" | sed 's/.*sha256 "//; s/"//')
OLD_URL=$(grep -E '^\s+url ' "${CASK_FILE}" | sed 's/.*url "//; s/"//')

sed -i '' \
  -e "s|version \"${OLD_VERSION}\"|version \"${VERSION}\"|" \
  -e "s|sha256 \"${OLD_SHA256}\"|sha256 \"${SHA256}\"|" \
  -e "s|url \"${OLD_URL}\"|url \"${URL}\"|" \
  "${CASK_FILE}"

echo "==> Done."
echo
echo "    version : ${OLD_VERSION} → ${VERSION}"
echo "    sha256  : ${OLD_SHA256} → ${SHA256}"
echo "    url     : ${OLD_URL}"
echo "          → ${URL}"
echo
echo "Next: commit and push homebrew-tap, then run:"
echo "  brew update && brew upgrade bsh-sdiagent"
