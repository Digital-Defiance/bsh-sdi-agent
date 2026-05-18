#!/bin/sh
set -e

VERSION=""
NOTES=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --notes)
      NOTES="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "Error: --version is required" >&2
  exit 1
fi

if [ -z "$NOTES" ]; then
  echo "Error: --notes is required" >&2
  exit 1
fi

# Strip leading "v" so v1.0.2 -> 1.0.2 to match dist/BSH-SDIAgent-<version>.zip
VERSION_BARE="${VERSION#v}"
ZIPFILE="dist/BSH-SDIAgent-${VERSION_BARE}.zip"

if [ ! -f "$ZIPFILE" ]; then
  echo "Error: $ZIPFILE not found." >&2
  echo "       Run scripts/release.sh first, or check the --version value." >&2
  exit 1
fi

echo "Releasing $ZIPFILE as version $VERSION"

gh release create "$VERSION" \
  "$ZIPFILE" \
  --title "BSH SDIAgent $VERSION" \
  --notes "$NOTES"
