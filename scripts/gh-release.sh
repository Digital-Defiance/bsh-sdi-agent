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

ZIPFILE=$(ls dist/BSH-SDIAgent-*.zip 2>/dev/null | head -n 1)

if [ -z "$ZIPFILE" ]; then
  echo "Error: no dist/BSH-SDIAgent-*.zip file found" >&2
  exit 1
fi

echo "Releasing $ZIPFILE as version $VERSION"

gh release create "$VERSION" \
  "$ZIPFILE" \
  --title "BSH SDIAgent $VERSION" \
  --notes "$NOTES"
