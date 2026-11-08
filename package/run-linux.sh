#!/bin/bash
# Run the cracked Linux engine the way the manager's launcher would.
#
#   ./run.sh --fingerprint 123456 [extra chromium flags] [url]
#
# Without --fingerprint the engine picks a random seed, so a stable identity
# needs the seed passed explicitly (that is all the manager does too).
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)

export CLOAKBROWSER_BINARY_PATH="$DIR/chrome"
args=()
for a in "$@"; do
  case "$a" in
  --fingerprint | --fingerprint=*) args+=("$a") ;;
  *) args+=("$a") ;;
  esac
done

exec "$DIR/chrome" \
  --no-first-run \
  --no-default-browser-check \
  --disable-quic \
  "${args[@]}"
