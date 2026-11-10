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

# Linux has no manager, so nothing supplies a GPU model and a seeded persona
# reports a blank chip ("Apple ").  The manager derives one from the seed; do
# the same here so a seed keeps one stable identity.  Kept in step with
# apple_gpu_model() in launcher.c / backend/browser_manager.py.
gpu_for_seed() {
  python3 - "$1" <<'PY'
import hashlib, sys
tiers = (
    ("M1", "M1 Pro", "M1 Max", "M1 Ultra"),
    ("M2", "M2 Pro", "M2 Max", "M2 Ultra"),
    ("M3", "M3 Pro", "M3 Max"),
    ("M4", "M4 Pro", "M4 Max"),
    ("M5", "M5 Pro", "M5 Max"),
    ("M6", "M6 Pro", "M6 Max"),
)
d = hashlib.sha256(sys.argv[1].encode()).digest()
tier = tiers[d[0] % len(tiers)]
print(tier[d[1] % len(tier)])
PY
}

seed=
i=1
while [ $i -le $# ]; do
  a=${!i}
  case "$a" in
  --fingerprint=*) seed=${a#--fingerprint=} ;;
  --fingerprint)
    i=$((i + 1))
    [ $i -le $# ] && seed=${!i}
    ;;
  esac
  i=$((i + 1))
done
extra=()
have_gpu=0
for a in "$@"; do
  case "$a" in --fingerprint-gpu-renderer*) have_gpu=1 ;; esac
done
if [ -n "$seed" ] && [ "$have_gpu" -eq 0 ]; then
  extra+=("--fingerprint-gpu-renderer=$(gpu_for_seed "$seed")")
fi

exec "$DIR/chrome" \
  --no-first-run \
  --no-default-browser-check \
  --disable-quic \
  ${extra[@]+"${extra[@]}"} \
  "$@"
