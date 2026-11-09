#!/bin/bash
# Prove a patched engine is keyless and seed-stable.
#
#   ./verify.sh <engine-root>
#
# <engine-root> is the directory holding the engine binary:
#   Chromium.app/Contents/MacOS/Chromium   (macOS)
#   chrome                                 (Linux)
#   Engine/chrome.exe                      (Windows)
#
# Two headless renders with the same seed must produce the same canvas hash and
# a different seed must change it; without the patch the first run exits 77
# (missing key) long before any DOM is dumped.
set -uo pipefail

ROOT=${1:?usage: verify.sh <engine-root>}
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
PAGE="file://$TMP/fp.html"
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT

RUN=()
case "$(uname -s)" in
Darwin)
  if [ -x "$ROOT/Contents/MacOS/Chromium" ]; then APP="$ROOT"
  else APP="$ROOT/Chromium.app"; fi
  BIN="$APP/Contents/MacOS/Chromium"
  # an x64 engine on an arm64 host needs Rosetta; native needs nothing
  if [ "$(uname -m)" = arm64 ] && [ "$(file -b "$BIN" | grep -c x86_64)" = 1 ]; then
    RUN=(arch -x86_64)
  fi
  ;;
MINGW* | MSYS* | CYGWIN*)
  # The shipped chrome.exe is a licence-injecting wrapper around chrome.real.exe
  # that also loses the --remote-debugging-pipe descriptors Playwright needs;
  # drive the real binary so what verify proves is what a launch runs.
  BIN="$ROOT/Engine/chrome.real.exe"
  [ -x "$BIN" ] || BIN="$ROOT/Engine/chrome.exe"
  # The browser needs a drive-letter URL, not a Git Bash /tmp path.
  PAGE=$(cygpath -w "$TMP/fp.html")
  PAGE="file:///${PAGE//\\//}"
  echo "verify page: $PAGE" >&2
  ;;
*) BIN="$ROOT/chrome" ;;
esac
[ -x "$BIN" ] || {
  echo "verify: no engine at $BIN" >&2
  exit 1
}

cat >"$TMP/fp.html" <<'HTML'
<html><body><div id=o>pending</div><script>
function h(s){let x=0;for(let i=0;i<s.length;i++)x=(x*31+s.charCodeAt(i))|0;return x}
try{
 const c=document.createElement('canvas'),g=c.getContext('2d');
 g.textBaseline='top';g.font='14px Arial';g.fillText('Cloak fp probe',2,2);
 g.fillStyle='#f60';g.fillRect(1,1,50,20);
 document.getElementById('o').textContent=JSON.stringify({canvas:h(c.toDataURL()),cores:navigator.hardwareConcurrency});
}catch(e){document.getElementById('o').textContent='ERR '+e}
</script></body></html>
HTML

render() { # seed -> canvas hash
  local dir="$TMP/run$1"
  mkdir -p "$dir"
  # --virtual-time-budget makes the dump deterministic; without it macOS can
  # hang in teardown ("watchdog expired") and lose the output. Keep the exit
  # status and stderr visible: an unlicensed engine produces no stdout, so the
  # old pipeline made a launch failure indistinguishable from a missing match.
  local out="$dir/stdout"
  HOME="$dir" TMPDIR="$dir" CLOAKBROWSER_LICENSE_API=http://127.0.0.1:1 ${RUN[@]+"${RUN[@]}"} "$BIN" \
    --user-data-dir="$dir/u" --headless=new --dump-dom --no-sandbox \
    --no-first-run --virtual-time-budget=2000 \
    --fingerprint="$1" "$PAGE" >"$out" 2>"$dir/stderr"
  local status=$?
  echo "render $1 exit $status, $(wc -c <"$out") output bytes" >&2
  tail -20 "$dir/stderr" >&2
  grep -o '{"canvas":[^}]*}' "$out" | head -1
}

fail=0
a=$(render 111222)
[ -n "$a" ] || {
  echo "verify: first render produced nothing (license still active?)" >&2
  fail=1
}
b=$(render 111222)
c=$(render 333444)
echo "seed 111222 -> ${a:-<none>}"
echo "seed 111222 -> ${b:-<none>}"
echo "seed 333444 -> ${c:-<none>}"

# canvas is the same in every profile; hardware concurrency follows the seed,
# so a byte-identical pair proves determinism and a differing pair proves the
# seed reaches the fingerprint engine at all
[ "$a" = "$b" ] || {
  echo "verify: same seed gave different fingerprints" >&2
  fail=1
}
if [ "$a" = "$c" ]; then
  # the engine ignores --fingerprint on Linux (a keyed pristine build behaves
  # the same), so only macOS can prove the seed reaches the fp engine
  case "$(uname -s)" in
  Darwin) echo "verify: different seeds gave the same fingerprint" >&2; fail=1 ;;
  *) echo "verify: fingerprint inactive on this engine, determinism only" ;;
  esac
fi
[ "$fail" = 0 ] && echo "verify: ok"
exit "$fail"
