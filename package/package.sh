#!/bin/bash
# Package a keyless CloakBrowser Manager build.
#
#   ./package.sh macos   <engine.app>                  <out-dir>
#   ./package.sh windows <installed-tree>              <out-dir>
#   ./package.sh linux   <engine-dir>                  <out-dir>
#
# `macos`   expects the pristine DMG somewhere above or in $PWD and a
#           patched Chromium.app.
# `windows` expects the tree produced by running the vendor installer silently
#           (see the workflow); the engine is expected in <installed-tree>/Engine.
# `linux`   ships the engine plus a run script, since the vendor publishes no
#           Linux manager build.
#
# Everything here is deliberately layout-agnostic: it looks for the manager
# executable by shape, never by hard-coded name.
set -euo pipefail

MODE=${1:?usage: package.sh <macos|windows|linux> <input> <out-dir>}
IN=${2:?missing input}
OUT=${3:?missing output dir}
HERE=$(cd "$(dirname "$0")" && pwd)
# manager.dmg is looked up next to the script, its parent, or the invocation
# directory: the tool is both used in-tree and from a standalone checkout
dmg=
for d in "$HERE/.." "$HERE/../.." "$PWD" "$PWD/.."; do
  if [ -f "$d/manager.dmg" ]; then dmg=$(cd "$d" && pwd)/manager.dmg; break; fi
done

die() { echo "package: $*" >&2; exit 1; }
[ -e "$IN" ] || die "input not found: $IN"
rm -rf "$OUT"
mkdir -p "$OUT"

# Bake the licence key into the launcher (CI passes the CLOAKBROWSER_KEY secret,
# so the key never lives in the source). The SHA must describe the same key or
# the seeded validation cache never matches; derive it unless given.
ldefs=()
if [ -n "${LAUNCHER_KEY:-}" ]; then
  : "${LAUNCHER_KEY_SHA:=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$LAUNCHER_KEY")}"
  ldefs+=("-DBUNDLED_LICENSE_KEY=\"$LAUNCHER_KEY\"")
  ldefs+=("-DBUNDLED_LICENSE_SHA=\"$LAUNCHER_KEY_SHA\"")
fi

case "$MODE" in
macos)
  DMG="$dmg"
  [ -f "$DMG" ] || die "manager.dmg missing next to the tree"
  MNT=$(mktemp -d)
  hdiutil attach -nobrowse -readonly -mountpoint "$MNT" "$DMG" >/dev/null
  trap 'hdiutil detach "$MNT" >/dev/null 2>&1 || true; rm -rf "$MNT"' EXIT
  APP="$OUT/CloakBrowser Manager.app"
  cp -R "$MNT/CloakBrowser Manager.app" "$APP"
  chmod -R u+w "$APP"
  MACOS="$APP/Contents/MacOS"
  BIN="$MACOS/CloakBrowser Manager"
  [ -f "$BIN" ] || die "unexpected bundle layout"
  mv "$BIN" "$BIN.bin"
  mkdir -p "$APP/Contents/Resources/engine"
  cp -R "$IN" "$APP/Contents/Resources/engine/Chromium.app"
  chmod +x "$APP/Contents/Resources/engine/Chromium.app/Contents/MacOS/Chromium"
  # match the engine's arch so the stub also runs on an Intel Mac
  eng_arch=$(file -b "$IN/Contents/MacOS/Chromium" 2>/dev/null)
  case "$eng_arch" in
  *x86_64*) clang -arch x86_64 -O2 "${ldefs[@]+"${ldefs[@]}"}" -o "$BIN" "$HERE/../launcher.c" ;;
  *) clang -O2 "${ldefs[@]+"${ldefs[@]}"}" -o "$BIN" "$HERE/../launcher.c" ;;
  esac
  chmod +x "$BIN"
  xattr -cr "$APP"
  # sign bottom-up: deep signing alone trips over the nested playwright node
  find "$APP" -type f -perm -u+x | while read -r f; do
    case "$(file -b "$f")" in
    Mach-O*) codesign --force -s - "$f" >/dev/null 2>&1 || true ;;
    esac
  done
  codesign --force -s - "$APP"
  codesign -v "$APP" && echo "signed ok"
  # ship a compressed image: the tree itself is ~2.3x bigger and that is what
  # gets uploaded/handed over
  rm -f "$OUT.dmg"
  hdiutil create -quiet -srcfolder "$APP" -format UDZO \
    -volname "CloakBrowser Manager" "$OUT.dmg"
  echo "image $(du -h "$OUT.dmg" | cut -f1) (tree $(du -sh "$APP" | cut -f1))"
  ;;

windows)
  # The manager executable is the biggest .exe in the install root that is not
  # a vendor helper and not already renamed by us.
  BIN=
  for cand in "$IN"/*.exe; do
    case "$(basename "$cand")" in
    chrome* | elevation_service* | chrome_proxy* | chrome_pwa_launcher* | chrome_crashpad_handler*) continue ;;
    esac
    # keep the biggest candidate: the manager carries the most code
    if [ -z "$BIN" ] || [ "$(wc -c <"$cand")" -gt "$(wc -c <"$BIN")" ]; then
      BIN="$cand"
    fi
  done
  [ -n "$BIN" ] || die "no manager executable found in $IN"
  cp -R "$IN"/. "$OUT"/
  BIN="$OUT/$(basename "$BIN")"
  # launcher.exe looks up "CloakBrowser Manager.bin.exe". Appending .bin to
  # the original name yields "CloakBrowser Manager.exe.bin", which it misses.
  case "$BIN" in
    *.exe) mv "$BIN" "${BIN%.exe}.bin.exe" ;;
    *) mv "$BIN" "$BIN.bin" ;;
  esac
  # The launcher prefers chrome.real.exe (the shipped chrome.exe is a licence
  # injector whose re-exec drops the --remote-debugging-pipe descriptors), so the
  # wrapper is only a fallback.
  [ -f "$IN/Engine/chrome.exe" ] || [ -f "$IN/Engine/chrome.real.exe" ] ||
    die "engine missing: expected Engine/chrome.exe or Engine/chrome.real.exe"
  # CLOAKBROWSER_BINARY_PATH must be absolute; the stub derives it per run.
  cc_out="$OUT/launcher.exe"
  # cross-compile on Linux/macOS; on a Windows runner the native gcc already
  # emits PE
  case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) ccs="gcc cc" ;; *) ccs="x86_64-w64-mingw32-gcc" ;; esac
  for cc in $ccs; do
    command -v "$cc" >/dev/null 2>&1 || continue
    "$cc" -O2 ${ldefs[@]+"${ldefs[@]}"} -o "$cc_out" "$HERE/../launcher.c" && break
  done
  [ -f "$cc_out" ] || die "need a C compiler for the launcher"
  mv "$cc_out" "$BIN"
  ;;

linux)
  # No vendor manager: ship the engine with a wrapper that mirrors the
  # manager's contract (env var + fingerprint args) and the Playwright recipe.
  cp -R "$IN"/. "$OUT"/
  chmod +x "$OUT/chrome"
  cp "$HERE/run-linux.sh" "$OUT/run.sh"
  chmod +x "$OUT/run.sh"
  ;;

*) die "unknown mode $MODE" ;;
esac

echo "packaged $MODE -> $OUT"
