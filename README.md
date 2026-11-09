# cloakcrack — clue-free engine unlicensing

Turns a pristine, seat-limited CloakBrowser engine into a keyless, offline one and
repackages it behind a manager that no longer asks for a licence.

Everything is derived from the binary at run time: no hard-coded file offsets, no
per-release constants, no vendor licence server.

## What the crack does

The engine's licence path ends by calling `exit(77)` (no key) or `exit(79)`
(rejected). Every denial therefore tears the process down. Instead of re-implementing
the licence logic, the tool rewrites each of those `exit` call sites into a
`jmp` to the function epilogue, so the caller returns *early* and execution
continues with the default "unlicensed" state already in the registers. Nothing is
patched inside the licence routine itself, and no key is ever embedded.

Three things are located statically:

1. **The `exit` stub** — the hard anchor. A `/bin/launcher`-style wrapper must call
   `exit`; the tool finds that import/thunk in a platform-appropriate way
   (Mach-O `__stubs`/`__auth_stubs`, ELF `.rela.plt`+`.dynsym`+PLT, PE import
   directory). This is not an offset table: it is read out of the binary each time.
2. **The wrappers** — functions that call the `exit` stub within their first six
   instructions. Anything that returns soon after (loggers) is filtered out; a
   second union pass catches wrappers that funnel into another wrapper.
3. **The sites** — every `bl`/`call` to a wrapper, plus its enclosing epilogue, found
   by walking forward to the first stack restore followed by `ret`.

Finally the fingerprint-table key wait (a `movz`/`mov` of a large microsecond
constant followed by a `bl` to the sleep stub) is shortened from ~31 s to 2.5 s, so
a denied launch costs a couple of seconds instead of half a minute and a valid
embedded table still has room to load.

`--disable-quic` is patched into the frontend defaults as well: without it the
engine stalls ~25 s on QUIC/ECH before the first navigation.

## Usage

```
cloakcrack.py derive <container> [--out plan.json]
cloakcrack.py patch  <container> [--sites plan.json]
cloakcrack.py check  <container>
```

`derive` prints a plan; `patch` applies it (and writes the plan out for review when
`--out` is given). `check` reports what the binary looks like without touching it.
`--sites` replays a reviewed plan verbatim — that is what CI does, so a release can
be re-cracked deterministically.

Containers, per platform:

| platform | container |
| --- | --- |
| macOS | `…/Chromium Framework.framework/Versions/Current/Chromium Framework` |
| Windows | `chrome.dll` |
| Linux | the `chrome` ELF |

## Packaging

`package/package.sh <macos|windows|linux> <patched tree> <out dir>` builds a
self-contained, launchable bundle and signs it (ad-hoc on macOS). The repo needs
`manager.dmg` next to `package/` for the macOS mode; it is extracted, patched and
re-signed.

```
package/package.sh macos   /tmp/Chromium.app                /tmp/out
package/package.sh windows /tmp/extracted                   /tmp/out
package/package.sh linux   /tmp/x86                         /tmp/out
```

Each bundle gets a tiny `launcher` (compiled from `launcher.c` with the system
compiler or mingw) that exports `CLOAKBROWSER_BINARY_PATH` and execs the engine in
place, bypassing the manager's own binary-manifest check. It also seeds a valid
cache entry for a free key into `~/.cloakbrowser` on first run: the patched engine
ignores that key, but it keeps the manager's own `license_tier == "none"` screen
from asking for one, and a key entered in Settings still takes over. If the key
stored in Settings is malformed (it does not start with `cb_`), the launcher
exports the bundled one instead: a malformed key takes a denial path of its own
that the engine patch does not cover.

## Verification

`package/verify.sh <engine app>` renders a page three times — once with one seed
twice, once with another — and compares:

* the canvas hash must be identical between the two same-seed runs (determinism),
* `cores` must differ between the two seeds (the fingerprint table is live).

A pristine, still-licensed engine renders nothing and fails with
`verify: first render produced nothing (license still active?)`; a cracked one
exits `0`. `--virtual-time-budget=2000` is required on macOS, otherwise the headless
renderer can hang in teardown and drop its output.

## CI

`.github/workflows/crack.yml` runs three jobs on push:

* `macos-latest` matrix `[darwin-arm64, darwin-x64]` — derive, patch, package,
  verify; the x64 leg runs the verification under Rosetta.
* `windows-latest` — silent Inno install of the vendor manager, patch `chrome.dll`,
  repackage.
* `ubuntu-latest` — patch the ELF and ship it with `run-linux.sh`.

Runtime behaviour is CI-only for Windows (static CRT means no `exit` import, so the
PE path relies on the indirect-call + `int3` terminating rule and was validated
statically) and for Linux (a local qemu run traps in the engine's own startup).
