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
cloakcrack.py derive <container> --out plan.json
cloakcrack.py patch  <container> --sites plan.json
cloakcrack.py verify <container> --sites plan.json
cloakcrack.py dump   <container> --at <addr> [--count N]
```

`derive` writes a plan; `patch` applies it; `verify` statically confirms the plan
is present and well-formed (every deny site now branches to a real epilogue, no
exit-wrapper call survives in the licence window, and the fingerprint-table wait
is cut) **without launching the engine** — it exits non-zero otherwise, so it is
the cheap CI gate before the expensive launch test and the only check available
for the platforms whose engine cannot run on the build host. `dump` disassembles
around an address for review. `--sites` replays a reviewed plan verbatim — that is
what CI does, so a release can be re-cracked deterministically.

Nothing in the plan is a hard-coded offset: `derive` locates the licence window
from string anchors, and if a future version renames every anchor it falls back
to the fingerprint-table wait constant (a unique 31 s literal present on every
platform and every version so far) and re-derives the critical exit sites from
that alone. The same signature-based derivation runs unchanged on macOS arm64,
Windows x64, Linux x64 and Linux arm64 — only the addresses differ — so old and
future builds crack with no code change.

Containers, per platform:

| platform | container |
| --- | --- |
| macOS | `…/Chromium Framework.framework/Versions/Current/Chromium Framework` |
| Windows | `chrome.dll` |
| Linux | the `chrome` ELF (x86-64 or aarch64) |

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
place, bypassing the manager's own binary-manifest check.

The launcher also fixes the manager's own licence gate, which no engine patch can
reach: it seeds a **fake, local** key (`cb_` + 32 zeros) plus a validation-cache
entry stamped a century ahead, reported as plan "pro". The manager consults that
cache before the network, so the key is never validated remotely, never
revalidates and never expires. Because a file-sourced key is not
injected into the engine, launches stay keyless — the free key's single-seat cap
never applies and a second profile opens fine.

Every key stored in Settings is blanked at each start (a stored key *is* pushed
to the engine, where seats and malformed-key denials bite), and the seed files
are rewritten on every launch so upgrading over an older package drops whatever
it seeded before.

Nothing in the shipped path needs the real key. CI still uses the
`CLOAKBROWSER_KEY` secret only to download the engine; `LAUNCHER_KEY`/`_SHA` can
bake a real key instead. The key inside any binary is public by nature, so
rotating it is a secret update plus a rebuild, no code change.

Two more things the launcher does so a *launch*, not just the manager, comes up:

* It points `CLOAKBROWSER_LICENSE_API` at a dead loopback endpoint. The engine
  resolves a licence session before serving CDP; with a key, that is a slow
  network retry against a server that will reject it anyway. A dead endpoint
  fails fast with the transport denial the patch already defuses, so launches
  no longer depend on the licence host at all.
* It replaces `~/.cloakbrowser/denials` with an ordinary *file*. The wrapper only
  writes a denial report when it can create that directory, so making creation
  fail guarantees the manager never reads `77` (missing key) out of a file and
  aborts a perfectly good launch. Launches are then judged by CDP alone.

On Windows the launcher also prefers `Engine/chrome.real.exe` over the shipped
`Engine/chrome.exe`. The latter is only a licence injector that re-executes
`.real`, and the re-exec drops the inherited `--remote-debugging-pipe`
descriptors — Playwright's CDP handshake then never completes and every launch
dies after a 180 s timeout. Skipping it costs nothing now that the engine is
patched. (`verify.sh` drives `.real` for the same reason.)

## GPU model on macOS / Linux

The engine's seeded persona reports a blank chip (`ANGLE (Apple, ANGLE Metal
Renderer: Apple , …)`) whenever the licence session cannot deliver the model pool
— which a patched, offline engine never can. The manager does not send
`--fingerprint-gpu-renderer`, so the leak survives the crack.

The engine does accept that flag, and the value replaces the whole renderer
string. So on macOS the launcher doubles as an engine shim: it points
`CLOAKBROWSER_BINARY_PATH` at itself, recognises its own second invocation by
the `--fingerprint-platform=` switch Playwright carries, derives a chip from
`--fingerprint=<seed>` and re-execs the real engine with the flag appended (it
steps aside if a caller already sent one). `run-linux.sh` does the same for the
manager-less Linux build. Both use the exact hash that
`backend/browser_manager.py::apple_gpu_model` uses, so a profile reports the
same chip however it is started.

The mapping is sha256(seed) → tier by the first byte, binning by the second,
spread over the M1–M6 families. It is stable per profile, differs between
profiles, and needs no server round-trip.

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

`.github/workflows/crack.yml` runs four jobs:

* `macos-latest` matrix `[darwin-arm64, darwin-x64]` — derive, patch, package,
  verify; the x64 leg runs the verification under Rosetta.
* `windows-latest` — silent Inno install of the vendor manager, patch `chrome.dll`,
  repackage.
* `ubuntu-latest` / `ubuntu-24.04-arm` matrix `[linux-x64, linux-arm64]` — patch
  the ELF and ship it with `run-linux.sh`; each leg renders on a runner of its own
  architecture, so the arm64 artifact is built *and* verified, not just
  cross-patched.
* `release` — once the run has no failed job and at least one platform built,
  publishes one GitHub release tagged `v<engine>-crack.<n>` (the counter rolls
  on rebuilds of the same engine version). Assets: the two darwin dmg, a
  windows zip and linux tarballs per architecture. A `platform` input that
  narrows the build publishes just the platforms it built.

### Runner architectures

The x64 jobs run on `macos-latest`/`ubuntu-latest`/`windows-latest`; the aarch64
engine legs run on native arm64 runners (`macos-latest` is already arm64, the
Linux one is `ubuntu-24.04-arm`). Emulating the whole browser under `qemu-user` on
an x86_64 host is not sufficient — the guest needs a full aarch64 sysroot, and
without one exec fails up front with
`qemu-aarch64: Could not open '/lib/ld-linux-aarch64.so.1'`. Cross-*patching* is
independent of this; only the launch verification needs a native host.

Runtime behaviour is CI-only for Windows (static CRT means no `exit` import, so the
PE path relies on the indirect-call + `int3` terminating rule and was validated
statically). The Linux arm64 path was validated end to end locally on a native
aarch64 container: pristine exits `77`, patched renders (exit `0`), `verify.sh`
passes.
