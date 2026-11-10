/* Launcher stub for the cracked CloakBrowser Manager.
 *
 * The manager resolves its engine through a download manifest.  The cracked
 * build ships the engine next to the app instead, so this stub points the
 * manager at it and then hands over.

 * It never returns: the manager replaces this image.
 *
 * Build:  cl /O2 launcher.c /Fe:"CloakBrowser Manager.exe"
 *         clang -O2 -o launcher launcher.c        (macOS / Linux)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <time.h>

#ifdef _WIN32
#define SEP "\\"
#define EXE ".exe"
#else
#define SEP "/"
#define EXE ""
#endif

static int dir_of(const char *argv0, char *out, size_t cap) {
  size_t n;
#ifdef _WIN32
  if (!GetModuleFileNameA(NULL, out, (DWORD)cap)) return 0;
#else
  ssize_t k = readlink("/proc/self/exe", out, cap - 1);
  if (k <= 0) {
    if (!argv0) return 0;
    if (strlen(argv0) >= cap) return 0;
    strcpy(out, argv0);
  } else {
    out[k] = 0;
  }
#endif
  n = strlen(out);
  while (n > 0 && out[n - 1] != '/' && out[n - 1] != '\\') n--;
  if (n == 0) return 0;
  out[n - 1] = 0;
  return 1;
}

/* The engine is patched, so it never enforces a key.  The Manager itself still
 * resolves a licence_tier at startup and refuses to show the profile UI while
 * that is "none".  It only has to *believe* a key was validated, so the seeded
 * key is fake and local: the manager checks its validation cache before the
 * network, and the cache entry is stamped a century ahead, so it is never
 * stale, never revalidates, never expires — and the key never reaches the
 * engine (the manager hands it nothing for a file-sourced key).  The licence
 * plan is reported as "pro" purely for the badge.
 *
 * A key stored in Settings is blanked: a stored key *is* handed to the engine,
 * and a keyed engine enforces the licence seat cap, or takes denial paths the
 * patch does not cover when the key is malformed.  File-sourced launches stay
 * keyless, so every profile keeps working.
 *
 * The seed is rewritten on every start (not only when missing), so a package
 * upgraded over an older one that seeded a real key drops that key and its
 * cache.  Both macros can be overridden at build time (package.sh
 * LAUNCHER_KEY / _SHA) to seed a real key instead; nothing shipped needs one. */
#ifndef BUNDLED_LICENSE_KEY
#define BUNDLED_LICENSE_KEY "cb_00000000000000000000000000000000"
#endif
#ifndef BUNDLED_LICENSE_SHA
#define BUNDLED_LICENSE_SHA "0562cfc8017e11c6647c4d19648a7fc2c761b0762bf7810a7bedfa5ec69f9ae9"
#endif

/* The engine defers CDP startup until its licence session is resolved; with a
 * fake key that resolution is a slow network retry loop.  Point the engine at
 * a dead endpoint so the session fails instantly (a transport denial the patch
 * defuses) and the browser starts without touching the network.  The manager
 * resolves its own tier from the seeded cache and never reads this variable. */
#define DEAD_LICENSE_API "http://127.0.0.1:1"

static void write_file(const char *path, const char *text);

/* ------------------------------------------------------------------- sha256
 * Only used to turn a seed into a stable chip choice, so the seed string is all
 * we ever hash.  Self-contained to keep the stub dependency-free. */
static const unsigned int SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha256_block(unsigned int *h, const unsigned char *p) {
  unsigned int w[64], a, b, c, d, e, f, g, k, t1, t2;
  int i;
  for (i = 0; i < 16; i++)
    w[i] = (unsigned int)p[i * 4] << 24 | (unsigned int)p[i * 4 + 1] << 16 |
           (unsigned int)p[i * 4 + 2] << 8 | p[i * 4 + 3];
  for (; i < 64; i++)
    w[i] = w[i - 16] + (ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
           w[i - 7] + (ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10));
  a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; k = h[7];
  for (i = 0; i < 64; i++) {
    t1 = k + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) +
         SHA256_K[i] + w[i];
    t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}
static void sha256_string(const char *s, unsigned char out[32]) {
  unsigned int h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  unsigned char buf[64];
  size_t len = strlen(s), off = 0, rem, i;
  unsigned long long bits;
  int j;
  while (len - off >= 64) {
    sha256_block(h, (const unsigned char *)s + off);
    off += 64;
  }
  rem = len - off;
  memcpy(buf, s + off, rem);
  buf[rem] = 0x80;
  if (rem < 56) {
    memset(buf + rem + 1, 0, 56 - rem - 1);
  } else {
    memset(buf + rem + 1, 0, 64 - rem - 1);
    sha256_block(h, buf);
    memset(buf, 0, 56);
  }
  bits = (unsigned long long)len * 8ULL;
  for (j = 0; j < 8; j++) buf[56 + j] = (unsigned char)(bits >> (56 - 8 * j));
  sha256_block(h, buf);
  for (i = 0; i < 8; i++) {
    out[i * 4] = (unsigned char)(h[i] >> 24);
    out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
    out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
    out[i * 4 + 3] = (unsigned char)h[i];
  }
}


/* ---------------------------------------------------------------- engine mode
 *
 * The manager's own fingerprint code leaves the macOS GPU model blank: it
 * expects the licence session to deliver the model pool, which a patched
 * engine never sees, so WebGL reports "Apple " with no chip.  The manager is a
 * frozen executable we cannot recompile, but it resolves the engine path from
 * CLOAKBROWSER_BINARY_PATH — so the launcher doubles as a shim: it points that
 * variable at *itself*, sees its own name come back with Chromium arguments,
 * appends the chip flag and re-execs the real engine.
 *
 * The chip is derived from --fingerprint=<seed> exactly like the manager's
 * apple_gpu_model() (sha256, first byte picks the tier, second the binning), so
 * a profile keeps one stable identity whether or not the manager also passes
 * the flag itself (build_launch_args dedupes by key, last one wins).
 */
static const char *const APPLE_GPU_TIERS[][4] = {
    {"M1", "M1 Pro", "M1 Max", "M1 Ultra"},
    {"M2", "M2 Pro", "M2 Max", "M2 Ultra"},
    {"M3", "M3 Pro", "M3 Max", NULL},
    {"M4", "M4 Pro", "M4 Max", NULL},
    {"M5", "M5 Pro", "M5 Max", NULL},
    {"M6", "M6 Pro", "M6 Max", NULL},
};
#define APPLE_GPU_TIER_COUNT (sizeof APPLE_GPU_TIERS / sizeof APPLE_GPU_TIERS[0])

static int is_engine_invocation(int argc, char **argv) {
  int i;
  /* This file is both the manager stub and, via CLOAKBROWSER_BINARY_PATH, the
   * engine Playwright spawns.  Our own start has no arguments; an engine start
   * always carries the manager's fingerprint flags, and --fingerprint-platform
   * is the one the manager always adds.  --user-data-dir is a fallback for
   * callers that strip our flags. */
  for (i = 1; i < argc; i++) {
    if (!argv[i]) continue;
    if (strstr(argv[i], "--fingerprint-platform=")) return 1;
    if (strstr(argv[i], "--user-data-dir")) return 1;
  }
  return 0;
}

/* Convert a seed string to the model name.  This mirrors the Python
 * implementation byte for byte (sha256 + the same tier/bin indices), so the
 * build never depends on which side is authoritative. */
static int apple_gpu_model(const char *seed, char *out, size_t cap) {
  unsigned char digest[32];
  unsigned long long tier_i, chip_i;
  const char *const *tier;
  size_t avail = 0;
  if (!seed || !*seed) return 0;
  sha256_string(seed, digest);
  tier_i = digest[0] % APPLE_GPU_TIER_COUNT;
  tier = APPLE_GPU_TIERS[tier_i];
  while (avail < 4 && tier[avail]) avail++;
  chip_i = (unsigned long long)digest[1] % avail;
  if (strlen(tier[chip_i]) + 1 > cap) return 0;
  strcpy(out, tier[chip_i]);
  return 1;
}

/* Return the value of --fingerprint= from the argument list (not the
 * --fingerprint-* sub-flags). */
static const char *seed_arg(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; i++) {
    if (argv[i] && !strncmp(argv[i], "--fingerprint=", 14)) return argv[i] + 14;
  }
  return NULL;
}

static int has_gpu_renderer(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; i++) {
    if (argv[i] && !strncmp(argv[i], "--fingerprint-gpu-renderer", 26)) return 1;
  }
  return 0;
}


/* The wrapper hands the engine a denial-report file only when it can create
 * ~/.cloakbrowser/denials.  Make that path an ordinary file so creation always
 * fails: no denial file is ever minted, so the manager judges a launch by CDP
 * alone — the engine keeps serving even where a denial path was defused. */
static void block_denial_files(const char *dir) {
#ifdef _WIN32
  char path[4400], sub[4400];
  WIN32_FIND_DATAA fd;
  HANDLE h;
  snprintf(path, sizeof path, "%s" SEP "denials", dir);
  snprintf(sub, sizeof sub, "%s\\*", path);
  h = FindFirstFileA(sub, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      char full[4600];
      if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
      snprintf(full, sizeof full, "%s\\%s", path, fd.cFileName);
      DeleteFileA(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
  }
  RemoveDirectoryA(path);
  write_file(path, "x\n");
#else
  char path[4400];
  DIR *d;
  struct dirent *e;
  snprintf(path, sizeof path, "%s" SEP "denials", dir);
  if ((d = opendir(path))) {
    while ((e = readdir(d))) {
      char full[4600];
      if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
      snprintf(full, sizeof full, "%s/%s", path, e->d_name);
      unlink(full);
    }
    closedir(d);
    rmdir(path);
  }
  write_file(path, "x\n");
#endif
}

static void write_file(const char *path, const char *text) {
  FILE *f = fopen(path, "wb");
  if (!f) return;
  fwrite(text, 1, strlen(text), f);
  fclose(f);
}

/* Blank the value of "license_key" in the manager's settings.json, keeping the
 * rest of the file intact.  The manager treats an empty value as "not set". */
static void forget_stored_key(const char *path) {
  char buf[16384];
  char *p, *q, *a, *b;
  size_t n;
  FILE *f = fopen(path, "rb");
  if (!f) return;
  n = fread(buf, 1, sizeof buf - 1, f);
  fclose(f);
  buf[n] = 0;
  p = strstr(buf, "\"license_key\"");
  if (!p) return;
  q = strchr(p + 13, ':');
  if (!q) return;
  a = strchr(q, '"');
  if (!a) return;
  a++;
  b = strchr(a, '"');
  if (!b || a == b) return;
  memmove(a, b, strlen(b) + 1);
  f = fopen(path, "wb");
  if (!f) return;
  fwrite(buf, 1, strlen(buf), f);
  fclose(f);
}

static void seed_license(void) {
  char dir[4200];
  char path[4400];
  char json[512];
  const char *cache = getenv("CLOAKBROWSER_CACHE_DIR");
#ifdef _WIN32
  const char *home = getenv("USERPROFILE");
#else
  const char *home = getenv("HOME");
#endif

  if (!BUNDLED_LICENSE_KEY[0]) return;

  if (cache && *cache) {
    snprintf(dir, sizeof dir, "%s", cache);
  } else {
    if (!home || !*home) return;
    snprintf(dir, sizeof dir, "%s" SEP ".cloakbrowser", home);
  }
  if (home && *home) {
#ifdef _WIN32
    const char *local = getenv("LOCALAPPDATA");
    if (local && *local) {
      snprintf(path, sizeof path, "%s" SEP "CloakBrowser Manager" SEP
               "settings.json", local);
      forget_stored_key(path);
    }
#else
    snprintf(path, sizeof path, "%s" SEP "Library" SEP "Application Support" SEP
             "CloakBrowser Manager" SEP "settings.json", home);
    forget_stored_key(path);
#endif
  }
#ifdef _WIN32
  CreateDirectoryA(dir, NULL);
#else
  mkdir(dir, 0700);
#endif
  snprintf(path, sizeof path, "%s" SEP "license.key", dir);
  write_file(path, BUNDLED_LICENSE_KEY "\n");
  /* a century ahead: the manager's 24 h TTL never elapses, so the fake key is
   * never sent to the licence server and cannot be rejected there */
  snprintf(json, sizeof json,
           "{\"key_sha256\": \"" BUNDLED_LICENSE_SHA "\", \"valid\": true, "
           "\"plan\": \"pro\", \"expires\": null, \"validated_at\": %lld}",
           (long long)time(NULL) + 100LL * 365 * 86400);
  snprintf(path, sizeof path, "%s" SEP ".license_cache", dir);
  write_file(path, json);
  block_denial_files(dir);
}

int main(int argc, char **argv) {
  char dir[4096];
  char engine[4600];
  char real[4300];
  char self[4300];
  char model[64];
  const char *seed;

  if (!dir_of(argc ? argv[0] : NULL, dir, sizeof dir)) {
    fputs("launcher: cannot resolve own directory\n", stderr);
    return 1;
  }
#ifdef _WIN32
  GetModuleFileNameA(NULL, self, sizeof self);
#else
  if (!realpath(argv[0], self)) {
    if (readlink("/proc/self/exe", self, sizeof self - 1) <= 0) {
      fputs("launcher: cannot resolve own path\n", stderr);
      return 1;
    }
  }
#endif

  /* The manager resolves the engine from CLOAKBROWSER_BINARY_PATH, so it is
   * pointed at this very file: Playwright then runs us a second time with the
   * Chromium command line, and engine mode hands over to the real engine. */
  if (is_engine_invocation(argc, argv) && (seed = seed_arg(argc, argv)) != NULL &&
      !has_gpu_renderer(argc, argv) && apple_gpu_model(seed, model, sizeof model)) {
    static char flag[160];
    static char **nargv;
    snprintf(flag, sizeof flag, "--fingerprint-gpu-renderer=%s", model);
    nargv = malloc((size_t)(argc + 2) * sizeof *nargv);
    if (nargv) {
      memcpy(nargv, argv, (size_t)(argc + 1) * sizeof *argv);
      nargv[argc] = flag;
      nargv[argc + 1] = NULL;
      argv = nargv;
      argc++;
    }
  }
  seed_license();

  int engine_mode = is_engine_invocation(argc, argv);

#ifdef _WIN32
  SetEnvironmentVariableA("CLOAKBROWSER_LICENSE_API", DEAD_LICENSE_API);
  /* Prefer the unwrapped binary: the shipped chrome.exe is only a licence
   * injector that re-executes chrome.real.exe, and it swallows the
   * --remote-debugging-pipe descriptors Playwright relies on, so the CDP
   * handshake never completes (a 180 s launch timeout).  Skipping it costs
   * nothing now that the engine is patched and licensing is defused. */
  snprintf(engine, sizeof engine, "%s" SEP "Engine" SEP "chrome.real" EXE, dir);
  if (GetFileAttributesA(engine) == INVALID_FILE_ATTRIBUTES)
    snprintf(engine, sizeof engine, "%s" SEP "Engine" SEP "chrome" EXE, dir);
  /* Prefer the name package.sh now writes. Older packages appended .bin
   * after .exe, so fall back to that if the preferred file is absent. */
  snprintf(real, sizeof real, "%s" SEP "CloakBrowser Manager.bin" EXE, dir);
  if (GetFileAttributesA(real) == INVALID_FILE_ATTRIBUTES)
    snprintf(real, sizeof real, "%s" SEP "CloakBrowser Manager" EXE ".bin", dir);
  if (engine_mode)
    SetEnvironmentVariableA("CLOAKBROWSER_BINARY_PATH", engine);
  else
    SetEnvironmentVariableA("CLOAKBROWSER_BINARY_PATH", self);
#else
  snprintf(engine, sizeof engine, "%s" SEP ".." SEP "Resources" SEP "engine" SEP
                                "Chromium.app" SEP "Contents" SEP "MacOS" SEP "Chromium", dir);
  snprintf(real, sizeof real, "%s" SEP "CloakBrowser Manager.bin", dir);
  setenv("CLOAKBROWSER_LICENSE_API", DEAD_LICENSE_API, 1);
  setenv("CLOAKBROWSER_BINARY_PATH", engine_mode ? engine : self, 1);
#endif

  /* In engine mode the real engine takes over under our name; Playwright keys
   * nothing off argv[0], and this keeps process listings recognisable. */
  if (!engine_mode) argv[0] = real;
#ifdef _WIN32
  {
    intptr_t rc = _spawnv(_P_WAIT, engine_mode ? engine : real, (const char *const *)argv);
    if (rc == -1) {
      fprintf(stderr, "launcher: cannot start %s\n", engine_mode ? engine : real);
      return 1;
    }
    return (int)rc;
  }
#else
  execv(engine_mode ? engine : real, argv);
  perror("launcher: execv");
  return 1;
#endif
}
