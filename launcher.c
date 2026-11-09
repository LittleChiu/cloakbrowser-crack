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

  if (!dir_of(argc ? argv[0] : NULL, dir, sizeof dir)) {
    fputs("launcher: cannot resolve own directory\n", stderr);
    return 1;
  }
  seed_license();

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
  SetEnvironmentVariableA("CLOAKBROWSER_BINARY_PATH", engine);
#else
  snprintf(engine, sizeof engine, "%s" SEP ".." SEP "Resources" SEP "engine" SEP
                                "Chromium.app" SEP "Contents" SEP "MacOS" SEP "Chromium", dir);
  snprintf(real, sizeof real, "%s" SEP "CloakBrowser Manager.bin", dir);
  setenv("CLOAKBROWSER_LICENSE_API", DEAD_LICENSE_API, 1);
  setenv("CLOAKBROWSER_BINARY_PATH", engine, 1);
#endif

  argv[0] = real;
#ifdef _WIN32
  {
    intptr_t rc = _spawnv(_P_WAIT, real, (const char *const *)argv);
    if (rc == -1) {
      fprintf(stderr, "launcher: cannot start %s\n", real);
      return 1;
    }
    return (int)rc;
  }
#else
  execv(real, argv);
  perror("launcher: execv");
  return 1;
#endif
}
