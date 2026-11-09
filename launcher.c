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
 * that is "none".  Seed a real (free) key plus a fresh validation-cache entry
 * into the cache dir on first run, and export that key to the Manager.  The key
 * is exported because any key stored in Settings is otherwise used first, and a
 * malformed or expired one makes the engine deny before the patch is reached.
 * Settings keeps displaying the stored value; the cached entry re-validates
 * itself after a day. */
#define BUNDLED_LICENSE_KEY "<baked-at-build>"
#define BUNDLED_LICENSE_SHA "286b33018861895849bca547437f1b7b97eea22ab7f924c310a00766e11f702f"

static void write_if_missing(const char *path, const char *text) {
  FILE *f = fopen(path, "rb");
  if (f) {
    fclose(f);
    return;
  }
  f = fopen(path, "wb");
  if (!f) return;
  fwrite(text, 1, strlen(text), f);
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

  if (!getenv("CLOAKBROWSER_LICENSE_KEY")) {
#ifdef _WIN32
    SetEnvironmentVariableA("CLOAKBROWSER_LICENSE_KEY", BUNDLED_LICENSE_KEY);
#else
    setenv("CLOAKBROWSER_LICENSE_KEY", BUNDLED_LICENSE_KEY, 1);
#endif
  }

  if (cache && *cache) {
    snprintf(dir, sizeof dir, "%s", cache);
  } else {
    if (!home || !*home) return;
    snprintf(dir, sizeof dir, "%s" SEP ".cloakbrowser", home);
  }
#ifdef _WIN32
  CreateDirectoryA(dir, NULL);
#else
  mkdir(dir, 0700);
#endif
  snprintf(path, sizeof path, "%s" SEP "license.key", dir);
  write_if_missing(path, BUNDLED_LICENSE_KEY "\n");
  snprintf(json, sizeof json,
           "{\"key_sha256\": \"" BUNDLED_LICENSE_SHA "\", \"valid\": true, "
           "\"plan\": \"free\", \"expires\": null, \"validated_at\": %ld}",
           (long)time(NULL));
  snprintf(path, sizeof path, "%s" SEP ".license_cache", dir);
  write_if_missing(path, json);
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
