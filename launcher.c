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
#include <unistd.h>
#endif

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

int main(int argc, char **argv) {
  char dir[4096];
  char engine[4600];
  char real[4300];

  if (!dir_of(argc ? argv[0] : NULL, dir, sizeof dir)) {
    fputs("launcher: cannot resolve own directory\n", stderr);
    return 1;
  }

#ifdef _WIN32
  snprintf(engine, sizeof engine, "%s" SEP "Engine" SEP "chrome" EXE, dir);
  snprintf(real, sizeof real, "%s" SEP "CloakBrowser Manager.bin" EXE, dir);
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
