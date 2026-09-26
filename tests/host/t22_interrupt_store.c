/* SPDX-License-Identifier: Apache-2.0 */
/* Host acceptance only: stop a real Rust consumer after a partial snapshot
 * write. This interposes libc, not Product logic, and never runs on VPP. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int fsync (int fd) {
  static int (*real_fsync) (int);
  if (!real_fsync) *(void **) &real_fsync = dlsym (RTLD_NEXT, "fsync");
  char link[64], path[4096] = {0};
  snprintf (link, sizeof (link), "/proc/self/fd/%d", fd);
  ssize_t length = readlink (link, path, sizeof (path) - 1);
  if (length > 0) path[length] = 0;
  const char *fail_path = getenv ("SAKAMOTO_T22_FAIL_DIRECTORY");
  const char *fail_marker = getenv ("SAKAMOTO_T22_FAIL_DIRECTORY_MARKER");
  int result;
  if (fail_path && fail_marker && !strcmp (path, fail_path) && access (fail_marker, F_OK) == 0) {
    (void) unlink (fail_marker); errno = EIO; result = -1;
  } else result = real_fsync (fd);
  int saved_errno = errno;
  const char *witness = getenv ("SAKAMOTO_T22_FSYNC_LOG");
  if (witness && length > 0) {
    int log = open (witness, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
    if (log >= 0) { dprintf (log, "fsync result=%d path=%s\n", result, path); close (log); }
  }
  errno = saved_errno;
  return result;
}

ssize_t write (int fd, const void *bytes, size_t count) {
  static ssize_t (*real_write) (int, const void *, size_t);
  if (!real_write) *(void **) &real_write = dlsym (RTLD_NEXT, "write");
  const char *pending = getenv ("SAKAMOTO_T22_PENDING_PATH");
  const char *marker = getenv ("SAKAMOTO_T22_INTERRUPT_MARKER");
  if (pending && marker && count > 1 && access (marker, F_OK) == 0) {
    char link[64], path[4096];
    snprintf (link, sizeof (link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink (link, path, sizeof (path) - 1);
    if (length > 0) {
      path[length] = 0;
      if (!strcmp (path, pending)) {
        ssize_t written = real_write (fd, bytes, count / 2);
        if (written != (ssize_t) (count / 2)) _exit (111);
        /* The removed arm file and stopped process witness that this point,
         * after a genuine partial filesystem write, was reached. */
        (void) unlink (marker);
        (void) kill (getpid (), SIGSTOP);
        /* SIGSTOP can initially target a different thread. Never let this
         * writer finish write_all while group-stop is taking effect. */
        for (;;) pause ();
      }
    }
  }
  return real_write (fd, bytes, count);
}
