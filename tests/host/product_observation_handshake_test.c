/* SPDX-License-Identifier: Apache-2.0 */
/* Exercises the actual consumer boundary after a peer stops handshaking. */
#define _GNU_SOURCE
#include "sakamoto_product_observation.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
int main (int argc, char **argv) {
  assert (argc == 2);
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  assert (strlen (argv[1]) < sizeof (address.sun_path));
  strcpy (address.sun_path, argv[1]);
  int listener = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (listener < 0 || bind (listener, (void *) &address, sizeof (address)) || listen (listener, 1)) {
    perror ("handshake listener"); return 2;
  }
  pid_t child = fork (); assert (child >= 0);
  if (!child) {
    int peer = accept (listener, NULL, NULL); assert (peer >= 0);
    unsigned char request[48]; assert (recv (peer, request, sizeof (request), 0) == sizeof (request));
    sleep (4); close (peer); close (listener); _exit (0);
  }
  struct timespec before, after;
  assert (!clock_gettime (CLOCK_MONOTONIC, &before));
  product_observation_transport_t *t = product_observation_connect (argv[1], 77);
  assert (!clock_gettime (CLOCK_MONOTONIC, &after));
  assert (!t);
  double elapsed = after.tv_sec - before.tv_sec + (after.tv_nsec - before.tv_nsec) / 1e9;
  assert (elapsed < 3.5);
  int status; assert (waitpid (child, &status, 0) == child && WIFEXITED (status) && WEXITSTATUS (status) == 0);
  close (listener); unlink (argv[1]);
  printf ("handshake_timeout=PASS elapsed=%.3f\n", elapsed);
  return 0;
}
