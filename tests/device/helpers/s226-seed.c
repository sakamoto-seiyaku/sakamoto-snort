/* SPDX-License-Identifier: Apache-2.0 */
/* Independent bounded-concurrency UDP traffic generator. No Product library,
 * parser, flow table, hash function, timer driver, or synthetic packet input. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { WIDTH = 48, MAX_TUPLES = 8192 };
struct endpoint {
  int fd;
  unsigned family, port, length;
  char request[128];
};
static void fail (const char *what) { perror (what); exit (1); }
static unsigned long long clock_ns (void)
{
  struct timespec now;
  if (clock_gettime (CLOCK_MONOTONIC, &now)) fail ("clock");
  return (unsigned long long) now.tv_sec * 1000000000ULL + now.tv_nsec;
}
static socklen_t address (struct sockaddr_storage *storage, unsigned family,
                         const char *ip, unsigned port)
{
  memset (storage, 0, sizeof (*storage));
  if (family == 4) {
    struct sockaddr_in *a = (void *) storage;
    a->sin_family = AF_INET; a->sin_port = htons (port);
    if (inet_pton (AF_INET, ip, &a->sin_addr) != 1) exit (2);
    return sizeof (*a);
  }
  struct sockaddr_in6 *a = (void *) storage;
  a->sin6_family = AF_INET6; a->sin6_port = htons (port);
  if (inet_pton (AF_INET6, ip, &a->sin6_addr) != 1) exit (2);
  return sizeof (*a);
}

int main (int argc, char **argv)
{
  /* uid tuples.txt local4 local6 remote4 remote6 remote-port nonce echo
   * Tuple file lines: IP-family source-port. Host oracle is outside helper. */
  if (argc != 10) return 2;
  unsigned uid = strtoul (argv[1], NULL, 10), port = strtoul (argv[7], NULL, 10);
  unsigned echo = strtoul (argv[9], NULL, 10);
  if (!port || port > 65535 || echo > 1 || strlen (argv[8]) > 80) return 2;
  FILE *tuples = fopen (argv[2], "r");
  if (!tuples) fail ("tuples");
  struct endpoint *endpoints = calloc (MAX_TUPLES, sizeof (*endpoints));
  if (!endpoints) fail ("endpoints");
  unsigned total = 0, family, local_port;
  int fields;
  while ((fields = fscanf (tuples, "%u %u", &family, &local_port)) != EOF) {
    if (fields != 2 || total == MAX_TUPLES || (family != 4 && family != 6)
        || !local_port || local_port > 65535) return 2;
    endpoints[total++] = (struct endpoint) {.family = family, .port = local_port};
  }
  fclose (tuples);
  struct rlimit limit;
  if (getrlimit (RLIMIT_NOFILE, &limit)) fail ("getrlimit");
  if (limit.rlim_cur < total + 64) {
    if (limit.rlim_max < total + 64) { errno = EMFILE; fail ("hard fd limit"); }
    limit.rlim_cur = total + 64;
    if (setrlimit (RLIMIT_NOFILE, &limit)) fail ("helper fd limit");
  }
  if (getuid () != uid && (setgid (uid) || setuid (uid))) fail ("uid");
#ifdef __ANDROID__
  /* Own traffic helper only; Product remains on registered CPUs 0/1/2.
   * This finite setup is followed by the same quiet interval in both arms. */
  cpu_set_t cpus;
  CPU_ZERO (&cpus);
  CPU_SET (6, &cpus);
  if (sched_setaffinity (0, sizeof (cpus), &cpus)) fail ("helper affinity");
#endif
  setvbuf (stdout, NULL, _IOLBF, 0);
  unsigned long long started = clock_ns ();
  /* Socket creation/teardown is setup, not part of the simultaneous flow
   * arrival. Keep all sockets open and silent until the collector stops us.
   * Only WIDTH requests can be outstanding; native queue sizing is unchanged. */
  for (unsigned i = 0; i < total; i++) {
    struct endpoint *e = &endpoints[i];
    e->fd = socket (e->family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (e->fd < 0) fail ("socket");
    int one = 1;
    if (e->family == 6 && setsockopt (e->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof (one))) fail ("v6only");
    struct sockaddr_storage local, remote;
    socklen_t size = address (&local, e->family, argv[e->family == 4 ? 3 : 4], e->port);
    if (bind (e->fd, (void *) &local, size)) fail ("bind");
    size = address (&remote, e->family, argv[e->family == 4 ? 5 : 6], port);
    if (connect (e->fd, (void *) &remote, size)) fail ("connect");
    int length = snprintf (e->request, sizeof (e->request), "%c%s-%u-%u",
                           echo ? 'E' : 'S', argv[8], e->family, e->port);
    if (length < 0 || (size_t) length >= sizeof (e->request)) return 2;
    e->length = length;
  }
  unsigned long long prepared = clock_ns ();
  printf ("seed-prepared count=%u started_ns=%llu prepared_ns=%llu retained_fds=%u setup_cpu=%d\n",
          total, started, prepared, total, sched_getcpu ());
  if (!echo) {
    for (unsigned i = 0; i < total; i++) {
      struct endpoint *e = &endpoints[i];
      unsigned long long sent = clock_ns ();
      if (send (e->fd, e->request, e->length, 0) != e->length) fail ("send");
      printf ("seed family=%u port=%u nonce=%s sent_ns=%llu received_ns=0 echo=0\n",
              e->family, e->port, e->request + 1, sent);
    }
  } else {
    struct pollfd fds[WIDTH];
    unsigned indices[WIDTH], count = total < WIDTH ? total : WIDTH;
    unsigned long long sent[WIDTH];
    unsigned next = 0, remaining = total;
    for (unsigned i = 0; i < count; i++) fds[i] = (struct pollfd) {-1, POLLIN, 0};
    /* Rolling, bounded window: one completed reply admits one next send.
     * A slow tail does not serialize an entire following batch. */
    while (remaining) {
      /* Let the bounded startup trace drain before the steady rolling load.
       * Both arms have exactly this same setup; no Product flags change. */
      unsigned window = next < 128 && count > 8 ? 8 : count;
      for (unsigned i = 0; i < window && next < total; i++) {
        if (fds[i].fd >= 0) continue;
        struct endpoint *e = &endpoints[next];
        indices[i] = next++;
        fds[i] = (struct pollfd) {e->fd, POLLIN, 0};
        sent[i] = clock_ns ();
        if (send (e->fd, e->request, e->length, 0) != e->length) fail ("send");
      }
      for (unsigned i = 0; i < count; i++)
        if (fds[i].fd >= 0 && clock_ns () - sent[i] >= 5000000000ULL)
          { errno = ETIMEDOUT; fail ("reply deadline"); }
      int ready = poll (fds, count, 100);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) fail ("poll");
      for (unsigned i = 0; i < count; i++) {
        if (!fds[i].revents) continue;
        struct endpoint *e = &endpoints[indices[i]];
        char response[128];
        ssize_t size = recv (fds[i].fd, response, sizeof (response), 0);
        if (size != e->length || memcmp (response, e->request, e->length)) fail ("echo");
        printf ("seed family=%u port=%u nonce=%s sent_ns=%llu received_ns=%llu echo=1\n",
                e->family, e->port, e->request + 1, sent[i], clock_ns ());
        fds[i].fd = -1; remaining--;
      }
    }
  }
  printf ("seed-summary count=%u started_ns=%llu prepared_ns=%llu ended_ns=%llu width=%u retained_fds=%u\n",
          total, started, prepared, clock_ns (), WIDTH, total);
  for (;;) pause ();
}
