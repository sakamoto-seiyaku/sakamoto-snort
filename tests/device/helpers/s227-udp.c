/* SPDX-License-Identifier: Apache-2.0 */
/* Independent retained UDP sockets with real, monotonic scheduled sends.
 * No Product library, owner hash, flow handle, synthetic clock or packet API. */
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

enum { MAX_ENDPOINTS = 8192, WIDTH = 48 };
typedef struct {
  int fd;
  unsigned owner, family, port, target, length;
  char request[192];
} endpoint_t;
static void fail (const char *operation) { perror (operation); exit (1); }
static unsigned long long now_ns (void)
{
  struct timespec now;
  if (clock_gettime (CLOCK_MONOTONIC, &now)) fail ("clock");
  return (unsigned long long) now.tv_sec * 1000000000ULL + now.tv_nsec;
}
static void wait_until (unsigned long long deadline)
{
  struct timespec at = {deadline / 1000000000ULL, deadline % 1000000000ULL};
  int result;
  do result = clock_nanosleep (CLOCK_MONOTONIC, TIMER_ABSTIME, &at, NULL);
  while (result == EINTR);
  if (result) { errno = result; fail ("clock_nanosleep"); }
}
static socklen_t address (struct sockaddr_storage *storage, unsigned family,
                         const char *ip, unsigned port)
{
  memset (storage, 0, sizeof (*storage));
  if (family == 4)
    {
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

static unsigned long long
send_phase (endpoint_t *endpoints, unsigned total, unsigned echo,
            const char *nonce, unsigned phase, int targets_only)
{
  unsigned selected[MAX_ENDPOINTS], count = 0;
  for (unsigned i = 0; i < total; i++)
    {
      if (targets_only && !endpoints[i].target) continue;
      selected[count++] = i;
      endpoint_t *e = &endpoints[i];
      int length = snprintf (e->request, sizeof (e->request), "%c%s-%u-%u-%u",
                             echo ? 'E' : 'S', nonce, phase, e->family, e->port);
      if (length < 0 || (size_t) length >= sizeof (e->request)) exit (2);
      e->length = length;
    }
  if (!echo)
    {
      for (unsigned i = 0; i < count; i++)
        {
          endpoint_t *e = &endpoints[selected[i]];
          unsigned long long sent = now_ns ();
          if (send (e->fd, e->request, e->length, 0) != e->length) fail ("send");
          printf ("endpoint phase=%u owner=%u family=%u port=%u target=%u nonce=%s sent_ns=%llu received_ns=0 echo=0\n",
                  phase, e->owner, e->family, e->port, e->target, e->request+1, sent);
        }
    }
  else
    {
      struct pollfd fds[WIDTH];
      unsigned indices[WIDTH], width = count < WIDTH ? count : WIDTH;
      unsigned long long sent[WIDTH];
      unsigned next = 0, remaining = count;
      for (unsigned i = 0; i < width; i++) fds[i] = (struct pollfd) {-1, POLLIN, 0};
      while (remaining)
        {
          unsigned window = next < 128 && width > 8 ? 8 : width;
          for (unsigned i = 0; i < window && next < count; i++)
            {
              if (fds[i].fd >= 0) continue;
              indices[i] = selected[next++];
              endpoint_t *e = &endpoints[indices[i]];
              fds[i] = (struct pollfd) {e->fd, POLLIN, 0};
              sent[i] = now_ns ();
              if (send (e->fd, e->request, e->length, 0) != e->length) fail ("send");
            }
          for (unsigned i = 0; i < width; i++)
            if (fds[i].fd >= 0 && now_ns ()-sent[i] > 5000000000ULL)
              { errno = ETIMEDOUT; fail ("reply deadline"); }
          int ready = poll (fds, width, 100);
          if (ready < 0 && errno == EINTR) continue;
          if (ready < 0) fail ("poll");
          for (unsigned i = 0; i < width; i++)
            {
              if (!fds[i].revents) continue;
              endpoint_t *e = &endpoints[indices[i]];
              char reply[192];
              ssize_t length = recv (e->fd, reply, sizeof (reply), 0);
              if (length != e->length || memcmp (reply, e->request, length)) fail ("echo");
              printf ("endpoint phase=%u owner=%u family=%u port=%u target=%u nonce=%s sent_ns=%llu received_ns=%llu echo=1\n",
                      phase, e->owner, e->family, e->port, e->target,
                      e->request+1, sent[i], now_ns ());
              fds[i].fd = -1;
              remaining--;
            }
        }
    }
  unsigned long long finished = now_ns ();
  printf ("stage phase=%u count=%u mono_ns=%llu\n", phase, count, finished);
  return finished;
}

int main (int argc, char **argv)
{
  /* mode uid tuples.txt local4 local6 remote4 remote6 port nonce
   * Tuple lines: independently assigned owner family source-port. */
  if (argc != 10) return 2;
  const char *mode = argv[1];
  int first = !strcmp (mode, "first") || !strcmp (mode, "stop");
  int renew_first = !strcmp (mode, "renew-first"), shorten = !strcmp (mode, "shorten");
  int renew_bidir = !strcmp (mode, "renew-bidir"), bulk = !strcmp (mode, "bulk");
  int lookup = !strcmp (mode, "lookup");
  if (!(first || renew_first || shorten || renew_bidir || bulk || lookup)) return 2;
  unsigned uid = strtoul (argv[2], NULL, 10), port = strtoul (argv[8], NULL, 10);
  if (!port || port > 65535 || strlen (argv[9]) > 96) return 2;
  FILE *input = fopen (argv[3], "r");
  if (!input) fail ("tuples");
  endpoint_t *endpoints = calloc (MAX_ENDPOINTS, sizeof (*endpoints));
  if (!endpoints) fail ("endpoints");
  unsigned total = 0, owner, family, local_port, picked[2][2] = {{0}};
  int fields;
  while ((fields = fscanf (input, "%u %u %u", &owner, &family, &local_port)) != EOF)
    {
      if (fields != 3 || total == MAX_ENDPOINTS || owner > 1 || (family != 4 && family != 6)
          || !local_port || local_port > 65535) return 2;
      unsigned *selected = &picked[owner][family == 6];
      endpoints[total++] = (endpoint_t) {.owner=owner, .family=family,
                                       .port=local_port, .target=!(*selected)};
      *selected = 1;
    }
  fclose (input);
  if (!total || !picked[0][0] || !picked[0][1] || !picked[1][0] || !picked[1][1]) return 2;
  struct rlimit limit;
  if (getrlimit (RLIMIT_NOFILE, &limit)) fail ("getrlimit");
  if (limit.rlim_cur < total+64)
    {
      if (limit.rlim_max < total+64) { errno=EMFILE; fail ("hard fd limit"); }
      limit.rlim_cur = total+64;
      if (setrlimit (RLIMIT_NOFILE, &limit)) fail ("fd limit");
    }
  if (getuid () != uid && (setgid (uid) || setuid (uid))) fail ("uid");
#ifdef __ANDROID__
  cpu_set_t cpus;
  CPU_ZERO (&cpus); CPU_SET (6, &cpus);
  if (sched_setaffinity (0, sizeof (cpus), &cpus)) fail ("helper affinity");
#endif
  setvbuf (stdout, NULL, _IOLBF, 0);
  for (unsigned i = 0; i < total; i++)
    {
      endpoint_t *e = &endpoints[i];
      e->fd = socket (e->family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
      if (e->fd < 0) fail ("socket");
      int one = 1;
      if (e->family == 6 && setsockopt (e->fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof (one))) fail ("v6only");
      struct sockaddr_storage local, remote;
      socklen_t size = address (&local, e->family, argv[e->family == 4 ? 4 : 5], e->port);
      if (bind (e->fd, (void *) &local, size)) fail ("bind");
      size = address (&remote, e->family, argv[e->family == 4 ? 6 : 7], port);
      if (connect (e->fd, (void *) &remote, size)) fail ("connect");
    }
  unsigned long long start = now_ns ();
  printf ("prepared count=%u retained_fds=%u mode=%s mono_ns=%llu\n", total, total, mode, start);
  send_phase (endpoints, total, renew_bidir || bulk || lookup, argv[9], 0, 0);
  if (renew_first || shorten || renew_bidir)
    {
      wait_until (start + (shorten ? 10000000000ULL : 20000000000ULL));
      send_phase (endpoints, total, !renew_first, argv[9], 1, 0);
    }
  else if (lookup)
    {
      unsigned long long refreshed = send_phase (endpoints, total, 1, argv[9], 1, 1);
      /* Last-deadline entries remain in the real bounded bulk backlog. Their
       * next actual packet must take logical expiry, not reuse the old flow. */
      wait_until (refreshed + 30100000000ULL);
      send_phase (endpoints, total, 1, argv[9], 2, 1);
    }
  printf ("holding count=%u retained_fds=%u mono_ns=%llu\n", total, total, now_ns ());
  for (;;) pause ();
}
