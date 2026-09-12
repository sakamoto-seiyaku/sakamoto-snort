/* Independent kernel UDP endpoints. No Product parser, owner or tracker code. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void fail (const char *message) { perror (message); exit (1); }
static socklen_t address (struct sockaddr_storage *storage, int family,
                          const char *ip, unsigned port)
{
  memset (storage, 0, sizeof *storage);
  if (family == 4)
    {
      struct sockaddr_in *a = (void *) storage;
      a->sin_family = AF_INET; a->sin_port = htons (port);
      if (inet_pton (AF_INET, ip, &a->sin_addr) != 1) exit (2);
      return sizeof *a;
    }
  struct sockaddr_in6 *a = (void *) storage;
  a->sin6_family = AF_INET6; a->sin6_port = htons (port);
  if (inet_pton (AF_INET6, ip, &a->sin6_addr) != 1) exit (2);
  return sizeof *a;
}

int main (int argc, char **argv)
{
  /* server uid family bind-ip port
   * client uid family bind-ip port peer-ip port count nonce echo timeout-ms */
  if (argc != 6 && argc != 12) return 2;
  int server = !strcmp (argv[1], "server");
  if ((server && argc != 6) || (!server && (argc != 12 || strcmp (argv[1], "client")))) return 2;
  unsigned uid = strtoul (argv[2], NULL, 10), family = atoi (argv[3]);
  unsigned port = strtoul (argv[5], NULL, 10);
  if ((family != 4 && family != 6) || !port || port > 65535) return 2;
  if (getuid () != uid && (setgid (uid) || setuid (uid))) fail ("uid");
  setvbuf (stdout, NULL, _IOLBF, 0);
  int fd = socket (family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, 0), one = 1;
  if (fd < 0) fail ("socket");
  if (family == 6 && setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one))
    fail ("v6only");
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one)) fail ("reuse");
  struct sockaddr_storage local, peer;
  socklen_t length = address (&local, family, argv[4], port);
  if (bind (fd, (void *) &local, length)) fail ("bind");
  if (server)
    {
      printf ("listen uid=%u family=%u address=%s port=%u\n", uid, family, argv[4], port);
      for (;;)
        {
          char bytes[256]; socklen_t peer_length = sizeof peer;
          ssize_t count = recvfrom (fd, bytes, sizeof bytes, 0, (void *) &peer, &peer_length);
          if (count < 1) fail ("recvfrom");
          /* First byte is the explicit test request to echo, not a protocol heuristic. */
          printf ("received family=%u nonce=%.*s echo=%u\n", family,
                  (int) count - 1, bytes + 1, bytes[0] == 'E');
          if (bytes[0] == 'E' && sendto (fd, bytes, count, 0,
                                        (void *) &peer, peer_length) != count)
            fail ("sendto");
        }
    }
  unsigned peer_port = strtoul (argv[7], NULL, 10), count = atoi (argv[8]);
  unsigned echo = atoi (argv[10]), timeout_ms = atoi (argv[11]);
  if (!peer_port || peer_port > 65535 || !count || count > 4 || echo > 1
      || strlen (argv[9]) > 128 || !timeout_ms || timeout_ms > 60000) return 2;
  struct timeval timeout = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
  if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout)
      || setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout)) fail ("timeout");
  length = address (&peer, family, argv[6], peer_port);
  if (connect (fd, (void *) &peer, length)) fail ("connect");
  for (unsigned i = 0; i < count; i++)
    {
      char request[256], response[256];
      int size = snprintf (request, sizeof request, "%c%s-%u", echo ? 'E' : 'S', argv[9], i);
      if (size < 0 || (size_t) size >= sizeof request) return 2;
      if (send (fd, request, size, 0) != size) fail ("send");
      if (echo)
        {
          ssize_t received = recv (fd, response, sizeof response, 0);
          if (received != size || memcmp (request, response, size)) fail ("echo");
        }
      printf ("endpoint uid=%u family=%u number=%u nonce=%s-%u sent=1 received=%u\n",
              uid, family, port, argv[9], i, echo);
    }
  close (fd);
  return 0;
}
