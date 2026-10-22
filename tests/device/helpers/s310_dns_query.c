/* Independent system-UID UDP fixture; no Product or DNS parser code. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int nibble (char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

int main (int argc, char **argv)
{
  if (argc != 4 || getuid () != 2000) return 2;
  unsigned port = strtoul (argv[2], NULL, 10);
  size_t size = strlen (argv[3]);
  if (port < 1024 || port > 65535 || size < 2 || size > 8192 || size % 2) return 2;
  unsigned char wire[4096], reply[8192];
  for (size_t i = 0; i < size / 2; ++i)
    {
      int high = nibble (argv[3][i * 2]), low = nibble (argv[3][i * 2 + 1]);
      if (high < 0 || low < 0) return 2;
      wire[i] = (high << 4) | low;
    }
  struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons (port) };
  struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons (53) };
  struct timeval timeout = { .tv_sec = 1 };
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 || inet_pton (AF_INET, argv[1], &remote.sin_addr) != 1
      || bind (fd, (void *) &local, sizeof (local))
      || connect (fd, (void *) &remote, sizeof (remote))
      || setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout)))
    { perror ("bounded UDP fixture"); return 1; }
  socklen_t length = sizeof (local);
  if (getsockname (fd, (void *) &local, &length) || ntohs (local.sin_port) != port
      || send (fd, wire, size / 2, 0) != (ssize_t) (size / 2))
    { perror ("fixture source/send"); return 1; }
  ssize_t received = recv (fd, reply, sizeof (reply), 0);
  if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    { perror ("fixture receive"); return 1; }
  printf ("{\"uid\":%u,\"source_port\":%u,\"timed_out\":%s,\"reply_hex\":\"",
          (unsigned) getuid (), ntohs (local.sin_port), received < 0 ? "true" : "false");
  for (ssize_t i = 0; i < received; ++i) printf ("%02x", reply[i]);
  puts ("\"}");
  close (fd);
  return 0;
}
