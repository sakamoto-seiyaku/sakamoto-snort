/* Independent known system-UID socket fixture; not Android resolver IPC. */
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
  if (argc != 5 || getuid () != 2000) return 2;
  unsigned port = strtoul (argv[2], NULL, 10);
  if (port < 1024 || port > 65535) return 2;
  struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons (port) };
  struct sockaddr_in remote = { .sin_family = AF_INET, .sin_port = htons (53) };
  struct timeval timeout = { .tv_sec = 1 };
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0 || inet_pton (AF_INET, argv[1], &remote.sin_addr) != 1
      || bind (fd, (void *) &local, sizeof (local))
      || connect (fd, (void *) &remote, sizeof (remote))
      || setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout)))
    { perror ("bounded system UID fixture"); return 1; }
  printf ("{\"uid\":%u,\"source_port\":%u,\"exchanges\":[", (unsigned) getuid (), port);
  for (int item = 0; item < 2; ++item)
    {
      unsigned char wire[4096], reply[8192];
      size_t length = strlen (argv[item + 3]);
      if (length < 2 || length > sizeof (wire) * 2 || length % 2) return 2;
      for (size_t i = 0; i < length / 2; ++i)
        {
          int high = nibble (argv[item + 3][2 * i]), low = nibble (argv[item + 3][2 * i + 1]);
          if (high < 0 || low < 0) return 2;
          wire[i] = (unsigned char) ((high << 4) | low);
        }
      if (item) usleep (150000);
      if (send (fd, wire, length / 2, 0) != (ssize_t) (length / 2)) return 1;
      ssize_t received = recv (fd, reply, sizeof (reply), 0);
      if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 1;
      printf ("%s{\"timed_out\":%s,\"reply_hex\":\"", item ? "," : "", received < 0 ? "true" : "false");
      for (ssize_t i = 0; i < received; ++i) printf ("%02x", reply[i]);
      printf ("\"}");
    }
  puts ("]}"); close (fd); return 0;
}
