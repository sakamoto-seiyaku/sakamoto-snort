/* SPDX-License-Identifier: Apache-2.0
 * Diagnostic endpoint: real UDP datagrams, one send per nonce, no graph API. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main (int argc, char **argv)
{
  if (argc != 6) return 2; /* uid family destination port nonce-prefix */
  unsigned uid = (unsigned) strtoul (argv[1], NULL, 10);
  int family = atoi (argv[2]) == 6 ? AF_INET6 : AF_INET;
  int port = atoi (argv[4]);
  if (setgid (uid) || setuid (uid)) { perror ("setuid"); return 3; }
  int fd = socket (family, SOCK_DGRAM, 0), capacity = 262144;
  if (fd < 0) { perror ("socket"); return 4; }
  setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &capacity, sizeof capacity);
  struct sockaddr_storage address = {0};
  socklen_t length;
  if (family == AF_INET)
    {
      struct sockaddr_in *v4 = (struct sockaddr_in *) &address;
      v4->sin_family = AF_INET; v4->sin_port = htons ((unsigned short) port);
      if (inet_pton (AF_INET, argv[3], &v4->sin_addr) != 1) return 5;
      length = sizeof *v4;
    }
  else
    {
      struct sockaddr_in6 *v6 = (struct sockaddr_in6 *) &address;
      v6->sin6_family = AF_INET6; v6->sin6_port = htons ((unsigned short) port);
      if (inet_pton (AF_INET6, argv[3], &v6->sin6_addr) != 1) return 5;
      length = sizeof *v6;
    }
  if (connect (fd, (struct sockaddr *) &address, length)) { perror ("connect"); return 6; }
  length = sizeof address;
  if (getsockname (fd, (struct sockaddr *) &address, &length)) return 7;
  unsigned source_port = family == AF_INET
    ? ntohs (((struct sockaddr_in *) &address)->sin_port)
    : ntohs (((struct sockaddr_in6 *) &address)->sin6_port);
  setvbuf (stdin, NULL, _IONBF, 0);
  setvbuf (stdout, NULL, _IOLBF, 0);
  printf ("client.ready uid=%u euid=%u pid=%u port=%u family=%u\n",
          (unsigned) getuid (), (unsigned) geteuid (), (unsigned) getpid (),
          source_port, family == AF_INET ? 4 : 6);
  for (;;)
    {
      struct pollfd fds[2] = {{STDIN_FILENO, POLLIN, 0}, {fd, POLLIN, 0}};
      if (poll (fds, 2, -1) < 0) { if (errno == EINTR) continue; return 8; }
      if (fds[0].revents & (POLLIN | POLLHUP))
        {
          char input[256], phase[100]; unsigned count, interval;
          if (!fgets (input, sizeof input, stdin) || !strcmp (input, "quit\n")) break;
          if (sscanf (input, "send %99s %u %u", phase, &count, &interval) != 3
              || count > 256 || interval > 500000) return 9;
          for (unsigned i = 0; i < count; i++)
            {
              char data[256];
              int size = snprintf (data, sizeof data, "%s-%s-%u\n", argv[5], phase, i);
              if (size < 0 || (size_t) size >= sizeof data
                  || send (fd, data, (size_t) size, 0) != size) { perror ("send"); return 10; }
              if (interval)
                {
                  struct timespec delay = {0, (long) interval * 1000};
                  while (nanosleep (&delay, &delay) && errno == EINTR) { }
                }
            }
          printf ("client.sent phase=%s count=%u\n", phase, count);
        }
      if (fds[1].revents & POLLIN)
        {
          char data[512]; ssize_t size = recv (fd, data, sizeof data - 1, 0);
          if (size < 0) { perror ("recv"); return 11; }
          data[size] = 0;
          printf ("client.received nonce=%s", data);
          if (!size || data[size - 1] != '\n') putchar ('\n');
        }
    }
  close (fd);
  puts ("client.closed=1");
  return 0;
}
