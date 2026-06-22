// SPDX-License-Identifier: Apache-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int recv_exact (int fd, void *buf, size_t len)
{
  uint8_t *p = buf;
  size_t got = 0;

  while (got < len)
    {
      ssize_t n = recv (fd, p + got, len - got, 0);
      if (n <= 0)
	return -1;
      got += (size_t) n;
    }
  return 0;
}

static uint16_t read_be16 (const uint8_t *p)
{
  return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static void log_now (const char *message)
{
  time_t now = time (NULL);
  fprintf (stdout, "%lld %s\n", (long long) now, message);
  fflush (stdout);
}

static void handle_client (int fd)
{
  uint8_t buf[8192];
  uint8_t head[4];
  char host[INET6_ADDRSTRLEN + 1];
  uint16_t port = 0;

  struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));

  if (recv_exact (fd, head, 2) < 0)
    {
      log_now ("short greeting");
      return;
    }
  if (head[0] != 5)
    {
      log_now ("bad greeting");
      return;
    }
  if (recv_exact (fd, buf, head[1]) < 0)
    {
      log_now ("short methods");
      return;
    }
  log_now ("greeting ok");
  uint8_t auth_reply[2] = { 5, 0 };
  if (send (fd, auth_reply, sizeof (auth_reply), 0) != (ssize_t) sizeof (auth_reply))
    return;

  if (recv_exact (fd, head, 4) < 0)
    {
      log_now ("short connect head");
      return;
    }
  if (head[0] != 5 || head[1] != 1)
    {
      log_now ("bad connect head");
      return;
    }

  memset (host, 0, sizeof (host));
  if (head[3] == 1)
    {
      uint8_t addr[4];
      if (recv_exact (fd, addr, sizeof (addr)) < 0)
	return;
      inet_ntop (AF_INET, addr, host, sizeof (host));
    }
  else if (head[3] == 3)
    {
      uint8_t len;
      if (recv_exact (fd, &len, 1) < 0 || len >= sizeof (host))
	return;
      if (recv_exact (fd, host, len) < 0)
	return;
      host[len] = 0;
    }
  else if (head[3] == 4)
    {
      uint8_t addr[16];
      if (recv_exact (fd, addr, sizeof (addr)) < 0)
	return;
      inet_ntop (AF_INET6, addr, host, sizeof (host));
    }
  else
    {
      log_now ("bad atyp");
      return;
    }

  uint8_t port_buf[2];
  if (recv_exact (fd, port_buf, sizeof (port_buf)) < 0)
    return;
  port = read_be16 (port_buf);
  fprintf (stdout, "connect %s:%u\n", host, port);
  fflush (stdout);

  uint8_t ok[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
  if (send (fd, ok, sizeof (ok), 0) != (ssize_t) sizeof (ok))
    return;

  ssize_t n = recv (fd, buf, sizeof (buf) - 1, 0);
  if (n > 0)
    {
      buf[n] = 0;
      fprintf (stdout, "payload-len %zd\n", n);
      fwrite (buf, 1, (size_t) n, stdout);
      fputc ('\n', stdout);
      fflush (stdout);
    }
  else
    {
      fprintf (stdout, "payload-len %zd errno %d\n", n, errno);
      fflush (stdout);
    }

  const char reply[] = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";
  send (fd, reply, sizeof (reply) - 1, 0);
}

int main (void)
{
  int server = socket (AF_INET, SOCK_STREAM, 0);
  if (server < 0)
    {
      perror ("socket");
      return 1;
    }

  int one = 1;
  setsockopt (server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));

  struct sockaddr_in addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (41080);
  inet_pton (AF_INET, "127.0.0.1", &addr.sin_addr);
  if (bind (server, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    {
      perror ("bind");
      close (server);
      return 1;
    }
  if (listen (server, 8) < 0)
    {
      perror ("listen");
      close (server);
      return 1;
    }

  log_now ("android socks5 smoke server ready 127.0.0.1:41080");
  for (int i = 0; i < 8; i++)
    {
      int fd = accept (server, NULL, NULL);
      if (fd < 0)
	{
	  perror ("accept");
	  break;
	}
      log_now ("accepted");
      handle_client (fd);
      close (fd);
    }

  close (server);
  log_now ("android socks5 smoke server stop");
  return 0;
}
