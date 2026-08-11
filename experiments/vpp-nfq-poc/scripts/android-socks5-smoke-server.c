// SPDX-License-Identifier: Apache-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
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

static void write_be16 (uint8_t *p, uint16_t v)
{
  p[0] = (uint8_t) (v >> 8);
  p[1] = (uint8_t) v;
}

static void log_now (const char *message)
{
  time_t now = time (NULL);
  fprintf (stdout, "%lld %s\n", (long long) now, message);
  fflush (stdout);
}

static int socks_addr_len (uint8_t atyp, uint8_t domain_len)
{
  if (atyp == 1)
    return 7;
  if (atyp == 4)
    return 19;
  if (atyp == 3)
    return 2 + domain_len + 2;
  return -1;
}

static int read_socks_addr (int fd, uint8_t atyp, uint8_t *addr, size_t addr_cap,
			    char *host, size_t host_cap, uint16_t *port)
{
  size_t len = 0;

  if (addr_cap == 0)
    return -1;
  addr[0] = atyp;

  if (atyp == 1)
    {
      len = 7;
      if (addr_cap < len || recv_exact (fd, addr + 1, len - 1) < 0)
	return -1;
      inet_ntop (AF_INET, addr + 1, host, host_cap);
      *port = read_be16 (addr + 5);
      return (int) len;
    }
  if (atyp == 4)
    {
      len = 19;
      if (addr_cap < len || recv_exact (fd, addr + 1, len - 1) < 0)
	return -1;
      inet_ntop (AF_INET6, addr + 1, host, host_cap);
      *port = read_be16 (addr + 17);
      return (int) len;
    }
  if (atyp == 3)
    {
      uint8_t name_len = 0;
      if (recv_exact (fd, &name_len, 1) < 0)
	return -1;
      len = (size_t) 2 + name_len + 2;
      if (addr_cap < len || host_cap <= name_len)
	return -1;
      addr[1] = name_len;
      if (recv_exact (fd, addr + 2, (size_t) name_len + 2) < 0)
	return -1;
      memcpy (host, addr + 2, name_len);
      host[name_len] = 0;
      *port = read_be16 (addr + 2 + name_len);
      return (int) len;
    }

  return -1;
}

static int socks_addr_to_sockaddr (const uint8_t *addr, struct sockaddr_storage *out,
				   socklen_t *out_len)
{
  memset (out, 0, sizeof (*out));

  if (addr[0] == 1)
    {
      struct sockaddr_in *sin = (struct sockaddr_in *) out;
      sin->sin_family = AF_INET;
      memcpy (&sin->sin_addr, addr + 1, 4);
      memcpy (&sin->sin_port, addr + 5, 2);
      *out_len = sizeof (*sin);
      return AF_INET;
    }
  if (addr[0] == 4)
    {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) out;
      sin6->sin6_family = AF_INET6;
      memcpy (&sin6->sin6_addr, addr + 1, 16);
      memcpy (&sin6->sin6_port, addr + 17, 2);
      *out_len = sizeof (*sin6);
      return AF_INET6;
    }

  return -1;
}

static int write_socks_success (int fd)
{
  uint8_t ok[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
  return send (fd, ok, sizeof (ok), 0) == (ssize_t) sizeof (ok) ? 0 : -1;
}

static ssize_t synthesize_dns_response (const uint8_t *query, size_t query_len,
					uint8_t *out, size_t out_cap)
{
  if (query_len < 17 || out_cap < query_len + 16)
    return -1;

  size_t question_end = 12;
  while (question_end < query_len && query[question_end] != 0)
    question_end += (size_t) query[question_end] + 1;
  if (question_end + 5 > query_len)
    return -1;
  question_end += 5;

  memcpy (out, query, question_end);
  out[2] = 0x81;
  out[3] = 0x80;
  out[6] = 0x00;
  out[7] = 0x01;
  out[8] = 0x00;
  out[9] = 0x00;
  out[10] = 0x00;
  out[11] = 0x00;

  uint8_t answer[] = {
    0xc0, 0x0c,             /* compressed name pointer to qname */
    0x00, 0x01,             /* type A */
    0x00, 0x01,             /* class IN */
    0x00, 0x00, 0x00, 0x3c, /* ttl 60s */
    0x00, 0x04,             /* rdlength */
    0x5d, 0xb8, 0xd8, 0x22, /* 93.184.216.34 */
  };
  memcpy (out + question_end, answer, sizeof (answer));
  return (ssize_t) (question_end + sizeof (answer));
}

static void handle_udp_in_tcp (int fd)
{
  uint8_t addr[260];
  uint8_t payload[2048];
  uint8_t response_payload[2048];
  uint8_t reply[3 + 260 + 2048];

  log_now ("udp-in-tcp start");
  for (;;)
    {
      uint8_t head[3];
      if (recv_exact (fd, head, sizeof (head)) < 0)
	{
	  log_now ("udp-in-tcp stop");
	  return;
	}

      uint16_t datlen = read_be16 (head);
      uint8_t hdrlen = head[2];
      if (hdrlen < 5 || (size_t) hdrlen > sizeof (addr) + 3
	  || datlen > sizeof (payload))
	{
	  log_now ("udp-in-tcp bad frame");
	  return;
	}

      size_t addr_len = (size_t) hdrlen - 3;
      if (recv_exact (fd, addr, addr_len) < 0
	  || recv_exact (fd, payload, datlen) < 0)
	return;

      int expected_addr_len = socks_addr_len (addr[0], addr[1]);
      if (expected_addr_len != (int) addr_len)
	{
	  log_now ("udp-in-tcp bad addr");
	  return;
	}

      struct sockaddr_storage dst;
      socklen_t dst_len = 0;
      int family = socks_addr_to_sockaddr (addr, &dst, &dst_len);
      if (family < 0)
	{
	  log_now ("udp-in-tcp unsupported addr");
	  return;
	}

      char host[INET6_ADDRSTRLEN + 1] = { 0 };
      uint16_t port = 0;
      if (addr[0] == 1)
	{
	  inet_ntop (AF_INET, addr + 1, host, sizeof (host));
	  port = read_be16 (addr + 5);
	}
      else if (addr[0] == 4)
	{
	  inet_ntop (AF_INET6, addr + 1, host, sizeof (host));
	  port = read_be16 (addr + 17);
	}
      fprintf (stdout, "udp %s:%u bytes %u\n", host, port, datlen);
      fflush (stdout);

      ssize_t got = -1;
      if (port == 53)
	{
	  got = synthesize_dns_response (payload, datlen, response_payload,
					 sizeof (response_payload));
	  if (got > 0)
	    log_now ("udp synthetic-dns response");
	}

      if (got > 0)
	goto write_response;

      int udp = socket (family, SOCK_DGRAM, 0);
      if (udp < 0)
	{
	  log_now ("udp socket failed");
	  return;
	}

      struct timeval tv = { .tv_sec = 4, .tv_usec = 0 };
      setsockopt (udp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
      setsockopt (udp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));

      ssize_t sent = sendto (udp, payload, datlen, 0, (struct sockaddr *) &dst, dst_len);
      if (sent != datlen)
	{
	  close (udp);
	  log_now ("udp send failed");
	  return;
	}

      got = recvfrom (udp, response_payload, sizeof (response_payload), 0, NULL, NULL);
      close (udp);
      if (got <= 0)
	{
	  fprintf (stdout, "udp response-len %zd errno %d\n", got, errno);
	  fflush (stdout);
	  continue;
	}

write_response:
      write_be16 (reply, (uint16_t) got);
      reply[2] = hdrlen;
      memcpy (reply + 3, addr, addr_len);
      memcpy (reply + 3 + addr_len, response_payload, (size_t) got);
      size_t total = (size_t) 3 + addr_len + (size_t) got;
      if (send (fd, reply, total, 0) != (ssize_t) total)
	{
	  log_now ("udp response write failed");
	  return;
	}
      fprintf (stdout, "udp response-len %zd\n", got);
      fflush (stdout);
    }
}

static void handle_client (int fd)
{
  uint8_t buf[8192];
  uint8_t head[4];
  uint8_t req_addr[260];
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
  if (head[0] != 5 || (head[1] != 1 && head[1] != 5))
    {
      log_now ("bad connect head");
      return;
    }

  memset (host, 0, sizeof (host));
  if (read_socks_addr (fd, head[3], req_addr, sizeof (req_addr), host,
		       sizeof (host), &port) < 0)
    {
      log_now ("bad atyp");
      return;
    }

  if (head[1] == 5)
    {
      fprintf (stdout, "fwd-udp %s:%u\n", host, port);
      fflush (stdout);
      if (write_socks_success (fd) < 0)
	return;
      handle_udp_in_tcp (fd);
      return;
    }

  fprintf (stdout, "connect %s:%u\n", host, port);
  fflush (stdout);

  if (write_socks_success (fd) < 0)
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
  addr.sin_addr.s_addr = htonl (INADDR_ANY);
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

  log_now ("android socks5 smoke server ready 0.0.0.0:41080");
  signal (SIGCHLD, SIG_IGN);
  for (;;)
    {
      int fd = accept (server, NULL, NULL);
      if (fd < 0)
	{
	  perror ("accept");
	  break;
	}
      log_now ("accepted");
      pid_t pid = fork ();
      if (pid == 0)
	{
	  close (server);
	  handle_client (fd);
	  close (fd);
	  return 0;
	}
      close (fd);
    }

  close (server);
  log_now ("android socks5 smoke server stop");
  return 0;
}
