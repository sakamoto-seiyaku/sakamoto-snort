/* Bounded read-only TCP53 underlay witness; no Product parsing or injection. */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned short u16 (const unsigned char *p)
{
  return (unsigned short) (p[0] * 256U + p[1]);
}

int main (int argc, char **argv)
{
  if (argc != 7 || getuid () != 0 || strcmp (argv[1], "wlan0")
      || strcmp (argv[2], "/data/local/tmp/s313-wire.stop")) return 2;
  unsigned char allowed[4][16] = {{0}};
  int families[4];
  for (int i = 0; i < 4; ++i)
    {
      families[i] = strchr (argv[i + 3], ':') ? AF_INET6 : AF_INET;
      if (inet_pton (families[i], argv[i + 3], allowed[i]) != 1) return 2;
    }
  int fd = socket (AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons (ETH_P_ALL));
  struct sockaddr_ll link = { .sll_family = AF_PACKET,
    .sll_protocol = htons (ETH_P_ALL), .sll_ifindex = (int) if_nametoindex (argv[1]) };
  if (fd < 0 || !link.sll_ifindex || bind (fd, (void *) &link, sizeof (link)))
    { perror ("underlay witness"); return 1; }
  setvbuf (stdout, NULL, _IOLBF, 0);
  puts ("{\"kind\":\"ready\",\"interface\":\"wlan0\"}");
  struct timespec start, now;
  if (clock_gettime (CLOCK_MONOTONIC, &start)) return 1;
  unsigned matched = 0;
  for (;;)
    {
      if (!access (argv[2], F_OK)) break;
      if (clock_gettime (CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 1200) break;
      struct pollfd pending = { .fd = fd, .events = POLLIN };
      int ready = poll (&pending, 1, 200);
      if (ready < 0 && errno == EINTR) continue;
      if (ready < 0) { perror ("underlay poll"); return 1; }
      if (!ready) continue;
      unsigned char packet[65536];
      ssize_t count = recv (fd, packet, sizeof (packet), 0);
      if (count < 0) { if (errno == EINTR) continue; perror ("underlay recv"); return 1; }
      size_t size = (size_t) count, ip = ETH_HLEN, tcp, total;
      int family;
      const unsigned char *source, *destination;
      if (size < ip + 20) continue;
      if (u16 (packet + 12) == ETH_P_IP)
        {
          family = AF_INET;
          size_t header = (packet[ip] & 15U) * 4U;
          total = u16 (packet + ip + 2);
          if ((packet[ip] >> 4) != 4 || header < 20 || packet[ip + 9] != 6
              || (u16 (packet + ip + 6) & 0x3fff) || total < header + 20 || total > size - ip) continue;
          tcp = ip + header; source = packet + ip + 12; destination = packet + ip + 16;
        }
      else if (u16 (packet + 12) == ETH_P_IPV6)
        {
          family = AF_INET6;
          if (size < ip + 60 || (packet[ip] >> 4) != 6 || packet[ip + 6] != 6) continue;
          total = 40U + u16 (packet + ip + 4);
          if (total < 60 || total > size - ip) continue;
          tcp = ip + 40; source = packet + ip + 8; destination = packet + ip + 24;
        }
      else continue;
      if (u16 (packet + tcp) != 53 && u16 (packet + tcp + 2) != 53) continue;
      int selected = 0;
      for (int i = 0; i < 4; ++i)
        if (families[i] == family &&
            (!memcmp (allowed[i], source, family == AF_INET ? 4 : 16) ||
             !memcmp (allowed[i], destination, family == AF_INET ? 4 : 16))) selected = 1;
      if (!selected) continue;
      size_t header = (packet[tcp + 12] >> 4) * 4U;
      size_t bytes = ip + total - tcp;
      if (header < 20 || header > bytes) continue;
      char from[INET6_ADDRSTRLEN], to[INET6_ADDRSTRLEN];
      if (!inet_ntop (family, source, from, sizeof (from)) ||
          !inet_ntop (family, destination, to, sizeof (to))) return 1;
      printf ("{\"kind\":\"tcp\",\"source\":\"%s\",\"destination\":\"%s\",\"source_port\":%u,\"destination_port\":%u,\"payload_hex\":\"",
              from, to, u16 (packet + tcp), u16 (packet + tcp + 2));
      for (size_t i = header; i < bytes; ++i) printf ("%02x", packet[tcp + i]);
      printf ("\",\"sequence\":%u,\"flags\":%u}\n",
        ((unsigned)packet[tcp+4]<<24)|((unsigned)packet[tcp+5]<<16)|((unsigned)packet[tcp+6]<<8)|packet[tcp+7],packet[tcp+13]);
      if (++matched == 16384) break;
    }
  close (fd);
  printf ("{\"kind\":\"stopped\",\"matched\":%u}\n", matched);
  return 0;
}
