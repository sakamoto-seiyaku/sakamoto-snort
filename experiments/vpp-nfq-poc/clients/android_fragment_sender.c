/* SPDX-License-Identifier: Apache-2.0 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint16_t
checksum (const uint8_t *data, size_t len)
{
  uint32_t sum = 0;
  while (len > 1)
    {
      sum += ((uint16_t) data[0] << 8) | data[1];
      data += 2;
      len -= 2;
    }
  if (len)
    sum += (uint16_t) data[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return htons ((uint16_t) ~sum);
}

int
main (int argc, char **argv)
{
  const char *dst_text = argc > 1 ? argv[1] : "192.168.4.1";
  int datagrams = argc > 2 ? atoi (argv[2]) : 2;
  size_t payload_len = argc > 3 ? (size_t) atoi (argv[3]) : 4000;
  struct sockaddr_in dst = { 0 };
  uint8_t *icmp_payload;
  int fd;

  if (datagrams < 1 || datagrams > 64 || payload_len < 64 || payload_len > 60000)
    return 2;
  if (inet_pton (AF_INET, dst_text, &dst.sin_addr) != 1)
    return 3;
  dst.sin_family = AF_INET;
  icmp_payload = calloc (1, payload_len);
  if (!icmp_payload)
    return 4;
  {
    struct icmphdr *icmp = (struct icmphdr *) icmp_payload;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons (0x4242);
    icmp->un.echo.sequence = htons (1);
    for (size_t i = sizeof (*icmp); i < payload_len; i++)
      icmp_payload[i] = (uint8_t) (i & 0xff);
    icmp->checksum = checksum (icmp_payload, payload_len);
  }

  fd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0)
    {
      fprintf (stderr, "socket errno=%d\n", errno);
      free (icmp_payload);
      return 5;
    }

  for (int d = 0; d < datagrams; d++)
    {
      const size_t fragment_payload = 1472; /* 1500 MTU, 8-byte aligned */
      size_t offset = 0;
      uint16_t ident = htons ((uint16_t) (0x4200 + d));
      while (offset < payload_len)
        {
          size_t chunk = payload_len - offset;
          uint8_t packet[1500];
          struct iphdr *ip = (struct iphdr *) packet;
          if (chunk > fragment_payload)
            chunk = fragment_payload;
          memset (packet, 0, sizeof (packet));
          ip->version = 4;
          ip->ihl = 5;
          ip->ttl = 64;
          ip->protocol = IPPROTO_ICMP;
          ip->id = ident;
          ip->frag_off = htons ((uint16_t) (offset / 8) |
                                (offset + chunk < payload_len ? 0x2000 : 0));
          ip->tot_len = htons ((uint16_t) (sizeof (*ip) + chunk));
          ip->daddr = dst.sin_addr.s_addr;
          memcpy (packet + sizeof (*ip), icmp_payload + offset, chunk);
          ip->check = checksum ((const uint8_t *) ip, sizeof (*ip));
          if (sendto (fd, packet, sizeof (*ip) + chunk, 0,
                      (struct sockaddr *) &dst, sizeof (dst)) < 0)
            {
              fprintf (stderr, "sendto datagram=%d offset=%zu errno=%d\n",
                       d, offset, errno);
              close (fd);
              free (icmp_payload);
              return 6;
            }
          offset += chunk;
        }
    }
  close (fd);
  free (icmp_payload);
  return 0;
}
