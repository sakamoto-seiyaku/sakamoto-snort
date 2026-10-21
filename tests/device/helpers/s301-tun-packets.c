/* SPDX-License-Identifier: Apache-2.0 */
/* Inject bounded real IPv4 packets through the running Android VPN TUN route. */
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  if (argc != 4 || (strcmp(argv[2], "valid") && strcmp(argv[2], "invalid") &&
                    strcmp(argv[2], "fragment"))) return 2;
  char *end = NULL;
  unsigned long count = strtoul(argv[3], &end, 10);
  if (!end || *end || count < 1 || count > 64 ||
      (!strcmp(argv[2], "fragment") && count != 1)) return 2;
  int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
  if (fd < 0) { perror("raw socket"); return 1; }
  int yes = 1;
  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) ||
      setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]) + 1)) {
    perror("socket options"); close(fd); return 1;
  }
  unsigned char packet[28] = {0};
  packet[0] = !strcmp(argv[2], "invalid") ? 0x44 : 0x45;
  packet[2] = 0; packet[3] = sizeof(packet);
  packet[8] = 64; packet[9] = 17;
  inet_pton(AF_INET, "10.111.0.2", packet + 12);
  inet_pton(AF_INET, "198.18.213.1", packet + 16);
  packet[20] = 0xa4; packet[21] = 0x10; /* UDP source 42000. */
  packet[22] = 0x9e; packet[23] = 0xb9; /* UDP destination 40633. */
  packet[24] = 0; packet[25] = 8;
  struct sockaddr_in destination = {.sin_family = AF_INET};
  inet_pton(AF_INET, "198.18.213.1", &destination.sin_addr);
  unsigned long sent = 0;
  if (!strcmp(argv[2], "fragment")) {
    unsigned char first[36] = {0}, second[28] = {0};
    memcpy(first, packet, 20);
    memcpy(second, packet, 20);
    first[2] = 0; first[3] = sizeof(first);
    second[2] = 0; second[3] = sizeof(second);
    first[4] = second[4] = 0x03;
    first[5] = second[5] = 0x01;
    first[6] = 0x20; first[7] = 0; /* MF, offset zero. */
    second[6] = 0; second[7] = 2; /* Final piece, offset 16 bytes. */
    memcpy(first + 20, packet + 20, 8);
    first[24] = 0; first[25] = 24; /* UDP header plus 16 payload bytes. */
    memcpy(first + 28, "S301PART", 8);
    memcpy(second + 20, "S301DONE", 8);
    if (sendto(fd, first, sizeof(first), 0,
               (struct sockaddr *)&destination, sizeof(destination)) == sizeof(first))
      ++sent;
    if (sendto(fd, second, sizeof(second), 0,
               (struct sockaddr *)&destination, sizeof(destination)) == sizeof(second))
      ++sent;
    count = 2;
  } else {
    for (unsigned long i = 0; i < count; ++i)
      if (sendto(fd, packet, sizeof(packet), 0,
                 (struct sockaddr *)&destination, sizeof(destination)) == sizeof(packet))
        ++sent;
  }
  printf("kind=%s requested=%lu sent=%lu errno=%d\n", argv[2], count, sent,
         sent == count ? 0 : errno);
  close(fd);
  return sent == count ? 0 : 1;
}
