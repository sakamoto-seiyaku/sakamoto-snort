/* SPDX-License-Identifier: Apache-2.0 */
/* Emit a controlled malformed IPv4 datagram onto a VPN TUN route. */
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
  if (argc != 2) return 2; /* interface */
  int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
  if (fd < 0) { perror("raw socket"); return 1; }
  int yes = 1;
  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) ||
      setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]) + 1)) {
    perror("socket options"); return 1;
  }
  unsigned char packet[28] = {0};
  packet[0] = 0x44; /* IPv4 IHL=4 is invalid but reaches the TUN egress fd. */
  packet[2] = 0; packet[3] = sizeof(packet);
  packet[8] = 64; packet[9] = 17;
  inet_pton(AF_INET, "10.111.0.2", packet + 12);
  inet_pton(AF_INET, "198.18.213.1", packet + 16);
  packet[20] = 0xa4; packet[21] = 0x10;
  packet[22] = 0x9e; packet[23] = 0xb9;
  packet[24] = 0; packet[25] = 8;
  struct sockaddr_in destination = {.sin_family = AF_INET};
  inet_pton(AF_INET, "198.18.213.1", &destination.sin_addr);
  ssize_t sent = sendto(fd, packet, sizeof(packet), 0,
                        (struct sockaddr *)&destination, sizeof(destination));
  printf("kind=invalid_ipv4_ihl sent=%zd errno=%d\n", sent,
         sent < 0 ? errno : 0);
  close(fd);
  return sent == (ssize_t)sizeof(packet) ? 0 : 1;
}
