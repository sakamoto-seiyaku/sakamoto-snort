/* SPDX-License-Identifier: Apache-2.0 */
/* Keep a real TUN read lane ready while Product UDP returns complete. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t monotonic_ns(void)
{
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now)) abort();
  return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

int main(int argc, char **argv)
{
  if (argc != 4) return 2;
  char *end = NULL;
  unsigned long count = strtoul(argv[2], &end, 10);
  if (!end || *end || count < 100 || count > 10000) return 2;
  unsigned long interval_us = strtoul(argv[3], &end, 10);
  if (!end || *end || interval_us > 100000) return 2;
  int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
  if (fd < 0) { perror("raw socket"); return 1; }
  int yes = 1;
  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) ||
      setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]) + 1)) {
    perror("socket options"); return 1;
  }
  unsigned char packet[28] = {0};
  packet[0] = 0x44; /* Real TUN ingress, invalid IPv4 IHL; no owner state. */
  packet[3] = sizeof(packet);
  packet[8] = 64; packet[9] = 17;
  inet_pton(AF_INET, "10.111.0.2", packet + 12);
  inet_pton(AF_INET, "198.18.213.1", packet + 16);
  packet[20] = 0xa4; packet[21] = 0x10;
  packet[22] = 0x9e; packet[23] = 0xb9;
  packet[25] = 8;
  struct sockaddr_in destination = {.sin_family = AF_INET};
  inet_pton(AF_INET, "198.18.213.1", &destination.sin_addr);
  struct timespec interval = {.tv_sec = interval_us / 1000000,
                               .tv_nsec = (interval_us % 1000000) * 1000};
  unsigned long sent = 0, failed = 0;
  uint64_t started = monotonic_ns();
  for (unsigned long i = 0; i < count; ++i) {
    ssize_t n = sendto(fd, packet, sizeof(packet), 0,
                       (struct sockaddr *)&destination, sizeof(destination));
    if (n == (ssize_t)sizeof(packet)) ++sent; else ++failed;
    if (interval_us) nanosleep(&interval, NULL);
  }
  uint64_t ended = monotonic_ns();
  printf("started_ns=%llu ended_ns=%llu requested=%lu sent=%lu failed=%lu\n",
         (unsigned long long)started, (unsigned long long)ended,
         count, sent, failed);
  close(fd);
  return sent >= count / 2 ? 0 : 1;
}
