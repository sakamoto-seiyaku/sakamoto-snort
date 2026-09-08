/* SPDX-License-Identifier: Apache-2.0
 * Independent kernel endpoint and Ethernet capture, never a VPP injector. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/capability.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void fail (const char *name) { perror (name); exit (1); }
static void put16 (uint8_t *p, unsigned n) { p[0] = n >> 8; p[1] = n; }
static void put32 (uint8_t *p, uint32_t n) { put16 (p, n >> 16); put16 (p+2, n); }
static unsigned sum16 (const uint8_t *p, size_t n)
{
  unsigned value = 0;
  while (n > 1) { value += ((unsigned) p[0] << 8) | p[1]; p += 2; n -= 2; }
  if (n) value += (unsigned) p[0] << 8;
  return value;
}
static uint16_t finish_sum (unsigned value)
{
  while (value >> 16) value = (value & 65535) + (value >> 16);
  return (uint16_t) ~value;
}
static void become (uid_t uid)
{
  if (getuid () == uid && geteuid () == uid) return;
  if (prctl (PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) || setgid (uid) || setuid (uid)) fail ("setuid");
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct data[2] = {{0}};
  data[0].permitted = data[0].effective = 1U << CAP_NET_RAW;
  if (syscall (SYS_capset, &header, data)) fail ("capset NET_RAW");
}
static socklen_t address (int family, const char *ip, unsigned port,
                           struct sockaddr_storage *storage)
{
  memset (storage, 0, sizeof *storage);
  if (family == 4)
    {
      struct sockaddr_in *a = (void *) storage;
      a->sin_family = AF_INET; a->sin_port = htons (port);
      if (inet_pton (AF_INET, ip, &a->sin_addr) != 1) exit (2);
      return sizeof *a;
    }
  struct sockaddr_in6 *a = (void *) storage;
  a->sin6_family = AF_INET6; a->sin6_port = htons (port);
  if (inet_pton (AF_INET6, ip, &a->sin6_addr) != 1) exit (2);
  return sizeof *a;
}
static void bind_device (int fd, const char *name)
{
  if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen (name)+1)) fail ("SO_BINDTODEVICE");
}
static void mac (const char *name, uint8_t *bytes)
{
  int fd = socket (AF_INET, SOCK_DGRAM, 0);
  struct ifreq request = {0};
  snprintf (request.ifr_name, sizeof request.ifr_name, "%s", name);
  if (fd < 0 || ioctl (fd, SIOCGIFHWADDR, &request)) fail ("MAC");
  memcpy (bytes, request.ifr_hwaddr.sa_data, 6); close (fd);
}
static void payload (uint8_t *p, size_t size, const char *nonce)
{
  size_t length = strlen (nonce);
  if (length+1 > size) exit (2);
  memset (p, '~', size); memcpy (p, nonce, length); p[length] = '\n';
}
static void hex (const uint8_t *p, size_t size)
{
  for (size_t i = 0; i < size; i++) printf ("%02x", p[i]);
}
static void fragments (int argc, char **argv)
{
  if (argc != 11) exit (2);
  int whole = !strcmp (argv[1], "inject-whole");
  int inject = whole || !strcmp (argv[1], "inject"), family = atoi (argv[3]);
  const char *tx = argv[4], *rx = argv[5];
  unsigned id = strtoul (argv[8], NULL, 0), reverse = atoi (argv[9]);
  become ((uid_t) strtoul (argv[2], NULL, 10));
  uint8_t source[16], destination[16], udp[104] = {0}, pseudo[40] = {0};
  if (inet_pton (family == 4 ? AF_INET : AF_INET6, argv[6], source) != 1
      || inet_pton (family == 4 ? AF_INET : AF_INET6, argv[7], destination) != 1) exit (2);
  put16 (udp, 37031); put16 (udp+2, 40631); put16 (udp+4, sizeof udp);
  payload (udp+8, sizeof udp-8, argv[10]);
  size_t pseudo_size;
  if (family == 4)
    {
      memcpy (pseudo, source, 4); memcpy (pseudo+4, destination, 4);
      pseudo[9] = 17; put16 (pseudo+10, sizeof udp); pseudo_size = 12;
    }
  else
    {
      memcpy (pseudo, source, 16); memcpy (pseudo+16, destination, 16);
      put32 (pseudo+32, sizeof udp); pseudo[39] = 17; pseudo_size = 40;
    }
  uint16_t checksum = finish_sum (sum16 (pseudo, pseudo_size)+sum16 (udp, sizeof udp));
  put16 (udp+6, checksum ? checksum : 65535);
  int fd = socket (inject ? AF_PACKET : family == 4 ? AF_INET : AF_INET6,
                   SOCK_RAW, inject ? htons (family == 4 ? ETH_P_IP : ETH_P_IPV6) : IPPROTO_RAW);
  if (fd < 0) fail ("raw socket");
  uint8_t ether[14] = {0};
  struct sockaddr_ll link = {0};
  struct sockaddr_storage remote;
  socklen_t remote_size = address (family, argv[7], 0, &remote);
  if (inject)
    {
      mac (rx, ether); mac (tx, ether+6); put16 (ether+12, family == 4 ? ETH_P_IP : ETH_P_IPV6);
      link.sll_family = AF_PACKET; link.sll_ifindex = if_nametoindex (tx);
      link.sll_halen = 6; memcpy (link.sll_addr, ether, 6);
      if (!link.sll_ifindex) fail ("ifindex");
    }
  else
    {
      int one = 1;
      bind_device (fd, tx);
      if (setsockopt (fd, family == 4 ? IPPROTO_IP : IPPROTO_IPV6,
                      family == 4 ? IP_HDRINCL : IPV6_HDRINCL, &one, sizeof one)) fail ("HDRINCL");
    }
  for (unsigned order = 0; order < (whole ? 1U : 2U); order++)
    {
      unsigned fragment = reverse ? 1-order : order;
      size_t offset = whole ? 0 : fragment ? 48 : 0;
      size_t size = whole ? sizeof udp : fragment ? sizeof udp-48 : 48;
      uint8_t packet[256] = {0}, frame[270];
      size_t packet_size;
      if (family == 4)
        {
          packet[0] = 0x45; put16 (packet+2, 20+size); put16 (packet+4, id);
          put16 (packet+6, whole ? 0 : fragment ? offset/8 : 0x2000); packet[8] = 64; packet[9] = 17;
          memcpy (packet+12, source, 4); memcpy (packet+16, destination, 4);
          put16 (packet+10, finish_sum (sum16 (packet, 20)));
          memcpy (packet+20, udp+offset, size); packet_size = 20+size;
        }
      else
        {
          packet[0] = 0x60; put16 (packet+4, (whole ? 0 : 8)+size); packet[6] = whole ? 17 : 44; packet[7] = 64;
          memcpy (packet+8, source, 16); memcpy (packet+24, destination, 16);
          if (!whole) { packet[40] = 17; put16 (packet+42, offset | (fragment ? 0 : 1)); put32 (packet+44, id); }
          memcpy (packet+(whole ? 40 : 48), udp+offset, size); packet_size = (whole ? 40 : 48)+size;
        }
      ssize_t sent;
      if (inject)
        {
          memcpy (frame, ether, 14); memcpy (frame+14, packet, packet_size);
          sent = sendto (fd, frame, packet_size+14, 0, (void *) &link, sizeof link);
          if (sent != (ssize_t) packet_size+14) fail ("packet send");
        }
      else
        {
          sent = sendto (fd, packet, packet_size, 0, (void *) &remote, remote_size);
          if (sent != (ssize_t) packet_size) fail ("raw send");
        }
      printf ("send mode=%s uid=%u euid=%u family=%u id=%u order=%u offset=%zu more=%u bytes=%zu sent=%zd raw=",
              argv[1], (unsigned) getuid (), (unsigned) geteuid (), family, id, order, offset,
              !whole && !fragment, packet_size, sent);
      hex (packet, packet_size); putchar ('\n'); usleep (10000);
    }
  close (fd);
}
static void kernel_udp (int argc, char **argv)
{
  if (argc != 8) exit (2);
  become ((uid_t) strtoul (argv[2], NULL, 10));
  int family = atoi (argv[3]), fd = socket (family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) fail ("UDP socket");
  bind_device (fd, argv[4]);
  int discover = family == 4 ? IP_PMTUDISC_DONT : IPV6_PMTUDISC_DONT;
  if (setsockopt (fd, family == 4 ? IPPROTO_IP : IPPROTO_IPV6,
                  family == 4 ? IP_MTU_DISCOVER : IPV6_MTU_DISCOVER, &discover, sizeof discover)) fail ("MTU discovery");
  struct sockaddr_storage source, destination;
  socklen_t source_size = address (family, argv[5], 37032, &source);
  socklen_t destination_size = address (family, argv[6], 40631, &destination);
  if (bind (fd, (void *) &source, source_size)) fail ("UDP bind");
  uint8_t data[1300]; payload (data, sizeof data, argv[7]);
  ssize_t sent = sendto (fd, data, sizeof data, 0, (void *) &destination, destination_size);
  if (sent != sizeof data) fail ("kernel UDP send");
  printf ("send mode=kernel uid=%u family=%u payload_bytes=%zu sent=%zd nonce=%s\n",
          (unsigned) getuid (), family, sizeof data, sent, argv[7]);
  close (fd);
}
static void probe (int argc, char **argv)
{
  if (argc != 8 && argc != 9) exit (2);
  int blocked = argc == 9 && !strcmp (argv[8], "drop");
  become ((uid_t) strtoul (argv[2], NULL, 10));
  int family = atoi (argv[3]), tcp = atoi (argv[4]) == 6;
  int fd = socket (family == 4 ? AF_INET : AF_INET6, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
  if (fd < 0) fail ("probe socket");
  struct timeval timeout = {blocked ? 0 : 8, blocked ? 250000 : 0};
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
  if (tcp) { int one = 1; setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); }
  struct sockaddr_storage destination;
  socklen_t size = address (family, argv[5], atoi (argv[6]), &destination);
  if (connect (fd, (void *) &destination, size)) fail ("probe connect");
  char sent[256], received[256];
  int length = snprintf (sent, sizeof sent, "%s\n", argv[7]);
  if (length < 0 || length >= (int) sizeof sent) exit (2);
  if (send (fd, sent, length, 0) != length) fail ("probe send");
  size_t have = 0;
  while (have < (size_t) length)
    {
      ssize_t n = recv (fd, received+have, sizeof received-have, 0);
      if (blocked && n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
          printf ("probe.blocked uid=%u family=%u protocol=%u nonce=%s\n",
                  (unsigned) getuid (), family, tcp ? 6 : 17, argv[7]);
          close (fd); return;
        }
      if (n <= 0) fail ("probe receive");
      have += n;
    }
  if (have != (size_t) length || memcmp (sent, received, have)) exit (3);
  if (blocked) { fprintf (stderr, "DROP probe unexpectedly delivered\n"); exit (4); }
  printf ("probe uid=%u family=%u protocol=%u received=%zu nonce=%s\n",
          (unsigned) getuid (), family, tcp ? 6 : 17, have, argv[7]);
  close (fd);
}
static volatile sig_atomic_t stopping;
static void stop_capture (int signal_number) { (void) signal_number; stopping = 1; }
static void capture (int argc, char **argv)
{
  if (argc != 4) exit (2);
  int fd = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
  struct sockaddr_ll link = {.sll_family=AF_PACKET, .sll_protocol=htons (ETH_P_ALL), .sll_ifindex=if_nametoindex (argv[2])};
  if (fd < 0 || !link.sll_ifindex || bind (fd, (void *) &link, sizeof link)) fail ("capture bind");
  FILE *out = fopen (argv[3], "wb"); if (!out) fail ("pcap");
  struct { uint32_t magic; uint16_t major, minor; int32_t zone; uint32_t sigfigs, snaplen, linktype; }
    header = {0xa1b2c3d4, 2, 4, 0, 0, 8192, 1};
  _Static_assert (sizeof header == 24, "pcap header");
  if (fwrite (&header, sizeof header, 1, out) != 1) fail ("pcap header");
  signal (SIGTERM, stop_capture); signal (SIGINT, stop_capture);
  printf ("capture.ready pid=%u ifindex=%u interface=%s\n", (unsigned) getpid (), link.sll_ifindex, argv[2]);
  unsigned count = 0;
  while (!stopping)
    {
      struct pollfd descriptor = {fd, POLLIN, 0};
      int ready = poll (&descriptor, 1, 100);
      if (ready < 0) { if (errno == EINTR) continue; fail ("capture poll"); }
      if (!ready) continue;
      uint8_t bytes[8192]; socklen_t size = sizeof link;
      ssize_t n = recvfrom (fd, bytes, sizeof bytes, 0, (void *) &link, &size);
      if (n < 0) fail ("capture receive");
      struct timeval now; gettimeofday (&now, NULL);
      uint32_t record[4] = {(uint32_t) now.tv_sec, (uint32_t) now.tv_usec, (uint32_t) n, (uint32_t) n};
      if (fwrite (record, sizeof record, 1, out) != 1 || fwrite (bytes, n, 1, out) != 1) fail ("pcap write");
      printf ("capture.packet index=%u ifindex=%u type=%u bytes=%zd\n", count++, link.sll_ifindex, link.sll_pkttype, n);
    }
  if (fclose (out)) fail ("pcap close");
  close (fd);
  printf ("capture.closed packets=%u\n", count);
}
int main (int argc, char **argv)
{
  setvbuf (stdout, NULL, _IOLBF, 0);
  if (argc < 2) return 2;
  if (!strcmp (argv[1], "capture")) capture (argc, argv);
  else if (!strcmp (argv[1], "probe")) probe (argc, argv);
  else if (!strcmp (argv[1], "kernel")) kernel_udp (argc, argv);
  else if (!strcmp (argv[1], "raw") || !strcmp (argv[1], "inject") || !strcmp (argv[1], "inject-whole")) fragments (argc, argv);
  else return 2;
  return 0;
}
