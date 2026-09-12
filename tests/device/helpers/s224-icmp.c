/* Independent Linux/Android kernel Echo endpoint; no Product code/library. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static void fail (const char *what) { perror (what); exit (1); }
static uint64_t now_ns (void) {
  struct timespec t;
  if (clock_gettime (CLOCK_MONOTONIC, &t)) fail ("clock");
  return (uint64_t)t.tv_sec * UINT64_C (1000000000) + t.tv_nsec;
}
static unsigned number (const char *text, unsigned maximum) {
  char *end; errno = 0;
  unsigned long value = strtoul (text, &end, 10);
  if (errno || !*text || *end || value > maximum) { fprintf (stderr, "bad number\n"); exit (2); }
  return (unsigned)value;
}
static unsigned sum_bytes (const unsigned char *bytes, size_t size, unsigned sum) {
  for (size_t i = 0; i < size; i += 2)
    sum += ((unsigned)bytes[i] << 8) + (i + 1 < size ? bytes[i+1] : 0);
  return sum;
}
static unsigned checksum (int family, const unsigned char *source, const unsigned char *destination,
                          const unsigned char *bytes, size_t size) {
  unsigned sum = 0;
  if (family == 6) {
    sum = sum_bytes (source, 16, sum);
    sum = sum_bytes (destination, 16, sum);
    sum += (unsigned)size + IPPROTO_ICMPV6;
  }
  sum = sum_bytes (bytes, size, sum);
  while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
  return (~sum) & 65535;
}
static const unsigned char *address_bytes (const struct sockaddr_storage *address, int family) {
  return family == 4 ? (const void *)&((const struct sockaddr_in *)address)->sin_addr
                     : (const void *)&((const struct sockaddr_in6 *)address)->sin6_addr;
}
static socklen_t address (struct sockaddr_storage *value, int family, const char *text) {
  memset (value, 0, sizeof *value);
  if (family == 4) {
    struct sockaddr_in *a = (void *)value; a->sin_family = AF_INET;
    if (inet_pton (AF_INET, text, &a->sin_addr) != 1) fail ("IPv4 address");
    return sizeof *a;
  }
  struct sockaddr_in6 *a = (void *)value; a->sin6_family = AF_INET6;
  if (inet_pton (AF_INET6, text, &a->sin6_addr) != 1) fail ("IPv6 address");
  return sizeof *a;
}
static void endpoint_uid (unsigned uid) {
  if (getuid () == uid) return;
  if (prctl (PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) || setgid (uid) || setuid (uid)) fail ("endpoint uid");
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct caps[2] = {{0}};
  caps[0].effective = caps[0].permitted = 1U << CAP_NET_RAW;
  if (syscall (SYS_capset, &header, caps)) fail ("raw endpoint capability");
}
static int raw_socket (unsigned uid, int family, const char *local, struct sockaddr_storage *bound) {
  endpoint_uid (uid);
  int fd = socket (family == 4 ? AF_INET : AF_INET6, SOCK_RAW, family == 4 ? IPPROTO_ICMP : IPPROTO_ICMPV6);
  if (fd < 0) fail ("raw socket");
  socklen_t length = address (bound, family, local);
  if (bind (fd, (void *)bound, length)) fail ("bind raw endpoint");
  return fd;
}
static size_t received (int fd, int family, unsigned char *data, struct sockaddr_storage *peer) {
  socklen_t peer_length = sizeof *peer;
  ssize_t count = recvfrom (fd, data, 4096, 0, (void *)peer, &peer_length);
  if (count < 0) { if (errno == EINTR) return 0; fail ("receive"); }
  size_t offset = 0;
  if (family == 4) {
    if (count < 20 || data[0] >> 4 != 4) return 0;
    offset = (data[0] & 15) * 4U;
    if (offset < 20 || offset > (size_t)count) return 0;
  }
  if ((size_t)count < offset + 8) return 0;
  memmove (data, data + offset, (size_t)count - offset);
  return (size_t)count - offset;
}
static void print_hex (const unsigned char *data, size_t count) {
  for (size_t i = 0; i < count; i++) printf ("%02x", data[i]);
}

int main (int argc, char **argv) {
  setvbuf (stdout, NULL, _IOLBF, 0);
  if (argc != 5 && argc != 11) return 2;
  unsigned uid = number (argv[2], UINT32_MAX);
  int family = (int)number (argv[3], 6);
  if (family != 4 && family != 6) return 2;
  struct sockaddr_storage bound;
  int fd = raw_socket (uid, family, argv[4], &bound);
  if (!strcmp (argv[1], "listen") && argc == 5) {
    printf ("listen family=%d local=%s uid=%u fd=%d\n", family, argv[4], (unsigned)getuid (), fd);
    for (;;) {
      unsigned char data[4096]; struct sockaddr_storage peer;
      size_t count = received (fd, family, data, &peer);
      if (count < 8 || count > 256 || data[1] ||
          (family == 4 ? (data[0] != 0 && data[0] != 8) : (data[0] != 128 && data[0] != 129))) continue;
      char source[INET6_ADDRSTRLEN];
      if (!inet_ntop (family == 4 ? AF_INET : AF_INET6, address_bytes (&peer, family), source, sizeof source)) fail ("peer address");
      printf ("received family=%d local=%s source=%s uid=%u type=%u code=%u identifier=%u sequence=%u bytes=%zu mono_ns=%llu checksum_valid=%u raw=",
        family, argv[4], source, (unsigned)getuid (), data[0], data[1], data[4]*256U+data[5], data[6]*256U+data[7],
        count, (unsigned long long)now_ns (), checksum (family, address_bytes (&peer, family), address_bytes (&bound, family), data, count) == 0);
      print_hex (data, count); puts ("");
    }
  }
  if (strcmp (argv[1], "probe") || argc != 11) return 2;
  struct sockaddr_storage destination;
  socklen_t length = address (&destination, family, argv[5]);
  unsigned id = number (argv[6], 65535), sequence = number (argv[7], 65535), count = number (argv[8], 16);
  int reply = !strcmp (argv[9], "reply");
  if (!count || (!reply && strcmp (argv[9], "echo")) || strlen (argv[10]) > 120) return 2;
  for (unsigned index = 0; index < count; index++) {
    unsigned seq = (sequence + index) & 65535;
    char nonce[160];
    int nonce_size = snprintf (nonce, sizeof nonce, "%s-%u", argv[10], index);
    if (nonce_size <= 0 || nonce_size >= (int)sizeof nonce) return 2;
    unsigned char packet[256] = {0};
    packet[0] = family == 4 ? (reply ? 0 : 8) : (reply ? 129 : 128);
    packet[4] = id >> 8; packet[5] = id; packet[6] = seq >> 8; packet[7] = seq;
    memcpy (packet + 8, nonce, (size_t)nonce_size);
    size_t size = 8 + (size_t)nonce_size;
    if (family == 4) {
      unsigned sum = checksum (family, NULL, NULL, packet, size);
      packet[2] = sum >> 8; packet[3] = sum;
    } /* ICMPv6's kernel raw-socket path supplies the pseudo-header checksum. */
    uint64_t sent_ns = now_ns (), reply_ns = 0;
    if (sendto (fd, packet, size, 0, (void *)&destination, length) != (ssize_t)size) fail ("send Echo");
    if (!reply) {
      uint64_t end = sent_ns + UINT64_C (3000000000);
      while (now_ns () < end) {
        struct pollfd polling = {fd, POLLIN, 0};
        int rc = poll (&polling, 1, 100);
        if (rc < 0) { if (errno == EINTR) continue; fail ("poll Echo"); }
        if (!rc) continue;
        unsigned char data[4096]; struct sockaddr_storage peer;
        size_t got = received (fd, family, data, &peer);
        if (got != size || data[0] != (family == 4 ? 0 : 129) || data[1] ||
            memcmp (data + 4, packet + 4, size - 4) ||
            memcmp (address_bytes (&peer, family), address_bytes (&destination, family), family == 4 ? 4 : 16) ||
            checksum (family, address_bytes (&peer, family), address_bytes (&bound, family), data, got)) continue;
        reply_ns = now_ns (); break;
      }
      if (!reply_ns) { fprintf (stderr, "Echo reply timeout id=%u sequence=%u\n", id, seq); return 1; }
    }
    printf ("endpoint family=%d source=%s destination=%s uid=%u fd=%d identifier=%u sequence=%u type=%u bytes=%zu nonce=%s sent_ns=%llu reply_ns=%llu echo=%u\n",
      family, argv[4], argv[5], (unsigned)getuid (), fd, id, seq, packet[0], size, nonce,
      (unsigned long long)sent_ns, (unsigned long long)reply_ns, !reply);
  }
  close (fd);
  return 0;
}
