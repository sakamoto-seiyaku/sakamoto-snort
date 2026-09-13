/* Independent AF_PACKET witness for selected real endpoint tuples. */
#define main s224_endpoint_main
#include "s224-icmp.c"
#undef main
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

typedef struct { unsigned owner, family, protocol, value; } selected_t;

int main(int argc, char **argv) {
  /* uid selected-tuples control destination-port */
  if (argc != 5) return 2;
  selected_t selected[32]; unsigned count = 0;
  FILE *input = fopen(argv[2], "r"), *control = fopen(argv[3], "r");
  if (!input || !control) fail("witness inputs");
  int fields;
  while (count < 32 && (fields = fscanf(input, "%u %u %u %u", &selected[count].owner,
       &selected[count].family, &selected[count].protocol, &selected[count].value)) != EOF) {
    if (fields != 4) return 2;
    count++;
  }
  fclose(input);
  if (!count) return 2;
  unsigned port = number(argv[4], 65535), uid = number(argv[1], UINT32_MAX);
  endpoint_uid(uid);
  int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
  if (fd < 0) fail("AF_PACKET witness");
  struct sockaddr_ll local = {.sll_family=AF_PACKET, .sll_protocol=htons(ETH_P_ALL), .sll_ifindex=if_nametoindex("lo")};
  if (!local.sll_ifindex || bind(fd, (void *)&local, sizeof local)) fail("witness loopback bind");
  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("listen source=AF_PACKET uid=%u selected=%u mono_ns=%llu\n", uid, count, (unsigned long long)now_ns());
  unsigned char local4[4], remote4[4], local6[16], remote6[16];
  if (inet_pton(AF_INET, "127.0.0.1", local4) != 1 || inet_pton(AF_INET, "127.0.0.2", remote4) != 1 ||
      inet_pton(AF_INET6, "::1", local6) != 1 || inet_pton(AF_INET6, "fd20:6236::2", remote6) != 1) return 2;
  int full = 0;
  for (;;) {
    if (!full) {
      char line[32]; clearerr(control);
      if (fgets(line, sizeof line, control)) {
        if (strcmp(line, "capture-ready\n")) return 2;
        full = 1;
        printf("window full=1 mono_ns=%llu\n", (unsigned long long)now_ns());
      }
    }
    struct pollfd polling = {fd, POLLIN, 0};
    int ready = poll(&polling, 1, 100);
    if (ready < 0) { if (errno == EINTR) continue; fail("witness poll"); }
    if (!ready) continue;
    unsigned char raw[4096]; struct sockaddr_ll peer; socklen_t size = sizeof peer;
    ssize_t n = recvfrom(fd, raw, sizeof raw, 0, (void *)&peer, &size);
    if (n < 0) { if (errno == EINTR) continue; fail("witness recv"); }
    if (peer.sll_pkttype != PACKET_OUTGOING || n < 28 || n > 512) continue;
    unsigned family = raw[0] >> 4, offset, protocol;
    if (family == 4) { offset = (raw[0] & 15)*4; protocol = raw[9]; }
    else if (family == 6) { offset = 40; protocol = raw[6]; }
    else continue;
    if (offset+8 > (unsigned)n) continue;
    const unsigned char *src = raw+(family == 4 ? 12 : 8), *dst = raw+(family == 4 ? 16 : 24);
    const unsigned char *a = family == 4 ? local4 : local6, *b = family == 4 ? remote4 : remote6;
    unsigned address_size = family == 4 ? 4 : 16;
    if ((memcmp(src, a, address_size) || memcmp(dst, b, address_size)) &&
        (memcmp(src, b, address_size) || memcmp(dst, a, address_size))) continue;
    const unsigned char *segment = raw+offset;
    unsigned value;
    if (protocol == 6 || protocol == 17) {
      unsigned source = segment[0]*256U+segment[1], destination = segment[2]*256U+segment[3];
      if (source != port && destination != port) continue;
      value = source == port ? destination : source;
    } else if (protocol == (family == 4 ? 1U : 58U)) value = segment[4]*256U+segment[5];
    else continue;
    for (unsigned i = 0; i < count; i++) {
      selected_t *s = &selected[i];
      if (s->family != family || s->protocol != protocol || s->value != value) continue;
      printf("wire family=%u protocol=%u value=%u full=%u mono_ns=%llu raw=", family, protocol, value, full,
             (unsigned long long)now_ns());
      print_hex(raw, n); putchar('\n'); break;
    }
  }
}
