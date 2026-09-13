/* Independent mixed kernel endpoints. Reuse only our test socket helpers;
 * never link Product code or alter its clock, scheduler, or default timeout. */
#define main s227_endpoint_main
#include "s227-udp.c"
#undef main
#define main s224_endpoint_main
#define fail icmp_fail
#define now_ns icmp_now_ns
#define address icmp_address
#include "s224-icmp.c"
#undef address
#undef now_ns
#undef fail
#undef main
#include <sys/wait.h>
#define main s236_tcp_endpoint_main
#define fail tcp_fail
#define address tcp_address
#include "s236-tcp.c"
#undef address
#undef fail
#undef main

typedef struct {
  unsigned owner, family, protocol, value;
  int fd;
  char nonce[144];
} mixed_endpoint_t;

static void query(mixed_endpoint_t *e, char **argv, unsigned phase) {
  char family[8], id[16], sequence[16], nonce[160];
  snprintf(family, sizeof family, "%u", e->family);
  snprintf(id, sizeof id, "%u", e->value);
  snprintf(sequence, sizeof sequence, "%u", phase);
  snprintf(nonce, sizeof nonce, "%s-%u", e->nonce, phase);
  char *probe[] = {argv[0], "probe", argv[2], family,
    argv[e->family == 4 ? 5 : 6], argv[e->family == 4 ? 7 : 8],
    id, sequence, "1", "echo", nonce};
  if (s224_endpoint_main(11, probe)) exit(1);
}

static void connect_tcp(mixed_endpoint_t *e, char **argv) {
  e->fd = socket(e->family == 4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
  if (e->fd < 0) fail("mixed TCP socket");
  options(e->fd);
  struct sockaddr_storage local, remote;
  socklen_t length = address(&local, e->family, argv[e->family == 4 ? 5 : 6], e->value);
  address(&remote, e->family, argv[e->family == 4 ? 7 : 8], number(argv[9], 65535));
  if (bind(e->fd, (void *)&local, length) || connect(e->fd, (void *)&remote, length)) fail("mixed connect");
  echo(e->fd, e->nonce, 0);
  printf("tcp_connected family=%u value=%u owner=%u nonce=%s keepalive=0 mono_ns=%llu\n",
         e->family, e->value, e->owner, e->nonce, now_ns());
}

static void reset_tcp(mixed_endpoint_t *e) {
  struct linger reset = {1, 0};
  if (setsockopt(e->fd, SOL_SOCKET, SO_LINGER, &reset, sizeof reset) || close(e->fd)) fail("mixed reset");
  e->fd = -1;
  printf("tcp_reset nonce=%s mono_ns=%llu\n", e->nonce, now_ns());
}

int main(int argc, char **argv) {
  /* mode uid udp-tuples control local4 local6 remote4 remote6 port nonce mixed-tuples */
  if (argc != 12 || (strcmp(argv[1], "batch") && strcmp(argv[1], "renew") && strcmp(argv[1], "lookup"))) return 2;
  if (strlen(argv[10]) > 90) return 2;
  setvbuf(stdout, NULL, _IOLBF, 0);
  endpoint_t *udp = calloc(MAX_ENDPOINTS, sizeof *udp);
  mixed_endpoint_t mixed[64] = {{0}};
  if (!udp) fail("mixed endpoints");
  unsigned total = 0, count = 0, owner, family, value, protocol, picked[2][2] = {{0}};
  FILE *input = fopen(argv[3], "r");
  if (!input) fail("UDP tuples");
  int fields;
  while ((fields = fscanf(input, "%u %u %u", &owner, &family, &value)) != EOF) {
    if (fields != 3 || total == MAX_ENDPOINTS || owner > 1 || (family != 4 && family != 6) || !value || value > 65535) return 2;
    udp[total++] = (endpoint_t){.owner=owner, .family=family, .port=value, .target=!picked[owner][family == 6]++};
  }
  fclose(input);
  input = fopen(argv[11], "r");
  if (!input) fail("mixed tuples");
  while ((fields = fscanf(input, "%u %u %u %u", &owner, &family, &protocol, &value)) != EOF) {
    if (fields != 4 || count == 64 || owner > 1 || (family != 4 && family != 6) ||
        (protocol != 6 && protocol != (family == 4 ? 1U : 58U)) || !value || value > 65535) return 2;
    mixed[count] = (mixed_endpoint_t){.owner=owner, .family=family, .protocol=protocol, .value=value, .fd=-1};
    snprintf(mixed[count].nonce, sizeof mixed[count].nonce, "%s-p%u-f%u-v%u", argv[10], protocol, family, value);
    count++;
  }
  fclose(input);
  if (!total || !count) return 2;
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit)) fail("getrlimit");
  if (limit.rlim_cur < total+128) {
    if (limit.rlim_max < total+128) return 2;
    limit.rlim_cur = total+128;
    if (setrlimit(RLIMIT_NOFILE, &limit)) fail("fd limit");
  }
  /* Retain only CAP_NET_RAW when the device endpoint assumes the app UID. */
  endpoint_uid(number(argv[2], UINT32_MAX));
#ifdef __ANDROID__
  cpu_set_t cpus;
  CPU_ZERO(&cpus); CPU_SET(6, &cpus);
  if (sched_setaffinity(0, sizeof cpus, &cpus)) fail("mixed helper affinity");
#endif
  for (unsigned i = 0; i < total; i++) {
    endpoint_t *e = &udp[i];
    e->fd = socket(e->family == 4 ? AF_INET : AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (e->fd < 0) fail("UDP socket");
    struct sockaddr_storage local, remote;
    socklen_t length = address(&local, e->family, argv[e->family == 4 ? 5 : 6], e->port);
    address(&remote, e->family, argv[e->family == 4 ? 7 : 8], number(argv[9], 65535));
    if (bind(e->fd, (void *)&local, length) || connect(e->fd, (void *)&remote, length)) fail("UDP bind/connect");
  }
  printf("prepared mode=%s udp=%u mixed=%u uid=%u mono_ns=%llu\n", argv[1], total, count, getuid(), now_ns());
  if (!strcmp(argv[1], "batch")) {
    /* Establish all real TCP sockets before the deadline cluster. Two reset
     * anchors start the ordinary owner pacing interval; the remaining real
     * resets and concurrent Echo probes follow 20 ms later. */
    for (unsigned i = 0; i < count; i++) if (mixed[i].protocol == 6) connect_tcp(&mixed[i], argv);
    unsigned anchors[2] = {0};
    for (unsigned i = 0; i < count; i++) if (mixed[i].protocol == 6 && !anchors[mixed[i].owner]++) reset_tcp(&mixed[i]);
    unsigned long long anchor = now_ns();
    wait_until(anchor+20000000ULL);
    for (unsigned i = 0; i < count; i++) if (mixed[i].protocol == 6 && mixed[i].fd >= 0) reset_tcp(&mixed[i]);
    pid_t children[64]; unsigned children_count = 0;
    for (unsigned i = 0; i < count; i++) if (mixed[i].protocol != 6) {
      pid_t pid = fork();
      if (pid < 0) fail("Echo fork");
      if (!pid) { query(&mixed[i], argv, 0); _exit(0); }
      children[children_count++] = pid;
    }
    send_phase(udp, total, 1, argv[10], 0, 0);
    for (unsigned i = 0; i < children_count; i++) {
      int status;
      if (waitpid(children[i], &status, 0) != children[i] || !WIFEXITED(status) || WEXITSTATUS(status)) fail("Echo child");
    }
  }
  if (!strcmp(argv[1], "lookup")) {
    /* Full raw tracing costs more than S227's 256-packet sample. Keep at most
     * eight echo requests outstanding so credit-loss fail-open cannot be
     * mistaken for a complete mixed flow population. */
    if (total > 4096) send_phase(udp, total, 1, argv[10], 0, 0);
    else for (unsigned first = 0; first < total; first += 8)
      send_phase(udp+first, total-first < 8 ? total-first : 8, 1, argv[10], 0, 0);
  }
  for (unsigned i = 0; i < count; i++) {
    if (!strcmp(argv[1], "batch")) break;
    if (mixed[i].protocol == 6) connect_tcp(&mixed[i], argv);
    else query(&mixed[i], argv, 0);
    if (strcmp(argv[1], "lookup") && i % 2 == 1) {
      /* Interleave all three protocols' real 30-second deadlines. */
      unsigned index = i/2;
      if (index < total) send_phase(udp+index, 1, 1, argv[10], 0, 0);
    }
  }
  if (!strcmp(argv[1], "lookup")) send_phase(udp, total, 1, argv[10], 1, 1);
  unsigned long long seeded = now_ns();
  printf("mixed_stage phase=0 mono_ns=%llu\n", seeded);
  if (!strcmp(argv[1], "renew") || !strcmp(argv[1], "lookup")) {
    int lookup = !strcmp(argv[1], "lookup");
    wait_until(seeded + (lookup ? 30001000000ULL : 10000000000ULL));
    FILE *control = fopen(argv[4], "r");
    char ready[32] = {0};
    if (!control || !fgets(ready, sizeof ready, control) || strcmp(ready, "capture-ready\n")) {
      fprintf(stderr, "collector capture window was not ready before scheduled stimulus\n"); return 1;
    }
    fclose(control);
    for (unsigned i = 0; i < count; i++) {
      if (mixed[i].protocol == 6) echo(mixed[i].fd, mixed[i].nonce, 1);
      else query(&mixed[i], argv, 1);
    }
    send_phase(udp, total, 1, argv[10], lookup ? 2 : 1, lookup);
    printf("mixed_stage phase=1 mono_ns=%llu\n", now_ns());
  }
  printf("holding udp=%u mixed=%u mono_ns=%llu\n", total, count, now_ns());
  for (;;) pause();
}
