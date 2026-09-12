/* Independent continuous kernel endpoints. Never links Product packet code. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) exit(2);
  return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}
static void wait_us(unsigned us) {
  struct timespec pause = {us / 1000000, (long)(us % 1000000) * 1000};
  while (nanosleep(&pause, &pause) && errno == EINTR) {}
}
static socklen_t address(struct sockaddr_storage *storage, unsigned family,
                         const char *host, unsigned port) {
  memset(storage, 0, sizeof(*storage));
  if (family == 4) {
    struct sockaddr_in *a = (void *)storage;
    a->sin_family = AF_INET; a->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a->sin_addr) != 1) exit(2);
    return sizeof(*a);
  }
  struct sockaddr_in6 *a = (void *)storage;
  a->sin6_family = AF_INET6; a->sin6_port = htons(port);
  if (inet_pton(AF_INET6, host, &a->sin6_addr) != 1) exit(2);
  return sizeof(*a);
}
static int ready(int fd, short events, uint64_t deadline) {
  struct pollfd item = {fd, events, 0};
  for (;;) {
    uint64_t current = now_ns();
    if (current >= deadline) return 0;
    int timeout = (int)((deadline - current) / 1000000);
    int result = poll(&item, 1, timeout > 0 ? timeout : 1);
    if (result > 0) return 1;
    if (result < 0 && errno != EINTR) return 0;
  }
}
static void socket_wait(const char *phase, int fd, const char *nonce, uint64_t started) {
  struct tcp_info info = {0};
  socklen_t length = sizeof(info);
  int result = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length);
  printf("%s_wait nonce=%s elapsed_ns=%llu info_result=%d state=%u retransmits=%u total_retrans=%u rto_us=%u unacked=%u\n",
    phase, nonce, (unsigned long long)(now_ns()-started), result, info.tcpi_state,
    info.tcpi_retransmits, info.tcpi_total_retrans, info.tcpi_rto, info.tcpi_unacked);
}
int main(int argc, char **argv) {
  /* uid tcp|udp family source-ip source-port peer-ip peer-port duration-ms interval-us nonce gate|- [connect-ms] */
  if (argc != 12 && argc != 13) return 2;
  unsigned uid = strtoul(argv[1], NULL, 10), family = strtoul(argv[3], NULL, 10);
  unsigned source_port = strtoul(argv[5], NULL, 10), peer_port = strtoul(argv[7], NULL, 10);
  unsigned duration = strtoul(argv[8], NULL, 10), interval = strtoul(argv[9], NULL, 10);
  unsigned connect_ms = argc == 13 ? strtoul(argv[12], NULL, 10) : 5000;
  int tcp = !strcmp(argv[2], "tcp");
  if ((!tcp && strcmp(argv[2], "udp")) || (family != 4 && family != 6)
      || !source_port || source_port > 65535 || !peer_port || peer_port > 65535
      || !duration || duration > 30000 || interval < 1000 || interval > 1000000
      || connect_ms < 2000 || connect_ms > 30000
      || !*argv[10] || strlen(argv[10]) > 128) return 2;
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (strcmp(argv[11], "-")) {
    uint64_t deadline = now_ns() + 20000000000ULL;
    printf("waiting_gate nonce=%s\n", argv[10]);
    while (access(argv[11], F_OK)) {
      if (errno != ENOENT || now_ns() >= deadline) return 1;
      wait_us(1000);
    }
  }
  if (getuid() != uid && (setgid(uid) || setuid(uid))) {perror("uid");return 1;}
  int fd = socket(family == 4 ? AF_INET : AF_INET6, tcp ? SOCK_STREAM : SOCK_DGRAM, 0), one = 1;
  if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))
      || (tcp && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
      || fcntl(fd, F_SETFL, O_NONBLOCK)) {perror("socket");return 1;}
  struct sockaddr_storage local, peer;
  socklen_t size = address(&local, family, argv[4], source_port);
  address(&peer, family, argv[6], peer_port);
  if (bind(fd, (void *)&local, size)) {perror("bind");return 1;}
  uint64_t connect_started = now_ns();
  printf("connect_begin nonce=%s protocol=%s family=%u source=%u mono_ns=%llu\n",
    argv[10], argv[2], family, source_port, (unsigned long long)connect_started);
  if (connect(fd, (void *)&peer, size)) {
    if (errno != EINPROGRESS) {perror("connect");return 1;}
    if (!ready(fd, POLLOUT, connect_started+2000000000ULL)) {
      socket_wait("connect", fd, argv[10], connect_started);
      /* Observe the kernel's next SYN retransmission after deliberate
       * ingress shutdown. This changes only the endpoint observation window,
       * not Product's two-second native drain budget. */
      if (!ready(fd, POLLOUT, connect_started+(uint64_t)connect_ms*1000000)) {
        socket_wait("connect", fd, argv[10], connect_started);
        errno = ETIMEDOUT; perror("connect"); return 1;
      }
    }
    int error = 0; socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error) {errno=error;perror("connect status");return 1;}
  }
  printf("connect_ready nonce=%s elapsed_ns=%llu mono_ns=%llu\n", argv[10],
    (unsigned long long)(now_ns()-connect_started), (unsigned long long)now_ns());
  uint64_t started = now_ns(), deadline = started + (uint64_t)duration * 1000000;
  unsigned sequence = 0, received = 0, failed = 0;
  printf("traffic_begin uid=%u protocol=%s family=%u source=%u nonce=%s mono_ns=%llu\n",
    uid, argv[2], family, source_port, argv[10], (unsigned long long)started);
  while (now_ns() < deadline) {
    char request[256], response[256];
    int size = snprintf(request, sizeof(request), "E%s:%08u", argv[10], sequence);
    /* This lifecycle observer is not the later latency/performance gate.
     * A fifty-millisecond UDP cutoff discarded real late echoes before
     * the ordinary stop scenario could establish its pre-stop witness. */
    uint64_t before = now_ns(), operation_deadline = before + 1000000000ULL;
    ssize_t sent = send(fd, request, size, MSG_NOSIGNAL);
    size_t got = 0;
    int matched = 0;
    if (sent == size) {
      for (;;) {
        if (!ready(fd, POLLIN, operation_deadline)) {
          if (tcp && operation_deadline == before+1000000000ULL) {
            /* Preserve the one-second observation and keep the SAME stream
             * request outstanding across kernel queue/RCU reclamation.
             * No application resend and no native verdict retry occurs. */
            socket_wait("data", fd, argv[10], before);
            operation_deadline = before+20000000000ULL;
            continue;
          }
          break;
        }
        ssize_t count = recv(fd, response + got, sizeof(response) - got, 0);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count <= 0) break;
        if (tcp) got += (size_t)count;
        else got = (size_t)count;
        if (got == (size_t)size && !memcmp(request, response, size)) {matched=1;break;}
        if (tcp && got >= (size_t)size) break;
        if (!tcp) got = 0; /* A delayed older datagram is not this sequence. */
      }
    }
    received += matched;
    failed += !matched;
    printf("traffic sequence=%u protocol=%s family=%u source=%u nonce=%s sent=%zd received=%d begin_ns=%llu end_ns=%llu\n",
      sequence++, argv[2], family, source_port, argv[10], sent, matched,
      (unsigned long long)before, (unsigned long long)now_ns());
    if (tcp && !matched) break;
    wait_us(interval);
  }
  printf("traffic_end protocol=%s family=%u source=%u nonce=%s sent=%u received=%u failed=%u mono_ns=%llu\n",
    argv[2], family, source_port, argv[10], sequence, received, failed, (unsigned long long)now_ns());
  close(fd);
  return tcp && failed ? 1 : 0;
}
