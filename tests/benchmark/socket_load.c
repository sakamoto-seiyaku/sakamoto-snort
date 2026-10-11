#define _GNU_SOURCE
/* Test traffic endpoints only; no Product packet-domain implementation. */
#include <arpa/inet.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x53424e31u
#define PORTS 64
#define CASES 16
#define MAXFD 65536
#define SEQS (1u << 24)
#define TUPLES (1u << 19)
#define HIST 10001
typedef struct { uint32_t magic, id, op, size; uint64_t seq; } header;
_Static_assert(sizeof(header) == 24, "wire header size");
static volatile sig_atomic_t stopped;
static void stop_signal(int sig) { (void)sig; stopped = 1; }
static uint64_t now_ns(void) {
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static void die(const char *what) { perror(what); exit(1); }
static int number(const char *v, int lo, int hi) {
  char *end; long n = strtol(v, &end, 10);
  if (!*v || *end || n < lo || n > hi) { fprintf(stderr, "invalid number: %s\n", v); exit(2); }
  return (int)n;
}
static struct sockaddr_in address(const char *ip, int port) {
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
  if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { fprintf(stderr, "IPv4 required\n"); exit(2); }
  return a;
}
static header message(int id, int op, uint64_t seq, int size) {
  header h = {htonl(MAGIC), htonl(id), htonl(op), htonl(size), htobe64(seq)}; return h;
}
static int sock(int type) {
  return socket(AF_INET, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
}
static void watch(int ep, int fd, uint32_t events, int index) {
  struct epoll_event e = {.events = events, .data.u32 = (uint32_t)index};
  if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e)) die("epoll add");
}
static void modify(int ep, int fd, uint32_t events, int index) {
  struct epoll_event e = {.events = events, .data.u32 = (uint32_t)index};
  if (epoll_ctl(ep, EPOLL_CTL_MOD, fd, &e)) die("epoll modify");
}

typedef struct {
  uint64_t tcp_bytes, tcp_requests, udp_bytes, udp_packets, duplicates;
  uint64_t unique_tuples, tuple_overflow, sequence_overflow, malformed, send_errors;
  unsigned char *seen; uint64_t *tuples;
} peer_stats;
typedef struct { header h; size_t used, sent; int op, id; } peer_conn;
static peer_stats peer[CASES];
static void udp_count(int id, uint64_t seq, int bytes, uint64_t key) {
  peer_stats *s = &peer[id];
  if (!s->seen) { s->seen = calloc(SEQS / 8, 1); s->tuples = calloc(TUPLES, 8); if (!s->seen || !s->tuples) die("calloc"); }
  s->udp_packets++; s->udp_bytes += bytes;
  if (seq < SEQS) { unsigned char bit = 1u << (seq & 7); if (s->seen[seq >> 3] & bit) s->duplicates++; s->seen[seq >> 3] |= bit; }
  else s->sequence_overflow++;
  /* Exact tuple set until bounded capacity; report overflow rather than estimate. */
  uint32_t at = (uint32_t)((key * UINT64_C(11400714819323198485)) >> 45);
  if (s->unique_tuples >= TUPLES * 3 / 4) { s->tuple_overflow++; return; }
  while (s->tuples[at] && s->tuples[at] != key) at = (at + 1) & (TUPLES - 1);
  if (!s->tuples[at]) { s->tuples[at] = key; s->unique_tuples++; }
}
static int server(const char *ip, int port) {
  int ep = epoll_create1(EPOLL_CLOEXEC), listener = sock(SOCK_STREAM), one = 1;
  if (ep < 0 || listener < 0) die("server socket");
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in a = address(ip, port);
  if (bind(listener, (void *)&a, sizeof(a)) || listen(listener, 4096)) die("listen");
  watch(ep, listener, EPOLLIN, listener);
  unsigned char udp_fd[MAXFD] = {0}; int udp_port[MAXFD] = {0};
  peer_conn *conn = calloc(MAXFD, sizeof(*conn)); if (!conn) die("calloc");
  for (int p = 0; p < PORTS; p++) {
    int fd = sock(SOCK_DGRAM); a.sin_port = htons(port + p);
    if (fd < 0 || fd >= MAXFD || bind(fd, (void *)&a, sizeof(a))) die("UDP bind");
    udp_fd[fd] = 1; udp_port[fd] = port + p; watch(ep, fd, EPOLLIN, fd);
  }
  char bulk[65536]; memset(bulk, 0xa5, sizeof(bulk));
  printf("{\"ready\":true,\"bind\":\"%s\",\"port\":%d,\"udp_ports\":%d}\n", ip, port, PORTS); fflush(stdout);
  struct epoll_event events[128];
  while (!stopped) {
    int count = epoll_wait(ep, events, 128, 100);
    if (count < 0) { if (errno == EINTR) continue; die("epoll wait"); }
    for (int e = 0; e < count; e++) {
      int fd = (int)events[e].data.u32;
      if (fd == listener) {
        for (;;) { int c = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC); if (c < 0) break;
          if (c >= MAXFD) { close(c); continue; } memset(&conn[c], 0, sizeof(conn[c]));
          setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); watch(ep, c, EPOLLIN, c); }
      } else if (udp_fd[fd]) {
        struct mmsghdr m[32] = {0}; struct iovec io[32]; struct sockaddr_in from[32]; char data[32][2048];
        for (int j = 0; j < 32; j++) { io[j] = (struct iovec){data[j], sizeof(data[j])}; m[j].msg_hdr.msg_iov = &io[j]; m[j].msg_hdr.msg_iovlen = 1; m[j].msg_hdr.msg_name = &from[j]; m[j].msg_hdr.msg_namelen = sizeof(from[j]); }
        int n = recvmmsg(fd, m, 32, MSG_DONTWAIT, NULL);
        for (int j = 0; j < n; j++) {
          if (m[j].msg_len < sizeof(header)) continue;
          header h; memcpy(&h, data[j], sizeof(h)); unsigned id = ntohl(h.id), op = ntohl(h.op);
          if (ntohl(h.magic) != MAGIC || id >= CASES) continue;
          if (op == 'P') { if (sendto(fd, &h, sizeof(h), MSG_DONTWAIT, (void *)&from[j], sizeof(from[j])) < 0) peer[id].send_errors++; }
          else if (op == 'U' && ntohl(h.size) == m[j].msg_len) {
            uint64_t key = ((uint64_t)ntohl(from[j].sin_addr.s_addr) << 32) | ((uint64_t)ntohs(from[j].sin_port) << 16) | (unsigned)udp_port[fd];
            udp_count(id, be64toh(h.seq), (int)m[j].msg_len, key);
          } else peer[id].malformed++;
        }
      } else {
        peer_conn *c = &conn[fd]; int close_it = 0;
        if (!c->op) {
          ssize_t n = recv(fd, (char *)&c->h + c->used, sizeof(header) - c->used, 0);
          if (n > 0) c->used += (size_t)n;
          else if (!n || (errno != EAGAIN && errno != EINTR)) close_it = 1;
          if (c->used == sizeof(header)) {
            c->id = (int)ntohl(c->h.id); c->op = (int)ntohl(c->h.op);
            if (ntohl(c->h.magic) != MAGIC || c->id >= CASES || c->id < 0) close_it = 1;
            else { if (c->op == 'E') peer[c->id].tcp_requests++; modify(ep, fd, EPOLLOUT | EPOLLRDHUP, fd); }
          }
        } else if (c->op == 'D') {
          ssize_t n = send(fd, bulk, sizeof(bulk), MSG_NOSIGNAL);
          if (n > 0) peer[c->id].tcp_bytes += (uint64_t)n;
          else if (errno != EAGAIN && errno != EINTR) close_it = 1;
        } else if (c->op == 'E') {
          ssize_t n = send(fd, (char *)&c->h + c->sent, sizeof(header) - c->sent, MSG_NOSIGNAL);
          if (n > 0) c->sent += (size_t)n; else if (errno != EAGAIN && errno != EINTR) close_it = 1;
          if (c->sent == sizeof(header)) { memset(c, 0, sizeof(*c)); modify(ep, fd, EPOLLIN, fd); }
        } else if (c->op == 'Q' || c->op == 'R') {
          peer_stats *s = &peer[c->id]; char json[1024];
          if (c->op == 'R') { free(s->seen); free(s->tuples); memset(s, 0, sizeof(*s)); }
          int len = snprintf(json, sizeof(json), "{\"case_id\":%d,\"tcp_offered_bytes\":%"PRIu64",\"tcp_requests\":%"PRIu64",\"udp_received_bytes\":%"PRIu64",\"udp_received_packets\":%"PRIu64",\"udp_duplicates\":%"PRIu64",\"underlay_unique_tuples\":%"PRIu64",\"tuple_capacity_overflow_packets\":%"PRIu64",\"sequence_overflow_packets\":%"PRIu64",\"malformed\":%"PRIu64",\"send_errors\":%"PRIu64"}\n", c->id,s->tcp_bytes,s->tcp_requests,s->udp_bytes,s->udp_packets,s->duplicates,s->unique_tuples,s->tuple_overflow,s->sequence_overflow,s->malformed,s->send_errors);
          struct rusage usage; getrusage(RUSAGE_SELF, &usage);
          double cpu = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6 + usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
          len -= 2; /* replace closing brace/newline with process headroom counters */
          len += snprintf(json + len, sizeof(json) - (size_t)len, ",\"peer_cpu_seconds\":%.6f,\"peer_maxrss_kib\":%ld}\n", cpu, usage.ru_maxrss);
          /* Tiny local control reply; a partial reply is rejected by the caller. */
          if (send(fd, json, (size_t)len, MSG_NOSIGNAL) != len) fprintf(stderr, "query reply incomplete\n");
          close_it = 1;
        } else close_it = 1;
        if (events[e].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) close_it = 1;
        if (close_it) { epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL); close(fd); memset(c, 0, sizeof(*c)); }
      }
    }
  }
  return 0;
}

typedef struct { int fd, connected, sent, received; uint64_t since; header h, reply; } client_conn;
typedef struct {
  int index, threads, flows, mode, id, port, fixed_port_base, fixed_port_stride; const char *ip; uint64_t begin, end;
  uint64_t bytes, packets, attempts, completed, errors, timeouts, cancelled, tuples, exhausted;
  uint64_t samples, hist[HIST];
} worker;
static void latency(worker *w, uint64_t ns) { uint64_t bucket = ns / 100000; if (bucket >= HIST) bucket = HIST - 1; w->hist[bucket]++; w->samples++; }
static void open_conn(worker *w, int ep, client_conn *c, int i, int probe) {
  memset(c, 0, sizeof(*c)); c->fd = sock(SOCK_STREAM); w->attempts++; c->since = now_ns();
  if (c->fd < 0) { w->errors++; return; }
  int one = 1; setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  c->h = message(w->id, w->mode == 1 || probe ? 'E' : 'D', c->since, sizeof(header));
  struct sockaddr_in a = address(w->ip, w->port);
  if (connect(c->fd, (void *)&a, sizeof(a)) && errno != EINPROGRESS) { w->errors++; close(c->fd); c->fd = -1; return; }
  watch(ep, c->fd, EPOLLOUT | EPOLLRDHUP, i);
}
static void *tcp_worker(void *arg) {
  worker *w = arg; int ep = epoll_create1(EPOLL_CLOEXEC), total = w->flows + (w->mode == 0);
  client_conn *c = calloc((size_t)total, sizeof(*c)); if (!c || ep < 0) die("client allocation");
  for (int i = 0; i < total; i++) open_conn(w, ep, &c[i], i, i == w->flows);
  uint64_t next_probe = 0; char data[65536]; struct epoll_event events[128];
  while (!stopped && now_ns() < w->end) {
    int n = epoll_wait(ep, events, 128, 10);
    if (n < 0 && errno != EINTR) die("client epoll");
    for (int j = 0; j < n; j++) {
      int i = (int)events[j].data.u32, probe = w->mode == 0 && i == w->flows, finish = 0, failed = 0;
      client_conn *s = &c[i]; if (s->fd < 0) continue;
      if (!s->connected) { int error = 0; socklen_t len = sizeof(error);
        if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &error, &len) || error) failed = 1;
        else s->connected = 1; }
      if (!failed && s->sent < (int)sizeof(header)) {
        ssize_t b = send(s->fd, (char *)&s->h + s->sent, sizeof(header) - (size_t)s->sent, MSG_NOSIGNAL);
        if (b > 0) s->sent += (int)b; else if (errno != EAGAIN && errno != EINTR) failed = 1;
        if (s->sent == (int)sizeof(header)) modify(ep, s->fd, EPOLLIN | EPOLLRDHUP, i);
      }
      if (!failed && s->sent == (int)sizeof(header) && (events[j].events & EPOLLIN)) {
        ssize_t b = recv(s->fd, w->mode == 0 && !probe ? (void *)data : (char *)&s->reply + s->received,
                         w->mode == 0 && !probe ? sizeof(data) : sizeof(header) - (size_t)s->received, 0);
        if (b > 0) {
          if (w->mode == 0 && !probe) w->bytes += (uint64_t)b;
          else { s->received += (int)b; if (s->received == (int)sizeof(header)) {
            if (memcmp(&s->reply, &s->h, sizeof(header))) failed = 1;
            else { latency(w, now_ns() - s->since); if (!probe) { w->completed++; w->bytes += sizeof(header); finish = 1; }
              else { s->received = 0; next_probe = now_ns() + 20000000; } }
          } }
        } else if (!b || (errno != EAGAIN && errno != EINTR)) failed = 1;
      }
      if (events[j].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) failed = !finish;
      if (finish || failed) {
        epoll_ctl(ep, EPOLL_CTL_DEL, s->fd, NULL); close(s->fd); s->fd = -1;
        if (failed) w->errors++;
        if (w->mode == 1) open_conn(w, ep, s, i, 0);
      }
    }
    uint64_t now = now_ns();
    for (int i = 0; i < total; i++) {
      client_conn *s = &c[i]; int probe = w->mode == 0 && i == w->flows;
      if (s->fd < 0) { if (w->mode == 1) open_conn(w, ep, s, i, 0); continue; }
      if ((w->mode == 1 || probe || !s->connected) && now - s->since > 1000000000 && (!probe || !next_probe)) {
        epoll_ctl(ep, EPOLL_CTL_DEL, s->fd, NULL); close(s->fd); s->fd = -1; w->timeouts++;
        if (w->mode == 1) open_conn(w, ep, s, i, 0);
      } else if (probe && next_probe && now >= next_probe) {
        s->since = now; s->sent = 0; next_probe = 0; s->h = message(w->id, 'E', now, sizeof(header)); modify(ep, s->fd, EPOLLOUT | EPOLLRDHUP, i);
      }
    }
  }
  for (int i = 0; i < total; i++) if (c[i].fd >= 0) { if (w->mode == 1) w->cancelled++; close(c[i].fd); }
  free(c); close(ep); return NULL;
}
static void *udp_worker(void *arg) {
  worker *w = arg; int *fds = calloc((size_t)w->flows, sizeof(int)); if (!fds) die("calloc");
  unsigned char *used = calloc((size_t)w->flows, 1); if (!used) die("calloc");
  struct sockaddr_in dest = address(w->ip, w->port), local = address("0.0.0.0", 0);
  int probe = sock(SOCK_DGRAM);
  if (probe < 0) die("probe");
  if (w->fixed_port_base) {
    local.sin_port = htons(w->fixed_port_base + (w->threads * w->flows + w->index) * w->fixed_port_stride);
    if (bind(probe, (void *)&local, sizeof(local))) die("probe bind");
  }
  if (connect(probe, (void *)&dest, sizeof(dest))) die("probe");
  for (int i = 0; i < w->flows; i++) {
    fds[i] = -1;
    if (w->mode == 2) { fds[i] = sock(SOCK_DGRAM); dest.sin_port = htons(w->port + (i + w->index * w->flows) % PORTS);
      if (fds[i] < 0) die("UDP socket");
      if (w->fixed_port_base) {
        local.sin_port = htons(w->fixed_port_base + (w->index * w->flows + i) * w->fixed_port_stride);
        if (bind(fds[i], (void *)&local, sizeof(local))) die("UDP fixed bind");
      }
      if (connect(fds[i], (void *)&dest, sizeof(dest))) die("UDP connect");
    }
  }
  char data[16][1200]; struct iovec io[16]; struct mmsghdr msgs[16];
  for (int i = 0; i < 16; i++) { memset(data[i], 0x5a, sizeof(data[i])); io[i] = (struct iovec){data[i], sizeof(data[i])}; memset(&msgs[i], 0, sizeof(msgs[i])); msgs[i].msg_hdr.msg_iov = &io[i]; msgs[i].msg_hdr.msg_iovlen = 1; }
  uint64_t tuple_index = 0, seq = 0, next_probe = 0, probe_since = 0; int fixed = 0;
  int per_thread = 20000 / w->threads;
  while (!stopped && now_ns() < w->end) {
    int fd, batch = w->mode == 2 ? 16 : 4, fixed_index = 0;
    if (w->mode == 2) { fixed_index = (fixed++) % w->flows; fd = fds[fixed_index]; }
    else {
      if (tuple_index >= (uint64_t)per_thread * PORTS) { w->exhausted++; break; }
      fd = sock(SOCK_DGRAM); local.sin_port = htons(40000 + w->index * per_thread + tuple_index % per_thread);
      dest.sin_port = htons(w->port + tuple_index / per_thread); tuple_index++; w->attempts++;
      if (fd < 0) { w->errors++; continue; }
      if (bind(fd, (void *)&local, sizeof(local)) || connect(fd, (void *)&dest, sizeof(dest))) { w->errors++; close(fd); continue; }
    }
    for (int i = 0; i < batch; i++) { header h = message(w->id, 'U', (seq + (uint64_t)i) * w->threads + w->index, sizeof(data[i])); memcpy(data[i], &h, sizeof(h)); }
    int n = sendmmsg(fd, msgs, (unsigned)batch, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n > 0) { w->packets += (uint64_t)n; w->bytes += (uint64_t)n * sizeof(data[0]);
      if (w->mode == 3 || !used[fixed_index]) { w->tuples++; used[fixed_index] = 1; }
    }
    if (n < batch) w->errors += (uint64_t)(batch - (n < 0 ? 0 : n));
    seq += (uint64_t)batch;
    if (w->mode == 3) close(fd);
    uint64_t now = now_ns();
    if (probe_since) { header reply; ssize_t b = recv(probe, &reply, sizeof(reply), MSG_DONTWAIT);
      if (b == sizeof(reply) && ntohl(reply.magic) == MAGIC && ntohl(reply.op) == 'P' && be64toh(reply.seq) == probe_since) { latency(w, now_ns() - probe_since); probe_since = 0; }
      else if (now - probe_since > 1000000000) { w->timeouts++; probe_since = 0; }
    }
    if (!probe_since && now >= next_probe) { header h = message(w->id, 'P', now, sizeof(header));
      if (send(probe, &h, sizeof(h), MSG_DONTWAIT) == sizeof(h)) probe_since = now; else w->errors++;
      next_probe = now + 20000000; }
  }
  if (probe_since) w->cancelled++;
  for (int i = 0; i < w->flows; i++) if (fds[i] >= 0) close(fds[i]);
  free(used); free(fds); close(probe); return NULL;
}
static int client(int argc, char **argv) {
  if (argc < 9 || argc > 11) { fprintf(stderr, "client IP PORT CASE_ID tcp-fixed|tcp-new|udp-fixed|udp-new MS THREADS FLOWS_PER_THREAD [UDP_FIXED_SOURCE_PORT_BASE [UDP_FIXED_SOURCE_PORT_STRIDE]]\n"); return 2; }
  const char *names[] = {"tcp-fixed", "tcp-new", "udp-fixed", "udp-new"}; int mode = -1;
  for (int i = 0; i < 4; i++) if (!strcmp(argv[5], names[i])) mode = i;
  if (mode < 0) return 2;
  int port = number(argv[3], 1024, 65472), id = number(argv[4], 0, CASES - 1), ms = number(argv[6], 100, 10000);
  int threads = number(argv[7], 1, 8), flows = number(argv[8], 1, 256);
  int fixed_port_stride = argc == 11 ? number(argv[10], 1, 16) : 1;
  int fixed_port_base = argc >= 10 ? number(argv[9], 1024, 65535 - (threads * flows + threads - 1) * fixed_port_stride) : 0;
  if (fixed_port_base && mode != 2) return 2;
  address(argv[2], port); signal(SIGPIPE, SIG_IGN);
  worker *w = calloc((size_t)threads, sizeof(*w)); pthread_t ids[8]; if (!w) die("calloc");
  struct rusage before, after; getrusage(RUSAGE_SELF, &before); uint64_t begin = now_ns(), end = begin + (uint64_t)ms * 1000000;
  for (int i = 0; i < threads; i++) { w[i] = (worker){.index=i,.threads=threads,.flows=flows,.mode=mode,.id=id,.port=port,.fixed_port_base=fixed_port_base,.fixed_port_stride=fixed_port_stride,.ip=argv[2],.begin=begin,.end=end}; if (pthread_create(&ids[i], NULL, mode < 2 ? tcp_worker : udp_worker, &w[i])) die("pthread_create"); }
  worker sum = {0};
  for (int i = 0; i < threads; i++) { pthread_join(ids[i], NULL);
    sum.bytes+=w[i].bytes; sum.packets+=w[i].packets; sum.attempts+=w[i].attempts; sum.completed+=w[i].completed; sum.errors+=w[i].errors; sum.timeouts+=w[i].timeouts; sum.cancelled+=w[i].cancelled; sum.tuples+=w[i].tuples; sum.samples+=w[i].samples; sum.exhausted+=w[i].exhausted;
    for (int j=0;j<HIST;j++) sum.hist[j]+=w[i].hist[j]; }
  uint64_t finished = now_ns(); getrusage(RUSAGE_SELF, &after);
  double cpu = (after.ru_utime.tv_sec-before.ru_utime.tv_sec)+(after.ru_utime.tv_usec-before.ru_utime.tv_usec)/1e6+(after.ru_stime.tv_sec-before.ru_stime.tv_sec)+(after.ru_stime.tv_usec-before.ru_stime.tv_usec)/1e6;
  int p99 = 0; uint64_t cumulative = 0, target = (sum.samples*99+99)/100;
  if (sum.samples) for (int j=0;j<HIST;j++) { cumulative+=sum.hist[j]; if (cumulative>=target) { p99=j+1; break; } }
  printf("{\"case\":\"%s\",\"case_id\":%d,\"pid\":%d,\"uid\":%d,\"start_monotonic_ns\":%"PRIu64",\"end_monotonic_ns\":%"PRIu64",\"requested_ms\":%d,\"threads\":%d,\"flows_per_thread\":%d,\"bytes\":%"PRIu64",\"packets\":%"PRIu64",\"attempts\":%"PRIu64",\"completed\":%"PRIu64",\"errors\":%"PRIu64",\"timeouts\":%"PRIu64",\"cancelled_at_deadline\":%"PRIu64",\"input_unique_udp_tuples\":%"PRIu64",\"tuple_space_exhausted\":%"PRIu64",\"latency_samples\":%"PRIu64",\"latency_overflow_samples\":%"PRIu64",\"p99_upper_us\":",names[mode],id,getpid(),getuid(),begin,finished,ms,threads,flows,sum.bytes,sum.packets,sum.attempts,sum.completed,sum.errors,sum.timeouts,sum.cancelled,sum.tuples,sum.exhausted,sum.samples,sum.hist[HIST-1]);
  if (!p99 || p99 >= HIST) printf("null"); else printf("%d",p99*100);
  printf(",\"generator_cpu_seconds\":%.6f,\"generator_maxrss_kib\":%ld,\"fixed_source_port_base\":%d,\"fixed_source_port_stride\":%d}\n",cpu,after.ru_maxrss,fixed_port_base,fixed_port_stride); free(w); return 0;
}
static int monitor(int pid, int ms) {
  uint64_t end=now_ns()+(uint64_t)ms*1000000; char path[128], line[2048];
  while (!stopped && now_ns()<end) {
    snprintf(path,sizeof(path),"/proc/%d/task",pid); DIR *d=opendir(path); if (!d) return 1;
    printf("{\"monotonic_ns\":%"PRIu64",\"clock_ticks\":%ld,\"page_size\":%ld,\"pid\":%d,\"threads\":[",now_ns(),sysconf(_SC_CLK_TCK),sysconf(_SC_PAGESIZE),pid); int comma=0; struct dirent *e;
    while ((e=readdir(d))) { if (e->d_name[0]=='.') continue;
      snprintf(path,sizeof(path),"/proc/%d/task/%.20s/stat",pid,e->d_name); FILE *f=fopen(path,"r"); if (!f) continue;
      if (fgets(line,sizeof(line),f)) { char *p=strrchr(line,')'); if(p) { char *save, *v=strtok_r(p+2," ",&save); int field=3; unsigned long long u=0,s=0,rss=0; int cpu=-1;
        for(;v;v=strtok_r(NULL," ",&save),field++) { if(field==14)u=strtoull(v,NULL,10); if(field==15)s=strtoull(v,NULL,10); if(field==24)rss=strtoull(v,NULL,10); if(field==39)cpu=atoi(v); }
        printf("%s{\"tid\":%s,\"utime\":%llu,\"stime\":%llu,\"rss_pages\":%llu,\"last_cpu\":%d}",comma?",":"",e->d_name,u,s,rss,cpu); comma=1;
      } } fclose(f);
    } closedir(d); puts("]}"); fflush(stdout); usleep(200000);
  } return 0;
}
static int cli(int argc, char **argv) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  if (strlen(argv[2]) >= sizeof(a.sun_path)) return 2;
  strcpy(a.sun_path, argv[2]);
  struct timeval timeout = {.tv_sec = 3};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  if (fd < 0 || connect(fd, (void *)&a, sizeof(a))) die("CLI connect");
  const size_t capacity = 16 * 1024 * 1024;
  char *all = calloc(capacity, 1), chunk[65536]; size_t used = 0; int sent = 0, telnet = 0, verb = 0;
  if (!all) die("calloc");
  while (!stopped) {
    ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
    if (n <= 0) { fprintf(stderr,"CLI ended before completion marker\n"); free(all); close(fd); return 1; }
    for (ssize_t i = 0; i < n; i++) {
      unsigned char byte = (unsigned char)chunk[i];
      if (telnet == 2) {
        /* Decline optional terminal features immediately, rather than waiting
         * for VPP's negotiation timeout before the first safe prompt. */
        if (verb == 251 || verb == 253) {
          unsigned char reply[3] = {255, verb == 251 ? 254 : 252, byte};
          if (send(fd, reply, sizeof(reply), MSG_NOSIGNAL) != sizeof(reply)) die("CLI negotiation");
        }
        telnet = 0;
      } else if (telnet == 1) {
        if (byte >= 251 && byte <= 254) { verb = byte; telnet = 2; }
        else telnet = 0;
      } else if (byte == 255) telnet = 1;
      if (chunk[i] == '\r') continue;
      if (used + 1 >= capacity) { fprintf(stderr,"CLI reply too large\n"); free(all); close(fd); return 1; }
      all[used++] = chunk[i] ? chunk[i] : '?';
    }
    if (!sent && strstr(all, "vpp# ")) {
      if (dprintf(fd, "\nset terminal pager off\n") < 0) die("CLI write");
      for (int i = 3; i < argc; i++) if (dprintf(fd, "%s\n", argv[i]) < 0) die("CLI write");
      if (dprintf(fd, "echo BENCHCLI_DONE\n") < 0) die("CLI write");
      sent = 1;
    }
    if (strstr(all, "\nBENCHCLI_DONE\n")) {
      /* Close the completed diagnostic socket directly; no netcat idle timeout. */
      fwrite(all, 1, used, stdout); free(all); close(fd); return 0;
    }
  }
  free(all); close(fd); return 1;
}
int main(int argc,char **argv) {
  signal(SIGINT,stop_signal); signal(SIGTERM,stop_signal); signal(SIGPIPE,SIG_IGN);
  if(argc>=2 && !strcmp(argv[1],"client"))return client(argc,argv);
  if(argc==4 && !strcmp(argv[1],"server"))return server(argv[2],number(argv[3],1024,65472));
  if(argc==4 && !strcmp(argv[1],"monitor"))return monitor(number(argv[2],1,10000000),number(argv[3],100,11000));
  if(argc>=4 && !strcmp(argv[1],"cli"))return cli(argc,argv);
  fprintf(stderr,"server BIND_IP PORT | client IP PORT CASE_ID CASE MS THREADS FLOWS | monitor PID MS | cli SOCKET COMMAND...\n");return 2;
}
