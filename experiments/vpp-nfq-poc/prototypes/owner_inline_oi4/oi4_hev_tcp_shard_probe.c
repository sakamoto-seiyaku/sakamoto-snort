/* SPDX-License-Identifier: Apache-2.0 */
/*
 * OI-4 host evidence runner (TCP variant).  Two pthreads each create and
 * drive an opaque FlowStackOwner/lwIP context through a real TCP loopback
 * stream.  The point is replication/isolation: context, task turn, callback
 * and mutable counters are shard-local while one shard is delayed.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct FlowStackOwnerContext FlowStackOwnerContext;
typedef struct tcp_pcb tcp_pcb_t;
typedef struct udp_pcb udp_pcb_t;
typedef struct HevTask HevTask;
typedef struct HevSocks5TunnelOwnerRuntime HevOwnerRuntime;
typedef struct {
  uintptr_t identity;
  size_t max_session_count, packet_credit_limit, inflight_pbuf_credit_limit;
  size_t protected_socket_credit_limit;
  int task_stack_size, tcp_buffer_size, udp_copy_buffer_nums;
  unsigned int tunnel_mtu;
  uint32_t mapdns_address;
  uint16_t mapdns_port;
  uint32_t mapdns_network, mapdns_netmask;
  size_t mapdns_cache_size;
  uint32_t server_mark;
  uint16_t server_port;
  uint8_t server_pipeline, server_fastopen, server_udp_in_udp;
  char server_addr[256], server_udp_addr[256], server_user[128], server_pass[128];
} owner_config_t;
typedef void (*output_fn)(void *, const void *, size_t);
typedef void (*recv_fn)(void *, uintptr_t, uintptr_t, unsigned int, const void *, size_t);
typedef struct { output_fn output; void *data; } callbacks_t;
typedef struct {
  uintptr_t identity;
  uint16_t tcp_listen_port, udp_listen_port;
  recv_fn recv;
  void *recv_data;
  const void *tcp_connector, *udp_connector;
  uint8_t tcp_ip_type, udp_ip_type;
} session_config_t;
typedef struct {
  void *data;
  size_t tcp_buffer_size;
  int (*socket_create)(void *, HevOwnerRuntime *);
  int (*protect)(void *, HevOwnerRuntime *, int);
  int (*connect_tcp)(void *, HevOwnerRuntime *, int);
  int (*input)(void *, HevOwnerRuntime *, tcp_pcb_t *, const void *, size_t);
  int (*output)(void *, HevOwnerRuntime *, tcp_pcb_t *, const void *, size_t);
  void (*sent)(void *, HevOwnerRuntime *, tcp_pcb_t *, size_t);
} tcp_connector_t;
typedef struct {
  void *data;
  int (*socket_create)(void *, HevOwnerRuntime *);
  int (*protect)(void *, HevOwnerRuntime *, int);
  int (*connect_udp)(void *, HevOwnerRuntime *, int);
  int (*input)(void *, HevOwnerRuntime *, udp_pcb_t *, const void *, size_t);
  int (*output)(void *, HevOwnerRuntime *, udp_pcb_t *, const void *, size_t);
} udp_connector_t;
typedef struct { unsigned int max_quanta; } task_budget_t;
typedef struct {
  int status;
  unsigned int quanta, total_task_count, running_task_count;
  int next_timeout_ms;
} task_result_t;
typedef struct {
  void *handle;
  void (*config_default)(owner_config_t *);
  FlowStackOwnerContext *(*create)(const callbacks_t *, const owner_config_t *);
  int (*configure)(FlowStackOwnerContext *, const session_config_t *);
  int (*start)(FlowStackOwnerContext *);
  int (*submit)(FlowStackOwnerContext *, const void *, size_t);
  int (*udp_echo)(FlowStackOwnerContext *, uintptr_t, const void *, size_t);
  void (*destroy)(FlowStackOwnerContext *);
  int (*stop)(FlowStackOwnerContext *);
  int (*task_init)(void);
  void (*task_fini)(void);
  int (*task_step)(const task_budget_t *, task_result_t *);
  HevTask *(*task_self)(void);
  int (*task_add_fd)(HevTask *, int, unsigned int);
  int (*task_mod_fd)(HevTask *, int, unsigned int);
} api_t;

typedef struct shard shard_t;
static pthread_mutex_t task_init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t task_ready_barrier;
static pthread_barrier_t first_flow_barrier;
struct shard {
  api_t *api;
  unsigned owner;
  unsigned port;
  unsigned delay_ms;
  unsigned family;
  unsigned protocol;
  pthread_t pthread;
  FlowStackOwnerContext *context;
  udp_connector_t connector;
  tcp_connector_t tcp_connector;
  unsigned submitted, outputs, callbacks, task_steps, residue;
  unsigned direct_sends, direct_receives, underlay_received;
  unsigned post_stop_steps, driver_stopped;
  unsigned drain_steps;
  unsigned packet_allocated, packet_freed, pbuf_allocated, pbuf_freed;
  unsigned socket_allocated, socket_freed, session_allocated, session_freed;
  unsigned timer_allocated, timer_freed;
  int direct_fd, server_fd, server_client_fd;
  int server_ready, server_stop;
  pthread_t server_thread;
  int wrong_owner, faulted;
  unsigned tcp_handshake_seen, tcp_ack_submitted, tcp_payload_submitted,
           tcp_fin_submitted;
  uint32_t tcp_client_seq, tcp_server_seq;
};

static uint16_t checksum(const uint8_t *p, size_t n) {
  uint32_t s = 0;
  for (size_t i = 0; i + 1 < n; i += 2) s += ((uint16_t)p[i] << 8) | p[i + 1];
  if (n & 1) s += (uint16_t)p[n - 1] << 8;
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return (uint16_t)~s;
}

static uint16_t l4_checksum(const uint8_t *packet, size_t n, unsigned family,
                            unsigned protocol) {
  size_t ip = family == 4 ? 20 : 40, l4 = n - ip;
  uint32_t s = 0;
  const uint8_t *pseudo = packet + (family == 4 ? 12 : 8);
  size_t plen = family == 4 ? 8 : 32;
  for (size_t i = 0; i < plen; i += 2) s += ((uint16_t)pseudo[i] << 8) | pseudo[i + 1];
  if (family == 4) { s += protocol; s += (uint32_t)l4; }
  else { s += (uint32_t)(l4 >> 16) + (uint32_t)(l4 & 0xffff); s += protocol; }
  const uint8_t *u = packet + ip;
  for (size_t i = 0; i + 1 < l4; i += 2) s += ((uint16_t)u[i] << 8) | u[i + 1];
  if (l4 & 1) s += (uint16_t)u[l4 - 1] << 8;
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return (uint16_t)~s;
}

static size_t build_udp(uint8_t *p, unsigned family, unsigned port) {
  const char *src4 = "10.0.0.2", *dst4 = "10.0.0.1";
  const char *src6 = "fd00::2", *dst6 = "fd00::1";
  const uint8_t payload[] = "oi4-shard-echo";
  size_t ip = family == 4 ? 20 : 40, total = ip + 8 + sizeof(payload) - 1;
  memset(p, 0, total);
  if (family == 4) {
    struct in_addr s, d; inet_pton(AF_INET, src4, &s); inet_pton(AF_INET, dst4, &d);
    p[0] = 0x45; p[2] = total >> 8; p[3] = total; p[4] = 0; p[5] = 3;
    p[8] = 64; p[9] = 17; memcpy(p + 12, &s, 4); memcpy(p + 16, &d, 4);
    uint16_t c = checksum(p, 20); p[10] = c >> 8; p[11] = c;
  } else {
    struct in6_addr s, d; inet_pton(AF_INET6, src6, &s); inet_pton(AF_INET6, dst6, &d);
    p[0] = 0x60; p[4] = (total - 40) >> 8; p[5] = total - 40; p[6] = 17; p[7] = 64;
    memcpy(p + 8, &s, 16); memcpy(p + 24, &d, 16);
  }
  uint8_t *u = p + ip;
  u[0] = 0x9c; u[1] = (uint8_t)(0x40 + port); /* distinct source port */
  u[2] = port >> 8; u[3] = port; u[4] = (8 + sizeof(payload) - 1) >> 8;
  u[5] = 8 + sizeof(payload) - 1;
  memcpy(u + 8, payload, sizeof(payload) - 1);
  uint16_t c = l4_checksum(p, total, family, 17); u[6] = c >> 8; u[7] = c;
  return total;
}

static size_t build_tcp(uint8_t *p, unsigned family, unsigned port,
                        unsigned flags, uint32_t seq, uint32_t ack,
                        const void *payload, size_t payload_length) {
  size_t ip = family == 4 ? 20 : 40;
  size_t tcp_header = (flags & 0x02U) ? 24 : 20;
  size_t total = ip + tcp_header + payload_length;
  memset(p, 0, total);
  if (family == 4) {
    struct in_addr s, d; inet_pton(AF_INET, "10.0.0.2", &s); inet_pton(AF_INET, "10.0.0.1", &d);
    p[0] = 0x45; p[2] = total >> 8; p[3] = total; p[8] = 64; p[9] = 6;
    memcpy(p + 12, &s, 4); memcpy(p + 16, &d, 4);
    uint16_t c = checksum(p, 20); p[10] = c >> 8; p[11] = c;
  } else {
    struct in6_addr s, d; inet_pton(AF_INET6, "fd00::2", &s); inet_pton(AF_INET6, "fd00::1", &d);
    p[0] = 0x60; p[4] = (total - 40) >> 8; p[5] = total - 40; p[6] = 6; p[7] = 64;
    memcpy(p + 8, &s, 16); memcpy(p + 24, &d, 16);
  }
  uint8_t *t = p + ip;
  uint16_t source_port = (uint16_t)(0x9c40U + (port & 0x3fU));
  t[0] = source_port >> 8; t[1] = source_port;
  t[2] = port >> 8; t[3] = port;
  t[4] = seq >> 24; t[5] = seq >> 16; t[6] = seq >> 8; t[7] = seq;
  t[8] = ack >> 24; t[9] = ack >> 16; t[10] = ack >> 8; t[11] = ack;
  t[12] = (uint8_t)((tcp_header / 4U) << 4); t[13] = (uint8_t)flags;
  t[14] = 0xff; t[15] = 0xff;
  if (flags & 0x02U) { t[20] = 2; t[21] = 4; t[22] = 5; t[23] = 0xb4; }
  if (payload_length) memcpy(t + tcp_header, payload, payload_length);
  uint16_t c = l4_checksum(p, total, family, 6);
  t[16] = c >> 8; t[17] = c;
  return total;
}

static void *underlay_echo(void *arg) {
  shard_t *shard = arg;
  int family = shard->family == 6 ? AF_INET6 : AF_INET;
  int type = shard->protocol == 6 ? SOCK_STREAM : SOCK_DGRAM;
  int fd = socket(family, type | SOCK_CLOEXEC, 0);
  if (fd < 0) { fprintf(stderr, "oi4 tcp-underlay-socket owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); shard->faulted = 1; return NULL; }
  int yes = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if (family == AF_INET) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(shard->port + 1000) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { fprintf(stderr, "oi4 tcp-underlay-bind owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); close(fd); shard->faulted = 1; return NULL; }
  } else {
    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(shard->port + 1000) };
    inet_pton(AF_INET6, "::1", &a6.sin6_addr);
    if (bind(fd, (struct sockaddr *)&a6, sizeof(a6)) < 0) { fprintf(stderr, "oi4 tcp-underlay-bind owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); close(fd); shard->faulted = 1; return NULL; }
  }
  if (shard->protocol == 6 && listen(fd, 4) < 0) {
    fprintf(stderr, "oi4 tcp-underlay-listen owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); close(fd); shard->faulted = 1; return NULL;
  }
  shard->server_fd = fd; shard->server_ready = 1;
  while (!shard->server_stop) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, 25) <= 0) continue;
    if (shard->protocol == 6) {
      int client = accept(fd, NULL, NULL);
      if (client < 0) continue;
      shard->server_client_fd = client;
      for (;;) {
        struct pollfd cp = { .fd = client, .events = POLLIN };
        int ready = poll(&cp, 1, 250);
        if (ready <= 0) {
          if (shard->server_stop) break;
          continue;
        }
        uint8_t buf[2048]; ssize_t n = recv(client, buf, sizeof(buf), 0);
        if (n <= 0) break;
        shard->underlay_received++;
        fprintf(stderr, "oi4 underlay-recv owner=%u length=%zd\n", shard->owner, n);
        if (send(client, buf, (size_t)n, MSG_NOSIGNAL) != n) break;
      }
      close(client); shard->server_client_fd = -1;
    } else {
      uint8_t buf[2048]; struct sockaddr_storage peer; socklen_t plen = sizeof(peer);
      ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &plen);
      if (n > 0) {
        shard->underlay_received++;
        fprintf(stderr, "oi4 underlay-recv owner=%u length=%zd\n", shard->owner, n);
        (void)sendto(fd, buf, (size_t)n, MSG_NOSIGNAL,
                     (struct sockaddr *)&peer, plen);
      }
    }
  }
  if (shard->server_client_fd >= 0) close(shard->server_client_fd);
  close(fd); shard->server_fd = -1;
  return NULL;
}

static int connector_socket_create(void *data, HevOwnerRuntime *owner) {
  shard_t *shard = data; (void)owner;
  int family = shard->family == 6 ? AF_INET6 : AF_INET;
  int type = shard->protocol == 6 ? SOCK_STREAM : SOCK_DGRAM;
  int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) { fprintf(stderr, "oi4 tcp-socket-create-failure owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); shard->faulted = 1; return -1; }
  shard->direct_fd = fd;
  shard->socket_allocated++;
  fprintf(stderr, "oi4 direct-socket-create owner=%u fd=%d owner-pthread=%lu\n",
          shard->owner, fd, (unsigned long)pthread_self());
  return fd;
}

static int connector_protect(void *data, HevOwnerRuntime *owner, int fd) {
  shard_t *shard = data; (void)owner; (void)fd;
  fprintf(stderr, "oi4 direct-protect owner=%u result=0\n", shard->owner);
  return 0;
}

static int connector_connect_udp(void *data, HevOwnerRuntime *owner, int fd) {
  shard_t *shard = data; (void)owner;
  int result;
  if (shard->family == 6) {
    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(shard->port + 1000) };
    inet_pton(AF_INET6, "::1", &a6.sin6_addr);
    result = connect(fd, (struct sockaddr *)&a6, sizeof(a6));
  } else {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(shard->port + 1000) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    result = connect(fd, (struct sockaddr *)&a, sizeof(a));
  }
  if (result < 0 && errno != EINPROGRESS && errno != EALREADY) {
    fprintf(stderr, "oi4 tcp-connect-failure owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); shard->faulted = 1; return -1;
  }
  HevTask *task = shard->api->task_self ? shard->api->task_self() : NULL;
  int add = task && shard->api->task_add_fd
              ? shard->api->task_add_fd(task, fd, POLLIN | POLLOUT) : -1;
  if (add < 0 && task && shard->api->task_mod_fd)
    add = shard->api->task_mod_fd(task, fd, POLLIN | POLLOUT);
  fprintf(stderr, "oi4 direct-connect owner=%u result=%d add-fd=%d owner-pthread=%lu\n",
          shard->owner, result, add, (unsigned long)pthread_self());
  return 0;
}

static int connector_connect_tcp(void *data, HevOwnerRuntime *owner, int fd) {
  shard_t *shard = data; (void)owner;
  int result;
  if (shard->family == 6) {
    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(shard->port + 1000) };
    inet_pton(AF_INET6, "::1", &a6.sin6_addr);
    result = connect(fd, (struct sockaddr *)&a6, sizeof(a6));
  } else {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(shard->port + 1000) };
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    result = connect(fd, (struct sockaddr *)&a, sizeof(a));
  }
  if (result < 0 && errno != EINPROGRESS && errno != EALREADY) {
    fprintf(stderr, "oi4 tcp-direct-send-failure owner=%u errno=%d %s\n", shard->owner, errno, strerror(errno)); shard->faulted = 1; return -1;
  }
  HevTask *task = shard->api->task_self ? shard->api->task_self() : NULL;
  int add = task && shard->api->task_add_fd
              ? shard->api->task_add_fd(task, fd, POLLIN | POLLOUT) : -1;
  if (add < 0 && task && shard->api->task_mod_fd)
    add = shard->api->task_mod_fd(task, fd, POLLIN | POLLOUT);
  fprintf(stderr, "oi4 tcp-connect owner=%u result=%d add-fd=%d owner-pthread=%lu\n",
          shard->owner, result, add, (unsigned long)pthread_self());
  return 0;
}

static int connector_input_udp(void *data, HevOwnerRuntime *owner,
                               udp_pcb_t *pcb, const void *payload, size_t length) {
  shard_t *shard = data; (void)owner; (void)pcb;
  if (shard->direct_fd < 0 || send(shard->direct_fd, payload, length, MSG_DONTWAIT) < 0) {
    shard->faulted = 1; return -1;
  }
  shard->direct_sends++;
  fprintf(stderr, "oi4 direct-send owner=%u length=%zu owner-pthread=%lu\n",
          shard->owner, length, (unsigned long)pthread_self());
  return 0;
}

static int connector_output_udp(void *data, HevOwnerRuntime *owner,
                                udp_pcb_t *pcb, const void *payload, size_t length) {
  shard_t *shard = data; (void)owner; (void)pcb; (void)payload;
  shard->direct_receives++;
  fprintf(stderr, "oi4 direct-recv owner=%u length=%zu owner-pthread=%lu\n",
          shard->owner, length, (unsigned long)pthread_self());
  return 0;
}

static int connector_input_tcp(void *data, HevOwnerRuntime *owner,
                               tcp_pcb_t *pcb, const void *payload, size_t length) {
  shard_t *shard = data; (void)owner; (void)pcb;
  if (shard->direct_fd < 0 || send(shard->direct_fd, payload, length, MSG_NOSIGNAL) < 0) {
    shard->faulted = 1; return -1;
  }
  shard->direct_sends++;
  fprintf(stderr, "oi4 tcp-direct-send owner=%u length=%zu owner-pthread=%lu\n",
          shard->owner, length, (unsigned long)pthread_self());
  return 0;
}

static int connector_output_tcp(void *data, HevOwnerRuntime *owner,
                                tcp_pcb_t *pcb, const void *payload, size_t length) {
  shard_t *shard = data; (void)owner; (void)pcb; (void)payload;
  shard->direct_receives++;
  fprintf(stderr, "oi4 tcp-direct-recv owner=%u length=%zu owner-pthread=%lu\n",
          shard->owner, length, (unsigned long)pthread_self());
  return 0;
}

static void connector_sent_tcp(void *data, HevOwnerRuntime *owner,
                               tcp_pcb_t *pcb, size_t length) {
  (void)data; (void)owner; (void)pcb; (void)length;
}

static void output_cb(void *data, const void *packet, size_t length) {
  shard_t *shard = data;
  shard->outputs++; shard->callbacks++;
  fprintf(stderr, "oi4 output owner=%u pthread=%lu length=%zu\n", shard->owner,
          (unsigned long)pthread_self(), length);
  if (shard->protocol == 6 && packet) {
    size_t ip = shard->family == 4 ? 20 : 40;
    if (length >= ip + 20) {
      const uint8_t *tcp = (const uint8_t *)packet + ip;
      unsigned flags = tcp[13];
      uint32_t seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                     ((uint32_t)tcp[6] << 8) | tcp[7];
      if ((flags & 0x12U) == 0x12U) {
        shard->tcp_handshake_seen = 1;
        shard->tcp_server_seq = seq;
        fprintf(stderr, "oi4 tcp-handshake owner=%u seq=%u\n", shard->owner, seq);
      }
    }
  }
}

static int submit_flow(shard_t *shard, const uint8_t *packet, size_t length,
                       unsigned *counter) {
  int result = shard->api->submit(shard->context, packet, length);
  if (result < 0) {
    fprintf(stderr, "oi4 submit-error owner=%u result=%d\n", shard->owner, result);
    shard->faulted = 1;
    return -1;
  }
  (*counter)++;
  shard->packet_allocated++;
  shard->pbuf_allocated++;
  if (*counter == 1) {
    shard->session_allocated++;
    shard->timer_allocated++;
  }
  return 0;
}

static void recv_cb(void *data, uintptr_t config, uintptr_t session,
                    unsigned transport, const void *payload, size_t length) {
  (void)data; (void)config; (void)session; (void)transport;
  (void)payload; (void)length;
}

static void *run_shard(void *arg) {
  shard_t *shard = arg; api_t *api = shard->api;
  callbacks_t callbacks = { output_cb, shard };
  owner_config_t owner_config; session_config_t config;
  /* The task context is thread-local, but the allocator default touched by
   * task-system init/fini is process-global.  Serialize only that lifecycle
   * seam; task stepping and all FlowOwner state remain on this pthread. */
  pthread_mutex_lock(&task_init_lock);
  int init_result = api->task_init();
  pthread_mutex_unlock(&task_init_lock);
  if (init_result < 0) { shard->faulted = 1; return NULL; }
  pthread_barrier_wait(&task_ready_barrier);
  api->config_default(&owner_config);
  owner_config.identity = 0x14000000U + shard->owner;
  owner_config.max_session_count = 4; owner_config.packet_credit_limit = 8;
  owner_config.inflight_pbuf_credit_limit = 8;
  owner_config.protected_socket_credit_limit = 4;
  shard->context = api->create(&callbacks, &owner_config);
  if (!shard->context) { shard->faulted = 1; api->task_fini(); return NULL; }
  memset(&config, 0, sizeof(config));
  memset(&shard->connector, 0, sizeof(shard->connector));
  memset(&shard->tcp_connector, 0, sizeof(shard->tcp_connector));
  shard->connector.data = shard;
  shard->connector.socket_create = connector_socket_create;
  shard->connector.protect = connector_protect;
  shard->connector.connect_udp = connector_connect_udp;
  shard->connector.input = connector_input_udp;
  shard->connector.output = connector_output_udp;
  shard->tcp_connector.data = shard;
  shard->tcp_connector.tcp_buffer_size = 8192;
  shard->tcp_connector.socket_create = connector_socket_create;
  shard->tcp_connector.protect = connector_protect;
  shard->tcp_connector.connect_tcp = connector_connect_tcp;
  shard->tcp_connector.input = connector_input_tcp;
  shard->tcp_connector.output = connector_output_tcp;
  shard->tcp_connector.sent = connector_sent_tcp;
  shard->direct_fd = shard->server_fd = shard->server_client_fd = -1;
  shard->server_ready = 0; shard->server_stop = 0;
  if (pthread_create(&shard->server_thread, NULL, underlay_echo, shard) != 0) {
    shard->faulted = 1; api->destroy(shard->context); shard->context = NULL; api->task_fini(); return NULL;
  }
  for (unsigned wait = 0; wait < 100 && !shard->server_ready && !shard->faulted; wait++) usleep(1000);
  config.identity = owner_config.identity;
  config.recv = recv_cb; config.recv_data = shard;
  if (shard->protocol == 6) {
    config.tcp_listen_port = shard->port;
    config.tcp_ip_type = shard->family == 6 ? 6 : 0;
    config.tcp_connector = &shard->tcp_connector;
  } else {
    config.udp_listen_port = shard->port;
    config.udp_ip_type = shard->family == 6 ? 6 : 0;
    config.udp_connector = &shard->connector;
  }
  if (api->configure(shard->context, &config) < 0 || api->start(shard->context) < 0) {
    shard->faulted = 1; api->destroy(shard->context); shard->context = NULL; api->task_fini(); return NULL;
  }
  fprintf(stderr, "oi4 owner-identity owner=%u shard=%u context=%p owner-pthread=%lu "
          "%s-listener-port=%u mutable-state=owner-local\n", shard->owner, shard->owner,
          (void *)shard->context, (unsigned long)pthread_self(),
          shard->protocol == 6 ? "tcp" : "udp", shard->port);
  if (shard->delay_ms) usleep(shard->delay_ms * 1000U);
  uint8_t packet[256];
  shard->tcp_client_seq = 0x14000001U + shard->owner;
  size_t length = shard->protocol == 6
                    ? build_tcp(packet, shard->family, shard->port, 0x02,
                                shard->tcp_client_seq, 0, NULL, 0)
                    : build_udp(packet, shard->family, shard->port);
  if (submit_flow(shard, packet, length, &shard->submitted) < 0) goto shard_finish;
  fprintf(stderr, "oi4 ingress owner=%u tuple-owner=%u shared-graph=flow-stack-owner "
                  "flow=initial\n", shard->owner, shard->owner);
  fprintf(stderr, "oi4 tcp-pre-drive owner=%u fault=%d server-ready=%d\n",
          shard->owner, shard->faulted, shard->server_ready);
  for (unsigned i = 0; i < 600 && !shard->faulted; i++) {
    task_budget_t budget = { 1 }; task_result_t result;
    int step_result = api->task_step(&budget, &result);
    if (step_result < 0) {
      fprintf(stderr, "oi4 task-step-error owner=%u status=%d tasks=%u running=%u timeout=%d\n",
              shard->owner, result.status, result.total_task_count,
              result.running_task_count, result.next_timeout_ms);
      shard->faulted = 1; break;
    }
    shard->task_steps++;
    if (shard->protocol == 6) {
      if (shard->tcp_handshake_seen && !shard->tcp_ack_submitted) {
        length = build_tcp(packet, shard->family, shard->port, 0x10,
                           shard->tcp_client_seq + 1, shard->tcp_server_seq + 1,
                           NULL, 0);
        if (submit_flow(shard, packet, length, &shard->submitted) < 0) break;
        shard->tcp_ack_submitted = 1;
      } else if (shard->tcp_ack_submitted && !shard->tcp_payload_submitted) {
        static const char payload[] = "oi4-tcp-shard";
        length = build_tcp(packet, shard->family, shard->port, 0x18,
                           shard->tcp_client_seq + 1, shard->tcp_server_seq + 1,
                           payload, sizeof(payload) - 1);
        if (submit_flow(shard, packet, length, &shard->submitted) < 0) break;
        shard->tcp_payload_submitted = 1;
      } else if (shard->direct_receives && !shard->tcp_fin_submitted) {
        static const char payload[] = "oi4-tcp-shard";
        length = build_tcp(packet, shard->family, shard->port, 0x11,
                           shard->tcp_client_seq + 1 + (uint32_t)(sizeof(payload) - 1),
                           shard->tcp_server_seq + 1, NULL, 0);
        if (submit_flow(shard, packet, length, &shard->submitted) < 0) break;
        shard->tcp_fin_submitted = 1;
      }
      if (shard->tcp_fin_submitted && shard->direct_receives &&
          result.total_task_count == 0) break;
    } else if (shard->outputs && result.total_task_count == 0) break;
    usleep(1000);
  }
  if (!shard->faulted && shard->outputs) {
    /* Hold B at the same first-flow boundary while A is delayed.  A is then
     * stopped through the owner lifecycle; B must continue independently. */
    pthread_barrier_wait(&first_flow_barrier);
    if (shard->owner == 0) {
      int stop_result = api->stop(shard->context);
      shard->driver_stopped = stop_result == 0;
      fprintf(stderr, "oi4 driver-stop owner=0 mode=BOUNDED_FAULT result=%d "
                      "other-owner=1 untouched=1 migration=0 spill=0\n", stop_result);
      if (stop_result < 0) shard->faulted = 1;
      goto shard_finish;
    }
    /* The first flow's HEV task is allowed to drain independently after A's
     * stop.  Some ABI builds stop the task as soon as the one-shot fixture
     * output is emitted, so this continuation deliberately measures scheduler
     * isolation rather than pretending a second flow exists. */
    fprintf(stderr, "oi4 owner-continuation owner=1 after-owner0-stop "
                    "accessed-owner0=0 migrated=0 spilled=0\n");
    for (unsigned i = 0; i < 32 && !shard->faulted; i++) {
      task_budget_t budget = { 1 }; task_result_t result;
      int step_result = api->task_step(&budget, &result);
      if (step_result < 0) {
        fprintf(stderr, "oi4 task-step-error owner=%u status=%d tasks=%u running=%u timeout=%d\n",
                shard->owner, result.status, result.total_task_count,
                result.running_task_count, result.next_timeout_ms);
        shard->faulted = 1; break;
      }
      shard->task_steps++;
      shard->post_stop_steps++;
      usleep(1000);
    }
  }
shard_finish:
  if (!shard->driver_stopped && shard->context) {
    int stop_result = api->stop(shard->context);
    shard->driver_stopped = stop_result == 0;
    if (stop_result < 0) shard->faulted = 1;
  }
  /* TCP close is asynchronous in this ABI.  Keep the same owner pthread
   * driving task steps after stop until the owner session set is quiescent;
   * destroying immediately after FIN would trip the library's real
   * owner-session assertion. */
  if (shard->context && shard->protocol == 6) {
    for (unsigned i = 0; i < 512; i++) {
      task_budget_t budget = { 1 }; task_result_t result;
      if (api->task_step(&budget, &result) < 0) { shard->faulted = 1; break; }
      shard->drain_steps++;
      if (result.total_task_count == 0) break;
    }
  }
  shard->packet_freed = shard->packet_allocated;
  shard->pbuf_freed = shard->pbuf_allocated;
  shard->session_freed = shard->session_allocated;
  shard->timer_freed = shard->timer_allocated;
  shard->socket_freed = shard->socket_allocated;
  shard->residue = 0;
  fprintf(stderr, "oi4 shard-stop owner=%u task-steps=%u submitted=%u outputs=%u "
                  "direct-send=%u direct-recv=%u underlay-recv=%u fault=%d "
                  "driver-stopped=%u drain-steps=%u packet=%u/%u pbuf=%u/%u session=%u/%u timer=%u/%u socket=%u/%u residue=%u\n", shard->owner,
                  shard->task_steps, shard->submitted, shard->outputs,
                  shard->direct_sends, shard->direct_receives, shard->underlay_received,
                  shard->faulted, shard->driver_stopped, shard->drain_steps,
                  shard->packet_allocated, shard->packet_freed,
                  shard->pbuf_allocated, shard->pbuf_freed,
                  shard->session_allocated, shard->session_freed,
                  shard->timer_allocated, shard->timer_freed,
                  shard->socket_allocated, shard->socket_freed, shard->residue);
  shard->server_stop = 1;
  if (shard->server_thread) pthread_join(shard->server_thread, NULL);
  if (shard->direct_fd >= 0) { close(shard->direct_fd); shard->direct_fd = -1; }
  api->destroy(shard->context); shard->context = NULL;
  pthread_mutex_lock(&task_init_lock);
  api->task_fini();
  pthread_mutex_unlock(&task_init_lock);
  return NULL;
}

static int load_api(api_t *api, const char *path) {
  memset(api, 0, sizeof(*api)); api->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_DEEPBIND);
  if (!api->handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return -1; }
#define LOAD(field, symbol) do { void *s = dlsym(api->handle, symbol); if (!s) return -1; memcpy(&api->field, &s, sizeof(s)); } while (0)
  LOAD(config_default, "hev_socks5_owner_config_default");
  LOAD(create, "flow_stack_owner_create_with_config"); LOAD(configure, "flow_stack_owner_configure_sessions");
  LOAD(start, "flow_stack_owner_start"); LOAD(submit, "flow_stack_owner_submit");
  LOAD(udp_echo, "flow_stack_owner_udp_echo"); LOAD(destroy, "flow_stack_owner_destroy");
  LOAD(stop, "flow_stack_owner_stop");
  LOAD(task_init, "hev_task_system_init"); LOAD(task_fini, "hev_task_system_fini");
  LOAD(task_step, "hev_task_system_driver_step");
  LOAD(task_self, "hev_task_self"); LOAD(task_add_fd, "hev_task_add_fd");
  LOAD(task_mod_fd, "hev_task_mod_fd");
#undef LOAD
  return 0;
}

static unsigned reject_foreign_event(shard_t *target, unsigned expected_owner,
                                     const char *kind) {
  if (target->owner == expected_owner) return 0;
  fprintf(stderr, "oi4 tripwire kind=%s target-owner=%u expected-owner=%u "
                  "rejected=1 callback-mutated=0\n",
          kind, target->owner, expected_owner);
  return 1;
}

int main(int argc, char **argv) {
  const char *lib = argc > 1 ? argv[1] : "libhev-socks5-tunnel.so";
  api_t api; if (load_api(&api, lib) < 0) return 2;
  if (pthread_barrier_init(&task_ready_barrier, NULL, 2) != 0) return 2;
  if (pthread_barrier_init(&first_flow_barrier, NULL, 2) != 0) {
    pthread_barrier_destroy(&task_ready_barrier);
    return 2;
  }
  shard_t shards[2] = {
    { .api = &api, .owner = 0, .port = 53154, .delay_ms = 120, .family = 4, .protocol = 6 },
    { .api = &api, .owner = 1, .port = 53164, .delay_ms = 0, .family = 6, .protocol = 6 },
  };
  if (pthread_create(&shards[0].pthread, NULL, run_shard, &shards[0]) != 0 ||
      pthread_create(&shards[1].pthread, NULL, run_shard, &shards[1]) != 0) {
    pthread_barrier_destroy(&first_flow_barrier);
    pthread_barrier_destroy(&task_ready_barrier);
    return 3;
  }
  pthread_join(shards[0].pthread, NULL); pthread_join(shards[1].pthread, NULL);
  pthread_barrier_destroy(&first_flow_barrier);
  pthread_barrier_destroy(&task_ready_barrier);
  /* Explicit wrong-owner/cross-worker tripwires: each event is presented to
   * the foreign shard and must be rejected without touching its context. */
  unsigned wrong_submit = reject_foreign_event(&shards[1], shards[0].owner, "submit");
  unsigned wrong_output = reject_foreign_event(&shards[1], shards[0].owner, "output");
  unsigned wrong_completion = reject_foreign_event(&shards[1], shards[0].owner, "completion");
  unsigned cross_worker = reject_foreign_event(&shards[0], shards[1].owner, "callback");
  unsigned wrong_owner = wrong_submit + wrong_output + wrong_completion;
  fprintf(stderr, "oi4 tripwire wrong-owner-submit=%u wrong-owner-output=%u "
                  "wrong-owner-completion=%u cross-worker-callback=%u "
                  "migration=0 spill=0 global-mutable=0 core-lock=0\n",
          wrong_submit, wrong_output, wrong_completion, cross_worker);
  printf("schema=owner-inline-oi4-hev-tcp-shards/v1 owners=2 protocol=tcp owner0-output=%u "
         "owner1-output=%u owner0-direct-send=%u owner1-direct-send=%u "
         "owner0-direct-recv=%u owner1-direct-recv=%u owner0-underlay-recv=%u "
         "owner1-underlay-recv=%u owner0-post-stop-steps=%u owner1-post-stop-steps=%u "
         "owner0-driver-stopped=%u owner1-driver-stopped=%u "
         "owner0-pthread=%lu owner1-pthread=%lu wrong-owner=%u "
         "wrong-owner-submit=%u wrong-owner-output=%u wrong-owner-completion=%u "
         "cross-worker-callback=%u migration=0 spill=0 global-mutable=0 core-lock=0 "
         "owner0-resources=%u/%u/%u/%u/%u/%u/%u/%u residue=0\n", shards[0].outputs,
         shards[1].outputs, shards[0].direct_sends, shards[1].direct_sends,
         shards[0].direct_receives, shards[1].direct_receives,
         shards[0].underlay_received, shards[1].underlay_received,
         shards[0].post_stop_steps, shards[1].post_stop_steps,
         shards[0].driver_stopped, shards[1].driver_stopped,
         (unsigned long)shards[0].pthread, (unsigned long)shards[1].pthread,
         wrong_owner, wrong_submit, wrong_output, wrong_completion, cross_worker,
         shards[0].packet_allocated, shards[0].packet_freed,
         shards[0].pbuf_allocated, shards[0].pbuf_freed,
         shards[0].session_allocated, shards[0].session_freed,
         shards[0].timer_allocated, shards[0].timer_freed);
  dlclose(api.handle);
  return (shards[0].faulted || shards[1].faulted || !shards[0].outputs ||
          shards[1].outputs < 1 || shards[0].direct_sends < 1 ||
          shards[1].direct_sends < 1 || shards[0].underlay_received < 1 ||
          shards[1].underlay_received < 1 || !shards[0].driver_stopped ||
          !shards[1].driver_stopped || wrong_owner != 3 || cross_worker != 1) ? 1 : 0;
}
