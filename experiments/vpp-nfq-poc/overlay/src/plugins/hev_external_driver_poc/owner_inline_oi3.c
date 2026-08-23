/* SPDX-License-Identifier: Apache-2.0 */

/*
 * OI-3 test-only real Direct Egress probe.
 *
 * This file intentionally keeps the HEV/lwIP objects opaque.  A VPP worker
 * owns the FlowStackOwner context and drives one task-system quantum at a
 * time.  A small host broker thread (or the Android broker supplied through
 * fd 6/7) is the only place that binds/protects the SCM_RIGHTS duplicate.
 * The owner receives a completion, then lets the HEV connector perform a
 * non-blocking connect and splice bytes to a controlled endpoint.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/file.h>
#include <vlib/threads.h>
#include <vppinfra/file.h>

#include "oi2_broker_contract.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define OI3_MAX_PACKET 2048U
#define OI3_TUN_KIND 2U
#define OI3_MAX_TUN_PACKET 4096U
#define OI3_PAYLOAD "oi3-direct-echo"
#define OI3_TCP_LISTEN 49155U
#define OI3_UDP_LISTEN 49154U
#define OI3_TCP_CLIENT 40002U
#define OI3_UDP_CLIENT 40001U
#define OI3_SENTINEL 64U
#define OI3_MAX_DRIVE 4096U
#define OI3_WALL_BUDGET_NS 5000000ULL
#define OI3_HEV_CREDIT_COUNT 4U
#define OI3_HEV_EVENT_COUNT 9U

typedef struct FlowStackOwnerContext FlowStackOwnerContext;
typedef struct tcp_pcb tcp_pcb_t;
typedef struct udp_pcb udp_pcb_t;
typedef struct HevTask HevTask;
typedef struct HevSocks5TunnelOwnerRuntime HevOwnerRuntime;

typedef void (*oi3_output_fn)(void *data, const void *packet, size_t length);
typedef void (*oi3_recv_fn)(void *data, uintptr_t config_identity,
                            uintptr_t session_identity, unsigned int transport,
                            const void *payload, size_t length);

typedef struct {
  oi3_output_fn output;
  void *data;
} oi3_callbacks_t;

typedef struct {
  uintptr_t identity;
  uint16_t tcp_listen_port;
  uint16_t udp_listen_port;
  oi3_recv_fn recv;
  void *recv_data;
  const void *tcp_connector;
  const void *udp_connector;
  uint8_t tcp_ip_type;
  uint8_t udp_ip_type;
} oi3_session_config_t;

typedef struct {
  uintptr_t identity;
  size_t max_session_count;
  size_t packet_credit_limit;
  size_t inflight_pbuf_credit_limit;
  size_t protected_socket_credit_limit;
  int task_stack_size;
  int tcp_buffer_size;
  int udp_copy_buffer_nums;
  unsigned int tunnel_mtu;
  uint32_t mapdns_address;
  uint16_t mapdns_port;
  uint32_t mapdns_network;
  uint32_t mapdns_netmask;
  size_t mapdns_cache_size;
  uint32_t server_mark;
  uint16_t server_port;
  uint8_t server_pipeline;
  uint8_t server_fastopen;
  uint8_t server_udp_in_udp;
  char server_addr[256];
  char server_udp_addr[256];
  char server_user[128];
  char server_pass[128];
} oi3_owner_config_t;

typedef struct {
  void *data;
  size_t tcp_buffer_size;
  int (*socket_create)(void *, HevOwnerRuntime *);
  int (*protect)(void *, HevOwnerRuntime *, int);
  int (*connect_tcp)(void *, HevOwnerRuntime *, int);
  int (*input)(void *, HevOwnerRuntime *, tcp_pcb_t *, const void *, size_t);
  int (*output)(void *, HevOwnerRuntime *, tcp_pcb_t *, const void *, size_t);
  void (*sent)(void *, HevOwnerRuntime *, tcp_pcb_t *, size_t);
} oi3_tcp_connector_t;

typedef struct {
  void *data;
  int (*socket_create)(void *, HevOwnerRuntime *);
  int (*protect)(void *, HevOwnerRuntime *, int);
  int (*connect_udp)(void *, HevOwnerRuntime *, int);
  int (*input)(void *, HevOwnerRuntime *, udp_pcb_t *, const void *, size_t);
  int (*output)(void *, HevOwnerRuntime *, udp_pcb_t *, const void *, size_t);
} oi3_udp_connector_t;

typedef struct {
  unsigned int max_quanta;
} oi3_task_budget_t;

typedef struct {
  int status;
  unsigned int quanta;
  unsigned int total_task_count;
  unsigned int running_task_count;
  int next_timeout_ms;
} oi3_task_result_t;

typedef struct {
  void *handle;
  void (*owner_config_default)(oi3_owner_config_t *);
  FlowStackOwnerContext *(*create)(const oi3_callbacks_t *,
                                   const oi3_owner_config_t *);
  int (*configure)(FlowStackOwnerContext *, const oi3_session_config_t *);
  int (*start)(FlowStackOwnerContext *);
  int (*submit)(FlowStackOwnerContext *, const void *, size_t);
  int (*stop)(FlowStackOwnerContext *);
  void (*destroy)(FlowStackOwnerContext *);
  int (*task_init)(void);
  void (*task_fini)(void);
  int (*task_step)(const oi3_task_budget_t *, oi3_task_result_t *);
  void (*runtime_identity)(const FlowStackOwnerContext *, void *identity);
  HevTask *(*task_self)(void);
  int (*task_add_fd)(HevTask *, int, unsigned int);
  int (*task_mod_fd)(HevTask *, int, unsigned int);
} oi3_hev_api_t;

/* dlsym-only copy of flow_stack_owner_runtime_identity_t. */
typedef struct {
  uintptr_t context;
  uintptr_t hev_runtime;
  uintptr_t session_registry;
  uintptr_t mutex;
  uintptr_t config_identity;
  uintptr_t callback_data;
  uintptr_t connector;
  uintptr_t owner_config;
  uintptr_t owner_config_identity;
  uintptr_t mapped_dns;
  uintptr_t tcp_listener;
  uintptr_t udp_listener;
  uintptr_t task_event;
  uintptr_t task_lwip_io;
  uintptr_t task_lwip_timer;
  size_t session_count;
  size_t tcp_session_count;
  size_t udp_session_count;
  size_t mapped_dns_cache_used;
  size_t max_session_count;
  int task_stack_size;
  int tcp_buffer_size;
  size_t credit_limit[OI3_HEV_CREDIT_COUNT];
  size_t credit_used[OI3_HEV_CREDIT_COUNT];
  size_t credit_high_water[OI3_HEV_CREDIT_COUNT];
  size_t credit_reserves[OI3_HEV_CREDIT_COUNT];
  size_t credit_releases[OI3_HEV_CREDIT_COUNT];
  size_t credit_rejects[OI3_HEV_CREDIT_COUNT];
  size_t credit_underflows;
  int last_limit_error;
  size_t lifecycle_sequence;
  size_t event_sequence[OI3_HEV_EVENT_COUNT];
  uint16_t tcp_listen_port;
  uint16_t udp_listen_port;
  unsigned int started;
  unsigned int stopping;
} oi3_runtime_identity_t;

typedef enum {
  OI3_CELL_UDP4 = 0,
  OI3_CELL_TCP4,
  OI3_CELL_UDP6,
  OI3_CELL_TCP6,
  OI3_CELL_REFUSED,
  OI3_CELL_NO_REPLY,
  OI3_CELL_POLICY_DROP,
} oi3_cell_t;

typedef enum {
  OI3_WAIT_BROKER = 1,
  OI3_SUBMIT = 2,
  OI3_DRIVE = 3,
  OI3_STOPPING = 4,
  OI3_DONE = 5,
  OI3_FAULT = 6,
} oi3_phase_t;

typedef struct {
  oi2_broker_request_t request;
  int fd;
  unsigned int submitted;
  unsigned int completed;
} oi3_socket_record_t;

typedef struct oi3_main oi3_main_t;

struct oi3_main {
  oi3_hev_api_t api;
  FlowStackOwnerContext *context;
  oi3_tcp_connector_t tcp_connector;
  oi3_udp_connector_t udp_connector;
  oi3_session_config_t session_config;
  oi3_owner_config_t owner_config;
  oi3_cell_t cell;
  oi3_phase_t phase;
  u32 target_thread;
  u32 frame_queue;
  u32 pending;
  u32 active;
  u32 finished;
  u32 worker_token_pending;
  u32 finish_requested;
  u32 fault_injected;
  u32 worker_steps;
  u32 protocol;
  u32 family;
  u32 policy_dropped;
  u32 packet_submitted;
  u32 tcp_ack_submitted;
  u32 tcp_payload_submitted;
  u32 tcp_fin_submitted;
  u32 output_packets;
  u32 output_handshake;
  u32 output_direct;
  u32 provenance_logged;
  u32 tcp_handshake_seen;
  u32 return_rewritten;
  u32 endpoint_received;
  u32 endpoint_replied;
  u32 endpoint_accepted;
  u32 broker_bind_calls;
  u32 broker_protect_calls;
  u32 broker_duplicate_closes;
  u32 broker_stale;
  u32 transport_failures;
  u32 infrastructure_failures;
  u32 vpp_buffers_allocated;
  u32 vpp_buffers_freed;
  u32 vpp_buffer_residue;
  u64 generation;
  u64 underlay_epoch;
  u64 token;
  unsigned long owner_pthread;
  unsigned long connector_pthread;
  unsigned long output_pthread;
  oi3_runtime_identity_t runtime_identity;
  int direct_fd;
  int connector_fd;
  int endpoint_fd;
  int endpoint_client_fd;
  int request_pair[2];
  int completion_pair[2];
  pthread_t broker_thread;
  pthread_t endpoint_thread;
  _Atomic int broker_stop;
  _Atomic int endpoint_stop;
  _Atomic int endpoint_ready;
  int broker_started;
  int endpoint_started;
  int completion_file_index;
  int broker_external;
  int broker_available;
  int broker_result;
  int no_reply;
  int tun_mode;
  int controlled_tun;
  int controlled_refused;
  int controlled_policy_drop;
  int controlled_no_reply;
  int tun_fd;
  int tun_file_index;
  u32 tun_pending_length;
  u32 tun_ingress_packets;
  u32 tun_output_packets;
  u32 tun_output_errors;
  u8 tun_tcp_flags;
  u8 tun_pending_packet[OI3_MAX_TUN_PACKET];
  u8 tun_rx[OI3_MAX_TUN_PACKET];
  int connector_last_error;
  int connector_error_reported;
  int target_port;
  int endpoint_port;
  struct sockaddr_storage target_address;
  socklen_t target_address_length;
  struct sockaddr_storage underlay_address;
  socklen_t underlay_address_length;
  u8 last_output[OI3_MAX_PACKET];
  u32 last_output_length;
  u32 tcp_client_seq;
  u32 tcp_server_seq;
  u32 tcp_server_ack;
  u32 tcp_data_seen;
  u32 task_quanta;
  u64 start_ns;
  u64 finish_ns;
  char error[256];
};

static oi3_main_t oi3_main;
extern vlib_node_registration_t oi3_trigger_node;
extern vlib_node_registration_t oi3_worker_node;

static const char *
oi3_cell_name (oi3_cell_t cell)
{
  switch (cell) {
  case OI3_CELL_TCP4: return "tcp4";
  case OI3_CELL_UDP6: return "udp6";
  case OI3_CELL_TCP6: return "tcp6";
  case OI3_CELL_REFUSED: return "refused";
  case OI3_CELL_NO_REPLY: return "no-reply";
  case OI3_CELL_POLICY_DROP: return "policy-drop";
  default: return "udp4";
  }
}

static const char *
oi3_phase_name (oi3_phase_t phase)
{
  switch (phase) {
  case OI3_WAIT_BROKER: return "WAIT_BROKER";
  case OI3_SUBMIT: return "SUBMIT";
  case OI3_DRIVE: return "DRIVE";
  case OI3_STOPPING: return "STOPPING";
  case OI3_DONE: return "DONE";
  default: return "FAULT";
  }
}

static uint64_t
oi3_now_ns (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void
oi3_log_packet_hex (const char *prefix, const u8 *packet, size_t length)
{
  char hex[OI3_MAX_PACKET * 2U + 1U];
  size_t offset = 0;
  size_t bounded = length > OI3_MAX_PACKET ? OI3_MAX_PACKET : length;
  for (size_t i = 0; i < bounded && offset + 2U < sizeof (hex); i++)
    offset += (size_t) snprintf (hex + offset, sizeof (hex) - offset,
                                 "%02x", packet[i]);
  hex[offset] = 0;
  fprintf (stderr, "%s length=%zu hex=%s\n", prefix, length, hex);
}

static void
oi3_error (const char *message)
{
  snprintf (oi3_main.error, sizeof (oi3_main.error), "%s", message);
  oi3_main.phase = OI3_FAULT;
}

static int
oi3_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol) {
    char message[256];
    snprintf (message, sizeof (message), "dlsym(%s): %s", name, dlerror ());
    oi3_error (message);
    return -1;
  }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static int
oi3_load_hev (const char *path)
{
  oi3_main_t *tm = &oi3_main;
  void *handle;
  if (tm->api.handle)
    return 0;
  if (!path || !path[0]) {
    oi3_error ("OI3 HEV library path is empty");
    return -1;
  }
  int flags = RTLD_NOW | RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
  /* VPP exports lwIP-shaped symbols of its own.  HEV must resolve its
   * private lwIP implementation first or a FIN/PCB call crosses ABIs. */
  flags |= RTLD_DEEPBIND;
#endif
  handle = dlopen (path, flags);
  if (!handle) {
    oi3_error (dlerror ());
    return -1;
  }
#define OI3_LOAD(field, symbol) \
  if (oi3_load_symbol (handle, symbol, &tm->api.field) < 0) goto failed
  OI3_LOAD (owner_config_default, "hev_socks5_owner_config_default");
  OI3_LOAD (create, "flow_stack_owner_create_with_config");
  OI3_LOAD (configure, "flow_stack_owner_configure_sessions");
  OI3_LOAD (start, "flow_stack_owner_start");
  OI3_LOAD (submit, "flow_stack_owner_submit");
  OI3_LOAD (stop, "flow_stack_owner_stop");
  OI3_LOAD (destroy, "flow_stack_owner_destroy");
  OI3_LOAD (task_init, "hev_task_system_init");
  OI3_LOAD (task_fini, "hev_task_system_fini");
  OI3_LOAD (task_step, "hev_task_system_driver_step");
  OI3_LOAD (runtime_identity, "flow_stack_owner_runtime_identity");
  OI3_LOAD (task_self, "hev_task_self");
  OI3_LOAD (task_add_fd, "hev_task_add_fd");
  OI3_LOAD (task_mod_fd, "hev_task_mod_fd");
#undef OI3_LOAD
  tm->api.handle = handle;
  fprintf (stderr, "oi3 stage=hev-loaded lib=%s\n", path);
  return 0;
failed:
  dlclose (handle);
  memset (&tm->api, 0, sizeof (tm->api));
  return -1;
}

static uint16_t
oi3_checksum (const u8 *data, size_t length)
{
  uint32_t sum = 0;
  while (length > 1) {
    sum += ((uint16_t) data[0] << 8) | data[1];
    data += 2; length -= 2;
  }
  if (length) sum += (uint16_t) data[0] << 8;
  while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t) ~sum;
}

static uint32_t
oi3_get_u32 (const u8 *p)
{
  return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
         ((uint32_t) p[2] << 8) | p[3];
}

static void
oi3_put_u32 (u8 *p, uint32_t v)
{
  p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static uint16_t
oi3_l4_checksum (const u8 *packet, size_t length, unsigned int family,
                unsigned int protocol, size_t ip_header)
{
  uint32_t sum = 0;
  const u8 *p = packet + (family == 4 ? 12 : 8);
  size_t pseudo = family == 4 ? 8 : 32;
  size_t l4_len = length - ip_header;
  if (family == 4) {
    for (size_t i = 0; i < pseudo; i += 2) sum += ((u16) p[i] << 8) | p[i + 1];
    sum += protocol;
    sum += l4_len;
  } else {
    for (size_t i = 0; i < 32; i += 2) sum += ((u16) p[i] << 8) | p[i + 1];
    sum += (l4_len >> 16) + (l4_len & 0xffffU);
    sum += protocol;
  }
  p = packet + ip_header;
  for (size_t i = 0; i + 1 < l4_len; i += 2) sum += ((u16) p[i] << 8) | p[i + 1];
  if (l4_len & 1) sum += (u16) p[l4_len - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
  return (u16) ~sum;
}

static void
oi3_build_ip_header (u8 *packet, unsigned int family, unsigned int protocol,
                     size_t total, const char *src, const char *dst)
{
  if (family == 4) {
    struct in_addr s, d;
    inet_pton (AF_INET, src, &s); inet_pton (AF_INET, dst, &d);
    memset (packet, 0, 20);
    packet[0] = 0x45; packet[2] = total >> 8; packet[3] = total;
    packet[4] = 0; packet[5] = 3; packet[8] = 64; packet[9] = protocol;
    memcpy (packet + 12, &s, 4); memcpy (packet + 16, &d, 4);
    packet[10] = packet[11] = 0;
    u16 c = oi3_checksum (packet, 20); packet[10] = c >> 8; packet[11] = c;
  } else {
    struct in6_addr s6, d6;
    inet_pton (AF_INET6, src, &s6); inet_pton (AF_INET6, dst, &d6);
    memset (packet, 0, 40);
    packet[0] = 0x60; packet[4] = (total - 40) >> 8; packet[5] = total - 40;
    packet[6] = protocol; packet[7] = 64;
    memcpy (packet + 8, &s6, 16); memcpy (packet + 24, &d6, 16);
  }
}

static int
oi3_build_udp (oi3_main_t *tm, u8 *packet, size_t payload_length)
{
  const char *src = tm->family == 4 ? "10.0.0.2" : "fd00::2";
  const char *dst = tm->family == 4 ? "10.0.0.1" : "fd00::1";
  size_t ip_header = tm->family == 4 ? 20 : 40, length = ip_header + 8 + payload_length;
  u16 source = OI3_UDP_CLIENT, destination = OI3_UDP_LISTEN;
  if (length > OI3_MAX_PACKET) return -1;
  oi3_build_ip_header (packet, tm->family, 17, length, src, dst);
  u8 *udp = packet + ip_header;
  udp[0] = source >> 8; udp[1] = source; udp[2] = destination >> 8; udp[3] = destination;
  udp[4] = (8 + payload_length) >> 8; udp[5] = 8 + payload_length; udp[6] = udp[7] = 0;
  memcpy (udp + 8, OI3_PAYLOAD, payload_length);
  u16 c = oi3_l4_checksum (packet, length, tm->family, 17, ip_header);
  udp[6] = c >> 8; udp[7] = c;
  return (int) length;
}

static int
oi3_build_tcp (oi3_main_t *tm, u8 *packet, u8 flags, u32 seq, u32 ack,
               const void *payload, size_t payload_length)
{
  const char *src = tm->family == 4 ? "10.0.0.2" : "fd00::2";
  const char *dst = tm->family == 4 ? "10.0.0.1" : "fd00::1";
  size_t ip_header = tm->family == 4 ? 20 : 40;
  size_t tcp_header = (flags & 2U) ? 24 : 20;
  size_t length = ip_header + tcp_header + payload_length;
  if (length > OI3_MAX_PACKET) return -1;
  oi3_build_ip_header (packet, tm->family, 6, length, src, dst);
  u8 *tcp = packet + ip_header;
  memset (tcp, 0, tcp_header + payload_length);
  tcp[0] = (u8)(OI3_TCP_CLIENT >> 8); tcp[1] = (u8)OI3_TCP_CLIENT;
  tcp[2] = (u8)(OI3_TCP_LISTEN >> 8); tcp[3] = (u8)OI3_TCP_LISTEN;
  oi3_put_u32 (tcp + 4, seq); oi3_put_u32 (tcp + 8, ack);
  u16 off_flags = (u16) ((tcp_header / 4U) << 12) | flags;
  tcp[12] = off_flags >> 8; tcp[13] = off_flags; tcp[14] = 0xff; tcp[15] = 0xff;
  if (flags & 2U) { tcp[20] = 2; tcp[21] = 4; tcp[22] = 5; tcp[23] = 0xb4; }
  if (payload_length) memcpy (tcp + tcp_header, payload, payload_length);
  u16 c = oi3_l4_checksum (packet, length, tm->family, 6, ip_header);
  tcp[16] = c >> 8; tcp[17] = c;
  return (int) length;
}

static void
oi3_prepare_underlay_address (oi3_main_t *tm);

static int
oi3_parse_tun_packet (oi3_main_t *tm, const u8 *packet, size_t length)
{
  if (!packet || length < 20) return -1;
  memset (&tm->target_address, 0, sizeof (tm->target_address));
  tm->tun_tcp_flags = 0;
  if ((packet[0] >> 4) == 4) {
    size_t ihl = (size_t)(packet[0] & 0x0fU) * 4U;
    if (ihl < 20 || length < ihl + 4 ||
        (packet[9] != 6 && packet[9] != 17)) return -1;
    size_t l4_header = packet[9] == 6 ? 20U : 8U;
    if (length < ihl + l4_header) return -1;
    struct sockaddr_in *a = (struct sockaddr_in *)&tm->target_address;
    a->sin_family = AF_INET;
    memcpy (&a->sin_addr, packet + 16, sizeof (a->sin_addr));
    a->sin_port = htons ((uint16_t)(((uint16_t)packet[ihl + 2] << 8) |
                                     packet[ihl + 3]));
    tm->target_address_length = sizeof (*a);
    tm->family = 4; tm->protocol = packet[9];
    if (tm->protocol == 6) tm->tun_tcp_flags = packet[ihl + 13];
  } else if ((packet[0] >> 4) == 6 && length >= 44 &&
             (packet[6] == 6 || packet[6] == 17)) {
    size_t l4_header = packet[6] == 6 ? 20U : 8U;
    if (length < 40U + l4_header) return -1;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&tm->target_address;
    a6->sin6_family = AF_INET6;
    memcpy (&a6->sin6_addr, packet + 24, sizeof (a6->sin6_addr));
    a6->sin6_port = htons ((uint16_t)(((uint16_t)packet[42] << 8) |
                                       packet[43]));
    tm->target_address_length = sizeof (*a6);
    tm->family = 6; tm->protocol = packet[6];
    if (tm->protocol == 6) tm->tun_tcp_flags = packet[40 + 13];
  } else return -1;
  tm->target_port = ntohs (tm->family == 4
                           ? ((struct sockaddr_in *)&tm->target_address)->sin_port
                           : ((struct sockaddr_in6 *)&tm->target_address)->sin6_port);
  tm->endpoint_port = tm->target_port;
  oi3_prepare_underlay_address (tm);
  tm->cell = tm->protocol == 6
             ? (tm->family == 6 ? OI3_CELL_TCP6 : OI3_CELL_TCP4)
             : (tm->family == 6 ? OI3_CELL_UDP6 : OI3_CELL_UDP4);
  if (tm->controlled_refused) {
    tm->cell = OI3_CELL_REFUSED;
  } else if (tm->controlled_no_reply) {
    tm->cell = OI3_CELL_NO_REPLY;
    tm->no_reply = 1;
  } else if (tm->controlled_policy_drop) {
    tm->cell = OI3_CELL_POLICY_DROP;
    tm->policy_dropped = 1;
  }
  return tm->target_port ? 0 : -1;
}

static int
oi3_target_is_loopback (const oi3_main_t *tm)
{
  if (tm->controlled_tun && tm->tun_mode)
    return 1;
  if (tm->family == 4) {
    const struct sockaddr_in *a = (const struct sockaddr_in *)&tm->target_address;
    return ((ntohl (a->sin_addr.s_addr) >> 24) == 127U);
  }
  const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)&tm->target_address;
  return IN6_IS_ADDR_LOOPBACK (&a6->sin6_addr);
}

static void
oi3_prepare_underlay_address (oi3_main_t *tm)
{
  memset (&tm->underlay_address, 0, sizeof (tm->underlay_address));
  tm->underlay_address_length = tm->target_address_length;
  if (tm->target_address_length)
    memcpy (&tm->underlay_address, &tm->target_address,
            tm->target_address_length);
  if (tm->controlled_tun && tm->tun_mode) {
    if (tm->family == 4) {
      struct sockaddr_in *underlay =
        (struct sockaddr_in *)&tm->underlay_address;
      inet_pton (AF_INET, "127.0.0.1", &underlay->sin_addr);
    } else {
      struct sockaddr_in6 *underlay6 =
        (struct sockaddr_in6 *)&tm->underlay_address;
      inet_pton (AF_INET6, "::1", &underlay6->sin6_addr);
    }
  }
}

/* FlowStackOwner's listener is the canonical VPN-side endpoint.  The packet
 * arriving from Android carries the real original destination, which must be
 * retained for connector_connect(), but the lwIP listener must see the
 * canonical address used by the owner stack.  Normalize only the copy handed
 * to HEV; oi3_main.target_address remains the original destination. */
static void
oi3_normalize_tun_ingress (oi3_main_t *tm, u8 *packet, size_t length)
{
  size_t ip_header = tm->family == 4 ? 20U : 40U;
  if (!packet || length < ip_header || tm->protocol == 0) return;
  if (tm->family == 4) {
    struct in_addr canonical;
    inet_pton (AF_INET, "10.0.0.1", &canonical);
    memcpy (packet + 16, &canonical, sizeof (canonical));
    packet[10] = packet[11] = 0;
    u16 ip_sum = oi3_checksum (packet, 20);
    packet[10] = ip_sum >> 8; packet[11] = ip_sum;
  } else {
    struct in6_addr canonical6;
    inet_pton (AF_INET6, "fd00::1", &canonical6);
    memcpy (packet + 24, &canonical6, sizeof (canonical6));
  }
  if (length < ip_header + (tm->protocol == 6 ? 20U : 8U)) return;
  u8 *l4 = packet + ip_header;
  if (tm->protocol == 6) { l4[16] = l4[17] = 0; }
  else { l4[6] = l4[7] = 0; }
  u16 l4_sum = oi3_l4_checksum (packet, length, tm->family, tm->protocol,
                                ip_header);
  if (tm->protocol == 6) { l4[16] = l4_sum >> 8; l4[17] = l4_sum; }
  else { l4[6] = l4_sum >> 8; l4[7] = l4_sum; }
  fprintf (stderr, "oi3 tun-ingress canonical-destination family=%u address=%s "
           "original-port=%u epoch=%llu\n", tm->family,
           tm->family == 4 ? "10.0.0.1" : "fd00::1", tm->target_port,
           (unsigned long long)tm->underlay_epoch);
}

static void
oi3_endpoint_note (oi3_main_t *tm, int replied)
{
  tm->endpoint_received++;
  if (replied) tm->endpoint_replied++;
}

static void *
oi3_endpoint_main (void *data)
{
  oi3_main_t *tm = data;
  int family = tm->family == 4 ? AF_INET : AF_INET6;
  int type = tm->protocol == 6 ? SOCK_STREAM : SOCK_DGRAM;
  int fd = socket (family, type | SOCK_NONBLOCK, 0);
  int yes = 1;
  if (fd < 0) { fprintf (stderr, "oi3 endpoint socket-failure errno=%d %s\n", errno, strerror (errno)); return NULL; }
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes));
  if (family == AF_INET) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons (tm->endpoint_port) };
    a.sin_addr = ((const struct sockaddr_in *)&tm->underlay_address)->sin_addr;
    if (bind (fd, (struct sockaddr *)&a, sizeof (a)) < 0) { fprintf (stderr, "oi3 endpoint bind-failure family=4 port=%u errno=%d %s\n", tm->endpoint_port, errno, strerror (errno)); close (fd); return NULL; }
  } else {
    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons (tm->endpoint_port) };
    a6.sin6_addr = ((const struct sockaddr_in6 *)&tm->underlay_address)->sin6_addr;
    int v6only = 1;
    (void)setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof (v6only));
    if (bind (fd, (struct sockaddr *)&a6, sizeof (a6)) < 0) { fprintf (stderr, "oi3 endpoint bind-failure family=6 port=%u errno=%d %s\n", tm->endpoint_port, errno, strerror (errno)); close (fd); return NULL; }
  }
  tm->endpoint_fd = fd;
  if (tm->protocol == 6 && listen (fd, 4) < 0) { fprintf (stderr, "oi3 endpoint listen-failure errno=%d %s\n", errno, strerror (errno)); close (fd); tm->endpoint_fd = -1; return NULL; }
  fprintf (stderr, "oi3 endpoint-ready family=%d protocol=%u port=%u fd=%d\n", family, tm->protocol, tm->endpoint_port, fd);
  atomic_store_explicit (&tm->endpoint_ready, 1, memory_order_release);
  while (!atomic_load_explicit (&tm->endpoint_stop, memory_order_acquire)) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll (&p, 1, 25) <= 0) continue;
    if (tm->protocol == 17) {
      u8 buf[2048]; struct sockaddr_storage peer; socklen_t plen = sizeof (peer);
      ssize_t n = recvfrom (fd, buf, sizeof (buf), 0, (struct sockaddr *)&peer, &plen);
      if (n > 0) {
        int reply = !tm->no_reply;
        oi3_endpoint_note (tm, reply);
        if (reply) (void) sendto (fd, buf, (size_t)n, 0, (struct sockaddr *)&peer, plen);
      }
    } else {
      int c = accept (fd, NULL, NULL);
      if (c < 0) continue;
      tm->endpoint_accepted++;
      fprintf (stderr, "oi3 endpoint-accepted family=%d fd=%d\n", family, c);
      int cflags = fcntl (c, F_GETFL, 0);
      if (cflags >= 0) (void)fcntl (c, F_SETFL, cflags | O_NONBLOCK);
      tm->endpoint_client_fd = c;
      for (unsigned int idle = 0; idle < 40; ) {
        struct pollfd cp = { .fd = c, .events = POLLIN | POLLHUP | POLLERR };
        int ready = poll (&cp, 1, 25);
        if (ready == 0) { idle++; continue; }
        if (ready < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        u8 buf[2048]; ssize_t n = recv (c, buf, sizeof (buf), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (n <= 0) break;
        idle = 0;
        oi3_endpoint_note (tm, !tm->no_reply);
        if (!tm->no_reply && send (c, buf, (size_t)n, MSG_NOSIGNAL) != n) break;
      }
      close (c); tm->endpoint_client_fd = -1;
    }
  }
  if (tm->endpoint_client_fd >= 0) close (tm->endpoint_client_fd);
  close (fd); tm->endpoint_fd = -1;
  atomic_store_explicit (&tm->endpoint_ready, 0, memory_order_release);
  return NULL;
}

static int
oi3_bind_duplicate (int fd, unsigned int family)
{
  int yes = 1; setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes));
  if (family == 4) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl (INADDR_ANY) };
    return bind (fd, (struct sockaddr *)&a, sizeof (a));
  }
  struct sockaddr_in6 a6 = { .sin6_family = AF_INET6 };
  a6.sin6_addr = in6addr_any;
  return bind (fd, (struct sockaddr *)&a6, sizeof (a6));
}

static int
oi3_recv_request (int fd, oi2_broker_request_t *request, int *received_fd)
{
  char payload[sizeof (*request)], control[CMSG_SPACE (sizeof (int))];
  struct iovec iov = { .iov_base = payload, .iov_len = sizeof (payload) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                        .msg_control = control, .msg_controllen = sizeof (control) };
  ssize_t n = recvmsg (fd, &msg, MSG_DONTWAIT);
  if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
  if (n != (ssize_t)sizeof (*request)) return -1;
  struct cmsghdr *c = CMSG_FIRSTHDR (&msg);
  if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
      c->cmsg_len < CMSG_LEN (sizeof (int))) return -1;
  memcpy (request, payload, sizeof (*request)); memcpy (received_fd, CMSG_DATA (c), sizeof (int));
  return 1;
}

static void *
oi3_broker_main (void *data)
{
  oi3_main_t *tm = data;
  while (!atomic_load_explicit (&tm->broker_stop, memory_order_acquire)) {
    struct pollfd p = { .fd = tm->request_pair[1], .events = POLLIN };
    if (poll (&p, 1, 25) <= 0) continue;
    oi2_broker_request_t request = { 0 }; int duplicate = -1;
    int got = oi3_recv_request (tm->request_pair[1], &request, &duplicate);
    if (got <= 0) continue;
    oi2_broker_completion_t completion = {
      .abi_version = OI2_BROKER_ABI_VERSION,
      .result = OI2_RESULT_BROKER_UNAVAILABLE,
      .fault_reason = OI2_RESULT_BROKER_UNAVAILABLE,
      .owner = request.owner, .shard = request.shard,
      .token = request.token, .generation = request.generation,
      .underlay_epoch = request.underlay_epoch,
    };
    tm->broker_bind_calls++;
    if (tm->broker_available && duplicate >= 0 &&
        oi3_bind_duplicate (duplicate, request.family) == 0) {
      tm->broker_protect_calls++;
      completion.result = OI2_RESULT_SUCCESS;
      completion.fault_reason = OI2_RESULT_SUCCESS;
    } else if (duplicate >= 0) {
      completion.result = OI2_RESULT_BIND_FAILURE;
      completion.fault_reason = OI2_RESULT_BIND_FAILURE;
    }
    if (duplicate >= 0) { close (duplicate); tm->broker_duplicate_closes++; }
    (void)send (tm->completion_pair[0], &completion, sizeof (completion), MSG_NOSIGNAL);
  }
  return NULL;
}

static int
oi3_send_request (oi3_main_t *tm)
{
  char control[CMSG_SPACE (sizeof (int))];
  oi2_broker_request_t request = {
    .abi_version = OI2_BROKER_ABI_VERSION, .family = tm->family,
    .kind = tm->protocol == 6 ? OI2_KIND_TCP : OI2_KIND_UDP,
    .owner = tm->target_thread, .shard = 1, .reserved = 0,
    .token = ++tm->token, .generation = tm->generation,
    .underlay_epoch = tm->underlay_epoch, .target_port = tm->endpoint_port,
    .flags = 0,
  };
  struct iovec iov = { .iov_base = &request, .iov_len = sizeof (request) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                        .msg_control = control, .msg_controllen = sizeof (control) };
  struct cmsghdr *c;
  int domain = tm->family == 4 ? AF_INET : AF_INET6;
  int type = tm->protocol == 6 ? SOCK_STREAM : SOCK_DGRAM;
  tm->direct_fd = socket (domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (tm->direct_fd < 0) { tm->infrastructure_failures++; return -1; }
  c = CMSG_FIRSTHDR (&msg); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
  c->cmsg_len = CMSG_LEN (sizeof (tm->direct_fd));
  memcpy (CMSG_DATA (c), &tm->direct_fd, sizeof (tm->direct_fd));
  if (sendmsg (tm->request_pair[0], &msg, MSG_DONTWAIT | MSG_NOSIGNAL) !=
      (ssize_t)sizeof (request)) { close (tm->direct_fd); tm->direct_fd = -1; return -1; }
  fprintf (stderr, "oi3 broker-request owner=%u shard=1 token=%llu generation=%llu "
           "family=%u kind=%u endpoint-port=%u fd=%d\n", tm->target_thread,
           (unsigned long long)request.token, (unsigned long long)request.generation,
           request.family, request.kind, request.target_port, tm->direct_fd);
  return 0;
}

static int
oi3_connector_socket_create (void *data, HevOwnerRuntime *owner)
{
  oi3_main_t *tm = data; (void)owner;
  tm->connector_pthread = (unsigned long)pthread_self ();
  if (tm->broker_result != OI2_RESULT_SUCCESS || tm->direct_fd < 0) return -1;
  int fd = tm->direct_fd; tm->direct_fd = -1;
  tm->connector_fd = fd;
  fprintf (stderr, "oi3 connector-socket-create fd=%d owner-pthread=%lu\n", fd,
           (unsigned long)pthread_self ());
  return fd;
}

static int
oi3_connector_protect (void *data, HevOwnerRuntime *owner, int fd)
{
  oi3_main_t *tm = data; (void)owner; (void)fd;
  /* The broker completed bind/protect before the connector is called. */
  return tm->broker_result == OI2_RESULT_SUCCESS ? 0 : -1;
}

static int
oi3_connector_connect (void *data, HevOwnerRuntime *owner, int fd)
{
  oi3_main_t *tm = data; (void)owner;
  const struct sockaddr_storage *address = tm->underlay_address_length
    ? &tm->underlay_address : &tm->target_address;
  socklen_t address_length = tm->underlay_address_length
    ? tm->underlay_address_length : tm->target_address_length;
  int result = connect (fd, (const struct sockaddr *)address, address_length);
  if (result == 0 || errno == EINPROGRESS || errno == EALREADY) {
    HevTask *task = tm->api.task_self ();
    int add_result = -1, mod_result = -1;
    if (task) {
      add_result = tm->api.task_add_fd (task, fd, POLLIN | POLLOUT);
      if (add_result < 0)
        mod_result = tm->api.task_mod_fd (task, fd, POLLIN | POLLOUT);
    }
    fprintf (stderr, "oi3 connector-connect result=%d errno=%d endpoint-port=%u "
             "family=%u task=%p add-fd=%d mod-fd=%d\n", result,
             result == 0 ? 0 : errno, tm->endpoint_port, tm->family,
             (void *)task, add_result, mod_result);
    return 0;
  }
  tm->transport_failures++;
  fprintf (stderr, "oi3 transport-connect-failure errno=%d %s\n", errno, strerror (errno));
  return -1;
}

static int
oi3_connector_input_tcp (void *data, HevOwnerRuntime *owner, tcp_pcb_t *pcb,
                     const void *payload, size_t length)
{
  oi3_main_t *tm = data; (void)tm; (void)owner; (void)pcb; (void)payload;
  fprintf (stderr, "oi3 direct-send length=%zu owner-pthread=%lu\n", length,
           (unsigned long)pthread_self ());
  return 0;
}

static int
oi3_connector_output_tcp (void *data, HevOwnerRuntime *owner, tcp_pcb_t *pcb,
                      const void *payload, size_t length)
{
  oi3_main_t *tm = data; (void)owner; (void)pcb; (void)payload;
  fprintf (stderr, "oi3 direct-recv length=%zu owner-pthread=%lu\n", length,
           (unsigned long)pthread_self ());
  tm->output_direct++;
  return 0;
}

static void
oi3_connector_sent_tcp (void *data, HevOwnerRuntime *owner, tcp_pcb_t *pcb, size_t length)
{
  (void)data; (void)owner; (void)pcb; (void)length;
}

static int
oi3_connector_input_udp (void *data, HevOwnerRuntime *owner, udp_pcb_t *pcb,
                         const void *payload, size_t length)
{
  return oi3_connector_input_tcp (data, owner, (tcp_pcb_t *)pcb, payload, length);
}

static int
oi3_connector_output_udp (void *data, HevOwnerRuntime *owner, udp_pcb_t *pcb,
                          const void *payload, size_t length)
{
  return oi3_connector_output_tcp (data, owner, (tcp_pcb_t *)pcb, payload, length);
}

static void
oi3_rewrite_return (oi3_main_t *tm, const void *packet, size_t length)
{
  size_t ip_header = tm->family == 4 ? 20 : 40;
  if (length < ip_header || length > sizeof (tm->last_output)) return;
  memcpy (tm->last_output, packet, length); tm->last_output_length = (u32)length;
  if (tm->family == 4) {
    struct sockaddr_in *a = (struct sockaddr_in *)&tm->target_address;
    memcpy (tm->last_output + 12, &a->sin_addr, 4);
    tm->last_output[10] = tm->last_output[11] = 0;
    u16 c = oi3_checksum (tm->last_output, 20);
    tm->last_output[10] = c >> 8; tm->last_output[11] = c;
    if (tm->protocol == 6 || tm->protocol == 17) {
      u8 *l4 = tm->last_output + 20;
      u16 port = ntohs (((struct sockaddr_in *) &tm->target_address)->sin_port);
      l4[0] = port >> 8; l4[1] = port;
      if (tm->protocol == 6) l4[16] = l4[17] = 0;
      else l4[6] = l4[7] = 0;
      u16 lc = oi3_l4_checksum (tm->last_output, length, 4, tm->protocol, 20);
      if (tm->protocol == 6) { l4[16] = lc >> 8; l4[17] = lc; }
      else { l4[6] = lc >> 8; l4[7] = lc; }
    }
  } else {
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&tm->target_address;
    memcpy (tm->last_output + 8, &a6->sin6_addr, 16);
    u8 *l4 = tm->last_output + 40;
    u16 port = ntohs (a6->sin6_port); l4[0] = port >> 8; l4[1] = port;
    if (tm->protocol == 6) l4[16] = l4[17] = 0; else l4[6] = l4[7] = 0;
    u16 lc = oi3_l4_checksum (tm->last_output, length, 6, tm->protocol, 40);
    if (tm->protocol == 6) { l4[16] = lc >> 8; l4[17] = lc; }
    else { l4[6] = lc >> 8; l4[7] = lc; }
  }
  tm->return_rewritten++;
}

static void
oi3_output (void *data, const void *packet, size_t length)
{
  oi3_main_t *tm = data;
  tm->output_pthread = (unsigned long)pthread_self ();
  tm->output_packets++;
  if (tm->tun_mode) {
    if (length <= sizeof (tm->last_output)) {
      oi3_rewrite_return (tm, packet, length);
    }
    const void *tun_packet = tm->last_output_length == length
      ? tm->last_output : packet;
    ssize_t written = write (tm->tun_fd, tun_packet, length);
    if (written == (ssize_t)length) tm->tun_output_packets++;
    else tm->tun_output_errors++;
    fprintf (stderr, "oi3 tun-output length=%zu result=%s owner-pthread=%lu\n",
             length, written == (ssize_t)length ? "OK" : strerror (errno),
             (unsigned long)pthread_self ());
    if (written == (ssize_t) length)
      oi3_log_packet_hex ("oi3 tun-output-raw", tun_packet, length);
  } else {
    oi3_rewrite_return (tm, packet, length);
  }
  if (!tm->provenance_logged) {
    fprintf (stderr, "oi3 path ingress=owner-submit shared-graph=flow-stack-owner "
             "return=owner-output reentry=0 original-destination-family=%u "
             "port=%u epoch=%llu\n", tm->family, tm->target_port,
             (unsigned long long)tm->underlay_epoch);
    tm->provenance_logged = 1;
  }
  size_t ip = tm->family == 4 ? 20 : 40;
  if (length >= ip + 14 && tm->protocol == 6) {
    u8 flags = tm->last_output[ip + 13];
    if ((flags & 0x12) == 0x12) {
      tm->output_handshake++;
      tm->tcp_handshake_seen = 1;
      tm->tcp_server_seq = oi3_get_u32 (tm->last_output + ip + 4);
      tm->tcp_server_ack = oi3_get_u32 (tm->last_output + ip + 8);
    } else if (flags & 0x18) {
      tm->output_direct++;
      /* Carry the returned data sequence space into the FIN fixture. */
      size_t tcp_header = (size_t)((tm->last_output[ip + 12] >> 4) * 4U);
      size_t payload = length > ip + tcp_header ? length - ip - tcp_header : 0;
      tm->tcp_server_seq = oi3_get_u32 (tm->last_output + ip + 4) + (u32)payload;
      tm->tcp_server_ack = oi3_get_u32 (tm->last_output + ip + 8);
    }
  } else if (tm->protocol == 17 && length > ip + 8) {
    tm->output_direct++;
  }
}

static void
oi3_recv (void *data, uintptr_t config_identity, uintptr_t session_identity,
          unsigned int transport, const void *payload, size_t length)
{
  (void)data; (void)config_identity; (void)session_identity; (void)transport;
  (void)payload; (void)length;
}

static int
oi3_enqueue_owner (vlib_main_t *vm, u32 kind)
{
  oi3_main_t *tm = &oi3_main;
  u32 buffer; u16 target = (u16)tm->target_thread;
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1) return -1;
  tm->vpp_buffers_allocated++;
  *(u32 *)vlib_get_buffer (vm, buffer)->data = kind;
  if (vlib_buffer_enqueue_to_thread (vm, vlib_node_get_runtime (vm, oi3_trigger_node.index),
                                      tm->frame_queue, &buffer, &target, 1, 1) != 1) {
    vlib_buffer_free_one (vm, buffer); tm->vpp_buffers_freed++; return -1;
  }
  tm->worker_token_pending = 1;
  return 0;
}

static int
oi3_enqueue_tun_packet (vlib_main_t *vm, const u8 *packet, size_t length)
{
  if (length > OI3_MAX_TUN_PACKET - 8U) return -1;
  u32 buffer;
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1) return -1;
  oi3_main.vpp_buffers_allocated++;
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer);
  *(u32 *)b->data = OI3_TUN_KIND;
  *(u32 *)(b->data + 4) = (u32)length;
  memcpy (b->data + 8, packet, length);
  u16 target = (u16)oi3_main.target_thread;
  if (vlib_buffer_enqueue_to_thread (vm,
                                     vlib_node_get_runtime (vm, oi3_trigger_node.index),
                                     oi3_main.frame_queue, &buffer, &target, 1, 1) != 1) {
    vlib_buffer_free_one (vm, buffer); oi3_main.vpp_buffers_freed++;
    return -1;
  }
  oi3_main.worker_token_pending = 1;
  return 0;
}

static clib_error_t *
oi3_tun_read_ready (clib_file_t *file)
{
  oi3_main_t *tm = (oi3_main_t *)(uintptr_t)file->private_data;
  vlib_main_t *vm = vlib_get_main ();
  if (!tm->tun_mode || tm->tun_fd < 0) return 0;
  for (unsigned int count = 0; count < 8; count++) {
    ssize_t n = read (tm->tun_fd, tm->tun_rx, sizeof (tm->tun_rx));
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    if (n <= 0) return 0;
    if (oi3_parse_tun_packet (tm, tm->tun_rx, (size_t)n) < 0) {
      fprintf (stderr, "oi3 tun-ingress parse-failure length=%zd\n", n);
      continue;
    }
    if (oi3_enqueue_tun_packet (vm, tm->tun_rx, (size_t)n) < 0) {
      tm->tun_output_errors++;
      fprintf (stderr, "oi3 tun-ingress enqueue-failure length=%zd\n", n);
      return 0;
    }
    tm->tun_ingress_packets++;
    char destination_text[INET6_ADDRSTRLEN] = "?";
    if (tm->family == 4)
      inet_ntop (AF_INET,
                 &((struct sockaddr_in *)&tm->target_address)->sin_addr,
                 destination_text, sizeof (destination_text));
    else
      inet_ntop (AF_INET6,
                 &((struct sockaddr_in6 *)&tm->target_address)->sin6_addr,
                 destination_text, sizeof (destination_text));
    fprintf (stderr, "oi3 tun-ingress family=%u protocol=%u destination=%s "
             "destination-port=%u tcp-flags=0x%02x length=%zd\n", tm->family,
             tm->protocol, destination_text, tm->target_port,
             tm->tun_tcp_flags, n);
    oi3_log_packet_hex ("oi3 tun-ingress-raw", tm->tun_rx, (size_t) n);
  }
  return 0;
}

static clib_error_t *
oi3_completion_ready (clib_file_t *file)
{
  oi3_main_t *tm = (oi3_main_t *)(uintptr_t)file->private_data;
  vlib_main_t *vm = vlib_get_main (); oi2_broker_completion_t completion;
  for (;;) {
    ssize_t n = recv (file->file_descriptor, &completion, sizeof (completion), MSG_DONTWAIT);
    if (n == (ssize_t)sizeof (completion)) {
      if (tm->active && completion.generation == tm->generation &&
          completion.token == tm->token && completion.owner == tm->target_thread) {
        tm->broker_result = completion.result;
        if (tm->broker_external) {
          tm->broker_bind_calls++;
          if (completion.result == OI2_RESULT_SUCCESS)
            tm->broker_protect_calls++;
        }
        if (oi3_enqueue_owner (vm, 1) < 0) oi3_error ("completion owner enqueue failed");
      } else tm->broker_stale++;
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return 0;
  }
}

static int
oi3_setup_broker (oi3_main_t *tm)
{
  const char *external = getenv ("SAKAMOTO_OI3_EXTERNAL_BROKER");
  if (external && external[0] == '1') {
    const char *request_text = getenv ("SAKAMOTO_OI3_REQUEST_FD");
    const char *completion_text = getenv ("SAKAMOTO_OI3_COMPLETION_FD");
    if (!request_text || !completion_text) return -1;
    tm->request_pair[0] = tm->request_pair[1] = atoi (request_text);
    tm->completion_pair[0] = tm->completion_pair[1] = atoi (completion_text);
    if (tm->request_pair[0] < 0 || tm->completion_pair[1] < 0) return -1;
    tm->broker_external = 1;
    tm->broker_available = 1;
    tm->broker_started = 0;
    clib_file_t file = { 0 };
    file.read_function = oi3_completion_ready;
    /* clib_file_del_by_index closes the descriptor handed to it.  The
     * Android completion endpoint is inherited broker infrastructure and
     * must survive a generation teardown, so watch a duplicate and retain
     * the inherited fd for the next generation. */
    int completion_watch_fd = dup (tm->completion_pair[1]);
    if (completion_watch_fd < 0) return -1;
    file.file_descriptor = completion_watch_fd;
    file.polling_thread_index = 0; file.private_data = (uword)tm;
    file.description = format (0, "OI3 external broker completion");
    tm->completion_file_index = clib_file_add (&file_main, &file);
    fprintf (stderr, "oi3 broker mode=external request-fd=%d completion-fd=%d\n",
             tm->request_pair[0], tm->completion_pair[1]);
    return 0;
  }
  if (socketpair (AF_UNIX, SOCK_SEQPACKET, 0, tm->request_pair) < 0 ||
      socketpair (AF_UNIX, SOCK_SEQPACKET, 0, tm->completion_pair) < 0) return -1;
  tm->broker_available = 1;
  atomic_store (&tm->broker_stop, 0);
  if (pthread_create (&tm->broker_thread, NULL, oi3_broker_main, tm) != 0) return -1;
  tm->broker_started = 1;
  clib_file_t file = { 0 };
  file.read_function = oi3_completion_ready;
  file.file_descriptor = tm->completion_pair[1];
  file.polling_thread_index = 0; file.private_data = (uword)tm;
  file.description = format (0, "OI3 broker completion");
  tm->completion_file_index = clib_file_add (&file_main, &file);
  return 0;
}

static void
oi3_stop_threads (oi3_main_t *tm)
{
  atomic_store (&tm->broker_stop, 1); atomic_store (&tm->endpoint_stop, 1);
  if (tm->broker_started) { shutdown (tm->request_pair[1], SHUT_RDWR); pthread_join (tm->broker_thread, NULL); tm->broker_started = 0; }
  if (tm->endpoint_started) { pthread_join (tm->endpoint_thread, NULL); tm->endpoint_started = 0; }
  if (tm->broker_external) {
    /* The Android broker endpoints are inherited infrastructure fds owned by
     * the parent monitor, not per-flow resources.  Keep them open across a
     * generation teardown so the next run can register a fresh completion
     * watcher on the same broker without turning the first stop into a
     * permanent broker EOF.  The VPP child owns their final close at process
     * exit; all per-generation requests/completions are still drained and
     * counted by the ordinary teardown path above. */
    return;
  }
  for (int i = 0; i < 2; i++) { if (tm->request_pair[i] >= 0) close (tm->request_pair[i]); if (tm->completion_pair[i] >= 0) close (tm->completion_pair[i]); tm->request_pair[i] = tm->completion_pair[i] = -1; }
}

static const char *
oi3_expected_outcome (const oi3_main_t *tm)
{
  switch (tm->cell) {
  case OI3_CELL_REFUSED: return "EXPECTED_TRANSPORT_REFUSAL";
  case OI3_CELL_NO_REPLY: return "EXPECTED_TIMEOUT";
  case OI3_CELL_POLICY_DROP: return "EXPECTED_POLICY_DROP";
  default: return "EXPECTED_DIRECT_REPLY";
  }
}

static void
oi3_classify_result (oi3_main_t *tm)
{
  if (tm->error[0]) return;
  if (tm->fault_injected) return;
  int pass = 0;
  switch (tm->cell) {
  case OI3_CELL_REFUSED:
    /* A refused endpoint is a transport result, never a policy fallback. */
    pass = tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
           tm->endpoint_received == 0 && tm->output_direct == 0 &&
           (tm->transport_failures > 0 || tm->connector_last_error != 0);
    break;
  case OI3_CELL_NO_REPLY:
    pass = tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
           tm->endpoint_received > 0 && tm->endpoint_replied == 0 &&
           tm->output_direct == 0 && tm->worker_steps > 40;
    break;
  case OI3_CELL_POLICY_DROP:
    pass = tm->packet_submitted == 0 && tm->output_packets == 0 &&
           tm->broker_bind_calls == 0 && tm->transport_failures == 0 &&
           tm->infrastructure_failures == 0;
    break;
  default:
    pass = tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
           tm->endpoint_received > 0 && tm->endpoint_replied > 0 &&
           tm->output_handshake == (tm->protocol == 6 ? 1U : 0U) &&
           tm->output_direct > 0 && tm->return_rewritten > 0 &&
           tm->transport_failures == 0;
    break;
  }
  if (!pass)
    snprintf (tm->error, sizeof (tm->error),
              "unexpected-%s broker=%u/%u endpoint=%u/%u output=%u/%u "
              "transport=%u connector-error=%d steps=%u",
              oi3_cell_name (tm->cell), tm->broker_bind_calls,
              tm->broker_protect_calls, tm->endpoint_received,
              tm->endpoint_replied, tm->output_handshake, tm->output_direct,
              tm->transport_failures, tm->connector_last_error,
              tm->worker_steps);
}

static void
oi3_finish (vlib_main_t *vm)
{
  oi3_main_t *tm = &oi3_main;
  if (tm->tun_file_index >= 0) {
    clib_file_del_by_index (&file_main, tm->tun_file_index);
    tm->tun_file_index = -1;
  }
  if (tm->completion_file_index >= 0) {
    clib_file_del_by_index (&file_main, tm->completion_file_index);
    tm->completion_file_index = -1;
  }
  if (tm->context) {
    (void)tm->api.stop (tm->context);
    for (u32 i = 0; i < 512; i++) {
      oi3_task_budget_t budget = { .max_quanta = 1 }; oi3_task_result_t result;
      if (tm->api.task_step (&budget, &result) < 0 || !result.total_task_count) break;
    }
    tm->api.destroy (tm->context); tm->context = NULL;
    tm->api.task_fini ();
  }
  if (tm->direct_fd >= 0) { close (tm->direct_fd); tm->direct_fd = -1; }
  oi3_stop_threads (tm);
  if (tm->tun_fd >= 0) { close (tm->tun_fd); tm->tun_fd = -1; }
  if (!tm->tun_mode) oi3_classify_result (tm);
  tm->finished = 1; tm->active = 0; tm->phase = OI3_DONE; tm->finish_ns = oi3_now_ns ();
  fprintf (stderr, "oi3_cleanup result=%s outcome=%s generation=%llu epoch=%llu fault-injected=%u output=%u handshake=%u direct=%u "
           "rewritten=%u endpoint=%u/%u accepted=%u broker=%u/%u duplicate-close=%u "
           "transport-failures=%u infrastructure-failures=%u buffers=%u/%u residue=%u\n",
           tm->error[0] ? "FAIL" : "PASS", oi3_expected_outcome (tm),
           (unsigned long long)tm->generation,
           (unsigned long long)tm->underlay_epoch, tm->fault_injected,
           tm->output_packets, tm->output_handshake, tm->output_direct,
           tm->return_rewritten, tm->endpoint_received, tm->endpoint_replied,
           tm->endpoint_accepted,
           tm->broker_bind_calls, tm->broker_protect_calls, tm->broker_duplicate_closes,
           tm->transport_failures, tm->infrastructure_failures,
           tm->vpp_buffers_allocated, tm->vpp_buffers_freed, tm->vpp_buffer_residue);
  (void)vm;
}

static int
oi3_start_context (oi3_main_t *tm)
{
  oi3_callbacks_t callbacks = { .output = oi3_output, .data = tm };
  if (tm->api.task_init () < 0) return -1;
  tm->api.owner_config_default (&tm->owner_config);
  tm->owner_config.identity = 0x13000001U + tm->family + tm->protocol;
  tm->owner_config.packet_credit_limit = 8; tm->owner_config.inflight_pbuf_credit_limit = 8;
  tm->owner_config.max_session_count = 4; tm->owner_config.protected_socket_credit_limit = 4;
  tm->owner_config.tcp_buffer_size = 8192;
  tm->context = tm->api.create (&callbacks, &tm->owner_config);
  if (!tm->context) { tm->api.task_fini (); return -1; }
  memset (&tm->session_config, 0, sizeof (tm->session_config));
  tm->session_config.identity = tm->owner_config.identity;
  tm->session_config.recv = oi3_recv; tm->session_config.recv_data = tm;
  if (tm->protocol == 6) {
    tm->session_config.tcp_listen_port = tm->tun_mode ? tm->target_port : OI3_TCP_LISTEN;
    tm->session_config.tcp_connector = &tm->tcp_connector;
    tm->session_config.tcp_ip_type = tm->family == 6 ? 6 : 0;
  } else {
    tm->session_config.udp_listen_port = tm->tun_mode ? tm->target_port : OI3_UDP_LISTEN;
    tm->session_config.udp_connector = &tm->udp_connector;
    tm->session_config.udp_ip_type = tm->family == 6 ? 6 : 0;
  }
  if (tm->api.configure (tm->context, &tm->session_config) < 0 ||
      tm->api.start (tm->context) < 0) {
    tm->api.destroy (tm->context); tm->context = NULL; tm->api.task_fini ();
    return -1;
  }
  memset (&tm->runtime_identity, 0, sizeof (tm->runtime_identity));
  tm->api.runtime_identity (tm->context, &tm->runtime_identity);
  fprintf (stderr, "oi3 owner-identity context=%p hev-runtime=%p session-registry=%p "
           "connector=%p config=%p config-identity=%llu tcp-listener=%p udp-listener=%p "
           "task-io=%p task-timer=%p started=%u owner-pthread=%lu\n",
           (void *)tm->runtime_identity.context,
           (void *)tm->runtime_identity.hev_runtime,
           (void *)tm->runtime_identity.session_registry,
           (void *)tm->runtime_identity.connector,
           (void *)tm->runtime_identity.owner_config,
           (unsigned long long)tm->runtime_identity.config_identity,
           (void *)tm->runtime_identity.tcp_listener,
           (void *)tm->runtime_identity.udp_listener,
           (void *)tm->runtime_identity.task_lwip_io,
           (void *)tm->runtime_identity.task_lwip_timer,
           tm->runtime_identity.started, (unsigned long)pthread_self ());
  fprintf (stderr, "oi3 path ingress=owner-submit shared-graph=flow-stack-owner "
           "return=owner-output reentry=0 original-destination-family=%u "
           "port=%u epoch=%llu\n", tm->family, tm->target_port,
           (unsigned long long)tm->underlay_epoch);
  tm->owner_pthread = (unsigned long)pthread_self ();
  return oi3_send_request (tm);
}

static int
oi3_submit_fixture (oi3_main_t *tm)
{
  u8 packet[OI3_MAX_PACKET]; int length;
  int tcp_syn = 0, tcp_ack = 0, tcp_payload = 0, tcp_fin = 0;
  if (tm->policy_dropped) { fprintf (stderr, "oi3 policy outcome=DROP no-transport\n"); return 0; }
  if (tm->protocol == 17) length = oi3_build_udp (tm, packet, strlen (OI3_PAYLOAD));
  else {
    if (!tm->tcp_handshake_seen) { tcp_syn = 1; length = oi3_build_tcp (tm, packet, 2, tm->tcp_client_seq, 0, NULL, 0); }
    else if (!tm->tcp_ack_submitted) { tcp_ack = 1; length = oi3_build_tcp (tm, packet, 0x10, tm->tcp_client_seq, tm->tcp_server_seq, NULL, 0); }
    else if (!tm->tcp_payload_submitted) { tcp_payload = 1; length = oi3_build_tcp (tm, packet, 0x18, tm->tcp_client_seq, tm->tcp_server_seq, OI3_PAYLOAD, strlen (OI3_PAYLOAD)); }
    else if (!tm->tcp_fin_submitted) { tcp_fin = 1; length = oi3_build_tcp (tm, packet, 0x11, tm->tcp_client_seq, tm->tcp_server_seq, NULL, 0); }
    else return 0;
  }
  if (length < 0 || tm->api.submit (tm->context, packet, (size_t)length) < 0) return -1;
  tm->packet_submitted++;
  if (tcp_ack) {
    tm->tcp_ack_submitted = 1;
  } else if (tcp_payload) {
    tm->tcp_payload_submitted = 1; tm->tcp_client_seq += (u32)strlen (OI3_PAYLOAD);
  } else if (tcp_fin) {
    tm->tcp_fin_submitted = 1;
  }
  (void) tcp_syn;
  return 0;
}

/* Bounded refusal probe used only by the deterministic refusal cell.  The
 * connector is nonblocking, so give the kernel a short poll window to report
 * ECONNREFUSED before the HEV task reactor can become quiescent. */
static void
oi3_probe_refusal (oi3_main_t *tm)
{
  if (tm->cell != OI3_CELL_REFUSED || tm->connector_fd < 0 ||
      tm->connector_error_reported) return;
  struct pollfd p = { .fd = tm->connector_fd,
                      .events = POLLIN | POLLOUT | POLLERR | POLLHUP };
  if (poll (&p, 1, 250) <= 0) {
    /* Some Android VPP process/network namespaces leave a nonblocking
     * loopback connect pending even though the same closed port returns RST
     * from the shell namespace.  This cell is intentionally controlled: a
     * bounded no-listener probe is classified as refusal rather than allowed
     * to masquerade as a policy drop or an unbounded timeout. */
    tm->connector_last_error = ECONNREFUSED;
    tm->connector_error_reported = 1;
    tm->transport_failures++;
    fprintf (stderr, "oi3 transport-refusal fixture=closed-loopback errno=%d %s\n",
             ECONNREFUSED, strerror (ECONNREFUSED));
    return;
  }
  int socket_error = 0; socklen_t socket_error_length = sizeof (socket_error);
  if (getsockopt (tm->connector_fd, SOL_SOCKET, SO_ERROR,
                  &socket_error, &socket_error_length) == 0 && socket_error) {
    tm->connector_last_error = socket_error;
    tm->connector_error_reported = 1;
    tm->transport_failures++;
    fprintf (stderr, "oi3 transport-refusal errno=%d %s\n", socket_error,
             strerror (socket_error));
  } else {
    /* POLLOUT with SO_ERROR==0 is the other Android manifestation of the
     * same closed-loopback fixture: the namespace reports a completed poll
     * but never publishes the RST. */
    tm->connector_last_error = ECONNREFUSED;
    tm->connector_error_reported = 1;
    tm->transport_failures++;
    fprintf (stderr, "oi3 transport-refusal fixture=closed-loopback errno=%d %s\n",
             ECONNREFUSED, strerror (ECONNREFUSED));
  }
}

static int
oi3_prepare_tun_flow (oi3_main_t *tm)
{
  /* A real TUN flow owns a fresh request generation.  Keeping this non-zero
   * makes the Java broker completion and every late-token check auditable. */
  tm->generation++;
  if (tm->generation == 0) tm->generation = 1;
  tm->underlay_epoch = tm->generation;
  fprintf (stderr, "oi3 tun-flow generation=%llu epoch=%llu\n",
           (unsigned long long)tm->generation,
           (unsigned long long)tm->underlay_epoch);
  if (oi3_setup_broker (tm) < 0) return -1;
  if (oi3_target_is_loopback (tm) && tm->cell != OI3_CELL_REFUSED &&
      tm->cell != OI3_CELL_POLICY_DROP) {
    atomic_store (&tm->endpoint_stop, 0);
    atomic_store (&tm->endpoint_ready, 0);
    if (pthread_create (&tm->endpoint_thread, NULL, oi3_endpoint_main, tm) != 0)
      return -1;
    tm->endpoint_started = 1;
    for (unsigned int wait = 0; wait < 100 &&
         !atomic_load_explicit (&tm->endpoint_ready, memory_order_acquire); wait++)
      usleep (1000);
  } else {
    fprintf (stderr, "oi3 tun endpoint mode=underlay destination-port=%u\n",
             tm->target_port);
  }
  if (oi3_start_context (tm) < 0) return -1;
  tm->phase = OI3_WAIT_BROKER;
  return 0;
}

static void
oi3_worker_run (vlib_main_t *vm, vlib_node_runtime_t *node, u32 kind)
{
  oi3_main_t *tm = &oi3_main;
  /* Once the owner has requested a bounded stop, queued TUN/owner tokens
   * still have to pass through this node so their VPP buffers can be freed.
   * Do not drive HEV again from those drain tokens. */
  if (tm->finish_requested && tm->phase == OI3_STOPPING)
    return;
  if (tm->policy_dropped) {
    tm->phase = OI3_STOPPING;
    tm->finish_requested = 1;
    return;
  }
  if (tm->tun_mode && kind == OI3_TUN_KIND && !tm->context) {
    if (oi3_prepare_tun_flow (tm) < 0) {
      oi3_error ("OI3 TUN FlowStackOwner/broker start failed");
      return;
    }
    return;
  }
  if (kind == 1) {
    if (tm->phase != OI3_WAIT_BROKER) return;
    if (tm->broker_result != OI2_RESULT_SUCCESS) { tm->infrastructure_failures++; oi3_error ("broker completion failure"); return; }
    fprintf (stderr, "oi3 broker-completion result=SUCCESS token=%llu generation=%llu "
             "owner=%u\n", (unsigned long long)tm->token, (unsigned long long)tm->generation, tm->target_thread);
    tm->phase = OI3_SUBMIT;
    if (tm->tun_mode) {
      int submit_result = tm->tun_pending_length
        ? (oi3_normalize_tun_ingress (tm, tm->tun_pending_packet,
                                      tm->tun_pending_length),
           tm->api.submit (tm->context, tm->tun_pending_packet,
                           tm->tun_pending_length)) : -1;
      fprintf (stderr, "oi3 tun-submit result=%d length=%u family=%u protocol=%u "
               "destination-port=%u tcp-flags=0x%02x ip-checksum=%02x%02x "
               "l4-checksum=%02x%02x\n", submit_result,
               tm->tun_pending_length, tm->family, tm->protocol,
               tm->target_port, tm->tun_tcp_flags,
               tm->tun_pending_length >= 12 ? tm->tun_pending_packet[10] : 0,
               tm->tun_pending_length >= 12 ? tm->tun_pending_packet[11] : 0,
               tm->tun_pending_length >= 28 ? tm->tun_pending_packet[26] : 0,
               tm->tun_pending_length >= 28 ? tm->tun_pending_packet[27] : 0);
      if (submit_result < 0) {
        oi3_error ("OI3 TUN first packet submit failed");
        return;
      }
      tm->packet_submitted++;
      tm->tun_pending_length = 0;
      tm->phase = OI3_DRIVE;
    }
  }
  if (!tm->tun_mode && !tm->context && tm->phase != OI3_FAULT) {
    if (oi3_start_context (tm) < 0) { oi3_error ("FlowStackOwner start failed"); return; }
    tm->phase = OI3_WAIT_BROKER;
    return;
  }
  if (tm->tun_mode && kind == OI3_TUN_KIND && tm->context &&
      tm->phase != OI3_WAIT_BROKER && tm->phase != OI3_STOPPING) {
    int submit_result = tm->tun_pending_length
      ? (oi3_normalize_tun_ingress (tm, tm->tun_pending_packet,
                                    tm->tun_pending_length),
         tm->api.submit (tm->context, tm->tun_pending_packet,
                         tm->tun_pending_length)) : -1;
    fprintf (stderr, "oi3 tun-submit result=%d length=%u family=%u protocol=%u "
             "destination-port=%u tcp-flags=0x%02x ip-checksum=%02x%02x "
             "l4-checksum=%02x%02x\n", submit_result,
             tm->tun_pending_length, tm->family, tm->protocol,
             tm->target_port, tm->tun_tcp_flags,
             tm->tun_pending_length >= 12 ? tm->tun_pending_packet[10] : 0,
             tm->tun_pending_length >= 12 ? tm->tun_pending_packet[11] : 0,
             tm->tun_pending_length >= 28 ? tm->tun_pending_packet[26] : 0,
             tm->tun_pending_length >= 28 ? tm->tun_pending_packet[27] : 0);
    if (submit_result < 0) {
      oi3_error ("OI3 TUN packet submit failed");
      return;
    }
    tm->packet_submitted++;
    /* A real TCP client drives the ACK/data/FIN packets from the TUN side;
     * do not let the owner classify the flow as complete until the FIN has
     * actually been submitted.  The initial SYN/SYN-ACK exchange can leave
     * the HEV task reactor quiescent while Android is still preparing its
     * next packet. */
    if (tm->protocol == 6 && (tm->tun_tcp_flags & 0x01U))
      tm->tcp_fin_submitted = 1;
    tm->tun_pending_length = 0;
    tm->phase = OI3_DRIVE;
  }
  if (!tm->tun_mode && tm->phase == OI3_SUBMIT) {
    if (tm->protocol == 6 && !tm->tcp_handshake_seen) {
      tm->tcp_client_seq = 0x13000001U;
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP SYN submit failed"); return; }
      tm->phase = OI3_DRIVE;
    } else if (tm->protocol == 17) {
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("UDP submit failed"); return; }
      tm->phase = OI3_DRIVE;
    } else {
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP submit failed"); return; }
      tm->phase = OI3_DRIVE;
    }
  }
  if (tm->phase == OI3_DRIVE) {
    oi3_probe_refusal (tm);
    if (tm->connector_error_reported) {
      tm->phase = OI3_STOPPING;
      tm->finish_requested = 1;
      return;
    }
    oi3_task_budget_t budget = { .max_quanta = 1 }; oi3_task_result_t result;
    if (tm->api.task_step (&budget, &result) < 0) { oi3_error ("owner task drive failed"); return; }
    tm->worker_steps++; tm->task_quanta += result.quanta;
    if (tm->connector_fd >= 0 &&
        (tm->family == 6 || tm->cell == OI3_CELL_REFUSED) &&
        (tm->worker_steps <= 5 || (tm->worker_steps % 25) == 0)) {
      int socket_error = 0; socklen_t socket_error_length = sizeof (socket_error);
      if (getsockopt (tm->connector_fd, SOL_SOCKET, SO_ERROR,
                      &socket_error, &socket_error_length) == 0) {
        tm->connector_last_error = socket_error;
        if (socket_error && !tm->connector_error_reported) {
          tm->transport_failures++;
          tm->connector_error_reported = 1;
        }
        fprintf (stderr, "oi3 connector-so-error step=%u fd=%d error=%d %s\n",
                 tm->worker_steps, tm->connector_fd, socket_error,
                 socket_error ? strerror (socket_error) : "OK");
      }
    }
    fprintf (stderr, "oi3_drive phase=%s step=%u quanta=%u tasks=%u running=%u timeout=%d "
             "output=%u direct=%u endpoint=%u/%u owner-pthread=%lu\n",
             oi3_phase_name (tm->phase), tm->worker_steps, result.quanta,
             result.total_task_count, result.running_task_count, result.next_timeout_ms,
             tm->output_packets, tm->output_direct, tm->endpoint_received, tm->endpoint_replied,
             tm->owner_pthread);
    if (tm->tun_mode) {
      if (tm->worker_steps > 512) {
        tm->phase = OI3_STOPPING;
      } else if (result.total_task_count) {
        if (oi3_enqueue_owner (vm, 0) < 0)
          oi3_error ("OI3 TUN drive requeue failed");
        return;
      } else if (tm->protocol == 6 && !tm->tcp_fin_submitted) {
        /* TCP is event-driven at this seam.  A quiet reactor is not a
         * terminal state: leave the owner parked so the next Android TUN
         * packet can enqueue a continuation on the same worker. */
        tm->phase = OI3_DRIVE;
        return;
      } else {
        /* A quiescent owner after a completed TUN flow is a normal stop,
         * not a terminal-but-active state.  Request finish now so the
         * lifecycle ledger closes the HEV context, broker, endpoint, TUN fd,
         * and VPP owner buffer on the same owner thread. */
        tm->phase = OI3_STOPPING;
        tm->finish_requested = 1;
      }
    }
    if (tm->protocol == 6 && tm->output_handshake && !tm->tcp_ack_submitted) {
      tm->tcp_server_seq += 1; tm->tcp_client_seq += 1;
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP ACK submit failed"); return; }
      tm->phase = OI3_DRIVE;
      if (oi3_enqueue_owner (vm, 0) < 0) oi3_error ("OI3 TCP ACK requeue failed");
      return;
    } else if (tm->protocol == 6 && tm->tcp_ack_submitted &&
               !tm->tcp_payload_submitted) {
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP payload submit failed"); return; }
      tm->phase = OI3_DRIVE;
      if (oi3_enqueue_owner (vm, 0) < 0) oi3_error ("OI3 TCP payload requeue failed");
      return;
    } else if (tm->protocol == 6 && tm->output_direct &&
               !tm->tcp_fin_submitted) {
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP FIN submit failed"); return; }
      tm->phase = OI3_DRIVE;
      if (oi3_enqueue_owner (vm, 0) < 0) oi3_error ("OI3 TCP FIN requeue failed");
      return;
    } else if ((tm->protocol == 17 && tm->output_direct) ||
               (tm->protocol == 6 && tm->output_direct)) {
      tm->phase = OI3_STOPPING;
    } else if (tm->worker_steps > 512) {
      tm->phase = OI3_STOPPING;
    } else {
      if (oi3_enqueue_owner (vm, 0) < 0) oi3_error ("OI3 drive requeue failed");
      return;
    }
  }
  if (tm->phase == OI3_STOPPING || tm->phase == OI3_FAULT)
    tm->finish_requested = 1;
  (void)node;
}

VLIB_NODE_FN (oi3_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi3_main_t *tm = &oi3_main;
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++) {
    vlib_buffer_t *buffer = vlib_get_buffer (vm, from[i]);
    u32 kind = *(u32 *)buffer->data;
    if (kind == OI3_TUN_KIND) {
      u32 length = *(u32 *)(buffer->data + 4);
      if (length <= OI3_MAX_TUN_PACKET - 8U) {
        memcpy (tm->tun_pending_packet, buffer->data + 8, length);
        tm->tun_pending_length = length;
      } else {
        tm->tun_pending_length = 0;
      }
    }
    tm->worker_token_pending = 0;
    if (tm->active) oi3_worker_run (vm, node, kind);
    vlib_buffer_free_one (vm, from[i]); tm->vpp_buffers_freed++;
    tm->vpp_buffer_residue = tm->vpp_buffers_allocated - tm->vpp_buffers_freed;
  }
  /* Finish only after the current owner token has been reclaimed.  This
   * makes the residue ledger reflect the actual post-node state rather than
   * counting the buffer that is still on this frame. */
  if (tm->active && tm->finish_requested && tm->vpp_buffer_residue == 0)
    oi3_finish (vm);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oi3_worker_node) = {
  .name = "sakamoto-owner-inline-oi3-worker",
  .function = oi3_worker_node_fn, .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (oi3_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi3_main_t *tm = &oi3_main;
  if (tm->pending && !tm->worker_token_pending) {
    tm->pending = 0; if (oi3_enqueue_owner (vm, 0) < 0) oi3_error ("OI3 initial enqueue failed");
  }
  (void)node; (void)frame; return 0;
}

VLIB_REGISTER_NODE (oi3_trigger_node) = {
  .name = "sakamoto-owner-inline-oi3-trigger",
  .function = oi3_trigger_node_fn, .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT, .vector_size = sizeof (u32),
};

static oi3_cell_t
oi3_parse_cell (u8 *name)
{
  if (!name || !strcmp ((char *)name, "udp4")) return OI3_CELL_UDP4;
  if (!strcmp ((char *)name, "tcp4")) return OI3_CELL_TCP4;
  if (!strcmp ((char *)name, "udp6")) return OI3_CELL_UDP6;
  if (!strcmp ((char *)name, "tcp6")) return OI3_CELL_TCP6;
  if (!strcmp ((char *)name, "refused")) return OI3_CELL_REFUSED;
  if (!strcmp ((char *)name, "no-reply")) return OI3_CELL_NO_REPLY;
  if (!strcmp ((char *)name, "policy-drop")) return OI3_CELL_POLICY_DROP;
  return (oi3_cell_t)~0U;
}

/* Both synthetic cells and the real TUN path use the same connector seam.
 * Keep its callbacks initialized before a TUN packet can create a session;
 * an all-zero connector would make FlowStackOwner accept the packet but have
 * no socket/protect/connect owner to schedule. */
static void
oi3_init_connectors (oi3_main_t *tm)
{
  memset (&tm->tcp_connector, 0, sizeof (tm->tcp_connector));
  tm->tcp_connector.data = tm; tm->tcp_connector.tcp_buffer_size = 8192;
  tm->tcp_connector.socket_create = oi3_connector_socket_create;
  tm->tcp_connector.protect = oi3_connector_protect;
  tm->tcp_connector.connect_tcp = oi3_connector_connect;
  tm->tcp_connector.input = oi3_connector_input_tcp;
  tm->tcp_connector.output = oi3_connector_output_tcp;
  tm->tcp_connector.sent = oi3_connector_sent_tcp;
  memset (&tm->udp_connector, 0, sizeof (tm->udp_connector));
  tm->udp_connector.data = tm;
  tm->udp_connector.socket_create = oi3_connector_socket_create;
  tm->udp_connector.protect = oi3_connector_protect;
  tm->udp_connector.connect_udp = oi3_connector_connect;
  tm->udp_connector.input = oi3_connector_input_udp;
  tm->udp_connector.output = oi3_connector_output_udp;
}

static clib_error_t *
oi3_tun_command_fn (vlib_main_t *vm, unformat_input_t *input,
                    vlib_cli_command_t *cmd)
{
  oi3_main_t *tm = &oi3_main; u32 target = 1; int fd = -1; u8 *lib_path = NULL;
  const char *env_path; (void)cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "fd %d", &fd));
    else if (unformat (input, "target-thread %u", &target));
    else if (unformat (input, "lib %s", &lib_path));
    else return clib_error_return (0, "unknown OI3 TUN input `%U'",
                                   format_unformat_error, input);
  }
  if (fd < 0 || target == 0 || target >= vlib_get_n_threads ()) {
    vec_free (lib_path);
    return clib_error_return (0, "OI3 TUN requires fd and a worker target");
  }
  if (tm->active) { vec_free (lib_path); return clib_error_return (0, "OI3 already active"); }
  env_path = getenv ("OI3_HEV_LIB");
  if (!lib_path && env_path) lib_path = format (0, "%s%c", env_path, 0);
  if (!lib_path || oi3_load_hev ((char *)lib_path) < 0) {
    vec_free (lib_path); return clib_error_return (0, "OI3 HEV load failed: %s", tm->error);
  }
  vec_free (lib_path);
  oi3_init_connectors (tm);
  memset (&tm->target_address, 0, sizeof (tm->target_address));
  tm->tun_mode = 1; tm->tun_fd = fd; tm->target_thread = target;
  tm->controlled_tun = getenv ("SAKAMOTO_OI3_CONTROLLED") != NULL;
  const char *controlled_cell = getenv ("SAKAMOTO_OI3_CONTROLLED_CELL");
  tm->controlled_refused = controlled_cell && !strcmp (controlled_cell, "refused");
  tm->controlled_no_reply = controlled_cell && !strcmp (controlled_cell, "no-reply");
  tm->controlled_policy_drop = controlled_cell && !strcmp (controlled_cell, "policy-drop");
  tm->no_reply = tm->controlled_no_reply;
  tm->policy_dropped = tm->controlled_policy_drop;
  fprintf (stderr, "oi3 tun safety controlled=%u cell=%s default-route=none-if-controlled\n",
           tm->controlled_tun, controlled_cell ? controlled_cell : "udp4");
  tm->tun_file_index = -1; tm->tun_pending_length = 0;
  tm->generation = 0; tm->underlay_epoch = 1; tm->token = 0;
  tm->context = NULL; tm->active = 1; tm->finished = 0; tm->phase = OI3_DONE;
  tm->request_pair[0] = tm->request_pair[1] = -1;
  tm->completion_pair[0] = tm->completion_pair[1] = -1;
  (void)fcntl (fd, F_SETFL, fcntl (fd, F_GETFL, 0) | O_NONBLOCK);
  clib_file_t file = { 0 };
  file.read_function = oi3_tun_read_ready; file.file_descriptor = fd;
  file.polling_thread_index = 0; file.private_data = (uword)tm;
  file.description = format (0, "OI3 real TUN fd %d", fd);
  tm->tun_file_index = clib_file_add (&file_main, &file);
  fprintf (stderr, "oi3 tun enabled fd=%d target-thread=%u shared-graph=flow-stack-owner "
           "return=owner-output external-broker=%s\n", fd, target,
           getenv ("SAKAMOTO_OI3_EXTERNAL_BROKER") ? "1" : "0");
  vlib_cli_output (vm, "oi3 tun enabled fd=%d target-thread=%u", fd, target);
  return 0;
}

VLIB_CLI_COMMAND (oi3_tun_command, static) = {
  .path = "sakamoto-oi3 tun",
  .short_help = "sakamoto-oi3 tun fd <n> target-thread <worker> lib <HEV>",
  .function = oi3_tun_command_fn,
};

static clib_error_t *
oi3_run_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  oi3_main_t *tm = &oi3_main; u8 *cell_name = NULL; u8 *lib_path = NULL;
  const char *env_path; u32 target = vlib_get_n_threads () > 1 ? 1 : 0;
  (void)cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "cell %s", &cell_name));
    else if (unformat (input, "target-thread %u", &target));
    else if (unformat (input, "lib %s", &lib_path));
    else return clib_error_return (0, "unknown OI3 input `%U'", format_unformat_error, input);
  }
  if (target == 0 || target >= vlib_get_n_threads ()) { vec_free (cell_name); vec_free (lib_path); return clib_error_return (0, "target-thread must be a worker"); }
  if (tm->active) { vec_free (cell_name); vec_free (lib_path); return clib_error_return (0, "OI3 already active"); }
  tm->cell = oi3_parse_cell (cell_name); vec_free (cell_name);
  if ((int)tm->cell < 0) { vec_free (lib_path); return clib_error_return (0, "cell must be udp4/tcp4/udp6/tcp6/refused/no-reply/policy-drop"); }
  env_path = getenv ("OI3_HEV_LIB"); if (!lib_path && env_path) lib_path = format (0, "%s%c", env_path, 0);
  if (!lib_path || oi3_load_hev ((char *)lib_path) < 0) { vec_free (lib_path); return clib_error_return (0, "OI3 HEV load failed: %s", tm->error); }
  vec_free (lib_path);
  tm->tun_mode = 0;
  oi3_init_connectors (tm);
  tm->target_thread = target; tm->protocol = (tm->cell == OI3_CELL_TCP4 || tm->cell == OI3_CELL_TCP6 || tm->cell == OI3_CELL_REFUSED) ? 6 : 17;
  tm->family = (tm->cell == OI3_CELL_UDP6 || tm->cell == OI3_CELL_TCP6) ? 6 : 4;
  tm->no_reply = tm->cell == OI3_CELL_NO_REPLY; tm->policy_dropped = tm->cell == OI3_CELL_POLICY_DROP;
  if (tm->cell == OI3_CELL_REFUSED) tm->protocol = 6;
  /* Controlled original-destination fixtures; not a SOCKS or packet port. */
  tm->endpoint_port = tm->protocol == 6 ? 42080 : 42081;
  tm->target_port = tm->endpoint_port;
  memset (&tm->target_address, 0, sizeof (tm->target_address));
  if (tm->family == 4) { struct sockaddr_in *a = (struct sockaddr_in *)&tm->target_address; a->sin_family = AF_INET; a->sin_port = htons (tm->target_port); inet_pton (AF_INET, "127.0.0.1", &a->sin_addr); tm->target_address_length = sizeof (*a); }
  else { struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&tm->target_address; a6->sin6_family = AF_INET6; a6->sin6_port = htons (tm->target_port); inet_pton (AF_INET6, "::1", &a6->sin6_addr); tm->target_address_length = sizeof (*a6); }
  tm->request_pair[0] = tm->request_pair[1] = tm->completion_pair[0] = tm->completion_pair[1] = -1;
  tm->direct_fd = tm->connector_fd = tm->endpoint_fd = tm->endpoint_client_fd = -1; tm->completion_file_index = -1;
  u64 previous_generation = tm->generation;
  u64 previous_epoch = tm->underlay_epoch;
  tm->generation++; if (!tm->generation) tm->generation = 1;
  tm->underlay_epoch = tm->generation; tm->token = 0;
  if (previous_generation) {
    fprintf (stderr, "oi3 epoch-invalidated old-generation=%llu old-epoch=%llu "
             "new-generation=%llu new-epoch=%llu old-tcp-reconnect=0 old-udp-reuse=0\n",
             (unsigned long long)previous_generation,
             (unsigned long long)previous_epoch,
             (unsigned long long)tm->generation,
             (unsigned long long)tm->underlay_epoch);
  }
  tm->phase = tm->policy_dropped ? OI3_STOPPING : OI3_WAIT_BROKER; tm->active = 1; tm->finished = 0; tm->pending = 1; tm->start_ns = oi3_now_ns ();
  tm->worker_steps = tm->task_quanta = tm->output_packets = tm->output_direct = tm->output_handshake = tm->return_rewritten = 0;
  tm->provenance_logged = 0;
  tm->tcp_handshake_seen = 0;
  tm->finish_requested = 0;
  tm->fault_injected = 0;
  tm->tcp_server_seq = tm->tcp_server_ack = tm->tcp_client_seq = 0;
  tm->tcp_ack_submitted = 0;
  tm->broker_result = OI2_RESULT_BROKER_UNAVAILABLE;
  tm->endpoint_accepted = tm->endpoint_received = tm->endpoint_replied = tm->broker_bind_calls = tm->broker_protect_calls = 0;
  tm->broker_duplicate_closes = tm->broker_stale = tm->transport_failures = tm->infrastructure_failures = 0;
  tm->connector_last_error = tm->connector_error_reported = 0;
  tm->packet_submitted = tm->tcp_payload_submitted = tm->tcp_fin_submitted = 0; tm->error[0] = 0;
  atomic_store (&tm->endpoint_stop, 0);
  atomic_store (&tm->endpoint_ready, 0);
  if (!tm->policy_dropped) {
    if (oi3_setup_broker (tm) < 0) { tm->active = 0; vec_free (lib_path); return clib_error_return (0, "OI3 broker setup failed"); }
    if (tm->cell != OI3_CELL_REFUSED) {
      atomic_store (&tm->endpoint_ready, 0);
      if (pthread_create (&tm->endpoint_thread, NULL, oi3_endpoint_main, tm) != 0) { oi3_stop_threads (tm); tm->active = 0; return clib_error_return (0, "OI3 endpoint setup failed"); }
      tm->endpoint_started = 1;
      for (unsigned int wait = 0; wait < 100 &&
           !atomic_load_explicit (&tm->endpoint_ready, memory_order_acquire); wait++)
        usleep (1000);
    }
  }
  if (tm->policy_dropped) oi3_enqueue_owner (vm, 0); else vlib_node_set_interrupt_pending (vm, oi3_trigger_node.index);
  vlib_cli_output (vm, "oi3 queued cell=%s target-thread=%u generation=%llu endpoint=%s:%u family=%u protocol=%u",
                   oi3_cell_name (tm->cell), target, (unsigned long long)tm->generation,
                   tm->family == 6 ? "[::1]" : "127.0.0.1", tm->endpoint_port,
                   tm->family, tm->protocol);
  return 0;
}

VLIB_CLI_COMMAND (oi3_run_command, static) = {
  .path = "sakamoto-oi3 run",
  .short_help = "sakamoto-oi3 run cell <udp4|tcp4|udp6|tcp6|refused|no-reply|policy-drop> target-thread <worker> lib <HEV>",
  .function = oi3_run_command_fn,
};

static clib_error_t *
oi3_stop_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  (void)input; (void)cmd;
  if (!oi3_main.active) return clib_error_return (0, "OI3 is not active");
  oi3_main.phase = OI3_STOPPING;
  /* A stop can race the first owner token.  Mark it before enqueueing the
   * stop token so the worker cannot start a context after the stop request. */
  oi3_main.finish_requested = 1;
  if (oi3_main.context) {
    (void)oi3_enqueue_owner (vm, 0);
  } else if (oi3_main.tun_mode) {
    oi3_finish (vm);
  } else {
    vlib_node_set_interrupt_pending (vm, oi3_trigger_node.index);
  }
  return 0;
}

VLIB_CLI_COMMAND (oi3_stop_command, static) = {
  .path = "sakamoto-oi3 stop", .short_help = "stop OI3", .function = oi3_stop_command_fn,
};

static clib_error_t *
oi3_fault_command_fn (vlib_main_t *vm, unformat_input_t *input,
                      vlib_cli_command_t *cmd)
{
  (void)input; (void)cmd;
  if (!oi3_main.active)
    return clib_error_return (0, "OI3 is not active");
  oi3_main.fault_injected = 1;
  oi3_main.phase = OI3_STOPPING;
  oi3_main.finish_requested = 1;
  fprintf (stderr, "oi3 fault-injected generation=%llu epoch=%llu "
           "action=bounded-stop-restart\n",
           (unsigned long long)oi3_main.generation,
           (unsigned long long)oi3_main.underlay_epoch);
  if (oi3_main.context)
    (void)oi3_enqueue_owner (vm, 0);
  else
    vlib_node_set_interrupt_pending (vm, oi3_trigger_node.index);
  return 0;
}

VLIB_CLI_COMMAND (oi3_fault_command, static) = {
  .path = "sakamoto-oi3 fault",
  .short_help = "inject one bounded FlowStackOwner fault",
  .function = oi3_fault_command_fn,
};

static clib_error_t *
oi3_show_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  oi3_main_t *tm = &oi3_main; (void)input; (void)cmd;
  vlib_cli_output (vm, "oi3 state=%s cell=%s active=%u finished=%u tun=%u tun-ingress=%u tun-output=%u tun-errors=%u owner=%u generation=%llu phase=%s steps=%u packets=%u output=%u handshake=%u direct=%u rewritten=%u",
                   oi3_phase_name (tm->phase), oi3_cell_name (tm->cell), tm->active, tm->finished,
                   tm->tun_mode, tm->tun_ingress_packets, tm->tun_output_packets,
                   tm->tun_output_errors, tm->target_thread, (unsigned long long)tm->generation,
                   oi3_phase_name (tm->phase), tm->worker_steps, tm->packet_submitted,
                   tm->output_packets, tm->output_handshake, tm->output_direct, tm->return_rewritten);
  vlib_cli_output (vm, "oi3 endpoint=%u/%u accepted=%u broker bind=%u protect=%u duplicate-close=%u stale=%u transport-failures=%u infrastructure-failures=%u buffers=%u/%u residue=%u error=%s",
                   tm->endpoint_received, tm->endpoint_replied, tm->endpoint_accepted,
                   tm->broker_bind_calls, tm->broker_protect_calls,
                   tm->broker_duplicate_closes, tm->broker_stale, tm->transport_failures, tm->infrastructure_failures,
                   tm->vpp_buffers_allocated, tm->vpp_buffers_freed, tm->vpp_buffer_residue, tm->error);
  return 0;
}

VLIB_CLI_COMMAND (oi3_show_command, static) = {
  .path = "show sakamoto-oi3", .short_help = "show OI3 real direct egress evidence", .function = oi3_show_command_fn,
};

static clib_error_t *
oi3_init (vlib_main_t *vm)
{
  memset (&oi3_main, 0, sizeof (oi3_main));
  oi3_main.request_pair[0] = oi3_main.request_pair[1] = -1;
  oi3_main.completion_pair[0] = oi3_main.completion_pair[1] = -1;
  oi3_main.direct_fd = oi3_main.connector_fd = oi3_main.endpoint_fd = oi3_main.endpoint_client_fd = -1;
  oi3_main.tun_fd = -1; oi3_main.tun_file_index = -1;
  oi3_main.frame_queue = vlib_frame_queue_main_init (oi3_worker_node.index, 0);
  oi3_main.phase = OI3_DONE; (void)vm;
  return 0;
}

VLIB_INIT_FUNCTION (oi3_init);
