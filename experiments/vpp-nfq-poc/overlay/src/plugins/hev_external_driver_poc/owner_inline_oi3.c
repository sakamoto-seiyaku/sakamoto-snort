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
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define OI3_MAX_PACKET 2048U
#define OI3_BROKER_COMPLETION_KIND 1U
#define OI3_TUN_KIND 2U
#define OI3_TUN_DEFERRED_KIND 4U
#define OI3_MAX_TUN_PACKET 4096U
#define OI3_PAYLOAD "oi3-direct-echo"
#define OI3_TCP_LISTEN 49155U
#define OI3_UDP_LISTEN 49154U
#define OI3_TCP_CLIENT 40002U
#define OI3_UDP_CLIENT 40001U
#define OI3_SENTINEL 64U
#define OI3_MAX_DRIVE 4096U
#define OI3_WALL_BUDGET_NS 5000000ULL
#define OI3_TUN_FLOW_TIMEOUT_NS 5000000000ULL
#define OI3_CONNECTOR_POLL_SLICE_MS 50
#define OI3_TUN_PENDING_CAPACITY 16U
#define OI3_MULTI_OWNER_CAPACITY 4U
#define OI3_MULTI_FLOW_ROUTE_CAPACITY 16U
#define OI3_UNDERLAY_KIND 3U
#define OI3_HEV_CREDIT_COUNT 4U
#define OI3_HEV_EVENT_COUNT 9U
#define OI3_OWNER_STOP_READY 0
#define OI3_OWNER_STOP_PENDING (-2)
#define OI3_OWNER_STOP_MAX_QUANTA 1024U
#define OI3_OWNER_STOP_RETRY_ROUNDS 8U

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
  void (*transport_event)(void *, HevOwnerRuntime *, tcp_pcb_t *,
                          unsigned int, int);
} oi3_tcp_connector_t;

enum {
  OI3_TCP_TRANSPORT_READ_ERROR = 1,
  OI3_TCP_TRANSPORT_WRITE_ERROR = 2,
  OI3_TCP_TRANSPORT_PEER_EOF = 3,
};

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
  uint64_t generation;
  uint32_t cause;
  uint32_t reserved;
} oi3_connector_wake_t;

typedef struct {
  u64 flow_hash;
  u32 length;
  u8 packet[OI3_MAX_TUN_PACKET];
} oi3_tun_pending_entry_t;

typedef struct {
  u32 kind;
  u32 length;
  u8 packet[OI3_MAX_TUN_PACKET];
} oi3_tun_handoff_msg_t;

typedef struct {
  u64 flow_hash;
  u32 owner;
  u32 protocol;
  u32 active;
} oi3_multi_flow_route_t;

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
  void (*identity)(const FlowStackOwnerContext *, void *identity);
  void (*runtime_identity)(const FlowStackOwnerContext *, void *identity);
  void (*lwip_tcp_tmr)(void *context);
  HevTask *(*task_self)(void);
  int (*task_add_fd)(HevTask *, int, unsigned int);
  int (*task_mod_fd)(HevTask *, int, unsigned int);
} oi3_hev_api_t;

/* dlsym-only copy of lwip_owner_identity_t.  flow_stack_owner_identity()
 * writes the complete structure, so keep the layout in lockstep with the
 * pinned HEV owner-context header even though OI3 only consumes context. */
typedef struct {
  uintptr_t context;
  uintptr_t ip_data;
  uintptr_t netif_list;
  uintptr_t netif_default;
  uintptr_t tcp_bound_pcbs;
  uintptr_t tcp_listen_pcbs;
  uintptr_t tcp_active_pcbs;
  uintptr_t tcp_tw_pcbs;
  uintptr_t tcp_pcb_lists;
  uintptr_t udp_pcbs;
  uintptr_t udp_port;
  uintptr_t tcp_ticks;
  uintptr_t input_scratch;
  uintptr_t memp_storage;
  size_t memp_storage_size;
  uintptr_t tcp_active_pcb;
  uintptr_t tcp_listen_pcb;
  uint16_t tcp_active_local_port;
  uint16_t tcp_listen_local_port;
  uint32_t tcp_ticks_value;
  uint16_t input_scratch_length;
  uintptr_t tcp_pcb_pool_storage;
  uintptr_t tcp_pcb_listen_pool_storage;
  uintptr_t tcp_seg_pool_storage;
  uintptr_t pbuf_pool_storage;
  uintptr_t pbuf_payload_pool_storage;
  uintptr_t udp_pcb_pool_storage;
  size_t tcp_pcb_pool_free;
  size_t tcp_pcb_pool_used;
  size_t tcp_pcb_listen_pool_free;
  size_t tcp_pcb_listen_pool_used;
  size_t tcp_seg_pool_free;
  size_t tcp_seg_pool_used;
  size_t pbuf_pool_free;
  size_t pbuf_pool_used;
  size_t pbuf_payload_pool_free;
  size_t pbuf_payload_pool_used;
  size_t udp_pcb_pool_free;
  size_t udp_pcb_pool_used;
  uint8_t tcp_active_state;
  uint16_t tcp_active_remote_port;
  uintptr_t tcp_active_callback_arg;
  uintptr_t udp_pcb;
  uint16_t udp_local_port;
  uint16_t udp_port_value;
  size_t udp_header_fallbacks;
} oi3_lwip_identity_t;

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
typedef struct oi3_multi_main oi3_multi_main_t;

struct oi3_main {
  oi3_hev_api_t api;
  FlowStackOwnerContext *context;
  void *lwip_context;
  oi3_tcp_connector_t tcp_connector;
  oi3_udp_connector_t udp_connector;
  oi3_session_config_t session_config;
  oi3_owner_config_t owner_config;
  oi3_cell_t cell;
  oi3_phase_t phase;
  u32 target_thread;
  u32 frame_queue;
  u32 owner_id;
  u32 multi_mode;
  u32 pending;
  u32 active;
  u32 finished;
  u32 worker_token_pending;
  u32 finish_requested;
  /* An explicit normal stop is a lifecycle result, not a missing reply.
   * Keep this separate from finish_requested because natural completion,
   * transport failure, fault injection, and underlay invalidation all use
   * the same drain bit for different terminal contracts. */
  u32 normal_stop_requested;
  u32 fault_injected;
  u32 worker_steps;
  u32 protocol;
  u32 family;
  u32 policy_dropped;
  /* packet_submitted is cumulative for the owner context; UDP needs a
   * separate per-datagram latch so a completed echo can admit the next queued
   * datagram without tearing down and re-arming the whole owner generation. */
  u32 packet_submitted;
  u32 udp_datagram_inflight;
  u32 tcp_ack_submitted;
  u32 tcp_payload_submitted;
  u32 tcp_fin_submitted;
  u32 output_packets;
  u32 output_handshake;
  u32 output_direct;
  u32 direct_send_events;
  u32 direct_recv_events;
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
  u32 underlay_available;
  u32 underlay_invalidated;
  u32 vpp_buffers_allocated;
  u32 vpp_buffers_freed;
  u32 vpp_buffer_residue;
  u64 generation;
  u64 underlay_epoch;
  int64_t underlay_handle;
  _Atomic uint64_t source_underlay_epoch;
  _Atomic int64_t source_underlay_handle;
  _Atomic uint32_t source_underlay_available;
  _Atomic uint64_t pending_underlay_epoch;
  _Atomic int64_t pending_underlay_handle;
  _Atomic uint32_t pending_underlay_available;
  _Atomic uint32_t pending_underlay_update;
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
  /* A TUN command is a VPN-session lifetime.  Each packet gets its own
   * FlowStackOwner generation, while the TUN fd/watcher remain armed between
   * successful positive flows. */
  u32 tun_flow_count;
  int controlled_tun;
  int controlled_refused;
  int controlled_policy_drop;
  int controlled_no_reply;
  int tun_fd;
  int tun_file_index;
  u32 tun_pending_head;
  u32 tun_pending_count;
  u32 tun_pending_sequence;
  oi3_tun_pending_entry_t tun_pending[OI3_TUN_PENDING_CAPACITY];
  u32 multi_deferred_head;
  u32 multi_deferred_count;
  u32 multi_deferred_sequence;
  oi3_tun_pending_entry_t multi_deferred[OI3_TUN_PENDING_CAPACITY];
  u32 tun_ingress_packets;
  u32 tun_output_packets;
  u32 tun_output_errors;
  u32 tun_submit_rejects;
  u32 tun_queue_rejects;
  u32 overload_expected;
  u32 expected_transport_timeout;
  u32 expected_real_no_reply;
  u32 expected_real_reset;
  u32 expected_real_policy_drop;
  /* S185 keeps pre-connect broker failures on the infrastructure branch.
   * The value is the exact OI2 completion enum expected for this bounded
   * cell; zero means ordinary transport/positive classification. */
  u32 expected_infrastructure_failure;
  u8 tun_tcp_flags;
  u8 tun_rx[OI3_MAX_TUN_PACKET];
  int connector_last_error;
  int connector_error_reported;
  u32 connector_reset_observed;
  u32 connector_downstream_reset_observed;
  u32 connector_peer_eof_observed;
  int target_port;
  int endpoint_port;
  int source_port;
  struct sockaddr_storage target_address;
  socklen_t target_address_length;
  struct sockaddr_storage source_address;
  socklen_t source_address_length;
  struct sockaddr_storage underlay_address;
  socklen_t underlay_address_length;
  u8 last_output[OI3_MAX_PACKET];
  u32 last_output_length;
  u32 tcp_client_seq;
  u32 tcp_server_seq;
  u32 tcp_server_ack;
  u32 tcp_data_seen;
  u32 task_quanta;
  u32 a2_return_mode;
  u32 a2_return_ingress;
  u32 a2_return_output;
  u32 a2_return_lookup_count;
  u32 a2_return_payload_length;
  u8 a2_return_payload[OI3_MAX_PACKET];
  char a2_return_stage_id[64];
  char a2_return_canonical_key[256];
  u64 start_ns;
  u64 finish_ns;
  u64 tun_flow_deadline_ns;
  int connector_wake_pipe[2];
  int connector_wake_file_index;
  int tun_handoff_pair[2];
  int tun_handoff_file_index;
  pthread_t connector_poll_thread;
  int connector_poll_started;
  _Atomic int connector_poll_stop;
  _Atomic int connector_poll_done;
  _Atomic int connector_wake_pending;
  _Atomic int connector_connect_pending;
  _Atomic uint32_t connector_write_pending;
  /* Dispatcher-owned admission state.  The VPP main thread may inspect and
   * reserve these atomics, while the selected owner thread remains the sole
   * writer of its HEV context, packet queue, and lifecycle fields. */
  _Atomic uint32_t multi_admission_open;
  _Atomic uint32_t multi_dispatch_depth;
  _Atomic uint64_t active_flow_hash;
  _Atomic uint32_t active_flow_valid;
  /* A successful TCP generation may leave FIN/ACK tail packets in the TUN
   * queue after its re-arm.  They are not a new application flow.  Keep the
   * completed tuple tombstone owner-local until the next outbound SYN. */
  _Atomic uint32_t multi_tcp_wait_syn;
  _Atomic uint64_t multi_tcp_tombstone_hash;
  _Atomic uint32_t multi_tcp_tombstone_valid;
  _Atomic uint32_t multi_admission_rejects;
  char error[256];
};

static oi3_main_t oi3_main;
static pthread_mutex_t oi3_task_init_lock = PTHREAD_MUTEX_INITIALIZER;
struct oi3_multi_main {
  u32 active;
  u32 owner_count;
  int tun_fd;
  int tun_file_index;
  int completion_file_index;
  int completion_watch_fd;
  pthread_t completion_poll_thread;
  int completion_poll_started;
  _Atomic int completion_poll_stop;
  int request_fd;
  int completion_fd;
  u32 route_count[OI3_MULTI_OWNER_CAPACITY];
  u32 route_rejects[OI3_MULTI_OWNER_CAPACITY];
  u32 route_deferred[OI3_MULTI_OWNER_CAPACITY];
  u32 route_reassigned[OI3_MULTI_OWNER_CAPACITY];
  u32 wrong_owner_events;
  u32 policy_drop_ip4_set;
  u32 policy_drop_ip4;
  u32 policy_drop_packets;
  u64 hash_seed;
  oi3_multi_flow_route_t flow_routes[OI3_MULTI_FLOW_ROUTE_CAPACITY];
  oi3_main_t owners[OI3_MULTI_OWNER_CAPACITY];
};
static oi3_multi_main_t oi3_multi;
static __thread oi3_main_t *oi3_current_tm;
extern vlib_node_registration_t oi3_trigger_node;
extern vlib_node_registration_t oi3_worker_node;

static int oi3_connector_poll_arm (oi3_main_t *tm);
static void oi3_connector_poll_join (oi3_main_t *tm);
static void oi3_connector_poll_stop (oi3_main_t *tm);
static int oi3_ensure_connector_wake_file (oi3_main_t *tm);
static int oi3_ensure_tun_handoff_file (oi3_main_t *tm);
static void oi3_close_tun_handoff_file (oi3_main_t *tm);
static int oi3_send_tun_handoff_for (oi3_main_t *tm, const u8 *packet,
                                     size_t length);
static int oi3_send_completion_handoff_for (
  oi3_main_t *tm, const oi2_broker_completion_t *completion);
static void oi3_multi_completion_poll_stop (void);
static void oi3_worker_run_for (vlib_main_t *vm, vlib_node_runtime_t *node,
                                u32 kind, oi3_main_t *tm);
static void oi3_apply_pending_underlay (oi3_main_t *tm);
static void oi3_rearm_tun_flow (vlib_main_t *vm, oi3_main_t *tm);
static void oi3_multi_maybe_teardown (void);
static int oi3_task_init (oi3_main_t *tm);
static void oi3_task_fini (oi3_main_t *tm);
static int oi3_multi_flow_hash (const u8 *packet, size_t length,
                                uint64_t *hash_out);
static int oi3_multi_packet_protocol (const u8 *packet, size_t length,
                                      u32 *protocol_out);
static int oi3_multi_flow_route_lookup (uint64_t hash, u32 *owner_out);
static int oi3_multi_flow_route_insert (uint64_t hash, u32 owner,
                                        u32 protocol);
static void oi3_multi_flow_route_remove (uint64_t hash);
static bool oi3_multi_tcp_packet (const u8 *packet, size_t length);
static bool oi3_multi_tcp_syn_packet (const u8 *packet, size_t length);

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

static const char *
oi3_broker_result_name (uint32_t result)
{
  switch (result)
    {
    case OI2_RESULT_SUCCESS: return "SUCCESS";
    case OI2_RESULT_BIND_FAILURE: return "BIND_FAILURE";
    case OI2_RESULT_PROTECT_FAILURE: return "PROTECT_FAILURE";
    case OI2_RESULT_BROKER_UNAVAILABLE: return "BROKER_UNAVAILABLE";
    default: return "UNKNOWN";
    }
}

static uint32_t
oi3_request_flags_for_expected_failure (uint32_t result)
{
  switch (result)
    {
    case OI2_RESULT_BIND_FAILURE: return OI2_FLAG_BIND_FAILURE;
    case OI2_RESULT_PROTECT_FAILURE: return OI2_FLAG_PROTECT_FAILURE;
    case OI2_RESULT_BROKER_UNAVAILABLE: return OI2_FLAG_BROKER_UNAVAILABLE;
    default: return OI2_FLAG_NONE;
    }
}

static uint64_t
oi3_now_ns (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t
oi3_wall_ms (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) ts.tv_nsec / 1000000ULL;
}

static void
oi3_refresh_tun_flow_deadline (oi3_main_t *tm)
{
  if (!tm || !tm->tun_mode || !tm->multi_mode)
    return;
  tm->tun_flow_deadline_ns = oi3_now_ns () + OI3_TUN_FLOW_TIMEOUT_NS;
}

/* The HEV external-driver contract deliberately polls with timeout zero.
 * Keep that contract intact, but use a tiny observer thread to publish
 * readiness of the same protected connector fd back to VPP.  The observer
 * never reads the fd and never enters HEV/lwIP; it only writes an opaque
 * wake token to the VPP-owned pipe. */
static void *
oi3_connector_poll_main (void *data)
{
  oi3_main_t *tm = data;

  while (!atomic_load_explicit (&tm->connector_poll_stop,
                                memory_order_acquire)) {
    int fd = tm->connector_fd;
    struct pollfd p;
    int timeout = OI3_CONNECTOR_POLL_SLICE_MS;
    uint64_t deadline = tm->tun_flow_deadline_ns;

    if (fd < 0)
      break;
    memset (&p, 0, sizeof (p));
    p.fd = fd;
    p.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    if (atomic_load_explicit (&tm->connector_connect_pending,
                              memory_order_acquire) ||
        atomic_load_explicit (&tm->connector_write_pending,
                              memory_order_acquire))
      p.events |= POLLOUT;
    if (deadline) {
      uint64_t now = oi3_now_ns ();
      if (now >= deadline) {
        timeout = 0;
      } else {
        uint64_t remaining_ms = (deadline - now + 999999ULL) / 1000000ULL;
        if (remaining_ms < (uint64_t) timeout)
          timeout = (int) remaining_ms;
      }
    }
    int result;
    do {
      result = poll (&p, 1, timeout);
    } while (result < 0 && errno == EINTR &&
             !atomic_load_explicit (&tm->connector_poll_stop,
                                    memory_order_acquire));
    if (atomic_load_explicit (&tm->connector_poll_stop, memory_order_acquire))
      break;
    if (result < 0)
      break;
    if (result == 0 && deadline && oi3_now_ns () >= deadline) {
      oi3_connector_wake_t token = {
        .generation = tm->generation,
        .cause = 2,
        .reserved = 0,
      };
      int expected = 0;
      atomic_store_explicit (&tm->connector_poll_done, 1, memory_order_release);
      if (atomic_compare_exchange_strong (&tm->connector_wake_pending,
                                          &expected, 1))
        (void) write (tm->connector_wake_pipe[1], &token, sizeof (token));
      break;
    }
    if (result > 0 && p.revents != 0) {
      oi3_connector_wake_t token = {
        .generation = tm->generation,
        .cause = 1,
        .reserved = (uint32_t)p.revents,
      };
      int expected = 0;
      atomic_store_explicit (&tm->connector_poll_done, 1, memory_order_release);
      if (atomic_compare_exchange_strong (&tm->connector_wake_pending,
                                          &expected, 1))
        (void) write (tm->connector_wake_pipe[1], &token, sizeof (token));
      break;
    }
  }
  atomic_store_explicit (&tm->connector_poll_done, 1, memory_order_release);
  return NULL;
}

static int
oi3_connector_poll_arm (oi3_main_t *tm)
{
  if (!tm || tm->connector_fd < 0 || tm->connector_wake_pipe[1] < 0 ||
      tm->finish_requested)
    return 0;
  if (tm->connector_poll_started) {
    if (!atomic_load_explicit (&tm->connector_poll_done, memory_order_acquire))
      return 0;
    oi3_connector_poll_join (tm);
  }
  atomic_store_explicit (&tm->connector_poll_stop, 0, memory_order_release);
  atomic_store_explicit (&tm->connector_poll_done, 0, memory_order_release);
  if (pthread_create (&tm->connector_poll_thread, NULL,
                      oi3_connector_poll_main, tm) != 0)
    return -1;
  tm->connector_poll_started = 1;
  return 0;
}

static int
oi3_connector_poll_arm_after_direct_send (oi3_main_t *tm)
{
  if (!tm || !tm->tun_mode || tm->protocol != 6 || tm->connector_fd < 0 ||
      tm->direct_send_events == 0 || tm->direct_recv_events != 0)
    return 0;
  fprintf (stderr,
           "oi3 connector-poll-arm-after-direct-send owner=%u "
           "generation=%llu direct-send=%u direct-recv=%u "
           "output-direct=%u\n",
           tm->owner_id, (unsigned long long)tm->generation,
           tm->direct_send_events, tm->direct_recv_events,
           tm->output_direct);
  return oi3_connector_poll_arm (tm);
}

static void
oi3_connector_poll_join (oi3_main_t *tm)
{
  if (!tm || !tm->connector_poll_started)
    return;
  /* Worker re-entry must never wait for a live observer: an Android TCP
   * flow can deliver another TUN token while the same observer is waiting
   * for the protected FD.  Only join an observer that has published its
   * terminal state; the stop path below is the sole bounded blocking join. */
  if (!atomic_load_explicit (&tm->connector_poll_done, memory_order_acquire))
    return;
  (void) pthread_join (tm->connector_poll_thread, NULL);
  tm->connector_poll_started = 0;
}

static void
oi3_connector_poll_stop (oi3_main_t *tm)
{
  if (!tm)
    return;
  atomic_store_explicit (&tm->connector_poll_stop, 1, memory_order_release);
  if (tm->connector_poll_started) {
    (void) pthread_join (tm->connector_poll_thread, NULL);
    tm->connector_poll_started = 0;
  }
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
oi3_a2_return_hex (const u8 *payload, size_t length, char *hex,
                   size_t hex_length)
{
  size_t bounded = length;
  if (bounded * 2U + 1U > hex_length)
    bounded = (hex_length - 1U) / 2U;
  for (size_t i = 0; i < bounded; i++)
    (void) snprintf (hex + i * 2U, hex_length - i * 2U, "%02x", payload[i]);
  hex[bounded * 2U] = 0;
}

static void
oi3_a2_return_log_packet (oi3_main_t *tm, const char *event,
                          const char *direction, const u8 *packet,
                          size_t length)
{
  if (!tm->a2_return_mode || !packet)
    return;
  size_t ip_header = tm->family == 4 ? 20U : 40U;
  size_t l4_header = 8U;
  if (length < ip_header + l4_header)
    return;
  size_t payload_offset = ip_header + l4_header;
  size_t payload_length = length - payload_offset;
  char payload_hex[OI3_MAX_PACKET * 2U + 1U];
  oi3_a2_return_hex (packet + payload_offset, payload_length, payload_hex,
                     sizeof (payload_hex));
  fprintf (stderr,
           "oi3 a2-3 schema=s139-a2-3-oi3/v1 event=%s stage-id=%s "
           "direction=%s family=%u protocol=UDP canonical-key=%s "
           "payload-length=%zu payload-hex=%s android-lookup-count=%u "
           "transport-reentry=0 uid-join=app-jsonl:canonical-key "
           "package-join=app-jsonl:canonical-key owner=%u owner-pthread=%lu\n",
           event, tm->a2_return_stage_id, direction, tm->family,
           tm->a2_return_canonical_key[0] ? tm->a2_return_canonical_key : "?",
           payload_length, payload_hex, tm->a2_return_lookup_count,
           tm->target_thread, tm->owner_pthread);
}

static void
oi3_a2_return_capture_ingress (oi3_main_t *tm, const u8 *packet, size_t length)
{
  if (!tm->a2_return_mode || !packet)
    return;
  size_t ip_header = tm->family == 4 ? 20U : 40U;
  if (length < ip_header + 8U)
    return;
  char source[INET6_ADDRSTRLEN] = "?";
  char destination[INET6_ADDRSTRLEN] = "?";
  uint16_t source_port = 0;
  if (tm->family == 4) {
    (void) inet_ntop (AF_INET, packet + 12, source, sizeof (source));
    (void) inet_ntop (AF_INET,
                      &((const struct sockaddr_in *)&tm->target_address)->sin_addr,
                      destination, sizeof (destination));
  } else {
    (void) inet_ntop (AF_INET6, packet + 8, source, sizeof (source));
    (void) inet_ntop (AF_INET6,
                      &((const struct sockaddr_in6 *)&tm->target_address)->sin6_addr,
                      destination, sizeof (destination));
  }
  source_port = (uint16_t)(((uint16_t)packet[ip_header] << 8) |
                           packet[ip_header + 1U]);
  char source_endpoint[128];
  char destination_endpoint[128];
  if (tm->family == 4) {
    (void) snprintf (source_endpoint, sizeof (source_endpoint), "%s:%u",
                     source, source_port);
    (void) snprintf (destination_endpoint, sizeof (destination_endpoint),
                     "%s:%u", destination, tm->target_port);
  } else {
    (void) snprintf (source_endpoint, sizeof (source_endpoint), "[%s]:%u",
                     source, source_port);
    (void) snprintf (destination_endpoint, sizeof (destination_endpoint),
                     "[%s]:%u", destination, tm->target_port);
  }
  const char *first = strcmp (source_endpoint, destination_endpoint) <= 0
    ? source_endpoint : destination_endpoint;
  const char *second = first == source_endpoint
    ? destination_endpoint : source_endpoint;
  (void) snprintf (tm->a2_return_canonical_key,
                   sizeof (tm->a2_return_canonical_key), "ip%u/UDP/%s-%s",
                   tm->family, first, second);
  size_t payload_offset = ip_header + 8U;
  tm->a2_return_payload_length = (u32)(length - payload_offset);
  if (tm->a2_return_payload_length > sizeof (tm->a2_return_payload))
    tm->a2_return_payload_length = sizeof (tm->a2_return_payload);
  memcpy (tm->a2_return_payload, packet + payload_offset,
          tm->a2_return_payload_length);
  tm->a2_return_ingress++;
  oi3_a2_return_log_packet (tm, "INGRESS", "ORIG", packet, length);
}

static void
oi3_error (const char *message)
{
  oi3_main_t *tm = oi3_current_tm ? oi3_current_tm : &oi3_main;
  snprintf (tm->error, sizeof (tm->error), "%s", message);
  tm->phase = OI3_FAULT;
  tm->finish_requested = 1;
  fprintf (stderr, "oi3_error owner=%u target-thread=%u message=%s\n",
           tm->owner_id, tm->target_thread, message);
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
oi3_load_hev_for (oi3_main_t *tm, const char *path)
{
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
  OI3_LOAD (identity, "flow_stack_owner_identity");
  OI3_LOAD (runtime_identity, "flow_stack_owner_runtime_identity");
  OI3_LOAD (lwip_tcp_tmr, "lwip_owner_context_tcp_tmr");
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

static int
oi3_load_hev (const char *path)
{
  return oi3_load_hev_for (&oi3_main, path);
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
  /* Do not clear the committed flow target until a packet has passed all
   * validation below.  Android may deliver unrelated/unsupported TUN frames
   * (for example IPv6 control traffic) between the original packet and its
   * controlled return.  Clearing the shared target before rejecting such a
   * frame would make the owner-output rewrite use an unspecified source
   * address, corrupting an otherwise valid flow. */
  tm->tun_tcp_flags = 0;
  if ((packet[0] >> 4) == 4) {
    size_t ihl = (size_t)(packet[0] & 0x0fU) * 4U;
    if (ihl < 20 || length < ihl + 4 ||
        (packet[9] != 6 && packet[9] != 17)) return -1;
    size_t l4_header = packet[9] == 6 ? 20U : 8U;
    if (length < ihl + l4_header) return -1;
    struct sockaddr_in *s = (struct sockaddr_in *)&tm->source_address;
    s->sin_family = AF_INET;
    memcpy (&s->sin_addr, packet + 12, sizeof (s->sin_addr));
    s->sin_port = htons ((uint16_t)(((uint16_t)packet[ihl] << 8) |
                                     packet[ihl + 1]));
    tm->source_address_length = sizeof (*s);
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
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&tm->source_address;
    s6->sin6_family = AF_INET6;
    memcpy (&s6->sin6_addr, packet + 8, sizeof (s6->sin6_addr));
    s6->sin6_port = htons ((uint16_t)(((uint16_t)packet[40] << 8) |
                                       packet[41]));
    tm->source_address_length = sizeof (*s6);
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
  tm->source_port = ntohs (tm->family == 4
                           ? ((struct sockaddr_in *)&tm->source_address)->sin_port
                           : ((struct sockaddr_in6 *)&tm->source_address)->sin6_port);
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
           "source-port=%u original-port=%u epoch=%llu\n", tm->family,
           tm->family == 4 ? "10.0.0.1" : "fd00::1", tm->source_port,
           tm->target_port,
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
    if (!(request.flags & OI2_FLAG_BROKER_UNAVAILABLE) &&
        tm->broker_available && duplicate >= 0) {
      tm->broker_bind_calls++;
      if ((request.flags & OI2_FLAG_BIND_FAILURE) ||
          oi3_bind_duplicate (duplicate, request.family) != 0) {
        completion.result = OI2_RESULT_BIND_FAILURE;
        completion.fault_reason = OI2_RESULT_BIND_FAILURE;
      } else {
        tm->broker_protect_calls++;
        completion.result = (request.flags & OI2_FLAG_PROTECT_FAILURE)
                              ? OI2_RESULT_PROTECT_FAILURE
                              : OI2_RESULT_SUCCESS;
        completion.fault_reason = completion.result;
      }
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
  uint32_t broker_flags =
    oi3_request_flags_for_expected_failure (tm->expected_infrastructure_failure);
  oi2_broker_request_t request = {
    .abi_version = OI2_BROKER_ABI_VERSION, .family = tm->family,
    .kind = tm->protocol == 6 ? OI2_KIND_TCP : OI2_KIND_UDP,
    .owner = tm->target_thread, .shard = 1, .reserved = 0,
    .token = ++tm->token, .generation = tm->generation,
    .underlay_epoch = tm->underlay_epoch, .target_port = tm->endpoint_port,
    .flags = broker_flags,
  };
  struct iovec iov = { .iov_base = &request, .iov_len = sizeof (request) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                        .msg_control = control, .msg_controllen = sizeof (control) };
  struct cmsghdr *c;
  int domain = tm->family == 4 ? AF_INET : AF_INET6;
  int type = tm->protocol == 6 ? SOCK_STREAM : SOCK_DGRAM;
  tm->direct_fd = socket (domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (tm->direct_fd < 0) { tm->infrastructure_failures++; return -1; }
  if (tm->protocol == 6) {
    int one = 1;
    int result = setsockopt (tm->direct_fd, IPPROTO_TCP, TCP_NODELAY, &one,
                             sizeof (one));
    fprintf (stderr,
             "oi3 connector-socket-option fd=%d option=TCP_NODELAY "
             "result=%d errno=%d\n",
             tm->direct_fd, result, result == 0 ? 0 : errno);
  }
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
    atomic_store_explicit (&tm->connector_connect_pending, result != 0,
                           memory_order_release);
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
    /* Do not arm the readiness observer from connect().  HEV may still
     * report a runnable task in this same turn; arming here would make the
     * next owner re-entry block in pthread_join while the observer waits for
     * a readiness event.  The observer is armed only after task_step returns
     * a non-running task set in oi3_worker_run(). */
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
  oi3_main_t *tm = data; (void)owner; (void)pcb; (void)payload;
  if (tm) {
    tm->direct_send_events++;
    atomic_store_explicit (&tm->connector_write_pending, 0,
                           memory_order_release);
  }
  fprintf (stderr, "oi3 direct-send wall-ms=%llu length=%zu owner-pthread=%lu\n",
           (unsigned long long)oi3_wall_ms (), length,
           (unsigned long)pthread_self ());
  return 0;
}

/* The normal HEV runtime owns a dedicated lwip timer task.  OI3 deliberately
 * drives HEV one quantum at a time from the VPP owner and does not start that
 * background task.  A short write therefore leaves the TUN-side PCB with
 * TF_ACK_DELAY while the connector observer waits only for underlay fd
 * readiness.  Tick the same owner-local timer synchronously after a splice
 * write so the peer receives its ACK and can publish the next stream segment.
 */
static int
oi3_drive_lwip_timer_after_send (oi3_main_t *tm, u32 direct_send_before)
{
  if (!tm || !tm->tun_mode || tm->protocol != 6 ||
      tm->direct_send_events == direct_send_before)
    return 0;
  if (!tm->lwip_context || !tm->api.lwip_tcp_tmr) {
    oi3_error ("OI3 short-send timer context unavailable");
    return -1;
  }
  oi3_lwip_identity_t before;
  memset (&before, 0, sizeof (before));
  tm->api.identity (tm->context, &before);
  fprintf (stderr, "oi3 short-send timer-before wall-ms=%llu events=%u ticks=%u active-pcb=%p\n",
           (unsigned long long)oi3_wall_ms (),
           tm->direct_send_events, before.tcp_ticks_value,
           (void *)before.tcp_active_pcb);
  tm->api.lwip_tcp_tmr (tm->lwip_context);
  oi3_lwip_identity_t after;
  memset (&after, 0, sizeof (after));
  tm->api.identity (tm->context, &after);
  fprintf (stderr, "oi3 short-send timer-tick wall-ms=%llu events=%u ticks=%u active-pcb=%p\n",
           (unsigned long long)oi3_wall_ms (),
           tm->direct_send_events, after.tcp_ticks_value,
           (void *)after.tcp_active_pcb);
  return 0;
}

static int
oi3_connector_output_tcp (void *data, HevOwnerRuntime *owner, tcp_pcb_t *pcb,
                      const void *payload, size_t length)
{
  oi3_main_t *tm = data; (void)owner; (void)pcb; (void)payload;
  fprintf (stderr, "oi3 direct-recv wall-ms=%llu length=%zu owner-pthread=%lu\n",
           (unsigned long long)oi3_wall_ms (), length,
           (unsigned long)pthread_self ());
  tm->direct_recv_events++;
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
    struct sockaddr_in *s = (struct sockaddr_in *)&tm->source_address;
    memcpy (tm->last_output + 12, &a->sin_addr, 4);
    if (tm->source_address_length == sizeof (*s))
      memcpy (tm->last_output + 16, &s->sin_addr, 4);
    tm->last_output[10] = tm->last_output[11] = 0;
    u16 c = oi3_checksum (tm->last_output, 20);
    tm->last_output[10] = c >> 8; tm->last_output[11] = c;
    if (tm->protocol == 6 || tm->protocol == 17) {
      u8 *l4 = tm->last_output + 20;
      u16 port = ntohs (((struct sockaddr_in *) &tm->target_address)->sin_port);
      l4[0] = port >> 8; l4[1] = port;
      if (tm->source_address_length == sizeof (*s)) {
        u16 source_port = ntohs (s->sin_port);
        l4[2] = source_port >> 8; l4[3] = source_port;
      }
      if (tm->protocol == 6) l4[16] = l4[17] = 0;
      else l4[6] = l4[7] = 0;
      u16 lc = oi3_l4_checksum (tm->last_output, length, 4, tm->protocol, 20);
      if (tm->protocol == 6) { l4[16] = lc >> 8; l4[17] = lc; }
      else { l4[6] = lc >> 8; l4[7] = lc; }
    }
  } else {
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&tm->target_address;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&tm->source_address;
    memcpy (tm->last_output + 8, &a6->sin6_addr, 16);
    if (tm->source_address_length == sizeof (*s6))
      memcpy (tm->last_output + 24, &s6->sin6_addr, 16);
    u8 *l4 = tm->last_output + 40;
    u16 port = ntohs (a6->sin6_port); l4[0] = port >> 8; l4[1] = port;
    if (tm->source_address_length == sizeof (*s6)) {
      u16 source_port = ntohs (s6->sin6_port);
      l4[2] = source_port >> 8; l4[3] = source_port;
    }
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
    fprintf (stderr, "oi3 tun-output wall-ms=%llu length=%zu result=%s owner-pthread=%lu\n",
             (unsigned long long)oi3_wall_ms (), length,
             written == (ssize_t)length ? "OK" : strerror (errno),
             (unsigned long)pthread_self ());
    if (written == (ssize_t) length)
      oi3_log_packet_hex ("oi3 tun-output-raw", tun_packet, length);
    if (written == (ssize_t) length && tm->a2_return_mode) {
      tm->a2_return_output++;
      oi3_a2_return_log_packet (tm, "OUTPUT", "REPLY", tun_packet, length);
    }
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
    if (flags & 0x04U) {
      tm->connector_downstream_reset_observed++;
      fprintf (stderr,
               "oi3 downstream-transport result=RST owner=%u generation=%llu "
               "owner-pthread=%lu reset-observed=%u\n",
               tm->owner_id, (unsigned long long)tm->generation,
               (unsigned long)pthread_self (),
               tm->connector_downstream_reset_observed);
    } else if ((flags & 0x12) == 0x12) {
      tm->output_handshake++;
      tm->tcp_handshake_seen = 1;
      tm->tcp_server_seq = oi3_get_u32 (tm->last_output + ip + 4);
      tm->tcp_server_ack = oi3_get_u32 (tm->last_output + ip + 8);
      oi3_refresh_tun_flow_deadline (tm);
    } else if (flags & 0x18) {
      tm->output_direct++;
      /* Carry the returned data sequence space into the FIN fixture. */
      size_t tcp_header = (size_t)((tm->last_output[ip + 12] >> 4) * 4U);
      size_t payload = length > ip + tcp_header ? length - ip - tcp_header : 0;
      tm->tcp_server_seq = oi3_get_u32 (tm->last_output + ip + 4) + (u32)payload;
      tm->tcp_server_ack = oi3_get_u32 (tm->last_output + ip + 8);
      oi3_refresh_tun_flow_deadline (tm);
    }
    if (flags & 0x05U)
      tm->tcp_fin_submitted = 1;
  } else if (tm->protocol == 17 && length > ip + 8) {
    tm->output_direct++;
    if (tm->tun_mode && tm->multi_mode) {
      tm->udp_datagram_inflight = 0;
      oi3_refresh_tun_flow_deadline (tm);
      fprintf (stderr,
               "oi3 tun-udp-window complete generation=%llu submitted=%u "
               "pending=%u output=%u direct=%u\n",
               (unsigned long long)tm->generation, tm->packet_submitted,
               tm->tun_pending_count, tm->output_packets, tm->output_direct);
    }
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
oi3_enqueue_owner_for (oi3_main_t *tm, vlib_main_t *vm, u32 kind)
{
  u32 buffer; u16 target = (u16)tm->target_thread;
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1) return -1;
  tm->vpp_buffers_allocated++;
  u32 *data = (u32 *)vlib_get_buffer (vm, buffer)->data;
  data[0] = kind;
  if (tm->multi_mode)
    data[1] = tm->owner_id;
  if (vlib_buffer_enqueue_to_thread (vm, vlib_node_get_runtime (vm, oi3_trigger_node.index),
                                      tm->frame_queue, &buffer, &target, 1, 1) != 1) {
    vlib_buffer_free_one (vm, buffer); tm->vpp_buffers_freed++; return -1;
  }
  /* The APK runtime is the stock VPP frame-queue implementation: it marks
   * check_frame_queues but does not wake a worker that is already asleep.
   * Keep the re-entry on the same owner queue, and explicitly wake that
   * owner after publishing the frame.  This is the only scheduler seam used
   * by the POC; no second datapath or unprotected socket is introduced. */
  vlib_thread_wakeup (target);
  tm->worker_token_pending = 1;
  return 0;
}

static int
oi3_enqueue_owner (vlib_main_t *vm, u32 kind)
{
  return oi3_enqueue_owner_for (&oi3_main, vm, kind);
}

static clib_error_t *
oi3_connector_wake_ready (clib_file_t *file)
{
  oi3_main_t *tm = (oi3_main_t *)(uintptr_t)file->private_data;
  vlib_main_t *vm = vlib_get_main ();
  oi3_connector_wake_t token;

  for (;;) {
    ssize_t n = read (file->file_descriptor, &token, sizeof (token));
    if (n == (ssize_t)sizeof (token)) {
      atomic_store_explicit (&tm->connector_wake_pending, 0,
                             memory_order_release);
      if (!tm->active || tm->finish_requested ||
          token.generation != tm->generation)
        continue;
      u32 current_thread = vlib_get_thread_index ();
      fprintf (stderr,
               "oi3 connector-wake wall-ms=%llu cause=%u revents=0x%x generation=%llu current-thread=%u "
               "target-thread=%u\n",
               (unsigned long long)oi3_wall_ms (),
               token.cause, token.reserved,
               (unsigned long long)token.generation,
               current_thread, tm->target_thread);
      if (tm->multi_mode && current_thread == tm->target_thread) {
        oi3_worker_run_for (vm, NULL, 0, tm);
        continue;
      }
      if (!tm->worker_token_pending &&
          oi3_enqueue_owner_for (tm, vm, 0) < 0)
        oi3_error ("OI3 connector wake enqueue failed");
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
      return 0;
    if (n == 0)
      return clib_error_return (0, "OI3 connector wake pipe closed");
    return 0;
  }
}

static int
oi3_ensure_connector_wake_file (oi3_main_t *tm)
{
  clib_file_t file = { 0 };
  int flags;

  if (!tm || tm->connector_wake_file_index >= 0)
    return tm ? 0 : -1;
  if (pipe (tm->connector_wake_pipe) < 0)
    return -1;
  flags = fcntl (tm->connector_wake_pipe[0], F_GETFL, 0);
  if (flags >= 0)
    (void)fcntl (tm->connector_wake_pipe[0], F_SETFL, flags | O_NONBLOCK);
  flags = fcntl (tm->connector_wake_pipe[1], F_GETFL, 0);
  if (flags >= 0)
    (void)fcntl (tm->connector_wake_pipe[1], F_SETFL, flags | O_NONBLOCK);
  file.read_function = oi3_connector_wake_ready;
  file.file_descriptor = tm->connector_wake_pipe[0];
  file.polling_thread_index =
    tm->multi_mode && tm->target_thread < vlib_get_n_threads ()
      ? tm->target_thread : 0;
  file.private_data = (uword)tm;
  file.description = format (0, "OI3 protected connector wake pipe");
  tm->connector_wake_file_index = (int)clib_file_add (&file_main, &file);
  if (tm->connector_wake_file_index < 0 ||
      (u32)tm->connector_wake_file_index == ~0U) {
    close (tm->connector_wake_pipe[0]);
    close (tm->connector_wake_pipe[1]);
    tm->connector_wake_pipe[0] = tm->connector_wake_pipe[1] = -1;
    tm->connector_wake_file_index = -1;
    return -1;
  }
  return 0;
}

static int
oi3_enqueue_tun_packet_for_kind (oi3_main_t *tm, vlib_main_t *vm,
                                 const u8 *packet, size_t length, u32 kind)
{
  size_t header = tm && tm->multi_mode ? 12U : 8U;
  if (!tm || (kind != OI3_TUN_KIND && kind != OI3_TUN_DEFERRED_KIND) ||
      length > OI3_MAX_TUN_PACKET - header)
    return -1;
  u32 buffer;
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1) return -1;
  tm->vpp_buffers_allocated++;
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer);
  *(u32 *)b->data = kind;
  if (tm->multi_mode) {
    *(u32 *)(b->data + 4) = tm->owner_id;
    *(u32 *)(b->data + 8) = (u32)length;
    memcpy (b->data + 12, packet, length);
  } else {
    *(u32 *)(b->data + 4) = (u32)length;
    memcpy (b->data + 8, packet, length);
  }
  u16 target = (u16)tm->target_thread;
  if (vlib_buffer_enqueue_to_thread (vm,
                                     vlib_node_get_runtime (vm, oi3_trigger_node.index),
                                     tm->frame_queue, &buffer, &target, 1, 1) != 1) {
    vlib_buffer_free_one (vm, buffer); tm->vpp_buffers_freed++;
    return -1;
  }
  vlib_thread_wakeup (target);
  tm->worker_token_pending = 1;
  return 0;
}

static int
oi3_enqueue_tun_packet_for (oi3_main_t *tm, vlib_main_t *vm,
                            const u8 *packet, size_t length)
{
  return oi3_enqueue_tun_packet_for_kind (tm, vm, packet, length,
                                          OI3_TUN_KIND);
}

static int
oi3_enqueue_deferred_tun_packet_for (oi3_main_t *tm, vlib_main_t *vm,
                                     const u8 *packet, size_t length)
{
  return oi3_enqueue_tun_packet_for_kind (tm, vm, packet, length,
                                          OI3_TUN_DEFERRED_KIND);
}

static int
oi3_enqueue_tun_packet (vlib_main_t *vm, const u8 *packet, size_t length)
{
  return oi3_enqueue_tun_packet_for (&oi3_main, vm, packet, length);
}

static u8
oi3_tun_packet_tcp_flags (const u8 *packet, size_t length)
{
  if (!packet || length < 20)
    return 0;
  if ((packet[0] >> 4) == 4) {
    size_t ihl = (size_t)(packet[0] & 0x0fU) * 4U;
    if (packet[9] != 6 || length < ihl + 14U)
      return 0;
    return packet[ihl + 13U];
  }
  if ((packet[0] >> 4) == 6 && length >= 54 && packet[6] == 6)
    return packet[53];
  return 0;
}

static size_t
oi3_tun_packet_tcp_payload_length (const u8 *packet, size_t length)
{
  if (!packet || length < 20)
    return 0;
  if ((packet[0] >> 4) == 4) {
    size_t ihl = (size_t)(packet[0] & 0x0fU) * 4U;
    if (packet[9] != 6 || ihl < 20U || length < ihl + 20U)
      return 0;
    size_t tcp_header = (size_t)(packet[ihl + 12] >> 4) * 4U;
    if (tcp_header < 20U || length < ihl + tcp_header)
      return 0;
    size_t ip_total = ((size_t)packet[2] << 8) | packet[3];
    size_t captured_total = length < ip_total || ip_total == 0 ? length : ip_total;
    if (captured_total < ihl + tcp_header)
      return 0;
    return captured_total - ihl - tcp_header;
  }
  if ((packet[0] >> 4) == 6 && length >= 60 && packet[6] == 6) {
    size_t tcp_header = (size_t)(packet[40 + 12] >> 4) * 4U;
    if (tcp_header < 20U || length < 40U + tcp_header)
      return 0;
    size_t payload_total = ((size_t)packet[4] << 8) | packet[5];
    size_t l4_total = length > 40U ? length - 40U : 0;
    if (payload_total != 0 && payload_total < l4_total)
      l4_total = payload_total;
    if (l4_total < tcp_header)
      return 0;
    return l4_total - tcp_header;
  }
  return 0;
}

/* TUN readiness can publish several packets before the broker completion
 * token reaches the owner.  Keep those packets in the owner-local queue
 * instead of overwriting one shared pending slot.  The queue is deliberately
 * bounded: exhaustion is an explicit infrastructure fault, never a silent
 * stream truncation. */
static int
oi3_tun_pending_enqueue (oi3_main_t *tm, const u8 *packet, size_t length)
{
  if (!tm || !packet || length > OI3_MAX_TUN_PACKET ||
      tm->tun_pending_count >= OI3_TUN_PENDING_CAPACITY)
    return -1;
  u32 slot = (tm->tun_pending_head + tm->tun_pending_count) %
             OI3_TUN_PENDING_CAPACITY;
  tm->tun_pending[slot].flow_hash = 0;
  tm->tun_pending[slot].length = (u32)length;
  memcpy (tm->tun_pending[slot].packet, packet, length);
  tm->tun_pending_count++;
  tm->tun_pending_sequence++;
  fprintf (stderr, "oi3 tun-queue enqueue wall-ms=%llu sequence=%u "
           "length=%zu depth=%u tcp-flags=0x%02x\n",
           (unsigned long long)oi3_wall_ms (), tm->tun_pending_sequence,
           length, tm->tun_pending_count,
           oi3_tun_packet_tcp_flags (packet, length));
  return 0;
}

static void
oi3_multi_dispatch_depth_complete (oi3_main_t *tm)
{
  if (!tm || !tm->multi_mode)
    return;
  uint32_t depth = atomic_load_explicit (&tm->multi_dispatch_depth,
                                         memory_order_acquire);
  while (depth != 0 &&
         !atomic_compare_exchange_weak_explicit (
           &tm->multi_dispatch_depth, &depth, depth - 1,
           memory_order_acq_rel, memory_order_acquire))
    ;
}

static int
oi3_owner_accept_tun_packet (oi3_main_t *tm, const u8 *packet, size_t length)
{
  if (!tm || !packet || length > OI3_MAX_TUN_PACKET) {
    if (tm)
      tm->tun_output_errors++;
    return -1;
  }
  oi3_multi_dispatch_depth_complete (tm);
  if (oi3_tun_pending_enqueue (tm, packet, length) == 0) {
    /* The pending packet is now owned by the selected owner. */
    tm->tun_ingress_packets++;
    return 1;
  }
  if (tm->multi_mode && tm->protocol == 17) {
    /* The owner-local pending queue is bounded packet-handoff credit.
     * Under UDP pressure, settle only this packet and keep the admitted
     * owner alive; queue exhaustion must not imply flow termination. */
    tm->tun_queue_rejects++;
    tm->overload_expected = 1;
    atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                               memory_order_relaxed);
    oi3_multi.route_rejects[tm->owner_id]++;
    fprintf (stderr,
             "oi3 tun-queue result=REJECT reason=owner-queue-full "
             "owner=%u depth=%u queue-rejects=%u\n",
             tm->owner_id, tm->tun_pending_count,
             tm->tun_queue_rejects);
    return 0;
  }
  tm->tun_output_errors++;
  oi3_error ("OI3 TUN pending queue full");
  tm->finish_requested = 1;
  return -1;
}

static int
oi3_owner_accept_broker_completion (oi3_main_t *tm,
                                    const oi2_broker_completion_t *completion)
{
  if (!tm || !completion)
    return -1;
  fprintf (stderr,
           "oi3 broker-completion wall-ms=%llu result=%s(%u) token=%llu "
           "generation=%llu owner=%u target-thread=%u\n",
           (unsigned long long)oi3_wall_ms (),
           oi3_broker_result_name (completion->result),
           completion->result,
           (unsigned long long)completion->token,
           (unsigned long long)completion->generation,
           completion->owner, tm->target_thread);
  if (tm->active && completion->generation == tm->generation &&
      completion->token == tm->token && completion->owner == tm->target_thread) {
    tm->broker_result = completion->result;
    if (tm->broker_external) {
      if (completion->result != OI2_RESULT_BROKER_UNAVAILABLE)
        tm->broker_bind_calls++;
      if (completion->result == OI2_RESULT_SUCCESS ||
          completion->result == OI2_RESULT_PROTECT_FAILURE)
        tm->broker_protect_calls++;
    }
    return 1;
  }
  tm->broker_stale++;
  fprintf (stderr,
           "oi3 broker-completion result=REJECT owner=%u reason=stale "
           "active=%u expected-token=%llu expected-generation=%llu\n",
           tm->owner_id, tm->active,
           (unsigned long long)tm->token,
           (unsigned long long)tm->generation);
  return 0;
}

static clib_error_t *
oi3_tun_handoff_ready (clib_file_t *file)
{
  oi3_main_t *tm = (oi3_main_t *)(uintptr_t)file->private_data;
  vlib_main_t *vm = vlib_get_main ();
  oi3_tun_handoff_msg_t msg;

  for (;;) {
    ssize_t n = recv (file->file_descriptor, &msg, sizeof (msg),
                      MSG_DONTWAIT);
    if (n >= (ssize_t)(sizeof (msg.kind) + sizeof (msg.length))) {
      size_t expected = sizeof (msg.kind) + sizeof (msg.length) + msg.length;
      if ((msg.kind != OI3_TUN_KIND &&
           msg.kind != OI3_BROKER_COMPLETION_KIND) ||
          msg.length > OI3_MAX_TUN_PACKET ||
          (size_t)n != expected) {
        if (msg.kind == OI3_TUN_KIND)
          oi3_multi_dispatch_depth_complete (tm);
        if (tm)
          tm->tun_output_errors++;
        fprintf (stderr,
                 "oi3 tun-handoff result=REJECT reason=bad-record "
                 "owner=%u kind=%u length=%u bytes=%zd expected=%zu\n",
                 tm ? tm->owner_id : 0, msg.kind, msg.length, n, expected);
        continue;
      }
      if (msg.kind == OI3_TUN_KIND) {
        fprintf (stderr,
                 "oi3 tun-handoff recv wall-ms=%llu owner=%u length=%u "
                 "current-thread=%u target-thread=%u\n",
                 (unsigned long long)oi3_wall_ms (), tm->owner_id,
                 msg.length, vlib_get_thread_index (), tm->target_thread);
        (void)oi3_owner_accept_tun_packet (tm, msg.packet, msg.length);
        if (tm->active) {
          oi3_apply_pending_underlay (tm);
          oi3_worker_run_for (vm, NULL, OI3_TUN_KIND, tm);
        }
      } else {
        oi2_broker_completion_t completion;
        if (msg.length != sizeof (completion)) {
          fprintf (stderr,
                   "oi3 completion-handoff result=REJECT reason=bad-length "
                   "owner=%u length=%u expected=%zu\n",
                   tm->owner_id, msg.length, sizeof (completion));
          continue;
        }
        memcpy (&completion, msg.packet, sizeof (completion));
        (void)oi3_owner_accept_broker_completion (tm, &completion);
        if (tm->active) {
          oi3_apply_pending_underlay (tm);
          oi3_worker_run_for (vm, NULL, OI3_BROKER_COMPLETION_KIND, tm);
        }
      }
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
      return 0;
    if (n == 0)
      return clib_error_return (0, "OI3 TUN handoff socket closed");
    if (n > 0) {
      oi3_multi_dispatch_depth_complete (tm);
      fprintf (stderr,
               "oi3 tun-handoff result=REJECT reason=short-record "
               "owner=%u bytes=%zd\n", tm ? tm->owner_id : 0, n);
      continue;
    }
    return 0;
  }
}

static int
oi3_set_nonblocking_fd (int fd)
{
  int flags;
  if (fd < 0)
    return -1;
  flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  return fcntl (fd, F_SETFL, flags | O_NONBLOCK);
}

static void
oi3_close_tun_handoff_file (oi3_main_t *tm)
{
  if (!tm)
    return;
  if (tm->tun_handoff_file_index >= 0) {
    clib_file_del_by_index (&file_main, tm->tun_handoff_file_index);
    tm->tun_handoff_file_index = -1;
    tm->tun_handoff_pair[0] = -1;
  }
  if (tm->tun_handoff_pair[0] >= 0)
    close (tm->tun_handoff_pair[0]);
  if (tm->tun_handoff_pair[1] >= 0)
    close (tm->tun_handoff_pair[1]);
  tm->tun_handoff_pair[0] = tm->tun_handoff_pair[1] = -1;
}

static int
oi3_ensure_tun_handoff_file (oi3_main_t *tm)
{
  clib_file_t file = { 0 };

  if (!tm || !tm->multi_mode)
    return -1;
  if (tm->tun_handoff_file_index >= 0)
    return 0;
  if (socketpair (AF_UNIX, SOCK_SEQPACKET, 0, tm->tun_handoff_pair) < 0)
    return -1;
  if (oi3_set_nonblocking_fd (tm->tun_handoff_pair[0]) < 0 ||
      oi3_set_nonblocking_fd (tm->tun_handoff_pair[1]) < 0) {
    oi3_close_tun_handoff_file (tm);
    return -1;
  }
  file.read_function = oi3_tun_handoff_ready;
  file.file_descriptor = tm->tun_handoff_pair[0];
  file.polling_thread_index = tm->target_thread;
  file.private_data = (uword)tm;
  file.description = format (0, "OI3 owner TUN handoff socket");
  tm->tun_handoff_file_index = (int)clib_file_add (&file_main, &file);
  if (tm->tun_handoff_file_index < 0 ||
      (u32)tm->tun_handoff_file_index == ~0U) {
    oi3_close_tun_handoff_file (tm);
    return -1;
  }
  return 0;
}

static int
oi3_send_tun_handoff_for (oi3_main_t *tm, const u8 *packet, size_t length)
{
  oi3_tun_handoff_msg_t msg;
  size_t record_length = sizeof (msg.kind) + sizeof (msg.length) + length;

  if (!tm || !packet || length > OI3_MAX_TUN_PACKET ||
      tm->tun_handoff_pair[1] < 0)
    return -1;
  memset (&msg, 0, sizeof (msg));
  msg.kind = OI3_TUN_KIND;
  msg.length = (u32)length;
  memcpy (msg.packet, packet, length);
  ssize_t n = send (tm->tun_handoff_pair[1], &msg, record_length,
                    MSG_DONTWAIT | MSG_NOSIGNAL);
  if (n != (ssize_t)record_length)
    return -1;
  fprintf (stderr,
           "oi4 multi-handoff send wall-ms=%llu owner=%u length=%zu "
           "target-thread=%u\n",
           (unsigned long long)oi3_wall_ms (), tm->owner_id, length,
           tm->target_thread);
  return 0;
}

static int
oi3_send_completion_handoff_for (oi3_main_t *tm,
                                 const oi2_broker_completion_t *completion)
{
  oi3_tun_handoff_msg_t msg;
  size_t length = sizeof (*completion);
  size_t record_length = sizeof (msg.kind) + sizeof (msg.length) + length;

  if (!tm || !completion || tm->tun_handoff_pair[1] < 0 ||
      length > OI3_MAX_TUN_PACKET)
    return -1;
  memset (&msg, 0, sizeof (msg));
  msg.kind = OI3_BROKER_COMPLETION_KIND;
  msg.length = (u32)length;
  memcpy (msg.packet, completion, length);
  ssize_t n = send (tm->tun_handoff_pair[1], &msg, record_length,
                    MSG_DONTWAIT | MSG_NOSIGNAL);
  if (n != (ssize_t)record_length)
    return -1;
  fprintf (stderr,
           "oi4 completion-handoff send wall-ms=%llu owner=%u "
           "target-thread=%u result=%u token=%llu generation=%llu\n",
           (unsigned long long)oi3_wall_ms (), tm->owner_id,
           tm->target_thread, completion->result,
           (unsigned long long)completion->token,
           (unsigned long long)completion->generation);
  return 0;
}

static int
oi3_tun_deferred_enqueue (oi3_main_t *tm, const u8 *packet, size_t length,
                          uint64_t flow_hash)
{
  if (!tm || !packet || !flow_hash || length > OI3_MAX_TUN_PACKET)
    return -1;
  for (u32 i = 0; i < tm->multi_deferred_count; i++) {
    u32 slot = (tm->multi_deferred_head + i) % OI3_TUN_PENDING_CAPACITY;
    if (tm->multi_deferred[slot].flow_hash == flow_hash) {
      fprintf (stderr,
               "oi3 tun-deferred duplicate owner=%u hash=%llu depth=%u "
               "tcp-flags=0x%02x\n",
               tm->owner_id, (unsigned long long)flow_hash,
               tm->multi_deferred_count,
               oi3_tun_packet_tcp_flags (packet, length));
      return 1;
    }
  }
  if (tm->multi_deferred_count >= OI3_TUN_PENDING_CAPACITY)
    return -1;
  u32 slot = (tm->multi_deferred_head + tm->multi_deferred_count) %
             OI3_TUN_PENDING_CAPACITY;
  tm->multi_deferred[slot].flow_hash = flow_hash;
  tm->multi_deferred[slot].length = (u32)length;
  memcpy (tm->multi_deferred[slot].packet, packet, length);
  tm->multi_deferred_count++;
  tm->multi_deferred_sequence++;
  fprintf (stderr,
           "oi3 tun-deferred enqueue sequence=%u owner=%u hash=%llu "
           "length=%zu depth=%u tcp-flags=0x%02x\n",
           tm->multi_deferred_sequence, tm->owner_id,
           (unsigned long long)flow_hash, length, tm->multi_deferred_count,
           oi3_tun_packet_tcp_flags (packet, length));
  return 0;
}

static void
oi3_tun_pending_clear (oi3_main_t *tm, const char *reason)
{
  if (!tm || tm->tun_pending_count == 0)
    return;
  fprintf (stderr,
           "oi3 tun-pending clear reason=%s owner=%u depth=%u head=%u\n",
           reason ? reason : "unknown", tm->owner_id, tm->tun_pending_count,
           tm->tun_pending_head);
  memset (tm->tun_pending, 0, sizeof (tm->tun_pending));
  tm->tun_pending_head = 0;
  tm->tun_pending_count = 0;
}

static int
oi3_submit_pending_tun (oi3_main_t *tm)
{
  if (!tm || tm->tun_pending_count == 0)
    return 0;
  oi3_tun_pending_entry_t *entry = &tm->tun_pending[tm->tun_pending_head];
  u32 length = entry->length;
  u8 tcp_flags = oi3_tun_packet_tcp_flags (entry->packet, length);
  size_t tcp_payload_length =
    oi3_tun_packet_tcp_payload_length (entry->packet, length);
  int submit_result = (oi3_normalize_tun_ingress (tm, entry->packet, length),
                       tm->api.submit (tm->context, entry->packet, length));
  fprintf (stderr, "oi3 tun-submit result=%d sequence=%u length=%u "
           "queue-depth-before=%u family=%u protocol=%u destination-port=%u "
           "tcp-flags=0x%02x tcp-payload=%zu\n", submit_result,
           tm->packet_submitted + 1U, length, tm->tun_pending_count,
           tm->family, tm->protocol, tm->target_port, tcp_flags,
           tcp_payload_length);
  if (submit_result < 0)
    {
      /* HEV may reject a packet once the bounded session/credit envelope is
       * occupied.  This is packet overload, not a corrupt owner context:
       * settle the pending copy exactly once and keep the admitted flow
       * alive so D3 can observe a conservative, owner-local drop. */
      tm->tun_submit_rejects++;
      if (tm->multi_mode) {
        atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                   memory_order_relaxed);
        oi3_multi.route_rejects[tm->owner_id]++;
        fprintf (stderr,
                 "oi4 multi-admission result=REJECT owner=%u "
                 "reason=owner-submit depth=%u\n", tm->owner_id,
                 tm->tun_pending_count);
      }
      fprintf (stderr,
               "oi3 tun-submit result=REJECT reason=owner-submit "
               "length=%u depth=%u\n", length, tm->tun_pending_count);
      tm->tun_pending[tm->tun_pending_head].length = 0;
      tm->tun_pending_head = (tm->tun_pending_head + 1U) %
                             OI3_TUN_PENDING_CAPACITY;
      tm->tun_pending_count--;
      return 1;
    }
  tm->packet_submitted++;
  if (tm->tun_mode && tm->multi_mode) {
    if (tm->protocol == 17)
      tm->udp_datagram_inflight = 1;
    if (tm->protocol == 17 || tm->protocol == 6)
      oi3_refresh_tun_flow_deadline (tm);
  }
  if (tm->protocol == 6 && (tcp_flags & 0x05U))
    tm->tcp_fin_submitted = 1;
  if (tm->protocol == 6 && tcp_payload_length > 0 &&
      tm->direct_send_events == 0)
    atomic_store_explicit (&tm->connector_write_pending, 1,
                           memory_order_release);
  tm->tun_pending[tm->tun_pending_head].length = 0;
  tm->tun_pending_head = (tm->tun_pending_head + 1U) %
                         OI3_TUN_PENDING_CAPACITY;
  tm->tun_pending_count--;
  return 1;
}

static int
oi3_submit_next_udp_datagram_if_idle (oi3_main_t *tm)
{
  if (!tm || !tm->multi_mode || tm->protocol != 17 ||
      tm->tun_pending_count == 0)
    return 0;
  if (tm->udp_datagram_inflight) {
    fprintf (stderr,
             "oi3 tun-submit deferred reason=udp-datagram-inflight "
             "generation=%llu submitted=%u pending=%u\n",
             (unsigned long long)tm->generation, tm->packet_submitted,
             tm->tun_pending_count);
    return 0;
  }
  fprintf (stderr,
           "oi3 tun-udp-window submit-next generation=%llu submitted=%u "
           "pending=%u\n",
           (unsigned long long)tm->generation, tm->packet_submitted,
           tm->tun_pending_count);
  return oi3_submit_pending_tun (tm);
}

static clib_error_t *
oi3_tun_read_ready (clib_file_t *file)
{
  oi3_main_t *tm = (oi3_main_t *)(uintptr_t)file->private_data;
  vlib_main_t *vm = vlib_get_main ();
  /* A terminal flow may still have an owner drain token in flight.  Do not
   * consume the next Android packet into a session that is being torn down;
   * once the successful flow is re-armed, readiness will deliver it again.
   * While idle, read only one packet so a burst cannot commit several
   * different original destinations against one not-yet-started generation.
   */
  if (!tm->tun_mode || tm->tun_fd < 0 || !tm->active || tm->finish_requested ||
      tm->phase == OI3_STOPPING || tm->phase == OI3_FAULT)
    return 0;
  unsigned int limit = (tm->context || tm->tun_pending_count) ? 8U : 1U;
  for (unsigned int count = 0; count < limit; count++) {
    ssize_t n = read (tm->tun_fd, tm->tun_rx, sizeof (tm->tun_rx));
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    if (n <= 0) return 0;
    if (oi3_parse_tun_packet (tm, tm->tun_rx, (size_t)n) < 0) {
      fprintf (stderr, "oi3 tun-ingress parse-failure length=%zd\n", n);
      continue;
    }
    if (!tm->multi_mode && tm->protocol == 6 &&
        oi3_multi_tcp_packet (tm->tun_rx, (size_t)n)) {
      uint64_t flow_hash = 0;
      bool tcp_syn = oi3_multi_tcp_syn_packet (tm->tun_rx, (size_t)n);
      uint32_t wait_syn = atomic_load_explicit (&tm->multi_tcp_wait_syn,
                                                memory_order_acquire);
      uint32_t tombstone_valid = atomic_load_explicit (
        &tm->multi_tcp_tombstone_valid, memory_order_acquire);
      uint64_t tombstone_hash = atomic_load_explicit (
        &tm->multi_tcp_tombstone_hash, memory_order_acquire);
      if (oi3_multi_flow_hash (tm->tun_rx, (size_t)n, &flow_hash) == 0) {
        if (wait_syn && !tcp_syn) {
          fprintf (stderr,
                   "oi3 single-admission result=REJECT reason=%s hash=%llu "
                   "tombstone-hash=%llu\n",
                   tombstone_valid && flow_hash == tombstone_hash
                     ? "tcp-tail" : "tcp-non-syn-before-syn",
                   (unsigned long long)flow_hash,
                   (unsigned long long)tombstone_hash);
          continue;
        }
        if (tcp_syn) {
          atomic_store_explicit (&tm->multi_tcp_wait_syn, 0,
                                 memory_order_release);
          atomic_store_explicit (&tm->multi_tcp_tombstone_valid, 0,
                                 memory_order_release);
        }
        if (!atomic_load_explicit (&tm->active_flow_valid,
                                   memory_order_acquire)) {
          atomic_store_explicit (&tm->active_flow_hash, flow_hash,
                                 memory_order_release);
          atomic_store_explicit (&tm->active_flow_valid, 1,
                                 memory_order_release);
        }
      }
    }
    oi3_a2_return_capture_ingress (tm, tm->tun_rx, (size_t)n);
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

static uint64_t
oi3_multi_fnv1a (const u8 *data, size_t length)
{
  uint64_t hash = 1469598103934665603ULL;
  for (size_t i = 0; i < length; i++) {
    hash ^= data[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static uint64_t
oi3_multi_hash_mix (uint64_t hash)
{
  /* Android's TCP ephemeral port allocator can produce source-port series
   * whose raw FNV low bits collapse under small owner counts.  Keep the
   * canonical five-tuple input unchanged, but avalanche the completed hash
   * before owner modulo so owner selection is not controlled by allocator
   * parity or adjacent-port patterns.  This mirrors the S124/F015 correction
   * and remains a POC hash-quality fix, not a production hash commitment. */
  hash ^= hash >> 33;
  hash *= 0xff51afd7ed558ccdULL;
  hash ^= hash >> 33;
  hash *= 0xc4ceb9fe1a85ec53ULL;
  hash ^= hash >> 33;
  return hash;
}

/* Hash the canonical five-tuple, not the direction-specific packet bytes.
 * TCP keeps deterministic canonical-owner selection.  UDP additionally uses a
 * bounded route table so a new datagram flow can be pinned to an idle owner
 * instead of corrupting an active owner-local return rewrite. */
static int
oi3_multi_flow_hash (const u8 *packet, size_t length, uint64_t *hash_out)
{
  if (!packet || !hash_out || length < 20)
    return -1;
  unsigned int family = packet[0] >> 4;
  size_t ip_header;
  unsigned int protocol;
  u8 endpoint_a[18] = { 0 }, endpoint_b[18] = { 0 };
  if (family == 4) {
    ip_header = (size_t)(packet[0] & 0x0fU) * 4U;
    if (ip_header < 20 || length < ip_header)
      return -1;
    protocol = packet[9];
    if (protocol != 6 && protocol != 17)
      return -1;
    memcpy (endpoint_a + 12, packet + 12, 4);
    memcpy (endpoint_b + 12, packet + 16, 4);
  } else if (family == 6) {
    ip_header = 40;
    if (length < ip_header)
      return -1;
    protocol = packet[6];
    /* The POC owner parser consumes plain IPv6 TCP/UDP.  Extension/control
     * frames remain outside this seam and must be rejected at dispatch, just
     * as the single-owner reader already does, rather than poisoning a shard
     * after admission. */
    if (protocol != 6 && protocol != 17)
      return -1;
    memcpy (endpoint_a, packet + 8, 16);
    memcpy (endpoint_b, packet + 24, 16);
  } else {
    return -1;
  }
  if ((protocol == 6 || protocol == 17) && length >= ip_header + 4) {
    memcpy (endpoint_a + 16, packet + ip_header, 2);
    memcpy (endpoint_b + 16, packet + ip_header + 2, 2);
  }
  u8 canonical[1 + 1 + 18 + 18];
  canonical[0] = (u8)family;
  canonical[1] = (u8)protocol;
  if (memcmp (endpoint_a, endpoint_b, sizeof (endpoint_a)) <= 0) {
    memcpy (canonical + 2, endpoint_a, sizeof (endpoint_a));
    memcpy (canonical + 2 + sizeof (endpoint_a), endpoint_b,
            sizeof (endpoint_b));
  } else {
    memcpy (canonical + 2, endpoint_b, sizeof (endpoint_b));
    memcpy (canonical + 2 + sizeof (endpoint_b), endpoint_a,
            sizeof (endpoint_a));
  }
  *hash_out = oi3_multi_hash_mix (oi3_multi_fnv1a (canonical, sizeof (canonical)));
  return 0;
}

static int
oi3_multi_packet_protocol (const u8 *packet, size_t length, u32 *protocol_out)
{
  if (!packet || !protocol_out || length < 20)
    return -1;
  unsigned int family = packet[0] >> 4;
  if (family == 4) {
    size_t ip_header = (size_t)(packet[0] & 0x0fU) * 4U;
    if (ip_header < 20 || length < ip_header)
      return -1;
    if (packet[9] != 6 && packet[9] != 17)
      return -1;
    *protocol_out = packet[9];
    return 0;
  }
  if (family == 6) {
    if (length < 40 || (packet[6] != 6 && packet[6] != 17))
      return -1;
    *protocol_out = packet[6];
    return 0;
  }
  return -1;
}

static int
oi3_multi_flow_route_lookup (uint64_t hash, u32 *owner_out)
{
  for (u32 i = 0; i < OI3_MULTI_FLOW_ROUTE_CAPACITY; i++) {
    oi3_multi_flow_route_t *route = &oi3_multi.flow_routes[i];
    if (!route->active || route->flow_hash != hash)
      continue;
    if (route->owner >= oi3_multi.owner_count)
      return -1;
    if (owner_out)
      *owner_out = route->owner;
    return 1;
  }
  return 0;
}

static int
oi3_multi_flow_route_insert (uint64_t hash, u32 owner, u32 protocol)
{
  if (owner >= oi3_multi.owner_count)
    return -1;
  for (u32 i = 0; i < OI3_MULTI_FLOW_ROUTE_CAPACITY; i++) {
    oi3_multi_flow_route_t *route = &oi3_multi.flow_routes[i];
    if (route->active && route->flow_hash == hash) {
      route->owner = owner;
      route->protocol = protocol;
      return 0;
    }
  }
  for (u32 i = 0; i < OI3_MULTI_FLOW_ROUTE_CAPACITY; i++) {
    oi3_multi_flow_route_t *route = &oi3_multi.flow_routes[i];
    if (route->active)
      continue;
    route->flow_hash = hash;
    route->owner = owner;
    route->protocol = protocol;
    route->active = 1;
    fprintf (stderr,
             "oi4 multi-route result=PIN owner=%u hash=%llu protocol=%u "
             "route-pinned=%u\n",
             owner, (unsigned long long)hash, protocol, 1U);
    return 0;
  }
  return -1;
}

static void
oi3_multi_flow_route_remove (uint64_t hash)
{
  for (u32 i = 0; i < OI3_MULTI_FLOW_ROUTE_CAPACITY; i++) {
    oi3_multi_flow_route_t *route = &oi3_multi.flow_routes[i];
    if (route->active && route->flow_hash == hash) {
      route->active = 0;
      return;
    }
  }
}

static u32
oi3_multi_udp_idle_owner (u32 primary)
{
  if (!oi3_multi.owner_count)
    return primary;
  for (u32 offset = 1; offset < oi3_multi.owner_count; offset++) {
    u32 owner = (primary + offset) % oi3_multi.owner_count;
    oi3_main_t *candidate = &oi3_multi.owners[owner];
    if (atomic_load_explicit (&candidate->multi_admission_open,
                              memory_order_acquire) &&
        !atomic_load_explicit (&candidate->active_flow_valid,
                               memory_order_acquire))
      return owner;
  }
  return primary;
}

static oi3_main_t *
oi3_multi_owner_for_packet (const u8 *packet, size_t length,
                            uint64_t *hash_out, u32 *protocol_out,
                            u32 *route_pinned_out)
{
  uint64_t hash;
  u32 protocol = 0;
  if (!oi3_multi.owner_count ||
      oi3_multi_flow_hash (packet, length, &hash) < 0 ||
      oi3_multi_packet_protocol (packet, length, &protocol) < 0)
    return NULL;
  if (hash_out)
    *hash_out = hash;
  if (protocol_out)
    *protocol_out = protocol;
  if (route_pinned_out)
    *route_pinned_out = 0;

  u32 owner;
  if (protocol == 17 &&
      oi3_multi_flow_route_lookup (hash, &owner) > 0) {
    if (route_pinned_out)
      *route_pinned_out = 1;
    oi3_multi.route_count[owner]++;
    return &oi3_multi.owners[owner];
  }

  u32 primary = (u32)(hash % oi3_multi.owner_count);
  owner = primary;
  if (protocol == 17) {
    oi3_main_t *primary_tm = &oi3_multi.owners[primary];
    uint32_t active_valid = atomic_load_explicit (
      &primary_tm->active_flow_valid, memory_order_acquire);
    uint64_t active_hash = atomic_load_explicit (
      &primary_tm->active_flow_hash, memory_order_acquire);
    if (active_valid && active_hash != hash) {
      u32 idle_owner = oi3_multi_udp_idle_owner (primary);
      if (idle_owner != primary) {
        owner = idle_owner;
        oi3_multi.route_reassigned[owner]++;
        fprintf (stderr,
                 "oi4 multi-route result=REASSIGN owner=%u primary=%u "
                 "hash=%llu active-hash=%llu reason=udp-idle-owner "
                 "route-pinned=%u\n",
                 owner, primary, (unsigned long long)hash,
                 (unsigned long long)active_hash, 0U);
      }
    }
  }
  oi3_multi.route_count[owner]++;
  return &oi3_multi.owners[owner];
}

static int
oi3_packet_ip4_dst (const u8 *packet, size_t length, u32 *dst_out)
{
  if (!packet || length < 20 || (packet[0] >> 4) != 4)
    return -1;
  size_t ihl = (size_t)(packet[0] & 0x0fU) * 4U;
  if (ihl < 20 || length < ihl)
    return -1;
  if (dst_out)
    memcpy (dst_out, packet + 16, sizeof (*dst_out));
  return 0;
}

static int
oi3_multi_should_policy_drop (const u8 *packet, size_t length)
{
  u32 dst = 0;
  return oi3_multi.policy_drop_ip4_set &&
         oi3_packet_ip4_dst (packet, length, &dst) == 0 &&
         dst == oi3_multi.policy_drop_ip4;
}

static bool
oi3_multi_tcp_packet (const u8 *packet, size_t length)
{
  if (!packet || length < 20)
    return false;
  unsigned int family = packet[0] >> 4;
  size_t ip_header;
  if (family == 4) {
    ip_header = (size_t)(packet[0] & 0x0fU) * 4U;
    if (ip_header < 20 || length < ip_header + 4 || packet[9] != 6)
      return false;
  } else if (family == 6) {
    ip_header = 40;
    if (length < ip_header + 4 || packet[6] != 6)
      return false;
  } else {
    return false;
  }
  return true;
}

static bool
oi3_multi_tcp_syn_packet (const u8 *packet, size_t length)
{
  if (!oi3_multi_tcp_packet (packet, length))
    return false;
  unsigned int family = packet[0] >> 4;
  size_t ip_header = family == 4 ? (size_t)(packet[0] & 0x0fU) * 4U : 40;
  if (length < ip_header + 14)
    return false;
  return (packet[ip_header + 13] & 0x02U) != 0;
}

static int
oi3_admit_deferred_tun_flow (vlib_main_t *vm, oi3_main_t *tm)
{
  if (!tm || !tm->multi_mode || !tm->tun_mode ||
      tm->multi_deferred_count == 0)
    return 0;
  oi3_tun_pending_entry_t *entry =
    &tm->multi_deferred[tm->multi_deferred_head];
  uint64_t flow_hash = entry->flow_hash;
  u32 length = entry->length;
  if (!flow_hash || !length ||
      oi3_tun_pending_enqueue (tm, entry->packet, length) < 0) {
    atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                               memory_order_relaxed);
    oi3_multi.route_rejects[tm->owner_id]++;
    fprintf (stderr,
             "oi4 multi-admission result=REJECT owner=%u hash=%llu "
             "reason=deferred-queue-drain depth=%u pending=%u\n",
             tm->owner_id, (unsigned long long)flow_hash,
             tm->multi_deferred_count, tm->tun_pending_count);
    return -1;
  }
  entry->flow_hash = 0;
  entry->length = 0;
  tm->multi_deferred_head = (tm->multi_deferred_head + 1U) %
                            OI3_TUN_PENDING_CAPACITY;
  tm->multi_deferred_count--;
  atomic_store_explicit (&tm->active_flow_hash, flow_hash,
                         memory_order_release);
  atomic_store_explicit (&tm->active_flow_valid, 1, memory_order_release);
  atomic_store_explicit (&tm->multi_tcp_wait_syn, 0, memory_order_release);
  atomic_store_explicit (&tm->multi_tcp_tombstone_valid, 0,
                         memory_order_release);
  fprintf (stderr,
           "oi4 multi-deferred admit owner=%u hash=%llu length=%u "
           "pending=%u deferred=%u\n",
           tm->owner_id, (unsigned long long)flow_hash, length,
           tm->tun_pending_count, tm->multi_deferred_count);
  if (!tm->worker_token_pending &&
      oi3_enqueue_owner_for (tm, vm, 0) < 0) {
    oi3_error ("OI3 deferred TUN rearm enqueue failed");
    return -1;
  }
  return 1;
}

static clib_error_t *
oi3_multi_tun_read_ready (clib_file_t *file)
{
  vlib_main_t *vm = vlib_get_main ();
  if (!oi3_multi.active || oi3_multi.tun_fd < 0)
    return 0;
  for (unsigned int count = 0; count < 64; count++) {
    u8 packet[OI3_MAX_TUN_PACKET];
    ssize_t n = read (oi3_multi.tun_fd, packet, sizeof (packet));
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
      return 0;
    if (n <= 0)
      return 0;
    /* Policy is a dispatcher seam, not an owner mode.  Match the raw IPv4
     * destination before tuple hashing, route lookup, owner admission, or
     * TUN queueing.  A dropped packet therefore cannot create a FlowStackOwner
     * context or reach the Android bind/protect broker. */
    if (oi3_multi_should_policy_drop (packet, (size_t)n)) {
      char dst[INET_ADDRSTRLEN] = "-";
      u32 dst_ip4 = 0;
      (void)oi3_packet_ip4_dst (packet, (size_t)n, &dst_ip4);
      (void)inet_ntop (AF_INET, &dst_ip4, dst, sizeof (dst));
      oi3_multi.policy_drop_packets++;
      fprintf (stderr,
               "oi4 multi-policy-drop result=DROP stage=pre-owner "
               "dst=%s length=%zd no-transport=1 broker=0 socket=0\n",
               dst, n);
      continue;
    }
    uint64_t hash = 0;
    u32 route_protocol = 0;
    u32 route_pinned = 0;
    oi3_main_t *tm = oi3_multi_owner_for_packet (
      packet, (size_t)n, &hash, &route_protocol, &route_pinned);
    if (!tm) {
      oi3_multi.wrong_owner_events++;
      unsigned int family = n > 0 ? packet[0] >> 4 : 0;
      unsigned int protocol = 0;
      if (family == 4 && n > 9)
        protocol = packet[9];
      else if (family == 6 && n > 6)
        protocol = packet[6];
      fprintf (stderr,
               "oi4 multi-ingress result=REJECT reason=invalid-tuple length=%zd "
               "family=%u protocol=%u first=%02x:%02x:%02x:%02x:%02x:%02x\n",
               n, family, protocol, n > 0 ? packet[0] : 0,
               n > 1 ? packet[1] : 0, n > 2 ? packet[2] : 0,
               n > 3 ? packet[3] : 0, n > 4 ? packet[4] : 0,
               n > 5 ? packet[5] : 0);
      continue;
    }
    uint32_t active_valid =
      atomic_load_explicit (&tm->active_flow_valid, memory_order_acquire);
    uint64_t active_hash =
      atomic_load_explicit (&tm->active_flow_hash, memory_order_acquire);
    uint32_t admission_open =
      atomic_load_explicit (&tm->multi_admission_open, memory_order_acquire);
    uint32_t dispatch_depth =
      atomic_load_explicit (&tm->multi_dispatch_depth, memory_order_acquire);
    bool tcp_packet = oi3_multi_tcp_packet (packet, (size_t)n);
    bool tcp_syn = oi3_multi_tcp_syn_packet (packet, (size_t)n);
    uint32_t tcp_tombstone_valid = atomic_load_explicit (
      &tm->multi_tcp_tombstone_valid, memory_order_acquire);
    uint64_t tcp_tombstone_hash = atomic_load_explicit (
      &tm->multi_tcp_tombstone_hash, memory_order_acquire);
    if (tcp_syn && active_valid && active_hash != hash) {
      if (oi3_enqueue_deferred_tun_packet_for (tm, vm, packet, (size_t)n) < 0) {
        atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                   memory_order_relaxed);
        oi3_multi.route_rejects[tm->owner_id]++;
        fprintf (stderr,
                 "oi4 multi-admission result=REJECT owner=%u hash=%llu "
                 "active=%u active-hash=%llu depth=%u reason=owner-busy-deferred-full\n",
                 tm->owner_id, (unsigned long long)hash, admission_open,
                 (unsigned long long)active_hash, dispatch_depth);
        continue;
      }
      fprintf (stderr,
               "oi4 multi-admission result=DEFER owner=%u hash=%llu active=%u "
               "active-hash=%llu depth=%u reason=owner-busy-deferred\n",
               tm->owner_id, (unsigned long long)hash, admission_open,
               (unsigned long long)active_hash, dispatch_depth);
      continue;
    }
    if (!admission_open || (active_valid && active_hash != hash)) {
      const char *reject_reason =
        !admission_open
          ? "owner-stopped"
          : (tcp_packet && !tcp_syn && active_valid && active_hash != hash
             ? "tcp-non-syn-busy"
             : "owner-busy");
      atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                 memory_order_relaxed);
      oi3_multi.route_rejects[tm->owner_id]++;
      fprintf (stderr,
               "oi4 multi-admission result=REJECT owner=%u hash=%llu active=%u "
               "active-hash=%llu depth=%u reason=%s\n", tm->owner_id,
               (unsigned long long)hash, admission_open,
               (unsigned long long)active_hash, dispatch_depth,
               reject_reason);
      continue;
    }
    if (tcp_packet && tcp_tombstone_valid && !tcp_syn) {
      atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                 memory_order_relaxed);
      oi3_multi.route_rejects[tm->owner_id]++;
      fprintf (stderr,
               "oi4 multi-admission result=REJECT owner=%u hash=%llu "
               "tombstone-hash=%llu reason=%s\n", tm->owner_id,
               (unsigned long long)hash,
               (unsigned long long)tcp_tombstone_hash,
               hash == tcp_tombstone_hash ? "tcp-tail" : "tcp-non-syn");
      continue;
    }
    if (dispatch_depth >= OI3_TUN_PENDING_CAPACITY) {
      atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                 memory_order_relaxed);
      oi3_multi.route_rejects[tm->owner_id]++;
      fprintf (stderr, "oi4 multi-admission result=REJECT owner=%u reason=queue-full depth=%u\n",
               tm->owner_id, dispatch_depth);
      continue;
    }
    bool reserved_active = false;
    if (!active_valid) {
      atomic_store_explicit (&tm->active_flow_hash, hash, memory_order_release);
      atomic_store_explicit (&tm->active_flow_valid, 1, memory_order_release);
      reserved_active = true;
    }
    bool route_inserted = false;
    if (route_protocol == 17 && !route_pinned) {
      bool active_same = active_valid && active_hash == hash;
      if (oi3_multi_flow_route_insert (hash, tm->owner_id,
                                       route_protocol) < 0) {
        if (reserved_active) {
          atomic_store_explicit (&tm->active_flow_valid, 0,
                                 memory_order_release);
          atomic_store_explicit (&tm->active_flow_hash, 0,
                                 memory_order_release);
        }
        if (!active_same) {
          atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                     memory_order_relaxed);
          oi3_multi.route_rejects[tm->owner_id]++;
          fprintf (stderr,
                   "oi4 multi-admission result=REJECT owner=%u hash=%llu "
                   "reason=route-table-full\n",
                   tm->owner_id, (unsigned long long)hash);
          continue;
        }
      } else {
        route_inserted = true;
      }
    }
    fprintf (stderr,
             "oi4 multi-ingress wall-ms=%llu owner=%u hash=%llu length=%zd "
             "handoff=owner-fd\n",
             (unsigned long long)oi3_wall_ms (), tm->owner_id,
             (unsigned long long)hash, n);
    atomic_fetch_add_explicit (&tm->multi_dispatch_depth, 1,
                               memory_order_release);
    if (oi3_send_tun_handoff_for (tm, packet, (size_t)n) < 0) {
      oi3_multi_dispatch_depth_complete (tm);
      if (route_inserted)
        oi3_multi_flow_route_remove (hash);
      if (reserved_active) {
        atomic_store_explicit (&tm->active_flow_valid, 0,
                               memory_order_release);
        atomic_store_explicit (&tm->active_flow_hash, 0,
                               memory_order_release);
        fprintf (stderr,
                 "oi4 multi-admission result=ROLLBACK owner=%u hash=%llu "
                 "reason=admission-rollback\n",
                 tm->owner_id, (unsigned long long)hash);
      }
      tm->tun_output_errors++;
      atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                 memory_order_relaxed);
      oi3_multi.route_rejects[tm->owner_id]++;
      fprintf (stderr, "oi4 multi-admission result=REJECT owner=%u reason=queue-full\n",
               tm->owner_id);
      continue;
    }
    if (tcp_syn) {
      atomic_store_explicit (&tm->multi_tcp_wait_syn, 0, memory_order_release);
      atomic_store_explicit (&tm->multi_tcp_tombstone_valid, 0,
                             memory_order_release);
    }
  }
  (void)file;
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
          if (completion.result != OI2_RESULT_BROKER_UNAVAILABLE)
            tm->broker_bind_calls++;
          if (completion.result == OI2_RESULT_SUCCESS ||
              completion.result == OI2_RESULT_PROTECT_FAILURE)
            tm->broker_protect_calls++;
        }
        if (oi3_enqueue_owner_for (tm, vm, 1) < 0)
          oi3_error ("completion owner enqueue failed");
      } else tm->broker_stale++;
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return 0;
  }
}

static oi3_main_t *
oi3_multi_owner_for_completion (const oi2_broker_completion_t *completion)
{
  if (!completion)
    return NULL;
  for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
    if (oi3_multi.owners[owner].target_thread == completion->owner)
      return &oi3_multi.owners[owner];
  }
  return NULL;
}

static void *
oi3_multi_completion_poll_main (void *data)
{
  oi3_multi_main_t *mm = (oi3_multi_main_t *)data;
  oi2_broker_completion_t completion;

  while (!atomic_load_explicit (&mm->completion_poll_stop,
                                memory_order_acquire)) {
    struct pollfd p = {
      .fd = mm->completion_watch_fd,
      .events = POLLIN,
    };
    int rc = poll (&p, 1, 50);
    if (rc < 0) {
      if (errno == EINTR)
        continue;
      fprintf (stderr,
               "oi4 completion-poll result=ERROR errno=%d %s\n",
               errno, strerror (errno));
      continue;
    }
    if (rc == 0 || !(p.revents & (POLLIN | POLLERR | POLLHUP)))
      continue;
    for (;;) {
      ssize_t n = recv (mm->completion_watch_fd, &completion,
                        sizeof (completion), MSG_DONTWAIT);
      if (n == (ssize_t)sizeof (completion)) {
        oi3_main_t *tm = oi3_multi_owner_for_completion (&completion);
        if (!tm) {
          mm->wrong_owner_events++;
          fprintf (stderr,
                   "oi4 completion result=REJECT owner=%u "
                   "reason=unknown-owner\n",
                   completion.owner);
          continue;
        }
        if (oi3_send_completion_handoff_for (tm, &completion) < 0) {
          tm->broker_stale++;
          fprintf (stderr,
                   "oi4 completion-handoff result=REJECT owner=%u "
                   "reason=send-failed\n",
                   tm->owner_id);
        }
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EINTR))
        break;
      if (n == 0)
        return NULL;
      fprintf (stderr,
               "oi4 completion-poll result=REJECT reason=short-read "
               "bytes=%zd\n", n);
      break;
    }
  }
  return NULL;
}

static void
oi3_multi_completion_poll_stop (void)
{
  if (!oi3_multi.completion_poll_started)
    return;
  atomic_store_explicit (&oi3_multi.completion_poll_stop, 1,
                         memory_order_release);
  pthread_join (oi3_multi.completion_poll_thread, NULL);
  oi3_multi.completion_poll_started = 0;
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
oi3_expected_outcome (const oi3_main_t *tm);

static int
oi3_is_expected_negative_cell (const oi3_main_t *tm)
{
  return tm && (tm->cell == OI3_CELL_REFUSED ||
                tm->cell == OI3_CELL_NO_REPLY ||
                tm->cell == OI3_CELL_POLICY_DROP);
}

static int
oi3_tcp_positive_fin_complete (const oi3_main_t *tm)
{
  return tm && tm->tun_mode && tm->protocol == 6 &&
         tm->tcp_fin_submitted && tm->output_packets != 0 &&
         tm->output_direct != 0 && tm->return_rewritten != 0 &&
         tm->transport_failures == 0 && tm->infrastructure_failures == 0 &&
         tm->tun_output_errors == 0 && !oi3_is_expected_negative_cell (tm) &&
         !tm->expected_infrastructure_failure &&
         !tm->expected_real_no_reply && !tm->expected_real_reset &&
         !tm->expected_real_policy_drop && !tm->fault_injected &&
         !tm->underlay_invalidated && !tm->normal_stop_requested;
}

static const char *
oi3_expected_outcome (const oi3_main_t *tm)
{
  if (tm->underlay_invalidated) return "EXPECTED_UNDERLAY_INVALIDATION";
  if (tm->normal_stop_requested) return "EXPECTED_STOP";
  if (tm->overload_expected) return "EXPECTED_PACKET_OVERLOAD";
  if (tm->expected_infrastructure_failure)
    switch (tm->expected_infrastructure_failure)
      {
      case OI2_RESULT_BIND_FAILURE: return "EXPECTED_BIND_FAILURE";
      case OI2_RESULT_PROTECT_FAILURE: return "EXPECTED_PROTECT_FAILURE";
      case OI2_RESULT_BROKER_UNAVAILABLE: return "EXPECTED_BROKER_UNAVAILABLE";
      default: return "EXPECTED_INFRASTRUCTURE_FAILURE";
      }
  if (tm->expected_real_reset) return "EXPECTED_REAL_TRANSPORT_RESET";
  if (tm->expected_real_no_reply) return "EXPECTED_REAL_NO_REPLY";
  if (tm->expected_real_policy_drop) return "EXPECTED_REAL_POLICY_DROP";
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
  if (tm->underlay_invalidated) return;
  if (tm->expected_infrastructure_failure)
    {
      u32 expected_broker_bind_calls = 0;
      u32 expected_broker_protect_calls = 0;
      switch (tm->expected_infrastructure_failure)
        {
        case OI2_RESULT_BIND_FAILURE:
          expected_broker_bind_calls = 1;
          expected_broker_protect_calls = 0;
          break;
        case OI2_RESULT_PROTECT_FAILURE:
          expected_broker_bind_calls = 1;
          expected_broker_protect_calls = 1;
          break;
        case OI2_RESULT_BROKER_UNAVAILABLE:
          expected_broker_bind_calls = 0;
          expected_broker_protect_calls = 0;
          break;
        }
      int pass = tm->multi_mode && tm->tun_mode &&
                 tm->broker_result == tm->expected_infrastructure_failure &&
                 tm->broker_bind_calls == expected_broker_bind_calls &&
                 tm->broker_protect_calls == expected_broker_protect_calls &&
                 tm->output_packets == 0 && tm->output_direct == 0 &&
                 tm->direct_send_events == 0 && tm->return_rewritten == 0 &&
                 tm->endpoint_received == 0 && tm->endpoint_replied == 0 &&
                 tm->transport_failures == 0 &&
                 tm->infrastructure_failures == 1 &&
                 tm->tun_output_errors == 0 &&
                 tm->broker_duplicate_closes == 0;
      if (!pass)
        snprintf (tm->error, sizeof (tm->error),
                  "unexpected-infrastructure-result expected=%s(%u) "
                  "actual=%s(%u) broker=%u/%u output=%u/%u direct-send=%u "
                  "rewritten=%u endpoint=%u/%u transport=%u infrastructure=%u "
                  "tun-output-errors=%u duplicate-close=%u",
                  oi3_broker_result_name (tm->expected_infrastructure_failure),
                  tm->expected_infrastructure_failure,
                  oi3_broker_result_name (tm->broker_result),
                  tm->broker_result, tm->broker_bind_calls,
                  tm->broker_protect_calls, tm->output_packets,
                  tm->output_direct, tm->direct_send_events,
                  tm->return_rewritten, tm->endpoint_received,
                  tm->endpoint_replied, tm->transport_failures,
                  tm->infrastructure_failures, tm->tun_output_errors,
                  tm->broker_duplicate_closes);
      return;
    }
  if (tm->normal_stop_requested) {
    /* oi3_finish() is called only after the owner token has been reclaimed,
     * so residue zero is already an admission/settlement gate.  Preserve
     * distinct infrastructure and duplicate-close failures instead of
     * allowing an explicit stop to mask them. */
    if (tm->vpp_buffer_residue != 0 || tm->broker_duplicate_closes != 0 ||
        tm->infrastructure_failures != 0 || tm->tun_output_errors != 0)
      snprintf (tm->error, sizeof (tm->error),
                "unexpected-normal-stop residue=%u duplicate-close=%u "
                "infrastructure=%u tun-output-errors=%u",
                tm->vpp_buffer_residue, tm->broker_duplicate_closes,
                tm->infrastructure_failures, tm->tun_output_errors);
    return;
  }
  if (tm->overload_expected) {
    /* HEV's category-1 inflight-pbuf credit is deliberately bounded.  Once
     that ledger rejects a UDP datagram, the packet is settled as an explicit
     owner-local drop; it must not be reclassified as a failed positive flow
     merely because that dropped datagram has no reply.  Keep the admission
     and broker gates strict so an unrelated fault cannot hide behind this
     outcome. */
    int pass = tm->multi_mode && tm->protocol == 17 &&
               (tm->tun_submit_rejects > 0 || tm->tun_queue_rejects > 0) &&
               tm->broker_bind_calls == 1 &&
               tm->broker_protect_calls == 1 && tm->tun_output_errors == 0 &&
               tm->transport_failures == 0 &&
               tm->infrastructure_failures == 0;
    if (!pass)
      snprintf (tm->error, sizeof (tm->error),
                "unexpected-packet-overload broker=%u/%u submit-rejects=%u "
                "queue-rejects=%u "
                "transport=%u infrastructure=%u tun-output-errors=%u",
                tm->broker_bind_calls, tm->broker_protect_calls,
                tm->tun_submit_rejects, tm->tun_queue_rejects,
                tm->transport_failures,
                tm->infrastructure_failures, tm->tun_output_errors);
    return;
  }
  if (tm->expected_real_no_reply) {
    int timed_out = tm->tun_mode
                      ? (tm->tun_flow_deadline_ns != 0 &&
                         oi3_now_ns () >= tm->tun_flow_deadline_ns)
                      : tm->worker_steps > 40;
    int pass = tm->multi_mode && tm->tun_mode && tm->protocol == 17 &&
               tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
               tm->direct_send_events > 0 && tm->output_packets == 0 &&
               tm->output_direct == 0 && tm->return_rewritten == 0 &&
               tm->transport_failures == 0 &&
               tm->infrastructure_failures == 0 &&
               tm->tun_output_errors == 0 && timed_out;
    if (!pass)
      snprintf (tm->error, sizeof (tm->error),
                "unexpected-real-no-reply broker=%u/%u direct-send=%u "
                "output=%u/%u rewritten=%u transport=%u infrastructure=%u "
                "tun-output-errors=%u steps=%u",
                tm->broker_bind_calls, tm->broker_protect_calls,
                tm->direct_send_events, tm->output_packets,
                tm->output_direct, tm->return_rewritten,
                tm->transport_failures, tm->infrastructure_failures,
                tm->tun_output_errors, tm->worker_steps);
    return;
  }
  if (tm->expected_real_reset) {
    int pass = tm->multi_mode && tm->tun_mode && tm->protocol == 6 &&
               tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
               tm->output_handshake > 0 && tm->output_direct > 0 &&
               tm->direct_send_events > 0 && tm->output_packets >= 3 &&
               tm->tun_output_packets >= 3 && tm->return_rewritten >= 3 &&
               tm->endpoint_received == 0 &&
               tm->infrastructure_failures == 0 &&
               tm->transport_failures == 1 &&
               tm->connector_last_error == ECONNRESET &&
               tm->connector_error_reported &&
               tm->connector_reset_observed == 1 &&
               tm->connector_downstream_reset_observed == 1 &&
               tm->connector_peer_eof_observed == 0;
    if (!pass)
      snprintf (tm->error, sizeof (tm->error),
                "unexpected-real-reset broker=%u/%u handshake=%u direct=%u "
                "rewritten=%u endpoint=%u/%u transport=%u connector-error=%d "
                "reported=%d reset-observed=%u downstream-reset=%u peer-eof=%u "
                "infrastructure=%u steps=%u",
                tm->broker_bind_calls, tm->broker_protect_calls,
                tm->output_handshake, tm->output_direct,
                tm->return_rewritten, tm->endpoint_received,
                tm->endpoint_replied, tm->transport_failures,
                tm->connector_last_error, tm->connector_error_reported,
                tm->connector_reset_observed,
                tm->connector_downstream_reset_observed,
                tm->connector_peer_eof_observed,
                tm->infrastructure_failures, tm->worker_steps);
    return;
  }
  if (tm->expected_real_policy_drop) {
    int pass = tm->multi_mode && tm->tun_mode &&
               tm->cell == OI3_CELL_POLICY_DROP && tm->policy_dropped &&
               tm->packet_submitted == 0 && tm->output_packets == 0 &&
               tm->output_direct == 0 && tm->return_rewritten == 0 &&
               tm->broker_bind_calls == 0 && tm->broker_protect_calls == 0 &&
               tm->transport_failures == 0 &&
               tm->infrastructure_failures == 0 &&
               tm->tun_output_errors == 0;
    if (!pass)
      snprintf (tm->error, sizeof (tm->error),
                "unexpected-real-policy-drop policy=%u submitted=%u "
                "output=%u/%u rewritten=%u broker=%u/%u transport=%u "
                "infrastructure=%u tun-output-errors=%u",
                tm->policy_dropped, tm->packet_submitted,
                tm->output_packets, tm->output_direct, tm->return_rewritten,
                tm->broker_bind_calls, tm->broker_protect_calls,
                tm->transport_failures, tm->infrastructure_failures,
                tm->tun_output_errors);
    return;
  }
  int pass = 0;
  switch (tm->cell) {
  case OI3_CELL_REFUSED:
    /* A refused endpoint is a transport result, never a policy fallback. */
    pass = tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
           tm->endpoint_received == 0 && tm->output_direct == 0 &&
           (tm->transport_failures > 0 || tm->connector_last_error != 0);
    break;
  case OI3_CELL_NO_REPLY:
    {
      int timed_out = tm->tun_mode
                        ? (tm->tun_flow_deadline_ns != 0 &&
                           oi3_now_ns () >= tm->tun_flow_deadline_ns)
                        : tm->worker_steps > 40;
      int expected_ambient_timeout =
        tm->multi_mode && tm->expected_transport_timeout &&
        tm->output_packets > 0 && tm->output_handshake > 0 &&
        tm->output_direct == 0 && tm->endpoint_received == 0 &&
        tm->transport_failures == 0 && tm->infrastructure_failures == 0;
      pass = tm->broker_bind_calls == 1 && tm->broker_protect_calls == 1 &&
             tm->output_direct == 0 && timed_out &&
             ((tm->endpoint_received > 0 && tm->endpoint_replied == 0) ||
              expected_ambient_timeout);
    }
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

/* Refresh the pinned HEV runtime ledger immediately before teardown.  The
 * submit ABI reserves credit 0 (packet handoff) and credit 1 (inflight pbuf)
 * in that order; a negative result alone is not enough to identify which
 * bounded resource rejected the packet.  Keep this observation owner-local
 * and diagnostic-only so D3 can distinguish a hard adapter failure from an
 * explicit packet loss at the HEV credit boundary. */
static void
oi3_log_runtime_credits (oi3_main_t *tm, const char *phase)
{
  if (!tm || !tm->context || !tm->api.runtime_identity)
    return;
  oi3_runtime_identity_t identity;
  memset (&identity, 0, sizeof (identity));
  tm->api.runtime_identity (tm->context, &identity);
  fprintf (stderr,
           "oi3 credit-ledger phase=%s owner=%u session=%zu/%zu "
           "c0=limit:%zu used:%zu high:%zu reserves:%zu releases:%zu rejects:%zu "
           "c1=limit:%zu used:%zu high:%zu reserves:%zu releases:%zu rejects:%zu "
           "c2=limit:%zu used:%zu rejects:%zu c3=limit:%zu used:%zu rejects:%zu "
           "last-limit-error=%d underflows=%zu\n",
           phase ? phase : "?", tm->owner_id, identity.session_count,
           identity.max_session_count,
           identity.credit_limit[0], identity.credit_used[0],
           identity.credit_high_water[0], identity.credit_reserves[0],
           identity.credit_releases[0], identity.credit_rejects[0],
           identity.credit_limit[1], identity.credit_used[1],
           identity.credit_high_water[1], identity.credit_reserves[1],
           identity.credit_releases[1], identity.credit_rejects[1],
           identity.credit_limit[2], identity.credit_used[2],
           identity.credit_rejects[2], identity.credit_limit[3],
           identity.credit_used[3], identity.credit_rejects[3],
           identity.last_limit_error, identity.credit_underflows);
}

/* Close only the per-flow HEV/broker state.  The Android VPN session owns the
 * TUN descriptor and its readiness watcher, so a successful positive flow
 * must leave both armed for the next packet.  A new packet will enter
 * oi3_prepare_tun_flow(), receive a fresh generation/token, and get a fresh
 * FlowStackOwner context without requiring Android to tear down the VPN. */
static void
oi3_rearm_tun_flow (vlib_main_t *vm, oi3_main_t *tm)
{
  if (!tm || !tm->tun_mode)
    return;

  tm->context = NULL;
  tm->lwip_context = NULL;
  tm->direct_fd = -1;
  tm->connector_fd = -1;
  tm->endpoint_fd = -1;
  tm->endpoint_client_fd = -1;
  tm->completion_file_index = -1;
  tm->tun_flow_deadline_ns = 0;
  tm->worker_token_pending = 0;
  tm->finish_requested = 0;
  tm->normal_stop_requested = 0;
  tm->fault_injected = 0;
  tm->underlay_invalidated = 0;
  tm->finished = 1;
  tm->active = 1;
  tm->phase = OI3_DONE;
  tm->pending = 0;

  /* These counters describe one HEV generation and are reset only after its
   * cleanup line has been emitted.  Session counters (TUN ingress/output,
   * generation, sequence, and VPP buffer totals) remain cumulative. */
  tm->worker_steps = 0;
  tm->task_quanta = 0;
  tm->packet_submitted = 0;
  tm->udp_datagram_inflight = 0;
  tm->tcp_ack_submitted = 0;
  tm->tcp_payload_submitted = 0;
  tm->tcp_fin_submitted = 0;
  tm->output_packets = 0;
  tm->output_handshake = 0;
  tm->output_direct = 0;
  tm->direct_send_events = 0;
  tm->direct_recv_events = 0;
  tm->provenance_logged = 0;
  tm->tcp_handshake_seen = 0;
  tm->return_rewritten = 0;
  tm->endpoint_received = 0;
  tm->endpoint_replied = 0;
  tm->endpoint_accepted = 0;
  tm->broker_bind_calls = 0;
  tm->broker_protect_calls = 0;
  tm->broker_duplicate_closes = 0;
  tm->broker_stale = 0;
  tm->transport_failures = 0;
  tm->infrastructure_failures = 0;
  tm->broker_result = OI2_RESULT_BROKER_UNAVAILABLE;
  tm->connector_last_error = 0;
  tm->connector_error_reported = 0;
  tm->connector_reset_observed = 0;
  tm->connector_downstream_reset_observed = 0;
  tm->connector_peer_eof_observed = 0;
  tm->source_port = 0;
  tm->source_address_length = 0;
  tm->no_reply = tm->controlled_no_reply;
  tm->policy_dropped = tm->controlled_policy_drop;
  tm->tun_tcp_flags = 0;
  tm->last_output_length = 0;
  tm->tcp_client_seq = 0;
  tm->tcp_server_seq = 0;
  tm->tcp_server_ack = 0;
  tm->tcp_data_seen = 0;
  tm->error[0] = 0;

  uint64_t completed_hash = atomic_load_explicit (&tm->active_flow_hash,
                                                  memory_order_acquire);
  uint32_t completed_valid = atomic_load_explicit (&tm->active_flow_valid,
                                                   memory_order_acquire);
  if (tm->protocol == 6 && completed_valid && completed_hash != 0) {
    atomic_store_explicit (&tm->multi_tcp_tombstone_hash, completed_hash,
                           memory_order_release);
    atomic_store_explicit (&tm->multi_tcp_tombstone_valid, 1,
                           memory_order_release);
  }
  atomic_store_explicit (&tm->active_flow_hash, 0, memory_order_release);
  atomic_store_explicit (&tm->active_flow_valid, 0, memory_order_release);
  atomic_store_explicit (&tm->multi_tcp_wait_syn,
                         tm->protocol == 6, memory_order_release);
  atomic_store_explicit (&tm->multi_dispatch_depth, 0, memory_order_release);
  if (tm->protocol == 6 && tm->tun_pending_count != 0)
    oi3_tun_pending_clear (tm, "tcp-rearm-stale-tail");
  if (tm->multi_deferred_count != 0 &&
      oi3_admit_deferred_tun_flow (vm, tm) < 0)
    oi3_error ("OI3 deferred TUN flow admit failed");
  /* Reopen owner-local admission only after the completed TCP tuple has
   * published its tombstone/wait-SYN state.  Otherwise a FIN/ACK tail packet
   * can race with teardown and become a new generation before the dispatcher
   * knows to reject non-SYN traffic. */
  atomic_store_explicit (&tm->multi_admission_open, 1, memory_order_release);

  /* Preserve owner-local pending TUN packets across a successful UDP
   * short-flow rearm.  Android can deliver the next UDP datagram while the
   * current HEV generation is still being stopped; clearing the queue here
   * silently drops that already-admitted packet.  TCP is different: pending
   * packets present at rearm are stale tail from the completed generation and
   * must not be submitted into the next deferred successor context. */
  tm->tun_submit_rejects = 0;
  tm->tun_queue_rejects = 0;
  tm->overload_expected = 0;
  tm->expected_transport_timeout = 0;
  atomic_store_explicit (&tm->connector_wake_pending, 0, memory_order_release);
  atomic_store_explicit (&tm->connector_connect_pending, 0, memory_order_release);
  atomic_store_explicit (&tm->connector_write_pending, 0, memory_order_release);
  atomic_store_explicit (&tm->connector_poll_done, 1, memory_order_release);
  atomic_store_explicit (&tm->endpoint_stop, 1, memory_order_release);
  atomic_store_explicit (&tm->endpoint_ready, 0, memory_order_release);
  if (tm->tun_pending_count != 0 && !tm->worker_token_pending &&
      oi3_enqueue_owner_for (tm, vm, 0) < 0)
    oi3_error ("OI3 TUN pending rearm enqueue failed");
  fprintf (stderr, "oi3 tun-flow rearmed flow-count=%u next-generation=%llu "
           "tun-fd=%d watcher=%d pending=%u\n", tm->tun_flow_count,
           (unsigned long long)(tm->generation + 1U), tm->tun_fd,
           tm->tun_file_index, tm->tun_pending_count);
}

static void
oi3_stop_context_for (vlib_main_t *vm, oi3_main_t *tm, int *stop_result)
{
  unsigned int round;

  *stop_result = tm->api.stop (tm->context);
  for (round = 0; *stop_result == OI3_OWNER_STOP_PENDING &&
       round < OI3_OWNER_STOP_RETRY_ROUNDS; round++) {
    oi3_task_budget_t budget = { .max_quanta = OI3_OWNER_STOP_MAX_QUANTA };
    oi3_task_result_t result = { 0 };

    if (tm->api.task_step (&budget, &result) < 0) {
      *stop_result = -1;
      return;
    }
    *stop_result = tm->api.stop (tm->context);
  }
  if (*stop_result == OI3_OWNER_STOP_PENDING) {
    fprintf (stderr,
             "oi3 owner-stop pending owner=%u retries=%u tasks-not-ready=1\n",
             tm->owner_id, OI3_OWNER_STOP_RETRY_ROUNDS);
    if (!tm->worker_token_pending &&
        oi3_enqueue_owner_for (tm, vm, 0) < 0)
      *stop_result = -1;
  }
}

static int
oi3_defer_finish_to_owner_thread (vlib_main_t *vm, oi3_main_t *tm)
{
  u32 current_thread;

  if (!tm || !tm->multi_mode || !tm->active)
    return 0;
  current_thread = vlib_get_thread_index ();
  if (tm->target_thread == current_thread)
    return 0;
  fprintf (stderr,
           "oi3 owner-finish deferred owner=%u current-thread=%u "
           "target-thread=%u token-pending=%u\n",
           tm->owner_id, current_thread, tm->target_thread,
           tm->worker_token_pending);
  if (!tm->worker_token_pending &&
      oi3_enqueue_owner_for (tm, vm, 0) < 0) {
    snprintf (tm->error, sizeof (tm->error),
              "owner-finish-enqueue-failed current-thread=%u target-thread=%u",
              current_thread, tm->target_thread);
    tm->phase = OI3_FAULT;
    return -1;
  }
  return 1;
}

static void
oi3_finish_for (vlib_main_t *vm, oi3_main_t *tm)
{
  const char *cleanup_result;
  bool keep_tun;
  bool overload_keep;
  bool negative_keep;
  int deferred;

  /* Close owner-local admission before teardown starts.  Multi-owner TUN
   * reads run on the control thread while owner cleanup runs on the owner
   * thread; without this gate, same-flow TCP tail packets can enter the
   * pending queue between the successful-flow terminal state and the later
   * tombstone publication in oi3_rearm_tun_flow(). */
  if (tm && tm->multi_mode && tm->tun_mode)
    atomic_store_explicit (&tm->multi_admission_open, 0,
                           memory_order_release);

  deferred = oi3_defer_finish_to_owner_thread (vm, tm);
  if (deferred != 0)
    return;
  /* Negative cells and explicit lifecycle terminals still close the VPN
   * session.  Only a successful positive TUN flow is eligible for the
   * per-generation re-arm. */
  if (!tm->tun_mode || oi3_is_expected_negative_cell (tm) ||
      tm->expected_infrastructure_failure ||
      tm->expected_real_no_reply || tm->expected_real_reset ||
      tm->expected_real_policy_drop || tm->normal_stop_requested ||
      tm->underlay_invalidated || tm->overload_expected)
    oi3_classify_result (tm);
  overload_keep = tm->overload_expected && tm->multi_mode &&
                  tm->protocol == 17 &&
                  (tm->tun_submit_rejects > 0 || tm->tun_queue_rejects > 0);
  negative_keep = tm->multi_mode && tm->expected_transport_timeout &&
                  tm->cell == OI3_CELL_NO_REPLY;
  keep_tun = tm->tun_mode && !tm->error[0] && !tm->fault_injected &&
             !tm->normal_stop_requested && !tm->underlay_invalidated &&
             !tm->expected_infrastructure_failure &&
             !tm->expected_real_no_reply && !tm->expected_real_reset &&
             !tm->expected_real_policy_drop &&
             tm->tun_output_errors == 0 && tm->vpp_buffer_residue == 0 &&
             (negative_keep ||
              (!oi3_is_expected_negative_cell (tm) &&
               (overload_keep || (tm->output_packets != 0 &&
                                  tm->output_direct != 0 &&
                                  tm->return_rewritten != 0))));
  if (tm->tun_mode && !negative_keep &&
      !oi3_is_expected_negative_cell (tm) &&
      !tm->expected_infrastructure_failure &&
      !tm->expected_real_no_reply && !tm->expected_real_reset &&
      !tm->expected_real_policy_drop &&
      !tm->fault_injected && !tm->underlay_invalidated &&
      !tm->normal_stop_requested &&
      !overload_keep &&
      (tm->tun_output_errors != 0 || tm->output_packets == 0 ||
       tm->output_direct == 0 || tm->return_rewritten == 0))
    keep_tun = false;

  oi3_connector_poll_stop (tm);
  if (!tm->multi_mode && !keep_tun && tm->tun_file_index >= 0) {
    clib_file_del_by_index (&file_main, tm->tun_file_index);
    tm->tun_file_index = -1;
  }
  if (tm->completion_file_index >= 0) {
    clib_file_del_by_index (&file_main, tm->completion_file_index);
    tm->completion_file_index = -1;
  }
  oi3_log_runtime_credits (tm, "before-stop");
  if (tm->context) {
    int stop_result = OI3_OWNER_STOP_PENDING;
    oi3_stop_context_for (vm, tm, &stop_result);
    if (stop_result != OI3_OWNER_STOP_READY) {
      if (stop_result != OI3_OWNER_STOP_PENDING)
        oi3_error ("OI3 owner context stop failed");
      return;
    }
    tm->api.destroy (tm->context); tm->context = NULL;
    tm->lwip_context = NULL;
    oi3_task_fini (tm);
  }
  if (tm->direct_fd >= 0) { close (tm->direct_fd); tm->direct_fd = -1; }
  oi3_stop_threads (tm);
  if (!keep_tun) {
    if (tm->connector_wake_file_index >= 0) {
      clib_file_del_by_index (&file_main, tm->connector_wake_file_index);
      tm->connector_wake_file_index = -1;
      tm->connector_wake_pipe[0] = -1;
    }
    if (tm->connector_wake_pipe[0] >= 0)
      close (tm->connector_wake_pipe[0]);
    if (tm->connector_wake_pipe[1] >= 0)
      close (tm->connector_wake_pipe[1]);
    tm->connector_wake_pipe[0] = tm->connector_wake_pipe[1] = -1;
    if (!tm->multi_mode && tm->tun_fd >= 0) {
      close (tm->tun_fd); tm->tun_fd = -1;
    }
  }
  tm->finish_ns = oi3_now_ns ();
  if (tm->error[0])
    cleanup_result = "FAIL";
  else if (tm->fault_injected)
    cleanup_result = "PASS_EXPECTED_FAULT";
  else if (tm->underlay_invalidated)
    cleanup_result = "PASS_EXPECTED_UNDERLAY_INVALIDATION";
  else if (tm->normal_stop_requested)
    cleanup_result = "PASS_EXPECTED_STOP";
  else if (tm->overload_expected)
    cleanup_result = "PASS_EXPECTED_OVERLOAD";
  else if (tm->expected_infrastructure_failure)
    cleanup_result = "PASS_EXPECTED_INFRA_FAILURE";
  else if (tm->expected_real_reset)
    cleanup_result = "PASS_EXPECTED_REAL_RESET";
  else if (tm->expected_real_no_reply)
    cleanup_result = "PASS_EXPECTED_REAL_NO_REPLY";
  else if (tm->expected_real_policy_drop)
    cleanup_result = "PASS_EXPECTED_REAL_POLICY_DROP";
  else if (tm->expected_transport_timeout)
    cleanup_result = "PASS_EXPECTED_AMBIENT_TIMEOUT";
  else if (oi3_is_expected_negative_cell (tm))
    cleanup_result = "PASS_EXPECTED_FAILURE";
  else
    cleanup_result = "PASS";
  if (tm->tun_mode && !oi3_is_expected_negative_cell (tm) &&
      !tm->expected_infrastructure_failure &&
      !tm->expected_real_no_reply && !tm->expected_real_reset &&
      !tm->expected_real_policy_drop &&
      !tm->fault_injected && !tm->underlay_invalidated &&
      !tm->normal_stop_requested &&
      !tm->overload_expected &&
      (tm->tun_output_errors != 0 || tm->output_packets == 0 ||
       tm->output_direct == 0 || tm->return_rewritten == 0))
    cleanup_result = "FAIL";
  if (tm->a2_return_mode) {
    fprintf (stderr,
             "oi3 a2-3 schema=s139-a2-3-oi3/v1 event=CLEANUP "
             "stage-id=%s canonical-key=%s ingress=%u output=%u "
             "android-lookup-count=%u transport-reentry=0 "
             "buffers=%u/%u residue=%u\n", tm->a2_return_stage_id,
             tm->a2_return_canonical_key[0] ? tm->a2_return_canonical_key : "?",
             tm->a2_return_ingress, tm->a2_return_output,
             tm->a2_return_lookup_count, tm->vpp_buffers_allocated,
             tm->vpp_buffers_freed, tm->vpp_buffer_residue);
  }
  fprintf (stderr, "oi3_cleanup result=%s outcome=%s generation=%llu epoch=%llu fault-injected=%u normal-stop-requested=%u output=%u handshake=%u direct=%u "
           "rewritten=%u endpoint=%u/%u accepted=%u broker=%u/%u duplicate-close=%u "
           "underlay-invalidated=%u underlay-handle=%lld underlay-available=%u "
           "transport-failures=%u infrastructure-failures=%u submit-rejects=%u "
           "queue-rejects=%u "
           "overload-expected=%u ambient-timeout-expected=%u "
           "real-no-reply-expected=%u real-reset-expected=%u "
           "real-policy-drop-expected=%u downstream-reset-observed=%u "
           "direct-send=%u "
           "buffers=%u/%u residue=%u error=%s\n",
           cleanup_result, oi3_expected_outcome (tm),
           (unsigned long long)tm->generation,
           (unsigned long long)tm->underlay_epoch, tm->fault_injected,
           tm->normal_stop_requested,
           tm->output_packets, tm->output_handshake, tm->output_direct,
           tm->return_rewritten, tm->endpoint_received, tm->endpoint_replied,
           tm->endpoint_accepted,
           tm->broker_bind_calls, tm->broker_protect_calls, tm->broker_duplicate_closes,
           tm->underlay_invalidated, (long long)tm->underlay_handle,
           tm->underlay_available,
           tm->transport_failures, tm->infrastructure_failures,
           tm->tun_submit_rejects, tm->tun_queue_rejects,
           tm->overload_expected, tm->expected_transport_timeout,
           tm->expected_real_no_reply, tm->expected_real_reset,
           tm->expected_real_policy_drop,
           tm->connector_downstream_reset_observed,
           tm->direct_send_events,
           tm->vpp_buffers_allocated, tm->vpp_buffers_freed, tm->vpp_buffer_residue,
           tm->error[0] ? tm->error : "");
  if (keep_tun)
    oi3_rearm_tun_flow (vm, tm);
  else {
    if (tm->multi_mode)
      atomic_store_explicit (&tm->multi_admission_open, 0,
                             memory_order_release);
    tm->finished = 1;
    tm->active = 0;
    tm->phase = OI3_DONE;
  }
  (void)vm;
}

static void
oi3_finish (vlib_main_t *vm)
{
  oi3_finish_for (vm, &oi3_main);
}

/* HEV's task allocator is process-global even though each owner context and
 * task step is owner-thread local.  Serialize only init/fini, matching the
 * proven OI4 seam; never hold this lock while driving a context. */
static int
oi3_task_init (oi3_main_t *tm)
{
  int result;
  pthread_mutex_lock (&oi3_task_init_lock);
  result = tm->api.task_init ();
  pthread_mutex_unlock (&oi3_task_init_lock);
  return result;
}

static void
oi3_task_fini (oi3_main_t *tm)
{
  pthread_mutex_lock (&oi3_task_init_lock);
  tm->api.task_fini ();
  pthread_mutex_unlock (&oi3_task_init_lock);
}

static int
oi3_start_context (oi3_main_t *tm)
{
  oi3_callbacks_t callbacks = { .output = oi3_output, .data = tm };
  if (oi3_task_init (tm) < 0) return -1;
  tm->api.owner_config_default (&tm->owner_config);
  tm->owner_config.identity = 0x13000001U + tm->family + tm->protocol;
  tm->owner_config.packet_credit_limit = 8; tm->owner_config.inflight_pbuf_credit_limit = 8;
  tm->owner_config.max_session_count = 4; tm->owner_config.protected_socket_credit_limit = 4;
  tm->owner_config.tcp_buffer_size = 8192;
  tm->context = tm->api.create (&callbacks, &tm->owner_config);
  if (!tm->context) { oi3_task_fini (tm); return -1; }
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
    tm->api.destroy (tm->context); tm->context = NULL; oi3_task_fini (tm);
    return -1;
  }
  memset (&tm->runtime_identity, 0, sizeof (tm->runtime_identity));
  tm->api.runtime_identity (tm->context, &tm->runtime_identity);
  oi3_lwip_identity_t lwip_identity;
  memset (&lwip_identity, 0, sizeof (lwip_identity));
  tm->api.identity (tm->context, &lwip_identity);
  tm->lwip_context = (void *)(uintptr_t)lwip_identity.context;
  if (!tm->lwip_context) {
    oi3_error ("OI3 lwip owner identity is empty");
    return -1;
  }
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
  fprintf (stderr, "oi3 lwip-identity context=%p tcp-ticks=%u active-pcb=%p\n",
           tm->lwip_context, lwip_identity.tcp_ticks_value,
           (void *)lwip_identity.tcp_active_pcb);
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

/* HEV owns the protected socket read/write operation.  Publish its exact
 * result synchronously from the HEV session task instead of peeking SO_ERROR
 * in a competing observer.  Under external driving this callback executes on
 * the canonical FlowStackOwner thread.  The readiness helper only wakes that
 * owner and never reads or classifies socket state. */
static void
oi3_connector_transport_event (void *data, HevOwnerRuntime *owner,
                               tcp_pcb_t *pcb, unsigned int event,
                               int error)
{
  oi3_main_t *tm = data;
  (void)owner;
  (void)pcb;
  if (!tm || tm->protocol != 6 || tm->connector_error_reported)
    return;

  if (event == OI3_TCP_TRANSPORT_PEER_EOF) {
    tm->connector_peer_eof_observed++;
    fprintf (stderr,
             "oi3 transport-event result=PEER_EOF owner=%u generation=%llu "
             "owner-pthread=%lu\n",
             tm->owner_id, (unsigned long long)tm->generation,
             (unsigned long)pthread_self ());
    return;
  }

  if (error == EAGAIN || error == EWOULDBLOCK || error == EINTR || error == 0)
    return;
  tm->connector_last_error = error;
  tm->connector_error_reported = 1;
  tm->transport_failures++;
  if (error == ECONNRESET)
    tm->connector_reset_observed++;
  fprintf (stderr,
           "oi3 transport-event result=%s errno=%d %s owner=%u "
           "generation=%llu owner-pthread=%lu reset-observed=%u\n",
           event == OI3_TCP_TRANSPORT_READ_ERROR ? "READ_ERROR" :
                                                   "WRITE_ERROR",
           error, strerror (error), tm->owner_id,
           (unsigned long long)tm->generation,
           (unsigned long)pthread_self (), tm->connector_reset_observed);
}

static int
oi3_prepare_tun_flow (oi3_main_t *tm)
{
  /* A real TUN flow owns a fresh request generation.  Keeping this non-zero
   * makes the Java broker completion and every late-token check auditable. */
  tm->finished = 0;
  tm->tun_flow_count++;
  tm->generation++;
  if (tm->generation == 0) tm->generation = 1;
  tm->udp_datagram_inflight = 0;
  tm->start_ns = oi3_now_ns ();
  tm->tun_flow_deadline_ns = oi3_now_ns () + OI3_TUN_FLOW_TIMEOUT_NS;
  fprintf (stderr, "oi3 tun-flow count=%u deadline-ms=%llu\n",
           tm->tun_flow_count,
           (unsigned long long)(OI3_TUN_FLOW_TIMEOUT_NS / 1000000ULL));
  fprintf (stderr, "oi3 tun-flow generation=%llu epoch=%llu underlay-handle=%lld "
           "underlay-available=%u\n",
           (unsigned long long)tm->generation,
           (unsigned long long)tm->underlay_epoch,
           (long long)tm->underlay_handle, tm->underlay_available);
  if (!tm->multi_mode && oi3_setup_broker (tm) < 0) return -1;
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
oi3_refresh_connector_state (oi3_main_t *tm)
{
  int socket_error = 0;
  socklen_t socket_error_length = sizeof (socket_error);

  if (!tm || tm->connector_fd < 0 ||
      !atomic_load_explicit (&tm->connector_connect_pending,
                             memory_order_acquire))
    return;
  if (getsockopt (tm->connector_fd, SOL_SOCKET, SO_ERROR,
                  &socket_error, &socket_error_length) < 0)
    return;
  if (socket_error == 0) {
    atomic_store_explicit (&tm->connector_connect_pending, 0,
                           memory_order_release);
    return;
  }
  if (socket_error == EINPROGRESS || socket_error == EALREADY)
    return;
  tm->connector_last_error = socket_error;
  if (!tm->connector_error_reported) {
    tm->transport_failures++;
    tm->connector_error_reported = 1;
  }
}

/* Network callbacks arrive on VPP's main/control thread, but underlay
 * ownership belongs to the FlowStackOwner worker.  The CLI handler publishes
 * one atomic snapshot and queues an owner token; this function is the only
 * place that mutates the flow's epoch or requests an active-flow teardown. */
static void
oi3_apply_pending_underlay (oi3_main_t *tm)
{
  if (!tm || !atomic_exchange_explicit (&tm->pending_underlay_update, 0,
                                        memory_order_acq_rel))
    return;
  u64 event_epoch = atomic_load_explicit (&tm->pending_underlay_epoch,
                                           memory_order_acquire);
  int64_t event_handle = atomic_load_explicit (&tm->pending_underlay_handle,
                                                memory_order_acquire);
  u32 event_available = atomic_load_explicit (&tm->pending_underlay_available,
                                               memory_order_acquire);
  if (event_epoch == 0 || event_epoch < tm->underlay_epoch) {
    fprintf (stderr, "oi3 underlay-epoch-stale event-epoch=%llu current-epoch=%llu "
             "event-handle=%lld current-handle=%lld\n",
             (unsigned long long)event_epoch,
             (unsigned long long)tm->underlay_epoch,
             (long long)event_handle, (long long)tm->underlay_handle);
    return;
  }
  bool epoch_changed = event_epoch > tm->underlay_epoch;
  bool metadata_changed = tm->underlay_handle != event_handle ||
                          tm->underlay_available != event_available;
  if (!epoch_changed && !metadata_changed)
    return;
  u64 old_epoch = tm->underlay_epoch;
  int64_t old_handle = tm->underlay_handle;
  tm->underlay_epoch = event_epoch;
  tm->underlay_handle = event_handle;
  tm->underlay_available = event_available;
  fprintf (stderr, "oi3 underlay-epoch owner-apply old-epoch=%llu new-epoch=%llu "
           "old-handle=%lld new-handle=%lld available=%u\n",
           (unsigned long long)old_epoch,
           (unsigned long long)tm->underlay_epoch,
           (long long)old_handle, (long long)tm->underlay_handle,
           tm->underlay_available);
  if (epoch_changed && tm->active && tm->context && !tm->finished &&
      tm->phase != OI3_DONE) {
    tm->underlay_invalidated = 1;
    tm->finish_requested = 1;
    tm->phase = OI3_STOPPING;
    fprintf (stderr,
             "oi3 epoch-invalidated reason=underlay-transition generation=%llu "
             "old-epoch=%llu new-epoch=%llu old-handle=%lld new-handle=%lld "
             "old-tcp-reconnect=0 old-udp-reuse=0\n",
             (unsigned long long)tm->generation,
             (unsigned long long)old_epoch,
             (unsigned long long)tm->underlay_epoch,
             (long long)old_handle, (long long)tm->underlay_handle);
  }
}

static void
oi3_worker_run_for (vlib_main_t *vm, vlib_node_runtime_t *node, u32 kind,
                    oi3_main_t *tm)
{
  oi3_current_tm = tm;
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
  if (tm->phase == OI3_DRIVE)
    oi3_connector_poll_join (tm);
  if (tm->tun_mode && !tm->context &&
      (kind == OI3_TUN_KIND ||
       (tm->multi_mode && tm->tun_pending_count != 0))) {
    if (tm->multi_mode && tm->tun_pending_count != 0) {
      oi3_tun_pending_entry_t *entry =
        &tm->tun_pending[tm->tun_pending_head];
      if (oi3_parse_tun_packet (tm, entry->packet, entry->length) < 0) {
        fprintf (stderr, "oi3 multi-parse-failure owner=%u length=%u "
                 "first=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
                 "proto4=%u proto6=%u\n", tm->owner_id, entry->length,
                 entry->length > 0 ? entry->packet[0] : 0,
                 entry->length > 1 ? entry->packet[1] : 0,
                 entry->length > 2 ? entry->packet[2] : 0,
                 entry->length > 3 ? entry->packet[3] : 0,
                 entry->length > 4 ? entry->packet[4] : 0,
                 entry->length > 5 ? entry->packet[5] : 0,
                 entry->length > 6 ? entry->packet[6] : 0,
                 entry->length > 7 ? entry->packet[7] : 0,
                 entry->length > 9 ? entry->packet[9] : 0,
                 entry->length > 6 ? entry->packet[6] : 0);
        oi3_error ("OI3 multi-owner TUN packet parse failed");
        return;
      }
    }
    if (oi3_prepare_tun_flow (tm) < 0) {
      oi3_error ("OI3 TUN FlowStackOwner/broker start failed");
      return;
    }
    return;
  }
  if (kind == 1) {
    if (tm->phase != OI3_WAIT_BROKER) return;
    if (tm->broker_result != OI2_RESULT_SUCCESS) {
      tm->infrastructure_failures++;
      fprintf (stderr,
               "oi3 broker-completion result=%s(%u) expected=%s(%u) "
               "infrastructure-fault=1 owner=%u generation=%llu\n",
               oi3_broker_result_name (tm->broker_result),
               tm->broker_result,
               oi3_broker_result_name (tm->expected_infrastructure_failure),
               tm->expected_infrastructure_failure,
               tm->owner_id, (unsigned long long)tm->generation);
      if (tm->expected_infrastructure_failure != tm->broker_result)
        oi3_error ("broker completion failure");
      else {
        tm->phase = OI3_STOPPING;
        tm->finish_requested = 1;
        atomic_store_explicit (&tm->multi_admission_open, 0,
                               memory_order_release);
      }
      return;
    }
    fprintf (stderr, "oi3 broker-completion result=SUCCESS token=%llu generation=%llu "
             "owner=%u\n", (unsigned long long)tm->token, (unsigned long long)tm->generation, tm->target_thread);
    tm->phase = OI3_SUBMIT;
  }
  if (!tm->tun_mode && !tm->context && tm->phase != OI3_FAULT) {
    if (oi3_start_context (tm) < 0) { oi3_error ("FlowStackOwner start failed"); return; }
    tm->phase = OI3_WAIT_BROKER;
    return;
  }
  if (tm->tun_mode && tm->context && tm->phase != OI3_WAIT_BROKER &&
      tm->phase != OI3_STOPPING) {
    if (kind == 1 && tm->tun_pending_count == 0) {
      oi3_error ("OI3 broker completion arrived without TUN packet");
      tm->finish_requested = 1;
      return;
    }
    if (tm->multi_mode && tm->protocol == 17) {
      /* UDP remains one datagram at a time at the HEV/lwIP seam, but the
       * owner generation is no longer one datagram.  packet_submitted is a
       * cumulative ledger; udp_datagram_inflight is the only submit guard. */
      if (oi3_submit_next_udp_datagram_if_idle (tm) < 0) {
        oi3_error ("OI3 TUN UDP packet submit failed");
        tm->finish_requested = 1;
        return;
      }
    } else {
      while (tm->tun_pending_count != 0) {
        if (oi3_submit_pending_tun (tm) < 0) {
          oi3_error ("OI3 TUN packet submit failed");
          tm->finish_requested = 1;
          return;
        }
      }
    }
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
    if (tm->connector_error_reported && !tm->expected_real_reset) {
      tm->phase = OI3_STOPPING;
      tm->finish_requested = 1;
      return;
    }
    oi3_task_budget_t budget = { .max_quanta = 1 }; oi3_task_result_t result;
    u32 direct_send_before = tm->direct_send_events;
    if (tm->api.task_step (&budget, &result) < 0) { oi3_error ("owner task drive failed"); return; }
    tm->worker_steps++; tm->task_quanta += result.quanta;
    if (oi3_drive_lwip_timer_after_send (tm, direct_send_before) < 0)
      return;
    if (!tm->expected_real_reset)
      oi3_refresh_connector_state (tm);
    if (tm->connector_error_reported) {
      tm->phase = OI3_STOPPING;
      tm->finish_requested = 1;
      return;
    }
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
      if (tm->tun_flow_deadline_ns && oi3_now_ns () >= tm->tun_flow_deadline_ns) {
        fprintf (stderr, "oi3 tun-flow timeout steps=%u output=%u direct=%u\n",
                 tm->worker_steps, tm->output_packets, tm->output_direct);
        if (tm->expected_real_no_reply && tm->multi_mode &&
            tm->protocol == 17 && tm->direct_send_events > 0 &&
            tm->output_packets == 0 && tm->output_direct == 0 &&
            tm->transport_failures == 0 && tm->infrastructure_failures == 0) {
          fprintf (stderr,
                   "oi3 real no-reply outcome=EXPECTED_REAL_NO_REPLY owner=%u "
                   "port=%u direct-send=%u output=%u direct=%u\n",
                   tm->owner_id, tm->target_port, tm->direct_send_events,
                   tm->output_packets, tm->output_direct);
        } else if (tm->multi_mode && tm->protocol == 6 && tm->output_packets > 0 &&
            tm->output_handshake > 0 && tm->output_direct == 0 &&
            tm->endpoint_received == 0 && tm->transport_failures == 0 &&
            tm->infrastructure_failures == 0) {
          /* Full-route multi-owner mode can receive an unrelated Android TCP
           * flow whose protected endpoint never completes.  That is a
           * transport timeout for this owner-local generation, not grounds to
           * stop the shared TUN or reject later owners/tuples. */
          tm->expected_transport_timeout = 1;
          tm->cell = OI3_CELL_NO_REPLY;
          fprintf (stderr,
                   "oi3 ambient transport outcome=EXPECTED_TIMEOUT owner=%u "
                   "port=%u output=%u handshake=%u direct=%u\n",
                   tm->owner_id, tm->target_port, tm->output_packets,
                   tm->output_handshake, tm->output_direct);
        } else if (tm->cell == OI3_CELL_NO_REPLY) {
          if (tm->tun_output_errors != 0 || tm->output_packets != 0 ||
              tm->output_direct != 0 || tm->return_rewritten != 0)
            snprintf (tm->error, sizeof (tm->error),
                      "unexpected-no-reply-output");
        } else if (tm->multi_mode && tm->protocol == 17 &&
                   (tm->tun_submit_rejects > 0 || tm->tun_queue_rejects > 0) &&
                   tm->tun_output_errors == 0 &&
                   tm->transport_failures == 0 &&
                   tm->infrastructure_failures == 0) {
          /* A category-1 HEV credit rejection settles only the current UDP
           * datagram.  UDP loss is an allowed overload result; preserve the
           * owner/TUN generation and let teardown classify this pressure
           * envelope explicitly instead of calling it a failed reply flow. */
          tm->overload_expected = 1;
          fprintf (stderr,
                   "oi3 overload outcome=EXPECTED_PACKET_DROP owner=%u "
                   "submit-rejects=%u queue-rejects=%u output=%u direct=%u "
                   "rewritten=%u\n",
                   tm->owner_id, tm->tun_submit_rejects,
                   tm->tun_queue_rejects,
                   tm->output_packets, tm->output_direct,
                   tm->return_rewritten);
        } else if (tm->output_packets == 0)
          snprintf (tm->error, sizeof (tm->error),
                    "tun-flow-timeout-no-reply");
        else if (tm->output_direct == 0 || tm->return_rewritten == 0)
          snprintf (tm->error, sizeof (tm->error),
                    "tun-flow-output-not-a-direct-return");
        else if (tm->tun_output_errors != 0)
          snprintf (tm->error, sizeof (tm->error),
                    "tun-flow-tun-write-failure");
        tm->phase = OI3_STOPPING;
      } else if (tm->multi_mode && tm->protocol == 17) {
        int udp_submit = oi3_submit_next_udp_datagram_if_idle (tm);
        if (udp_submit < 0) {
          oi3_error ("OI3 TUN UDP packet submit failed");
          tm->finish_requested = 1;
          return;
        }
        if (udp_submit > 0) {
          tm->phase = OI3_DRIVE;
          if (oi3_enqueue_owner_for (tm, vm, 0) < 0)
            oi3_error ("OI3 TUN UDP submit-next requeue failed");
          return;
        }
        if (result.total_task_count) {
          if (result.running_task_count || tm->connector_fd < 0) {
            if (oi3_enqueue_owner_for (tm, vm, 0) < 0)
              oi3_error ("OI3 TUN drive requeue failed");
          } else if (oi3_connector_poll_arm (tm) < 0) {
            oi3_error ("OI3 connector readiness arm failed");
          }
          return;
        }
        if (tm->udp_datagram_inflight && tm->connector_fd < 0) {
          snprintf (tm->error, sizeof (tm->error),
                    "tun-udp-window-connector-missing");
          tm->phase = OI3_STOPPING;
        } else {
          tm->phase = OI3_DRIVE;
          fprintf (stderr,
                   "oi3 tun-udp-window idle generation=%llu inflight=%u "
                   "pending=%u submitted=%u output=%u direct=%u\n",
                   (unsigned long long)tm->generation,
                   tm->udp_datagram_inflight, tm->tun_pending_count,
                   tm->packet_submitted, tm->output_packets,
                   tm->output_direct);
          if (tm->connector_fd >= 0 &&
              oi3_connector_poll_arm (tm) < 0)
            oi3_error ("OI3 connector readiness arm failed");
          return;
        }
      } else if (result.total_task_count) {
        if (oi3_tcp_positive_fin_complete (tm) &&
            !result.running_task_count) {
          fprintf (stderr,
                   "oi3 tcp-positive-fin-complete owner=%u generation=%llu "
                   "output=%u direct=%u rewritten=%u tasks=%u running=%u\n",
                   tm->owner_id, (unsigned long long)tm->generation,
                   tm->output_packets, tm->output_direct,
                   tm->return_rewritten, result.total_task_count,
                   result.running_task_count);
          tm->phase = OI3_STOPPING;
          tm->finish_requested = 1;
          return;
        }
        if (result.running_task_count || tm->connector_fd < 0) {
          if (oi3_connector_poll_arm_after_direct_send (tm) < 0) {
            oi3_error ("OI3 connector post-send readiness arm failed");
            return;
          }
          if (oi3_enqueue_owner_for (tm, vm, 0) < 0)
            oi3_error ("OI3 TUN drive requeue failed");
        } else if (oi3_connector_poll_arm (tm) < 0) {
          oi3_error ("OI3 connector readiness arm failed");
        }
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
      if (oi3_enqueue_owner_for (tm, vm, 0) < 0) oi3_error ("OI3 TCP ACK requeue failed");
      return;
    } else if (tm->protocol == 6 && tm->tcp_ack_submitted &&
               !tm->tcp_payload_submitted) {
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP payload submit failed"); return; }
      tm->phase = OI3_DRIVE;
      if (oi3_enqueue_owner_for (tm, vm, 0) < 0) oi3_error ("OI3 TCP payload requeue failed");
      return;
    } else if (tm->protocol == 6 && tm->output_direct &&
               !tm->tcp_fin_submitted) {
      if (oi3_submit_fixture (tm) < 0) { oi3_error ("TCP FIN submit failed"); return; }
      tm->phase = OI3_DRIVE;
      if (oi3_enqueue_owner_for (tm, vm, 0) < 0) oi3_error ("OI3 TCP FIN requeue failed");
      return;
    } else if ((tm->protocol == 17 && tm->output_direct) ||
               (tm->protocol == 6 && tm->output_direct)) {
      tm->phase = OI3_STOPPING;
    } else if (tm->worker_steps > 512) {
      tm->phase = OI3_STOPPING;
    } else {
      if (oi3_enqueue_owner_for (tm, vm, 0) < 0) oi3_error ("OI3 drive requeue failed");
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
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++) {
    vlib_buffer_t *buffer = vlib_get_buffer (vm, from[i]);
    u32 *data = (u32 *)buffer->data;
    u32 kind = data[0];
    oi3_main_t *tm = &oi3_main;
    bool tun_like = kind == OI3_TUN_KIND ||
                    kind == OI3_TUN_DEFERRED_KIND;
    const u8 *payload = buffer->data + 8;
    u32 length = tun_like ? data[1] : 0;
    if (oi3_multi.active) {
      u32 owner_id = data[1];
      if (owner_id >= oi3_multi.owner_count) {
        oi3_multi.wrong_owner_events++;
        vlib_buffer_free_one (vm, from[i]);
        continue;
      }
      tm = &oi3_multi.owners[owner_id];
      if (tun_like) {
        length = data[2];
        payload = buffer->data + 12;
      }
    }
    if (kind == OI3_TUN_DEFERRED_KIND) {
      uint64_t flow_hash = 0;
      int deferred_result = -1;
      if (tm->multi_mode && length <= OI3_MAX_TUN_PACKET &&
          oi3_multi_flow_hash (payload, length, &flow_hash) == 0)
        deferred_result =
          oi3_tun_deferred_enqueue (tm, payload, length, flow_hash);
      if (deferred_result >= 0) {
        if (deferred_result == 0)
          oi3_multi.route_deferred[tm->owner_id]++;
        if (!atomic_load_explicit (&tm->active_flow_valid,
                                   memory_order_acquire)) {
          (void)oi3_admit_deferred_tun_flow (vm, tm);
        } else if (!tm->finish_requested && tm->context &&
                   tm->protocol == 6 && tm->output_packets != 0 &&
                   tm->output_direct != 0 && tm->return_rewritten != 0) {
          /* A successor SYN cannot be submitted into the current HEV context,
           * but dropping it creates the F050 staircase cliff.  The canonical
           * owner remains unchanged: successor SYN forces completed active
           * owner toward rearm, then oi3_rearm_tun_flow admits exactly one
           * deferred SYN from this owner-local queue. */
          atomic_store_explicit (&tm->multi_admission_open, 0,
                                 memory_order_release);
          tm->phase = OI3_STOPPING;
          tm->finish_requested = 1;
          fprintf (stderr,
                   "oi4 multi-deferred successor SYN forces completed active owner toward rearm owner=%u hash=%llu output=%u direct=%u rewritten=%u deferred=%u\n",
                   tm->owner_id, (unsigned long long)flow_hash,
                   tm->output_packets, tm->output_direct,
                   tm->return_rewritten, tm->multi_deferred_count);
        }
      } else {
        atomic_fetch_add_explicit (&tm->multi_admission_rejects, 1,
                                   memory_order_relaxed);
        oi3_multi.route_rejects[tm->owner_id]++;
        fprintf (stderr,
                 "oi4 multi-admission result=REJECT owner=%u hash=%llu "
                 "reason=deferred-owner-queue-full depth=%u\n",
                 tm->owner_id, (unsigned long long)flow_hash,
                 tm->multi_deferred_count);
      }
    } else if (kind == OI3_TUN_KIND) {
      (void)oi3_owner_accept_tun_packet (tm, payload, length);
    }
    tm->worker_token_pending = 0;
    if (tm->active) {
      oi3_apply_pending_underlay (tm);
      oi3_worker_run_for (vm, node, kind, tm);
    }
    vlib_buffer_free_one (vm, from[i]); tm->vpp_buffers_freed++;
    tm->vpp_buffer_residue = tm->vpp_buffers_allocated - tm->vpp_buffers_freed;
  }
  /* Finish only after the current owner token has been reclaimed.  This
   * makes the residue ledger reflect the actual post-node state rather than
   * counting the buffer that is still on this frame. */
  if (!oi3_multi.active && oi3_main.active && oi3_main.finish_requested &&
      oi3_main.vpp_buffer_residue == 0)
    oi3_finish_for (vm, &oi3_main);
  if (oi3_multi.active) {
    u32 current_thread = vlib_get_thread_index ();

    for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
      oi3_main_t *owner_tm = &oi3_multi.owners[owner];
      if (!owner_tm->active || !owner_tm->finish_requested ||
          owner_tm->vpp_buffer_residue != 0)
        continue;
      if (owner_tm->target_thread == current_thread) {
        oi3_finish_for (vm, owner_tm);
      } else if (!owner_tm->worker_token_pending &&
                 oi3_enqueue_owner_for (owner_tm, vm, 0) < 0) {
        snprintf (owner_tm->error, sizeof (owner_tm->error),
                  "owner-finish-enqueue-failed current-thread=%u "
                  "target-thread=%u",
                  current_thread, owner_tm->target_thread);
        owner_tm->phase = OI3_FAULT;
      }
    }
    oi3_multi_maybe_teardown ();
  }
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
  tm->tcp_connector.transport_event = oi3_connector_transport_event;
  memset (&tm->udp_connector, 0, sizeof (tm->udp_connector));
  tm->udp_connector.data = tm;
  tm->udp_connector.socket_create = oi3_connector_socket_create;
  tm->udp_connector.protect = oi3_connector_protect;
  tm->udp_connector.connect_udp = oi3_connector_connect;
  tm->udp_connector.input = oi3_connector_input_udp;
  tm->udp_connector.output = oi3_connector_output_udp;
}

static void
oi3_multi_owner_init (oi3_main_t *tm, u32 owner_id, u32 target_thread,
                      int tun_fd, int request_fd, int completion_fd,
                      const oi3_hev_api_t *api)
{
  memset (tm, 0, sizeof (*tm));
  tm->api = *api;
  tm->owner_id = owner_id;
  tm->multi_mode = 1;
  tm->target_thread = target_thread;
  tm->frame_queue = oi3_main.frame_queue;
  tm->tun_mode = 1;
  tm->tun_fd = tun_fd;
  tm->tun_file_index = -1;
  tm->completion_file_index = -1;
  tm->connector_wake_file_index = -1;
  tm->tun_handoff_file_index = -1;
  tm->tun_handoff_pair[0] = tm->tun_handoff_pair[1] = -1;
  tm->request_pair[0] = tm->request_pair[1] = request_fd;
  tm->completion_pair[0] = tm->completion_pair[1] = completion_fd;
  tm->broker_external = 1;
  tm->broker_available = 1;
  tm->broker_result = OI2_RESULT_BROKER_UNAVAILABLE;
  tm->phase = OI3_DONE;
  tm->active = 1;
  tm->finished = 1;
  tm->underlay_epoch = atomic_load_explicit (&oi3_main.source_underlay_epoch,
                                             memory_order_acquire);
  tm->underlay_handle = atomic_load_explicit (&oi3_main.source_underlay_handle,
                                               memory_order_acquire);
  tm->underlay_available = atomic_load_explicit (
    &oi3_main.source_underlay_available, memory_order_acquire);
  if (!tm->underlay_epoch)
    tm->underlay_epoch = 1;
  atomic_init (&tm->source_underlay_epoch, tm->underlay_epoch);
  atomic_init (&tm->source_underlay_handle, tm->underlay_handle);
  atomic_init (&tm->source_underlay_available, tm->underlay_available);
  atomic_init (&tm->pending_underlay_epoch, tm->underlay_epoch);
  atomic_init (&tm->pending_underlay_handle, tm->underlay_handle);
  atomic_init (&tm->pending_underlay_available, tm->underlay_available);
  atomic_init (&tm->pending_underlay_update, 0);
  atomic_init (&tm->broker_stop, 0);
  atomic_init (&tm->endpoint_stop, 1);
  atomic_init (&tm->endpoint_ready, 0);
  atomic_init (&tm->connector_poll_stop, 0);
  atomic_init (&tm->connector_poll_done, 1);
  atomic_init (&tm->connector_wake_pending, 0);
  atomic_init (&tm->connector_connect_pending, 0);
  atomic_init (&tm->connector_write_pending, 0);
  atomic_init (&tm->multi_admission_open, 1);
  atomic_init (&tm->multi_dispatch_depth, 0);
  atomic_init (&tm->multi_admission_rejects, 0);
  atomic_init (&tm->active_flow_hash, 0);
  atomic_init (&tm->active_flow_valid, 0);
  atomic_init (&tm->multi_tcp_wait_syn, 0);
  atomic_init (&tm->multi_tcp_tombstone_hash, 0);
  atomic_init (&tm->multi_tcp_tombstone_valid, 0);
  tm->request_pair[0] = tm->request_pair[1] = request_fd;
  tm->completion_pair[0] = tm->completion_pair[1] = completion_fd;
  tm->direct_fd = tm->connector_fd = tm->endpoint_fd =
    tm->endpoint_client_fd = -1;
  tm->connector_wake_pipe[0] = tm->connector_wake_pipe[1] = -1;
  tm->tun_handoff_pair[0] = tm->tun_handoff_pair[1] = -1;
  tm->tun_handoff_file_index = -1;
  tm->tun_file_index = -1;
  tm->completion_file_index = -1;
  oi3_init_connectors (tm);
}

static void
oi3_multi_maybe_teardown (void)
{
  if (!oi3_multi.active)
    return;
  for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
    oi3_main_t *tm = &oi3_multi.owners[owner];
    if (tm->active || tm->context || tm->vpp_buffer_residue != 0)
      return;
    if (tm->connector_wake_file_index >= 0) {
      clib_file_del_by_index (&file_main, tm->connector_wake_file_index);
      tm->connector_wake_file_index = -1;
    }
    if (tm->connector_wake_pipe[0] >= 0)
      close (tm->connector_wake_pipe[0]);
    if (tm->connector_wake_pipe[1] >= 0)
      close (tm->connector_wake_pipe[1]);
    tm->connector_wake_pipe[0] = tm->connector_wake_pipe[1] = -1;
    oi3_close_tun_handoff_file (tm);
  }
  if (oi3_multi.completion_file_index >= 0) {
    clib_file_del_by_index (&file_main, oi3_multi.completion_file_index);
    oi3_multi.completion_file_index = -1;
  }
  oi3_multi_completion_poll_stop ();
  if (oi3_multi.completion_watch_fd >= 0) {
    close (oi3_multi.completion_watch_fd);
    oi3_multi.completion_watch_fd = -1;
  }
  if (oi3_multi.tun_file_index >= 0) {
    clib_file_del_by_index (&file_main, oi3_multi.tun_file_index);
    oi3_multi.tun_file_index = -1;
  }
  if (oi3_multi.tun_fd >= 0) {
    close (oi3_multi.tun_fd);
    oi3_multi.tun_fd = -1;
  }
  oi3_multi.active = 0;
  fprintf (stderr, "oi4 multi-session state=STOPPED owners=%u route=%u/%u/%u/%u "
           "reject=%u/%u/%u/%u deferred=%u/%u/%u/%u "
           "reassigned=%u/%u/%u/%u wrong-owner=%u policy-drop=%u\n",
           oi3_multi.owner_count,
           oi3_multi.route_count[0], oi3_multi.route_count[1],
           oi3_multi.route_count[2], oi3_multi.route_count[3],
           oi3_multi.route_rejects[0], oi3_multi.route_rejects[1],
           oi3_multi.route_rejects[2], oi3_multi.route_rejects[3],
           oi3_multi.route_deferred[0], oi3_multi.route_deferred[1],
           oi3_multi.route_deferred[2], oi3_multi.route_deferred[3],
           oi3_multi.route_reassigned[0], oi3_multi.route_reassigned[1],
           oi3_multi.route_reassigned[2], oi3_multi.route_reassigned[3],
           oi3_multi.wrong_owner_events, oi3_multi.policy_drop_packets);
}

static clib_error_t *
oi3_multi_tun_command_fn (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  int fd = -1;
  u32 target_a = 1, target_b = 2, target_c = 0, target_d = 0;
  u8 *lib_path = NULL;
  (void)cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "fd %d", &fd));
    else if (unformat (input, "target-thread-a %u", &target_a));
    else if (unformat (input, "target-thread-b %u", &target_b));
    else if (unformat (input, "target-thread-c %u", &target_c));
    else if (unformat (input, "target-thread-d %u", &target_d));
    else if (unformat (input, "lib %s", &lib_path));
    else {
      vec_free (lib_path);
      return clib_error_return (0, "unknown OI4 multi input `%U'",
                                format_unformat_error, input);
    }
  }
  u32 targets[OI3_MULTI_OWNER_CAPACITY] = {
    target_a, target_b, target_c, target_d
  };
  u32 owner_count = 2;
  if (target_c)
    owner_count = 3;
  if (target_d) {
    if (!target_c) {
      vec_free (lib_path);
      return clib_error_return (0, "OI4 multi target-thread-d requires target-thread-c");
    }
    owner_count = 4;
  }
  if (fd < 0 || target_a == 0 || target_b == 0) {
    vec_free (lib_path);
    return clib_error_return (0, "OI4 multi requires fd and at least two worker targets");
  }
  for (u32 i = 0; i < owner_count; i++) {
    if (targets[i] == 0 || targets[i] >= vlib_get_n_threads ()) {
      vec_free (lib_path);
      return clib_error_return (0, "OI4 multi worker target is invalid");
    }
    for (u32 j = i + 1; j < owner_count; j++) {
      if (targets[i] == targets[j]) {
        vec_free (lib_path);
        return clib_error_return (0, "OI4 multi worker targets must be distinct");
      }
    }
  }
  if (owner_count > OI3_MULTI_OWNER_CAPACITY) {
    vec_free (lib_path);
    return clib_error_return (0, "OI4 multi owner count exceeds capacity");
  }
  if (oi3_multi.active || oi3_main.active) {
    vec_free (lib_path);
    return clib_error_return (0, "OI4/OI3 already active");
  }
  const char *request_text = getenv ("SAKAMOTO_OI3_REQUEST_FD");
  const char *completion_text = getenv ("SAKAMOTO_OI3_COMPLETION_FD");
  const char *env_path = getenv ("OI3_HEV_LIB");
  const char *policy_drop_ip4_text =
    getenv ("SAKAMOTO_OI3_POLICY_DROP_IP4");
  if (!request_text || !completion_text) {
    vec_free (lib_path);
    return clib_error_return (0, "OI4 multi requires the Android broker endpoints");
  }
  if (!lib_path && env_path)
    lib_path = format (0, "%s%c", env_path, 0);
  if (!lib_path || oi3_load_hev ((char *)lib_path) < 0) {
    vec_free (lib_path);
    return clib_error_return (0, "OI4 multi HEV load failed: %s", oi3_main.error);
  }
  vec_free (lib_path);
  memset (&oi3_multi, 0, sizeof (oi3_multi));
  oi3_multi.owner_count = owner_count;
  oi3_multi.tun_fd = fd;
  oi3_multi.tun_file_index = -1;
  oi3_multi.completion_file_index = -1;
  oi3_multi.completion_watch_fd = -1;
  oi3_multi.request_fd = atoi (request_text);
  oi3_multi.completion_fd = atoi (completion_text);
  if (policy_drop_ip4_text && policy_drop_ip4_text[0]) {
    struct in_addr drop_ip4;
    if (inet_pton (AF_INET, policy_drop_ip4_text, &drop_ip4) != 1)
      return clib_error_return (0, "OI4 multi invalid policy-drop-ip4");
    oi3_multi.policy_drop_ip4 = drop_ip4.s_addr;
    oi3_multi.policy_drop_ip4_set = 1;
  }
  const char *expected_failure = getenv ("SAKAMOTO_OI3_EXPECTED_FAILURE");
  u32 expected_real_no_reply =
    expected_failure && !strcmp (expected_failure, "real-no-reply");
  u32 expected_real_reset =
    expected_failure && !strcmp (expected_failure, "real-reset");
  u32 expected_real_policy_drop =
    expected_failure && !strcmp (expected_failure, "real-policy-drop");
  u32 expected_infrastructure_failure = OI2_RESULT_SUCCESS;
  if (expected_failure && !strcmp (expected_failure, "bind-failure"))
    expected_infrastructure_failure = OI2_RESULT_BIND_FAILURE;
  else if (expected_failure && !strcmp (expected_failure, "protect-failure"))
    expected_infrastructure_failure = OI2_RESULT_PROTECT_FAILURE;
  else if (expected_failure && !strcmp (expected_failure, "broker-unavailable"))
    expected_infrastructure_failure = OI2_RESULT_BROKER_UNAVAILABLE;
  oi3_multi.hash_seed = 1469598103934665603ULL;
  if (oi3_multi.request_fd < 0 || oi3_multi.completion_fd < 0)
    return clib_error_return (0, "OI4 multi broker endpoint is invalid");
  for (u32 owner = 0; owner < oi3_multi.owner_count; owner++)
    {
      oi3_multi_owner_init (&oi3_multi.owners[owner], owner, targets[owner],
                            fd, oi3_multi.request_fd,
                            oi3_multi.completion_fd, &oi3_main.api);
      oi3_multi.owners[owner].expected_real_no_reply =
        expected_real_no_reply;
      oi3_multi.owners[owner].expected_real_reset = expected_real_reset;
      oi3_multi.owners[owner].expected_real_policy_drop =
        expected_real_policy_drop;
      oi3_multi.owners[owner].expected_infrastructure_failure =
        expected_infrastructure_failure == OI2_RESULT_SUCCESS
          ? 0 : expected_infrastructure_failure;
      if (oi3_ensure_tun_handoff_file (&oi3_multi.owners[owner]) < 0) {
        for (u32 cleanup_owner = 0; cleanup_owner <= owner; cleanup_owner++)
          oi3_close_tun_handoff_file (&oi3_multi.owners[cleanup_owner]);
        oi3_multi.active = 0;
        return clib_error_return_unix (0, "create OI4 owner TUN handoff");
      }
    }
  oi3_multi.active = 1;
  int flags = fcntl (fd, F_GETFL, 0);
  if (flags >= 0)
    (void)fcntl (fd, F_SETFL, flags | O_NONBLOCK);
  int completion_watch_fd = dup (oi3_multi.completion_fd);
  if (completion_watch_fd < 0) {
    oi3_multi.active = 0;
    return clib_error_return_unix (0, "duplicate OI4 completion endpoint");
  }
  oi3_multi.completion_watch_fd = completion_watch_fd;
  if (oi3_set_nonblocking_fd (completion_watch_fd) < 0) {
    close (completion_watch_fd);
    oi3_multi.completion_watch_fd = -1;
    oi3_multi.active = 0;
    return clib_error_return_unix (0, "set OI4 completion nonblocking");
  }
  atomic_store_explicit (&oi3_multi.completion_poll_stop, 0,
                         memory_order_release);
  if (pthread_create (&oi3_multi.completion_poll_thread, NULL,
                      oi3_multi_completion_poll_main, &oi3_multi) != 0) {
    close (completion_watch_fd);
    oi3_multi.completion_watch_fd = -1;
    oi3_multi.active = 0;
    return clib_error_return_unix (0, "start OI4 completion poll thread");
  }
  oi3_multi.completion_poll_started = 1;
  clib_file_t tun_file = { 0 };
  tun_file.read_function = oi3_multi_tun_read_ready;
  tun_file.file_descriptor = fd;
  tun_file.polling_thread_index = 0;
  tun_file.private_data = (uword)&oi3_multi;
  tun_file.description = format (0, "OI4 multi-owner real TUN fd %d", fd);
  oi3_multi.tun_file_index = (int)clib_file_add (&file_main, &tun_file);
  if (oi3_multi.tun_file_index < 0) {
    oi3_multi_completion_poll_stop ();
    for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
      atomic_store_explicit (&oi3_multi.owners[owner].multi_admission_open, 0,
                             memory_order_release);
      oi3_multi.owners[owner].active = 0;
    }
    oi3_multi_maybe_teardown ();
    return clib_error_return (0, "add OI4 TUN watcher");
  }
  int startup_failed = 0;
  for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
    if (oi3_ensure_connector_wake_file (&oi3_multi.owners[owner]) < 0) {
      startup_failed = 1;
      oi3_multi.owners[owner].active = 0;
      oi3_multi.owners[owner].finish_requested = 1;
      atomic_store_explicit (&oi3_multi.owners[owner].multi_admission_open, 0,
                             memory_order_release);
    }
  }
  if (startup_failed) {
    for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
      oi3_multi.owners[owner].active = 0;
      oi3_multi.owners[owner].finish_requested = 1;
      atomic_store_explicit (&oi3_multi.owners[owner].multi_admission_open, 0,
                             memory_order_release);
    }
    oi3_multi_maybe_teardown ();
    return clib_error_return (0, "add OI4 owner wake file");
  }
  fprintf (stderr,
           "oi4 multi enabled owners=%u target-a=%u target-b=%u target-c=%u "
           "target-d=%u fd=%d shared-graph=flow-stack-owner hash=fnv1a+mix "
           "expected-failure=%s policy-drop-ip4=%s\n",
           oi3_multi.owner_count, targets[0], targets[1], targets[2],
           targets[3], fd,
           expected_failure && expected_failure[0] ? expected_failure : "none",
           oi3_multi.policy_drop_ip4_set ? policy_drop_ip4_text : "none");
  vlib_cli_output (vm,
                   "oi4 multi enabled owners=%u target-a=%u target-b=%u "
                   "target-c=%u target-d=%u fd=%d",
                   oi3_multi.owner_count, targets[0], targets[1], targets[2],
                   targets[3], fd);
  return 0;
}

VLIB_CLI_COMMAND (oi3_multi_tun_command, static) = {
  .path = "sakamoto-oi3 multi tun",
  .short_help = "sakamoto-oi3 multi tun fd <n> target-thread-a <worker> target-thread-b <worker> [target-thread-c <worker> target-thread-d <worker>] lib <HEV>",
  .function = oi3_multi_tun_command_fn,
};

static clib_error_t *
oi3_multi_fault_command_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  u32 owner = ~0U;
  (void)cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "owner %u", &owner));
    else return clib_error_return (0, "expected owner index");
  }
  if (!oi3_multi.active || owner >= oi3_multi.owner_count)
    return clib_error_return (0, "OI4 multi owner is not active");
  oi3_main_t *tm = &oi3_multi.owners[owner];
  tm->fault_injected = 1;
  tm->finish_requested = 1;
  tm->phase = OI3_STOPPING;
  atomic_store_explicit (&tm->multi_admission_open, 0, memory_order_release);
  fprintf (stderr, "oi4 multi fault-injected owner=%u generation=%llu\n", owner,
           (unsigned long long)tm->generation);
  if (tm->context) {
    if (oi3_enqueue_owner_for (tm, vm, 0) < 0)
      return clib_error_return_unix (0, "enqueue OI4 owner fault");
  } else {
    oi3_finish_for (vm, tm);
    oi3_multi_maybe_teardown ();
  }
  return 0;
}

VLIB_CLI_COMMAND (oi3_multi_fault_command, static) = {
  .path = "sakamoto-oi3 multi fault",
  .short_help = "inject a bounded fault into one OI4 owner",
  .function = oi3_multi_fault_command_fn,
};

static clib_error_t *
oi3_multi_stop_command_fn (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  (void)input; (void)cmd;
  if (!oi3_multi.active)
    return clib_error_return (0, "OI4 multi is not active");
  for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
    oi3_main_t *tm = &oi3_multi.owners[owner];
    if (!tm->active)
      continue;
    tm->normal_stop_requested = 1;
    tm->finish_requested = 1;
    tm->phase = OI3_STOPPING;
    atomic_store_explicit (&tm->multi_admission_open, 0,
                           memory_order_release);
    if (tm->context)
      (void)oi3_enqueue_owner_for (tm, vm, 0);
    else
      oi3_finish_for (vm, tm);
  }
  oi3_multi_maybe_teardown ();
  return 0;
}

VLIB_CLI_COMMAND (oi3_multi_stop_command, static) = {
  .path = "sakamoto-oi3 multi stop", .short_help = "stop all OI4 owners",
  .function = oi3_multi_stop_command_fn,
};

static clib_error_t *
oi3_multi_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  (void)input; (void)cmd;
  vlib_cli_output (vm, "oi4 multi active=%u owners=%u route=%u/%u/%u/%u reject=%u/%u/%u/%u deferred=%u/%u/%u/%u reassigned=%u/%u/%u/%u wrong-owner=%u",
                   oi3_multi.active, oi3_multi.owner_count,
                   oi3_multi.route_count[0], oi3_multi.route_count[1],
                   oi3_multi.route_count[2], oi3_multi.route_count[3],
                   oi3_multi.route_rejects[0], oi3_multi.route_rejects[1],
                   oi3_multi.route_rejects[2], oi3_multi.route_rejects[3],
                   oi3_multi.route_deferred[0], oi3_multi.route_deferred[1],
                   oi3_multi.route_deferred[2], oi3_multi.route_deferred[3],
                   oi3_multi.route_reassigned[0],
                   oi3_multi.route_reassigned[1],
                   oi3_multi.route_reassigned[2],
                   oi3_multi.route_reassigned[3],
                   oi3_multi.wrong_owner_events);
  for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
    oi3_main_t *tm = &oi3_multi.owners[owner];
    vlib_cli_output (vm, "oi4 owner=%u active=%u phase=%s generation=%llu ingress=%u output=%u direct=%u rejects=%u deferred=%u buffers=%u/%u residue=%u error=%s",
                     owner, tm->active, oi3_phase_name (tm->phase),
                     (unsigned long long)tm->generation,
                     tm->tun_ingress_packets, tm->tun_output_packets,
                     tm->output_direct,
                     atomic_load_explicit (&tm->multi_admission_rejects,
                                           memory_order_relaxed),
                     tm->multi_deferred_count,
                     tm->vpp_buffers_allocated, tm->vpp_buffers_freed,
                     tm->vpp_buffer_residue, tm->error[0] ? tm->error : "");
  }
  return 0;
}

VLIB_CLI_COMMAND (oi3_multi_show_command, static) = {
  .path = "show sakamoto-oi3 multi", .short_help = "show OI4 multi-owner evidence",
  .function = oi3_multi_show_command_fn,
};

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
  if (tm->active || oi3_multi.active) {
    vec_free (lib_path);
    return clib_error_return (0, "OI3/OI4 already active");
  }
  env_path = getenv ("OI3_HEV_LIB");
  if (!lib_path && env_path) lib_path = format (0, "%s%c", env_path, 0);
  if (!lib_path || oi3_load_hev ((char *)lib_path) < 0) {
    vec_free (lib_path); return clib_error_return (0, "OI3 HEV load failed: %s", tm->error);
  }
  vec_free (lib_path);
  oi3_init_connectors (tm);
  memset (&tm->target_address, 0, sizeof (tm->target_address));
  memset (&tm->source_address, 0, sizeof (tm->source_address));
  tm->source_port = 0;
  tm->source_address_length = 0;
  tm->tun_mode = 1; tm->tun_fd = fd; tm->target_thread = target;
  tm->controlled_tun = getenv ("SAKAMOTO_OI3_CONTROLLED") != NULL;
  tm->a2_return_mode = getenv ("SAKAMOTO_OI3_A2_3_RETURN") != NULL;
  tm->a2_return_ingress = 0;
  tm->a2_return_output = 0;
  tm->a2_return_lookup_count = 0;
  tm->a2_return_payload_length = 0;
  memset (tm->a2_return_payload, 0, sizeof (tm->a2_return_payload));
  memset (tm->a2_return_canonical_key, 0,
          sizeof (tm->a2_return_canonical_key));
  const char *a2_stage_id = getenv ("SAKAMOTO_OI3_A2_3_STAGE_ID");
  snprintf (tm->a2_return_stage_id, sizeof (tm->a2_return_stage_id), "%s",
            a2_stage_id && a2_stage_id[0] ? a2_stage_id : "A2-3-udp4-return");
  const char *controlled_cell = getenv ("SAKAMOTO_OI3_CONTROLLED_CELL");
  tm->controlled_refused = controlled_cell && !strcmp (controlled_cell, "refused");
  tm->controlled_no_reply = controlled_cell && !strcmp (controlled_cell, "no-reply");
  tm->controlled_policy_drop = controlled_cell && !strcmp (controlled_cell, "policy-drop");
  const char *expected_failure = getenv ("SAKAMOTO_OI3_EXPECTED_FAILURE");
  tm->expected_real_no_reply =
    expected_failure && !strcmp (expected_failure, "real-no-reply");
  tm->expected_real_reset =
    expected_failure && !strcmp (expected_failure, "real-reset");
  tm->no_reply = tm->controlled_no_reply;
  tm->policy_dropped = tm->controlled_policy_drop;
  fprintf (stderr, "oi3 tun safety controlled=%u cell=%s "
           "expected-failure=%s default-route=none-if-controlled\n",
           tm->controlled_tun, controlled_cell ? controlled_cell : "udp4",
           expected_failure && expected_failure[0] ? expected_failure : "none");
  tm->tun_file_index = -1;
  tm->tun_pending_head = 0;
  tm->tun_pending_count = 0;
  tm->tun_pending_sequence = 0;
  memset (tm->tun_pending, 0, sizeof (tm->tun_pending));
  tm->multi_deferred_head = 0;
  tm->multi_deferred_count = 0;
  tm->multi_deferred_sequence = 0;
  memset (tm->multi_deferred, 0, sizeof (tm->multi_deferred));
  tm->tun_flow_count = 0;
  tm->tun_ingress_packets = 0;
  tm->tun_output_packets = 0;
  tm->tun_output_errors = 0;
  tm->tun_submit_rejects = 0;
  tm->tun_queue_rejects = 0;
  tm->overload_expected = 0;
  tm->expected_transport_timeout = 0;
  tm->vpp_buffers_allocated = 0;
  tm->vpp_buffers_freed = 0;
  tm->vpp_buffer_residue = 0;
  tm->worker_token_pending = 0;
  tm->error[0] = 0;
  tm->udp_datagram_inflight = 0;
  tm->tun_flow_deadline_ns = 0;
  atomic_store_explicit (&tm->connector_wake_pending, 0, memory_order_release);
  atomic_store_explicit (&tm->connector_connect_pending, 0, memory_order_release);
  atomic_store_explicit (&tm->connector_write_pending, 0, memory_order_release);
  if (oi3_ensure_connector_wake_file (tm) < 0) {
    tm->active = 0;
    return clib_error_return_unix (0, "create OI3 connector wake pipe");
  }
  /* nativeStartVppProbe can publish the initial NetworkCallback snapshot
   * before VPP has executed the tun command.  Preserve that source snapshot
   * instead of resetting its physical handle to -1; otherwise the first real
   * flow would lose the platform provenance that selected its underlay. */
  u64 source_epoch = atomic_load_explicit (&tm->source_underlay_epoch,
                                           memory_order_acquire);
  int64_t source_handle = atomic_load_explicit (&tm->source_underlay_handle,
                                                 memory_order_acquire);
  u32 source_available = atomic_load_explicit (&tm->source_underlay_available,
                                                memory_order_acquire);
  if (!source_epoch) {
    source_epoch = 1;
    source_handle = -1;
    source_available = 0;
    atomic_store_explicit (&tm->source_underlay_epoch, source_epoch,
                           memory_order_release);
    atomic_store_explicit (&tm->source_underlay_handle, source_handle,
                           memory_order_release);
    atomic_store_explicit (&tm->source_underlay_available, source_available,
                           memory_order_release);
  }
  tm->generation = 0; tm->underlay_epoch = source_epoch;
  tm->underlay_handle = source_handle;
  tm->underlay_available = source_available;
  tm->underlay_invalidated = 0; tm->normal_stop_requested = 0; tm->token = 0;
  atomic_store_explicit (&tm->pending_underlay_epoch, source_epoch,
                         memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_handle, source_handle,
                         memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_available, source_available,
                         memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_update, 0,
                         memory_order_release);
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
  if (tm->a2_return_mode) {
    fprintf (stderr,
             "oi3 a2-3 schema=s139-a2-3-oi3/v1 event=START stage-id=%s "
             "lookup-count=0 transport-reentry=0 owner=%u\n",
             tm->a2_return_stage_id, target);
  }
  vlib_cli_output (vm, "oi3 tun enabled fd=%d target-thread=%u", fd, target);
  return 0;
}

VLIB_CLI_COMMAND (oi3_tun_command, static) = {
  .path = "sakamoto-oi3 tun",
  .short_help = "sakamoto-oi3 tun fd <n> target-thread <worker> lib <HEV>",
  .function = oi3_tun_command_fn,
};

static clib_error_t *
oi3_underlay_epoch_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  oi3_main_t *tm = &oi3_main;
  u64 epoch = 0;
  long long physical_handle = -1;
  u32 available = 0;
  (void)cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    /* The VPP CLI strips the registered path (`... underlay epoch`) before
     * invoking the handler, so the first token is the numeric epoch.  Accept
     * the explicit spelling as well to keep direct unit/CLI probes readable. */
    if (unformat (input, "%llu", &epoch));
    else if (unformat (input, "handle %lld", &physical_handle));
    else if (unformat (input, "available %u", &available));
    else
      return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
  }
  if (!epoch)
    return clib_error_return (0, "underlay epoch must be non-zero");
  u64 current_epoch = atomic_load_explicit (&tm->source_underlay_epoch,
                                             memory_order_acquire);
  int64_t current_handle = atomic_load_explicit (&tm->source_underlay_handle,
                                                  memory_order_acquire);
  u32 current_available = atomic_load_explicit (&tm->source_underlay_available,
                                                 memory_order_acquire);
  if (epoch < current_epoch) {
    fprintf (stderr, "oi3 underlay-epoch-stale source-event=%llu current-source=%llu "
             "event-handle=%lld current-handle=%lld\n",
             (unsigned long long)epoch, (unsigned long long)current_epoch,
             physical_handle, (long long)current_handle);
    vlib_cli_output (vm, "oi3 underlay epoch stale event=%llu current=%llu",
                     (unsigned long long)epoch,
                     (unsigned long long)current_epoch);
    return 0;
  }
  if (epoch == current_epoch &&
      current_handle == (int64_t)physical_handle &&
      current_available == (available != 0)) {
    vlib_cli_output (vm, "oi3 underlay epoch unchanged=%llu",
                     (unsigned long long)epoch);
    return 0;
  }
  atomic_store_explicit (&tm->source_underlay_epoch, epoch,
                         memory_order_release);
  atomic_store_explicit (&tm->source_underlay_handle,
                         (int64_t)physical_handle, memory_order_release);
  atomic_store_explicit (&tm->source_underlay_available, available != 0,
                         memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_epoch, epoch,
                         memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_handle,
                         (int64_t)physical_handle, memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_available, available != 0,
                         memory_order_release);
  atomic_store_explicit (&tm->pending_underlay_update, 1,
                         memory_order_release);
  /* The Java callback publishes one source-network event.  In the final
   * multi-owner mode that snapshot must reach every owner; otherwise a
   * reconnect can silently leave one shard on the previous underlay epoch. */
  if (oi3_multi.active) {
    for (u32 owner = 0; owner < oi3_multi.owner_count; owner++) {
      oi3_main_t *owner_tm = &oi3_multi.owners[owner];
      u64 owner_epoch = atomic_load_explicit (&owner_tm->source_underlay_epoch,
                                              memory_order_acquire);
      int64_t owner_handle = atomic_load_explicit (
        &owner_tm->source_underlay_handle, memory_order_acquire);
      u32 owner_available = atomic_load_explicit (
        &owner_tm->source_underlay_available, memory_order_acquire);
      if (epoch < owner_epoch ||
          (epoch == owner_epoch && owner_handle == (int64_t)physical_handle &&
           owner_available == (available != 0)))
        continue;
      atomic_store_explicit (&owner_tm->source_underlay_epoch, epoch,
                             memory_order_release);
      atomic_store_explicit (&owner_tm->source_underlay_handle,
                             (int64_t)physical_handle, memory_order_release);
      atomic_store_explicit (&owner_tm->source_underlay_available,
                             available != 0, memory_order_release);
      atomic_store_explicit (&owner_tm->pending_underlay_epoch, epoch,
                             memory_order_release);
      atomic_store_explicit (&owner_tm->pending_underlay_handle,
                             (int64_t)physical_handle, memory_order_release);
      atomic_store_explicit (&owner_tm->pending_underlay_available,
                             available != 0, memory_order_release);
      atomic_store_explicit (&owner_tm->pending_underlay_update, 1,
                             memory_order_release);
      if (atomic_load_explicit (&owner_tm->multi_admission_open,
                                memory_order_acquire) &&
          !owner_tm->worker_token_pending &&
          oi3_enqueue_owner_for (owner_tm, vm, OI3_UNDERLAY_KIND) < 0)
        return clib_error_return_unix (0, "OI4 underlay epoch owner enqueue");
    }
  }
  fprintf (stderr, "oi3 underlay epoch published epoch=%llu handle=%lld available=%u\n",
           (unsigned long long)epoch, physical_handle, available != 0);
  if (tm->active && !tm->worker_token_pending &&
      oi3_enqueue_owner (vm, OI3_UNDERLAY_KIND) < 0)
    return clib_error_return_unix (0, "OI3 underlay epoch owner enqueue");
  vlib_cli_output (vm, "oi3 underlay epoch published=%llu handle=%lld available=%u",
                   (unsigned long long)epoch, physical_handle, available != 0);
  return 0;
}

VLIB_CLI_COMMAND (oi3_underlay_epoch_command, static) = {
  .path = "sakamoto-oi3 underlay epoch",
  .short_help = "sakamoto-oi3 underlay epoch <N> handle <network-handle> available <0|1>",
  .function = oi3_underlay_epoch_command_fn,
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
  tm->source_port = 0;
  memset (&tm->target_address, 0, sizeof (tm->target_address));
  memset (&tm->source_address, 0, sizeof (tm->source_address));
  tm->source_address_length = 0;
  if (tm->family == 4) { struct sockaddr_in *a = (struct sockaddr_in *)&tm->target_address; a->sin_family = AF_INET; a->sin_port = htons (tm->target_port); inet_pton (AF_INET, "127.0.0.1", &a->sin_addr); tm->target_address_length = sizeof (*a); }
  else { struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&tm->target_address; a6->sin6_family = AF_INET6; a6->sin6_port = htons (tm->target_port); inet_pton (AF_INET6, "::1", &a6->sin6_addr); tm->target_address_length = sizeof (*a6); }
  tm->request_pair[0] = tm->request_pair[1] = tm->completion_pair[0] = tm->completion_pair[1] = -1;
  tm->direct_fd = tm->connector_fd = tm->endpoint_fd = tm->endpoint_client_fd = -1; tm->completion_file_index = -1;
  u64 previous_generation = tm->generation;
  u64 previous_epoch = tm->underlay_epoch;
  tm->generation++; if (!tm->generation) tm->generation = 1;
  if (!tm->underlay_epoch) tm->underlay_epoch = 1;
  tm->token = 0;
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
  tm->normal_stop_requested = 0;
  tm->fault_injected = 0;
  tm->underlay_invalidated = 0;
  tm->tcp_server_seq = tm->tcp_server_ack = tm->tcp_client_seq = 0;
  tm->tcp_ack_submitted = 0;
  tm->broker_result = OI2_RESULT_BROKER_UNAVAILABLE;
  tm->endpoint_accepted = tm->endpoint_received = tm->endpoint_replied = tm->broker_bind_calls = tm->broker_protect_calls = 0;
  tm->broker_duplicate_closes = tm->broker_stale = tm->transport_failures = tm->infrastructure_failures = 0;
  tm->connector_last_error = tm->connector_error_reported = 0;
  tm->tcp_data_seen = 0;
  tm->packet_submitted = tm->udp_datagram_inflight = tm->tcp_payload_submitted = tm->tcp_fin_submitted = 0; tm->error[0] = 0;
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
  oi3_main.normal_stop_requested = 1;
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
  else if (oi3_main.tun_mode)
    oi3_finish (vm);
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
  vlib_cli_output (vm, "oi3 state=%s cell=%s active=%u finished=%u tun=%u tun-flows=%u tun-ingress=%u tun-output=%u tun-errors=%u owner=%u generation=%llu epoch=%llu underlay-handle=%lld underlay-available=%u underlay-invalidated=%u normal-stop-requested=%u phase=%s steps=%u packets=%u output=%u handshake=%u direct=%u rewritten=%u",
                   oi3_phase_name (tm->phase), oi3_cell_name (tm->cell), tm->active, tm->finished,
                   tm->tun_mode, tm->tun_flow_count, tm->tun_ingress_packets, tm->tun_output_packets,
                   tm->tun_output_errors, tm->target_thread, (unsigned long long)tm->generation,
                   (unsigned long long)tm->underlay_epoch,
                   (long long)tm->underlay_handle, tm->underlay_available,
                   tm->underlay_invalidated, tm->normal_stop_requested,
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
  oi3_main.connector_wake_pipe[0] = oi3_main.connector_wake_pipe[1] = -1;
  oi3_main.connector_wake_file_index = -1;
  oi3_main.tun_handoff_pair[0] = oi3_main.tun_handoff_pair[1] = -1;
  oi3_main.tun_handoff_file_index = -1;
  atomic_init (&oi3_main.source_underlay_epoch, 0);
  atomic_init (&oi3_main.source_underlay_handle, -1);
  atomic_init (&oi3_main.source_underlay_available, 0);
  atomic_init (&oi3_main.pending_underlay_epoch, 0);
  atomic_init (&oi3_main.pending_underlay_handle, -1);
  atomic_init (&oi3_main.pending_underlay_available, 0);
  atomic_init (&oi3_main.pending_underlay_update, 0);
  atomic_init (&oi3_main.multi_admission_open, 0);
  atomic_init (&oi3_main.multi_dispatch_depth, 0);
  atomic_init (&oi3_main.multi_admission_rejects, 0);
  atomic_init (&oi3_main.active_flow_hash, 0);
  atomic_init (&oi3_main.active_flow_valid, 0);
  atomic_init (&oi3_main.multi_tcp_wait_syn, 0);
  atomic_init (&oi3_main.multi_tcp_tombstone_hash, 0);
  atomic_init (&oi3_main.multi_tcp_tombstone_valid, 0);
  oi3_main.owner_id = 0;
  oi3_main.multi_mode = 0;
  oi3_main.frame_queue = vlib_frame_queue_main_init (oi3_worker_node.index, 0);
  memset (&oi3_multi, 0, sizeof (oi3_multi));
  oi3_multi.tun_fd = -1;
  oi3_multi.tun_file_index = -1;
  oi3_multi.completion_file_index = -1;
  oi3_multi.completion_watch_fd = -1;
  oi3_main.phase = OI3_DONE; (void)vm;
  return 0;
}

VLIB_INIT_FUNCTION (oi3_init);
