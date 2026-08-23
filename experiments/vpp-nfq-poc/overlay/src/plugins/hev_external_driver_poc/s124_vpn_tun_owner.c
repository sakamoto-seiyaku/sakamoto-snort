/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-124 test-only real-VpnService TUN bridge.
 *
 * The detached Android TUN fd is read by VPP's main thread, a canonical
 * 4-tuple hash selects a worker-local owner, and that worker calls the same
 * flow_stack_owner_submit() seam used by S122/S123.  The HEV callback writes
 * the resulting packet back to the same TUN fd.  There is intentionally no
 * production ownership or zero-copy contract in this fixture.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/file.h>
#include <vlib/threads.h>
#include <vppinfra/time.h>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define S124_MAX_WORKERS 64U
#define S124_RX_BUF_SIZE 65536U
#define S124_HANDOFF_BURST 32U
#define S124_MAX_PACKET_LEN 65535U
#define S124_UDP_LISTEN_PORT 49154U
#define S124_TCP_LISTEN_PORT 49155U
#define S124_OBSERVE_SAMPLE_MASK 63U

/* s124_flow_owner() return values.  A foreign packet is valid TUN input but
 * outside this POC's IPv4 TCP/UDP target contract; it must be counted and
 * excluded from the target path rather than being hidden as a parse error. */
#define S124_PARSE_FOREIGN 1

typedef enum
{
  S124_PATH_FULL = 0,
  S124_PATH_UDP_REFLECT = 1,
  S124_PATH_INGRESS_ONLY = 2,
  S124_PATH_MEMCPY_CAL = 3,
} s124_path_mode_t;

typedef enum
{
  S124_OBSERVE_OFF = 0,
  S124_OBSERVE_SAMPLE64 = 1,
  S124_OBSERVE_FULL = 2,
} s124_observe_mode_t;

#define S124_HEV_CREDIT_COUNT 4U
#define S124_HEV_EVENT_COUNT 9U

/* Keep these two dlsym-only layouts in lockstep with the pinned HEV header.
 * The plugin intentionally does not include HEV headers at build time. */
typedef struct
{
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
} s124_lwip_identity_t;

typedef struct
{
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
  size_t credit_limit[S124_HEV_CREDIT_COUNT];
  size_t credit_used[S124_HEV_CREDIT_COUNT];
  size_t credit_high_water[S124_HEV_CREDIT_COUNT];
  size_t credit_reserves[S124_HEV_CREDIT_COUNT];
  size_t credit_releases[S124_HEV_CREDIT_COUNT];
  size_t credit_rejects[S124_HEV_CREDIT_COUNT];
  size_t credit_underflows;
  int last_limit_error;
  size_t lifecycle_sequence;
  size_t event_sequence[S124_HEV_EVENT_COUNT];
  uint16_t tcp_listen_port;
  uint16_t udp_listen_port;
  unsigned int started;
  unsigned int stopping;
} s124_runtime_identity_t;

typedef void (*s124_output_fn) (void *data, const void *packet, size_t length);
typedef void (*s124_recv_fn) (void *data, uintptr_t config_identity,
                              uintptr_t session_identity,
                              unsigned int transport, const void *payload,
                              size_t length);

typedef struct
{
  s124_output_fn output;
  void *data;
} s124_callbacks_t;

typedef struct
{
  uintptr_t identity;
  uint16_t tcp_listen_port;
  uint16_t udp_listen_port;
  s124_recv_fn recv;
  void *recv_data;
  const void *tcp_connector;
  const void *udp_connector;
  uint8_t tcp_ip_type;
  uint8_t udp_ip_type;
} s124_session_config_t;

/* This is the public HEV owner-config layout at pinned ref 3911f79. */
typedef struct
{
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
} s124_owner_config_t;

typedef void *(*s124_create_fn) (const s124_callbacks_t *callbacks,
                                 const s124_owner_config_t *config);
typedef void (*s124_config_default_fn) (s124_owner_config_t *config);
typedef int (*s124_configure_fn) (void *context,
                                  const s124_session_config_t *config);
typedef int (*s124_start_fn) (void *context);
typedef int (*s124_submit_fn) (void *context, const void *packet,
                               size_t length);
typedef int (*s124_udp_echo_fn) (void *context, uintptr_t session_identity,
                                 const void *payload, size_t length);
typedef int (*s124_tcp_echo_fn) (void *context, uintptr_t session_identity,
                                 const void *payload, size_t length);
typedef void (*s124_destroy_fn) (void *context);

typedef struct
{
  uint64_t submit_pbuf_alloc_ns;
  uint64_t submit_copy_ns;
  uint64_t submit_copy_bytes;
  uint64_t submit_pbuf_allocs;
  uint64_t submit_pbuf_frees;
  uint64_t udp_echo_pbuf_alloc_ns;
  uint64_t udp_echo_copy_ns;
  uint64_t udp_echo_copy_bytes;
  uint64_t udp_echo_pbuf_allocs;
  uint64_t udp_echo_pbuf_frees;
  uint64_t tcp_write_ns;
  uint64_t tcp_write_copy_bytes;
  uint64_t tcp_write_calls;
} s124_perf_metrics_t;

typedef void (*s124_perf_metrics_fn) (void *context,
                                      s124_perf_metrics_t *metrics);
typedef void (*s124_lwip_identity_fn) (const void *context,
                                       s124_lwip_identity_t *identity);
typedef void (*s124_runtime_identity_fn) (const void *context,
                                          s124_runtime_identity_t *identity);
typedef void (*s124_tcp_copy_metrics_fn) (const void *context,
                                          uint64_t *copy_ns,
                                          uint64_t *copy_bytes);
typedef void (*s124_tcp_copy_timing_enable_fn) (void *context, int enabled);

typedef struct
{
  void *handle;
  s124_create_fn create;
  s124_config_default_fn config_default;
  s124_configure_fn configure;
  s124_start_fn start;
  s124_submit_fn submit;
  s124_udp_echo_fn udp_echo;
  s124_tcp_echo_fn tcp_echo;
  s124_perf_metrics_fn perf_metrics;
  s124_lwip_identity_fn lwip_identity;
  s124_runtime_identity_fn runtime_identity;
  s124_tcp_copy_metrics_fn tcp_copy_metrics;
  s124_tcp_copy_timing_enable_fn tcp_copy_timing_enable;
  s124_destroy_fn destroy;
} s124_api_t;

typedef struct s124_main s124_main_t;

typedef struct
{
  s124_main_t *main;
  void *context;
  u32 owner_index;
  u32 started;
  u64 packets;
  u64 bytes;
  u64 submit_errors;
  u64 udp_echo_errors;
  u64 tcp_echo_errors;
  u64 queue_depth_max;
  u64 dequeue_packets;
  u64 queue_wait_ns;
  u64 dequeue_to_submit_ns;
  u64 submit_total_ns;
  u64 udp_echo_stack_ns;
  u64 tcp_echo_stack_ns;
  u64 tcp_copy_ns;
  u64 tcp_copy_bytes;
  u8 observe_current;
  u8 *memcpy_scratch;
  u8 memcpy_sink;
  s124_perf_metrics_t perf;
  s124_lwip_identity_t lwip_identity;
  s124_runtime_identity_t runtime_identity;
} s124_owner_t;

struct s124_main
{
  u8 enabled;
  int fd;
  u32 file_index;
  u32 frame_queue_index;
  u32 owner_count;
  u8 *rx_buf;
  void *hev_handle;
  s124_api_t api;
  s124_owner_t owners[S124_MAX_WORKERS];
  u64 ingress_packets;
  u64 ingress_bytes;
  u64 ingress_alloc_errors;
  u64 ingress_parse_errors;
  u64 ingress_foreign_packets;
  u64 ingress_foreign_bytes;
  u64 ingress_congestion_drops;
  u64 worker_packets;
  u64 worker_bytes;
  u64 worker_owner_mismatch;
  u64 submit_packets;
  u64 submit_bytes;
  u64 submit_errors;
  u64 output_packets;
  u64 output_bytes;
  u64 output_errors;
  u64 output_pbuf_bytes;
  u64 output_callback_calls;
  u64 output_write_calls;
  u64 output_write_bytes;
  u64 output_partial_writes;
  u64 output_eagain;
  u64 output_eintr;
  u64 output_other_errors;
  u64 output_callback_ns;
  u64 output_write_ns;
  u64 reflect_packets;
  u64 reflect_errors;
  u64 reflect_ns;
  u64 ingress_only_packets;
  u64 memcpy_cal_packets;
  u64 memcpy_cal_bytes;
  u64 memcpy_cal_ns;
  u64 memcpy_cal_errors;
  u64 tun_read_calls;
  u64 tun_read_bytes;
  u64 tun_read_eagain;
  u64 tun_read_errors;
  u64 tun_read_ns;
  u64 buffer_alloc_calls;
  u64 buffer_alloc_errors;
  u64 buffer_alloc_ns;
  u64 ingress_copy_ns;
  u64 ingress_copy_bytes;
  u64 parse_ns;
  u64 ingress_parse_success;
  u64 ingress_parse_error_bytes;
  u32 parse_error_last_len;
  u8 parse_error_last_version;
  u8 parse_error_last_proto;
  u32 foreign_last_len;
  u8 foreign_last_version;
  u8 foreign_last_proto;
  u32 tcp_input_last_len;
  u16 tcp_input_last_src_port;
  u16 tcp_input_last_dst_port;
  u8 tcp_input_last_flags;
  u32 tcp_input_last_src_ip;
  u32 tcp_input_last_dst_ip;
  u32 tcp_input_last_seq;
  u32 tcp_input_last_ack;
  u16 tcp_input_last_ip_checksum;
  u16 tcp_input_last_tcp_checksum;
  u64 tcp_input_checksum_checks;
  u64 tcp_input_checksum_errors;
  u64 udp_input_checksum_checks;
  u64 udp_input_checksum_errors;
  u64 tcp_input_syn_packets;
  u64 tcp_input_syn_ack_packets;
  u64 tcp_input_ack_packets;
  u64 tcp_input_data_packets;
  u32 tcp_output_last_len;
  u16 tcp_output_last_src_port;
  u16 tcp_output_last_dst_port;
  u8 tcp_output_last_flags;
  u32 tcp_output_last_src_ip;
  u32 tcp_output_last_dst_ip;
  u32 tcp_output_last_seq;
  u32 tcp_output_last_ack;
  u16 tcp_output_last_ip_checksum;
  u16 tcp_output_last_tcp_checksum;
  u64 tcp_output_checksum_checks;
  u64 tcp_output_checksum_errors;
  u64 udp_output_checksum_checks;
  u64 udp_output_checksum_errors;
  u64 tcp_output_syn_packets;
  u64 tcp_output_syn_ack_packets;
  u64 tcp_output_ack_packets;
  u64 tcp_output_data_packets;
  u64 enqueue_calls;
  u64 enqueue_ns;
  u64 enqueue_packets;
  u64 queue_depth_samples;
  u64 queue_depth_max[S124_MAX_WORKERS];
  u64 dequeue_packets[S124_MAX_WORKERS];
  u64 queue_wait_ns[S124_MAX_WORKERS];
  u64 dequeue_to_submit_ns[S124_MAX_WORKERS];
  u64 submit_total_ns[S124_MAX_WORKERS];
  u64 observed_packets;
  u64 owner_start_errors;
  u64 node_invocations;
  u8 path_mode;
  u8 observe_mode;
  unsigned long main_pthread;
  unsigned long worker_pthread[S124_MAX_WORKERS];
  char error[256];
};

static s124_main_t s124_main = {
  .fd = -1,
  .file_index = ~0,
  .frame_queue_index = ~0,
};

extern vlib_node_registration_t s124_vpn_tun_worker_node;

static pthread_once_t s124_clock_once = PTHREAD_ONCE_INIT;
static volatile int s124_clock_ready;
static int s124_clock_fallback;
static uint64_t s124_clock_tick_origin;
static uint64_t s124_clock_ns_origin;
static double s124_clock_ns_per_tick;

static uint64_t
s124_timespec_ns (const struct timespec *ts)
{
  return (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
}

/* clock_gettime is a useful correctness reference but too expensive for the
 * full per-stage timer set on a small packet.  Calibrate VPP's architecture
 * counter once against CLOCK_MONOTONIC, then use the counter in the hot path.
 * cntvct_el0 is system-wide on Android arm64; the fallback keeps host and
 * unusual builds correct if the counter cannot be sampled. */
static void
s124_clock_init (void)
{
  struct timespec start_ts;
  struct timespec end_ts;
  uint64_t start_tick;
  uint64_t end_tick;
  uint64_t start_ns;
  uint64_t end_ns;
  uint64_t wall_delta;
  uint64_t tick_delta;

  if (clock_gettime (CLOCK_MONOTONIC, &start_ts) != 0)
    {
      s124_clock_fallback = 1;
      s124_clock_ready = 1;
      return;
    }
  start_tick = clib_cpu_time_now ();
  start_ns = s124_timespec_ns (&start_ts);
  do
    {
      if (clock_gettime (CLOCK_MONOTONIC, &end_ts) != 0)
	{
	  s124_clock_fallback = 1;
	  s124_clock_ready = 1;
	  return;
	}
      end_tick = clib_cpu_time_now ();
      end_ns = s124_timespec_ns (&end_ts);
    }
  while (end_ns - start_ns < 1000000ULL);

  wall_delta = end_ns - start_ns;
  tick_delta = end_tick - start_tick;
  if (tick_delta == 0)
    {
      s124_clock_fallback = 1;
      s124_clock_ready = 1;
      return;
    }
  s124_clock_tick_origin = end_tick;
  s124_clock_ns_origin = end_ns;
  s124_clock_ns_per_tick = (double) wall_delta / (double) tick_delta;
  s124_clock_ready = 1;
}

static uint64_t
s124_now_ns (void)
{
  if (__builtin_expect (!s124_clock_ready, 0))
    pthread_once (&s124_clock_once, s124_clock_init);
  if (s124_clock_fallback)
    {
      struct timespec ts;
      clock_gettime (CLOCK_MONOTONIC, &ts);
      return s124_timespec_ns (&ts);
    }
  return s124_clock_ns_origin +
         (uint64_t) ((double) (clib_cpu_time_now () -
                                s124_clock_tick_origin) *
                     s124_clock_ns_per_tick);
}

/* The TUN reader is VPP main-thread owned, but output callbacks, checksum
 * validation and TCP event accounting run on one or more worker threads.
 * Keep the cross-worker test counters race-free; otherwise a two-worker cell
 * can report a false output byte shortfall simply because two callbacks
 * updated adjacent u64 fields concurrently. */
static inline void
s124_atomic_add_u64 (u64 *value, u64 delta)
{
  __atomic_fetch_add (value, delta, __ATOMIC_RELAXED);
}

static inline u64
s124_atomic_load_u64 (const u64 *value)
{
  return __atomic_load_n (value, __ATOMIC_RELAXED);
}

static int
s124_should_observe (s124_main_t *sm, u64 sequence)
{
  u8 observe_mode = __atomic_load_n (&sm->observe_mode, __ATOMIC_RELAXED);
  return observe_mode == S124_OBSERVE_FULL ||
         (observe_mode == S124_OBSERVE_SAMPLE64 &&
          (sequence & S124_OBSERVE_SAMPLE_MASK) == 0);
}

static u32
s124_queue_depth (u32 frame_queue_index, u32 thread_index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;
  vlib_frame_queue_t *fq;
  u64 tail;
  u64 head;

  if (!tm || frame_queue_index >= vec_len (tm->frame_queue_mains))
    return 0;
  fqm = vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);
  if (!fqm || thread_index >= vec_len (fqm->vlib_frame_queues))
    return 0;
  fq = fqm->vlib_frame_queues[thread_index];
  if (!fq)
    return 0;
  tail = __atomic_load_n (&fq->tail, __ATOMIC_ACQUIRE);
  head = __atomic_load_n (&fq->head, __ATOMIC_ACQUIRE);
  if (tail < head || tail - head > (u64) UINT32_MAX)
    return 0;
  return (u32) (tail - head);
}

static u16
s124_checksum (const u8 *data, uword length)
{
  u32 sum = 0;
  while (length > 1)
    {
      sum += ((u16) data[0] << 8) | data[1];
      data += 2;
      length -= 2;
    }
  if (length)
    sum += (u16) data[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (u16) ~sum;
}

static u32
s124_checksum_sum (u32 sum, const u8 *data, uword length)
{
  while (length > 1)
    {
      sum += ((u16) data[0] << 8) | data[1];
      data += 2;
      length -= 2;
    }
  if (length)
    sum += (u16) data[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return sum;
}

static int
s124_ipv4_header_checksum_valid (const u8 *packet, u32 length, u32 ihl)
{
  return packet && ihl >= 20 && length >= ihl &&
         s124_checksum_sum (0, packet, ihl) == 0xffffU;
}

static int
s124_ipv4_l4_checksum_valid (const u8 *packet, u32 length, u32 ihl,
                             u8 protocol)
{
  u16 total_length;
  u16 l4_length;
  const u8 *l4;
  u32 sum;

  if (!packet || length < ihl + 8 || ihl < 20 ||
      !s124_ipv4_header_checksum_valid (packet, length, ihl))
    return 0;
  total_length = ((u16) packet[2] << 8) | packet[3];
  if (total_length < ihl + 8 || total_length > length)
    return 0;
  l4 = packet + ihl;
  if (protocol == 6)
    {
      u8 data_offset = (u8) (l4[12] >> 4) * 4U;
      if (data_offset < 20 || total_length < ihl + data_offset)
        return 0;
      l4_length = (u16) (total_length - ihl);
    }
  else if (protocol == 17)
    {
      l4_length = ((u16) l4[4] << 8) | l4[5];
      if (l4_length < 8 || ihl + l4_length > total_length)
        return 0;
      /* A zero IPv4 UDP checksum is explicitly valid. */
      if (l4[6] == 0 && l4[7] == 0)
        return 1;
    }
  else
    return 0;
  sum = s124_checksum_sum (0, packet + 12, 8);
  sum = s124_checksum_sum (sum, (const u8[]) { 0, protocol }, 2);
  sum = s124_checksum_sum (sum,
                           (const u8[]) { (u8) (l4_length >> 8),
                                          (u8) l4_length }, 2);
  sum = s124_checksum_sum (sum, l4, l4_length);
  return sum == 0xffffU;
}

static void
s124_record_l4_checksum (s124_main_t *sm, const u8 *packet, u32 length,
                         int output)
{
  u32 ihl;
  u8 protocol;
  int valid;

  if (!sm || !packet || length < 20 || (packet[0] >> 4) != 4 ||
      packet[0] != 0x45)
    return;
  ihl = (u32) (packet[0] & 0x0fU) * 4U;
  protocol = packet[9];
  if (protocol != 6 && protocol != 17)
    return;
  valid = s124_ipv4_l4_checksum_valid (packet, length, ihl, protocol);
  if (protocol == 6)
    {
      if (output)
        {
          s124_atomic_add_u64 (&sm->tcp_output_checksum_checks, 1);
          if (!valid)
            s124_atomic_add_u64 (&sm->tcp_output_checksum_errors, 1);
        }
      else
        {
          s124_atomic_add_u64 (&sm->tcp_input_checksum_checks, 1);
          if (!valid)
            s124_atomic_add_u64 (&sm->tcp_input_checksum_errors, 1);
        }
    }
  else
    {
      if (output)
        {
          s124_atomic_add_u64 (&sm->udp_output_checksum_checks, 1);
          if (!valid)
            s124_atomic_add_u64 (&sm->udp_output_checksum_errors, 1);
        }
      else
        {
          s124_atomic_add_u64 (&sm->udp_input_checksum_checks, 1);
          if (!valid)
            s124_atomic_add_u64 (&sm->udp_input_checksum_errors, 1);
        }
    }
}

static void
s124_record_tcp_events (s124_main_t *sm, const u8 *packet, u32 length,
                        int output)
{
  u32 ihl;
  u32 total_length;
  u32 tcp_length;
  u32 tcp_header_length;
  u8 flags;
  u64 *syn_packets;
  u64 *syn_ack_packets;
  u64 *ack_packets;
  u64 *data_packets;

  if (!sm || !packet || length < 40 || packet[0] != 0x45 || packet[9] != 6)
    return;
  ihl = (u32) (packet[0] & 0x0fU) * 4U;
  if (ihl < 20 || length < ihl + 20)
    return;
  total_length = ((u32) packet[2] << 8) | packet[3];
  if (total_length < ihl + 20 || total_length > length)
    return;
  tcp_length = total_length - ihl;
  tcp_header_length = (u32) (packet[ihl + 12] >> 4) * 4U;
  if (tcp_header_length < 20 || tcp_header_length > tcp_length)
    return;
  flags = packet[ihl + 13];
  if (output)
    {
      syn_packets = &sm->tcp_output_syn_packets;
      syn_ack_packets = &sm->tcp_output_syn_ack_packets;
      ack_packets = &sm->tcp_output_ack_packets;
      data_packets = &sm->tcp_output_data_packets;
    }
  else
    {
      syn_packets = &sm->tcp_input_syn_packets;
      syn_ack_packets = &sm->tcp_input_syn_ack_packets;
      ack_packets = &sm->tcp_input_ack_packets;
      data_packets = &sm->tcp_input_data_packets;
    }
  if ((flags & 0x02U) && !(flags & 0x10U))
    s124_atomic_add_u64 (syn_packets, 1);
  if ((flags & 0x12U) == 0x12U)
    s124_atomic_add_u64 (syn_ack_packets, 1);
  if ((flags & 0x10U) && !(flags & 0x02U))
    s124_atomic_add_u64 (ack_packets, 1);
  if (tcp_length > tcp_header_length)
    s124_atomic_add_u64 (data_packets, 1);
}

static int
s124_udp_reflect (u8 *packet, u32 length)
{
  u8 *udp;
  u32 ihl;
  u16 total_length;
  u16 udp_length;
  u8 address[4];
  u8 ports[2];

  if (!packet || length < 28 || packet[0] != 0x45 || packet[9] != 17)
    return -1;
  ihl = (u32) (packet[0] & 0x0fU) * 4U;
  if (ihl < 20 || length < ihl + 8)
    return -1;
  total_length = ((u16) packet[2] << 8) | packet[3];
  if (total_length < ihl + 8 || total_length > length)
    return -1;
  udp = packet + ihl;
  udp_length = ((u16) udp[4] << 8) | udp[5];
  if (udp_length < 8 || ihl + udp_length > total_length)
    return -1;

  memcpy (address, packet + 12, sizeof (address));
  memcpy (packet + 12, packet + 16, sizeof (address));
  memcpy (packet + 16, address, sizeof (address));
  memcpy (ports, udp, sizeof (ports));
  memcpy (udp, udp + 2, sizeof (ports));
  memcpy (udp + 2, ports, sizeof (ports));

  udp[6] = 0;
  udp[7] = 0;
  packet[10] = 0;
  packet[11] = 0;
  {
    u16 checksum = s124_checksum (packet, ihl);
    packet[10] = (u8) (checksum >> 8);
    packet[11] = (u8) checksum;
  }
  /* IPv4 UDP checksum is optional.  Keep it zero for the reflect control so
   * this arm measures the same packet bytes without a second pseudo-header
   * implementation. */
  return 0;
}

static void
s124_error (const char *message)
{
  snprintf (s124_main.error, sizeof (s124_main.error), "%s", message);
}

static int
s124_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol)
    {
      snprintf (s124_main.error, sizeof (s124_main.error), "dlsym(%s): %s",
                name, dlerror ());
      return -1;
    }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static int
s124_load_hev (const char *path)
{
  s124_main_t *sm = &s124_main;
  void *handle;
  if (!path || !path[0])
    {
      s124_error ("S124 HEV library path is empty");
      return -1;
    }
  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      snprintf (sm->error, sizeof (sm->error), "dlopen(%s): %s", path,
                dlerror ());
      return -1;
    }
#define S124_LOAD(field, symbol)                                            \
  if (s124_load_symbol (handle, symbol, &sm->api.field) < 0)                \
    goto failed
  S124_LOAD (create, "flow_stack_owner_create_with_config");
  S124_LOAD (config_default, "hev_socks5_owner_config_default");
  S124_LOAD (configure, "flow_stack_owner_configure_sessions");
  S124_LOAD (start, "flow_stack_owner_start");
  S124_LOAD (submit, "flow_stack_owner_submit");
  S124_LOAD (udp_echo, "flow_stack_owner_udp_echo");
  S124_LOAD (tcp_echo, "flow_stack_owner_tcp_echo");
  S124_LOAD (destroy, "flow_stack_owner_destroy");
#undef S124_LOAD
  {
    void *symbol = dlsym (handle, "flow_stack_owner_perf_metrics");
    if (symbol)
      memcpy (&sm->api.perf_metrics, &symbol, sizeof (symbol));
  }
  {
    void *symbol = dlsym (handle, "flow_stack_owner_identity");
    if (symbol)
      memcpy (&sm->api.lwip_identity, &symbol, sizeof (symbol));
    symbol = dlsym (handle, "flow_stack_owner_runtime_identity");
    if (symbol)
      memcpy (&sm->api.runtime_identity, &symbol, sizeof (symbol));
  }
  {
    void *symbol = dlsym (handle, "flow_stack_owner_tcp_copy_metrics");
    if (symbol)
      memcpy (&sm->api.tcp_copy_metrics, &symbol, sizeof (symbol));
    symbol = dlsym (handle, "flow_stack_owner_tcp_copy_timing_enable");
    if (symbol)
      memcpy (&sm->api.tcp_copy_timing_enable, &symbol, sizeof (symbol));
  }
  sm->api.handle = handle;
  return 0;
failed:
  dlclose (handle);
  memset (&sm->api, 0, sizeof (sm->api));
  return -1;
}

static u64
s124_hash_bytes (u64 hash, const u8 *bytes, u32 length)
{
  for (u32 i = 0; i < length; i++)
    {
      hash ^= bytes[i];
      hash *= 1099511628211ULL;
    }
  return hash;
}

static u64
s124_hash_mix (u64 hash)
{
  /* Android's ephemeral TCP allocator commonly returns only even source
   * ports.  Taking the raw FNV low bit therefore collapses workers=2.  A
   * final avalanche keeps the same canonical tuple input while making the
   * owner selection independent of that allocator bit pattern. */
  hash ^= hash >> 33;
  hash *= 0xff51afd7ed558ccdULL;
  hash ^= hash >> 33;
  hash *= 0xc4ceb9fe1a85ec53ULL;
  hash ^= hash >> 33;
  return hash;
}

static int
s124_flow_owner (const u8 *packet, u32 length, u32 owner_count, u32 *owner)
{
  const u8 *l4;
  u32 ihl;
  u16 src_port;
  u16 dst_port;
  u8 tuple[13];
  u8 first[6];
  u8 second[6];

  if (!packet || length == 0)
    return -1;
  if ((packet[0] >> 4) == 6)
    return length >= 40 ? S124_PARSE_FOREIGN : -1;
  if ((packet[0] >> 4) != 4)
    return -1;
  if (length < 20 || packet[0] != 0x45)
    return -1;
  if (packet[9] != 6 && packet[9] != 17)
    return S124_PARSE_FOREIGN;
  if (length < 28)
    return -1;
  ihl = (u32) (packet[0] & 0x0fU) * 4U;
  if (ihl < 20 || length < ihl + 8)
    return -1;
  l4 = packet + ihl;
  src_port = ((u16) l4[0] << 8) | l4[1];
  dst_port = ((u16) l4[2] << 8) | l4[3];
  memcpy (first, packet + 12, 4);
  first[4] = (u8) (src_port >> 8);
  first[5] = (u8) src_port;
  memcpy (second, packet + 16, 4);
  second[4] = (u8) (dst_port >> 8);
  second[5] = (u8) dst_port;
  if (memcmp (first, second, sizeof (first)) > 0)
    {
      u8 swap[6];
      memcpy (swap, first, sizeof (swap));
      memcpy (first, second, sizeof (first));
      memcpy (second, swap, sizeof (second));
    }
  memcpy (tuple, first, sizeof (first));
  memcpy (tuple + sizeof (first), second, sizeof (second));
  tuple[12] = packet[9];
  *owner = (u32) (s124_hash_mix (s124_hash_bytes (1469598103934665603ULL,
                                                  tuple, sizeof (tuple)))
                  % owner_count);
  return 0;
}

static void
s124_record_tcp_header (const u8 *packet, u32 length, u32 *last_len,
                        u16 *last_src_port, u16 *last_dst_port,
                        u8 *last_flags, u32 *last_src_ip,
                        u32 *last_dst_ip, u32 *last_seq, u32 *last_ack,
                        u16 *last_ip_checksum, u16 *last_tcp_checksum)
{
  u32 ihl;
  const u8 *tcp;
  if (!packet || length < 28 || packet[0] != 0x45 || packet[9] != 6)
    return;
  ihl = (u32) (packet[0] & 0x0fU) * 4U;
  if (ihl < 20 || length < ihl + 14)
    return;
  tcp = packet + ihl;
  *last_len = length;
  *last_src_port = ((u16) tcp[0] << 8) | tcp[1];
  *last_dst_port = ((u16) tcp[2] << 8) | tcp[3];
  *last_flags = tcp[13];
  memcpy (last_src_ip, packet + 12, sizeof (*last_src_ip));
  memcpy (last_dst_ip, packet + 16, sizeof (*last_dst_ip));
  *last_seq = ((u32) tcp[4] << 24) | ((u32) tcp[5] << 16) |
              ((u32) tcp[6] << 8) | tcp[7];
  *last_ack = ((u32) tcp[8] << 24) | ((u32) tcp[9] << 16) |
              ((u32) tcp[10] << 8) | tcp[11];
  *last_ip_checksum = ((u16) packet[10] << 8) | packet[11];
  *last_tcp_checksum = ((u16) tcp[16] << 8) | tcp[17];
}

static int
s124_tun_write (s124_main_t *sm, const void *packet, size_t length)
{
  ssize_t written;
  int saved_errno = 0;

  s124_atomic_add_u64 (&sm->output_write_calls, 1);
  do
    {
      written = write (sm->fd, packet, length);
      if (written < 0 && errno == EINTR)
        s124_atomic_add_u64 (&sm->output_eintr, 1);
    }
  while (written < 0 && errno == EINTR);
  if (written == (ssize_t) length)
    {
      s124_atomic_add_u64 (&sm->output_write_bytes, (u64) written);
      return 0;
    }
  if (written >= 0)
    {
      s124_atomic_add_u64 (&sm->output_write_bytes, (u64) written);
      s124_atomic_add_u64 (&sm->output_partial_writes, 1);
      return -2;
    }
  saved_errno = errno;
  if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
    s124_atomic_add_u64 (&sm->output_eagain, 1);
  else
    s124_atomic_add_u64 (&sm->output_other_errors, 1);
  return -1;
}

static void
s124_output (void *data, const void *packet, size_t length)
{
  s124_owner_t *owner = data;
  s124_main_t *sm = owner ? owner->main : NULL;
  uint64_t callback_started = 0;
  uint64_t write_started = 0;
  uint64_t write_finished = 0;
  uint64_t callback_finished = 0;
  int write_result;
  int observe;
  if (!sm || !packet || !length || length > S124_MAX_PACKET_LEN)
    return;
  s124_record_l4_checksum (sm, packet, (u32) length, 1);
  s124_record_tcp_events (sm, packet, (u32) length, 1);
  s124_record_tcp_header (packet, (u32) length,
                          &sm->tcp_output_last_len,
                          &sm->tcp_output_last_src_port,
                          &sm->tcp_output_last_dst_port,
                          &sm->tcp_output_last_flags,
                          &sm->tcp_output_last_src_ip,
                          &sm->tcp_output_last_dst_ip,
                          &sm->tcp_output_last_seq,
                          &sm->tcp_output_last_ack,
                          &sm->tcp_output_last_ip_checksum,
                          &sm->tcp_output_last_tcp_checksum);
  observe = owner->observe_current || sm->observe_mode == S124_OBSERVE_FULL;
  if (observe)
    callback_started = s124_now_ns ();
  s124_atomic_add_u64 (&sm->output_callback_calls, 1);
  s124_atomic_add_u64 (&sm->output_pbuf_bytes, length);
  if (observe)
    write_started = s124_now_ns ();
  write_result = s124_tun_write (sm, packet, length);
  if (observe)
    write_finished = s124_now_ns ();
  if (write_result < 0)
    s124_atomic_add_u64 (&sm->output_errors, 1);
  else
    {
      s124_atomic_add_u64 (&sm->output_packets, 1);
      s124_atomic_add_u64 (&sm->output_bytes, length);
    }
  if (observe)
    {
      callback_finished = s124_now_ns ();
      s124_atomic_add_u64 (&sm->output_write_ns,
                           write_finished - write_started);
      s124_atomic_add_u64 (&sm->output_callback_ns,
                           callback_finished - callback_started);
    }
}

static void
s124_recv (void *data, uintptr_t config_identity, uintptr_t session_identity,
           unsigned int transport, const void *payload, size_t length)
{
  s124_owner_t *owner = data;
  s124_main_t *sm = owner ? owner->main : NULL;
  int result;
  u64 started = 0;
  (void) config_identity;
  if (!sm || !owner || !owner->context || !payload || !length)
    return;
  if (owner->observe_current)
    started = s124_now_ns ();
  if (transport == 1U && sm->api.tcp_copy_timing_enable)
    sm->api.tcp_copy_timing_enable (owner->context, owner->observe_current);
  if (transport == 2U)
    result = sm->api.udp_echo (owner->context, session_identity, payload,
                               length);
  else if (transport == 1U)
    result = sm->api.tcp_echo (owner->context, session_identity, payload,
                               length);
  else
    result = -1;
  if (started)
    {
      u64 elapsed = s124_now_ns () - started;
      if (transport == 2U)
        owner->udp_echo_stack_ns += elapsed;
      else if (transport == 1U)
        owner->tcp_echo_stack_ns += elapsed;
    }
  if (result < 0)
    {
      owner->submit_errors++;
      s124_atomic_add_u64 (&sm->submit_errors, 1);
      if (transport == 2U)
        owner->udp_echo_errors++;
      else if (transport == 1U)
        owner->tcp_echo_errors++;
    }
}

static int
s124_owner_start (s124_owner_t *owner)
{
  s124_main_t *sm = owner->main;
  s124_callbacks_t callbacks = {
    .output = s124_output,
    .data = owner,
  };
  s124_owner_config_t owner_config;
  s124_session_config_t config;
  if (owner->started)
    return 0;
  sm->api.config_default (&owner_config);
  owner_config.max_session_count = 64;
  owner_config.packet_credit_limit = 128;
  owner_config.inflight_pbuf_credit_limit = 32;
  owner_config.identity = (uintptr_t) (0x124000U + owner->owner_index);
  owner->context = sm->api.create (&callbacks, &owner_config);
  if (!owner->context)
    goto failed;
  memset (&config, 0, sizeof (config));
  config.identity = owner_config.identity;
  config.tcp_listen_port = S124_TCP_LISTEN_PORT;
  config.udp_listen_port = S124_UDP_LISTEN_PORT;
  config.recv = s124_recv;
  config.recv_data = owner;
  if (sm->api.configure (owner->context, &config) < 0 ||
      sm->api.start (owner->context) < 0)
    goto failed;
  owner->started = 1;
  return 0;
failed:
  sm->owner_start_errors++;
  s124_error ("worker-local HEV owner start failed");
  if (owner->context)
    sm->api.destroy (owner->context);
  owner->context = NULL;
  return -1;
}

static clib_error_t *
s124_fd_read_ready (clib_file_t *f)
{
  s124_main_t *sm = (s124_main_t *) f->private_data;
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *node =
    vlib_node_get_runtime (vm, s124_vpn_tun_worker_node.index);
  uword buffer_size = vlib_buffer_get_default_data_size (vm);
  u32 processed = 0;
  sm->main_pthread = (unsigned long) pthread_self ();
  while (processed < S124_HANDOFF_BURST)
    {
      int read_observed = s124_should_observe (sm, sm->ingress_packets);
      u64 read_started = read_observed ? s124_now_ns () : 0;
      ssize_t rv = read (sm->fd, sm->rx_buf, S124_RX_BUF_SIZE);
      u32 owner;
      u32 bi;
      vlib_buffer_t *b;
      u16 target;
      u64 sequence;
      u64 parse_started;
      u64 alloc_started;
      u64 copy_started;
      u64 enqueue_started;
      u32 queue_depth;
      int observed;
      u32 enqueued;
      u64 enqueue_timestamp = 0;
      int parse_result;

      sm->tun_read_calls++;
      if (read_observed)
        sm->tun_read_ns += s124_now_ns () - read_started;
      if (rv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
          sm->tun_read_eagain++;
          return 0;
        }
      if (rv < 0 && errno == EINTR)
        continue;
      if (rv <= 0)
        {
          sm->tun_read_errors++;
          return rv == 0 ? clib_error_return (0, "S124 TUN fd closed") :
                           clib_error_return_unix (0, "S124 TUN read");
        }
      processed++;
      sequence = sm->ingress_packets;
      observed = s124_should_observe (sm, sequence);
      sm->ingress_packets++;
      sm->ingress_bytes += rv;
      sm->tun_read_bytes += rv;
      if (observed)
        sm->observed_packets++;
      parse_started = observed ? s124_now_ns () : 0;
      parse_result = s124_flow_owner (sm->rx_buf, (u32) rv, sm->owner_count, &owner);
      if (observed)
        sm->parse_ns += s124_now_ns () - parse_started;
      if ((uword) rv <= buffer_size && parse_result == S124_PARSE_FOREIGN)
        {
          sm->ingress_foreign_packets++;
          sm->ingress_foreign_bytes += (u64) rv;
          sm->foreign_last_len = (u32) rv;
          sm->foreign_last_version = rv > 0 ? sm->rx_buf[0] >> 4 : 0;
          sm->foreign_last_proto =
            sm->foreign_last_version == 6 && rv > 6 ? sm->rx_buf[6] :
            (rv > 9 ? sm->rx_buf[9] : 0);
          continue;
        }
      if ((uword) rv > buffer_size || parse_result < 0)
        {
          sm->ingress_parse_errors++;
          sm->ingress_parse_error_bytes += (u64) rv;
          sm->parse_error_last_len = (u32) rv;
          sm->parse_error_last_version = rv > 0 ? sm->rx_buf[0] >> 4 : 0;
          sm->parse_error_last_proto =
            sm->parse_error_last_version == 6 && rv > 6 ? sm->rx_buf[6] :
            (rv > 9 ? sm->rx_buf[9] : 0);
          continue;
        }
      sm->ingress_parse_success++;
      s124_record_l4_checksum (sm, sm->rx_buf, (u32) rv, 0);
      s124_record_tcp_events (sm, sm->rx_buf, (u32) rv, 0);
      s124_record_tcp_header (sm->rx_buf, (u32) rv,
                              &sm->tcp_input_last_len,
                              &sm->tcp_input_last_src_port,
                              &sm->tcp_input_last_dst_port,
                              &sm->tcp_input_last_flags,
                              &sm->tcp_input_last_src_ip,
                              &sm->tcp_input_last_dst_ip,
                              &sm->tcp_input_last_seq,
                              &sm->tcp_input_last_ack,
                              &sm->tcp_input_last_ip_checksum,
                              &sm->tcp_input_last_tcp_checksum);
      sm->buffer_alloc_calls++;
      alloc_started = observed ? s124_now_ns () : 0;
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
        {
          sm->buffer_alloc_errors++;
          sm->ingress_alloc_errors++;
          continue;
        }
      if (observed)
        sm->buffer_alloc_ns += s124_now_ns () - alloc_started;
      b = vlib_get_buffer (vm, bi);
      b->current_data = 0;
      b->current_length = rv;
      b->opaque[0] = owner;
      b->opaque[1] = (u32) sequence;
      b->opaque[2] = (u32) (sequence >> 32);
      b->opaque[3] = observed ? 1U : 0U;
      copy_started = observed ? s124_now_ns () : 0;
      clib_memcpy_fast (vlib_buffer_get_current (b), sm->rx_buf, rv);
      if (observed)
        {
          sm->ingress_copy_ns += s124_now_ns () - copy_started;
          sm->ingress_copy_bytes += rv;
          enqueue_timestamp = s124_now_ns ();
          b->opaque[4] = (u32) enqueue_timestamp;
          b->opaque[5] = (u32) (enqueue_timestamp >> 32);
        }
      target = (u16) (owner + 1U);
      queue_depth = observed ? s124_queue_depth (sm->frame_queue_index, target) : 0;
      if (observed)
        {
          sm->queue_depth_samples++;
          if (owner < S124_MAX_WORKERS && queue_depth > sm->queue_depth_max[owner])
            sm->queue_depth_max[owner] = queue_depth;
          if (owner < sm->owner_count &&
              queue_depth > sm->owners[owner].queue_depth_max)
            sm->owners[owner].queue_depth_max = queue_depth;
        }
      enqueue_started = observed ? s124_now_ns () : 0;
      enqueued = vlib_buffer_enqueue_to_thread (vm, node, sm->frame_queue_index,
                                                &bi, &target, 1, 1);
      if (observed)
        sm->enqueue_ns += s124_now_ns () - enqueue_started;
      sm->enqueue_calls++;
      if (enqueued == 1)
        {
          sm->enqueue_packets++;
          if (observed)
            {
              queue_depth = s124_queue_depth (sm->frame_queue_index, target);
              if (owner < S124_MAX_WORKERS && queue_depth > sm->queue_depth_max[owner])
                sm->queue_depth_max[owner] = queue_depth;
              if (owner < sm->owner_count &&
                  queue_depth > sm->owners[owner].queue_depth_max)
                sm->owners[owner].queue_depth_max = queue_depth;
            }
        }
      else
        {
          sm->ingress_congestion_drops++;
          /* drop_on_congestion=1 makes VPP's enqueue helper reclaim dropped
           * buffers.  Do not free bi again here: that is a double-free under
           * a fire-and-count control load and can take down the VPP child. */
        }
    }
  return 0;
}

VLIB_NODE_FN (s124_vpn_tun_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s124_main_t *sm = &s124_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 actual = vlib_get_thread_index ();
  u32 owner_index = actual > 0 ? actual - 1U : ~0U;
  s124_owner_t *owner = owner_index < sm->owner_count
                          ? &sm->owners[owner_index] : NULL;
  (void) node;
  if (!owner)
    {
      for (u32 i = 0; i < frame->n_vectors; i++)
        vlib_buffer_free_one (vm, from[i]);
      s124_atomic_add_u64 (&sm->worker_owner_mismatch, frame->n_vectors);
      return frame->n_vectors;
  }
  sm->worker_pthread[owner_index] = (unsigned long) pthread_self ();
  if (sm->path_mode == S124_PATH_FULL && s124_owner_start (owner) < 0)
    {
      for (u32 i = 0; i < frame->n_vectors; i++)
        vlib_buffer_free_one (vm, from[i]);
      return frame->n_vectors;
    }
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 expected = b->opaque[0];
      u32 length = vlib_buffer_length_in_chain (vm, b);
      int observed = b->opaque[3] != 0;
      u64 enqueue_timestamp = ((u64) b->opaque[5] << 32) | b->opaque[4];
      u64 stage_started;
      u64 now;
      u64 copy_started;
      int snapshot;
      if (expected != owner_index)
        s124_atomic_add_u64 (&sm->worker_owner_mismatch, 1);
      else
        {
          owner->observe_current = observed;
          /* HEV perf/runtime/lwIP snapshots are cumulative diagnostics, not
           * per-packet timings.  Calling all four dlsym seams for every full
           * packet made the observer itself dominate small-packet throughput.
           * Keep the first snapshot and then refresh at the registered
           * sample cadence; stage timers and copy attribution remain full-rate
           * when observe=full. */
          snapshot = observed && sm->path_mode == S124_PATH_FULL &&
                     ((owner->packets & S124_OBSERVE_SAMPLE_MASK) == 0);
          if (observed && enqueue_timestamp)
            {
              now = s124_now_ns ();
              owner->queue_wait_ns += now - enqueue_timestamp;
              sm->queue_wait_ns[owner_index] += now - enqueue_timestamp;
              owner->dequeue_packets++;
              sm->dequeue_packets[owner_index]++;
            }
          stage_started = observed ? s124_now_ns () : 0;
          if (sm->path_mode == S124_PATH_INGRESS_ONLY)
            {
              s124_atomic_add_u64 (&sm->ingress_only_packets, 1);
            }
          else if (sm->path_mode == S124_PATH_UDP_REFLECT)
            {
              int result;
              u64 reflect_started = observed ? s124_now_ns () : 0;
              result = s124_udp_reflect (vlib_buffer_get_current (b), length);
              if (observed)
                s124_atomic_add_u64 (&sm->reflect_ns,
                                     s124_now_ns () - reflect_started);
              if (result < 0)
                s124_atomic_add_u64 (&sm->reflect_errors, 1);
              else
                {
                  s124_atomic_add_u64 (&sm->reflect_packets, 1);
                  s124_output (owner, vlib_buffer_get_current (b), length);
                }
            }
          else if (sm->path_mode == S124_PATH_MEMCPY_CAL)
            {
              if (!owner->memcpy_scratch || length > S124_MAX_PACKET_LEN)
                s124_atomic_add_u64 (&sm->memcpy_cal_errors, 1);
              else
                {
                  copy_started = observed ? s124_now_ns () : 0;
                  clib_memcpy_fast (owner->memcpy_scratch,
                                    vlib_buffer_get_current (b), length);
                  owner->memcpy_sink ^= owner->memcpy_scratch[0];
                  if (observed)
                    s124_atomic_add_u64 (&sm->memcpy_cal_ns,
                                         s124_now_ns () - copy_started);
                  s124_atomic_add_u64 (&sm->memcpy_cal_packets, 1);
                  s124_atomic_add_u64 (&sm->memcpy_cal_bytes, length);
                }
            }
          else
            {
              int result = sm->api.submit (owner->context,
                                           vlib_buffer_get_current (b), length);
              if (result < 0)
                {
                  owner->submit_errors++;
                  s124_atomic_add_u64 (&sm->submit_errors, 1);
                }
            }
          /* Keep the worker-path envelope comparable across full and control
           * arms.  For full this is dequeue -> HEV return; for controls it is
           * dequeue -> reflect/calibration/drop completion.  HEV identity
           * snapshots below are deliberately outside this interval. */
          if (observed)
            {
              now = s124_now_ns ();
              owner->submit_total_ns += now - stage_started;
              sm->submit_total_ns[owner_index] += now - stage_started;
            }
          /* These HEV snapshots are owner-context operations.  Take them on
           * the same worker that owns the context, after the packet interval
           * has ended; the CLI path only prints the cached values. */
          if (snapshot && owner->context)
            {
              if (sm->api.perf_metrics)
                sm->api.perf_metrics (owner->context, &owner->perf);
              if (sm->api.tcp_copy_metrics)
                sm->api.tcp_copy_metrics (owner->context,
                                           &owner->tcp_copy_ns,
                                           &owner->tcp_copy_bytes);
              if (sm->api.runtime_identity)
                sm->api.runtime_identity (owner->context,
                                          &owner->runtime_identity);
              if (sm->api.lwip_identity)
                sm->api.lwip_identity (owner->context, &owner->lwip_identity);
            }
          if (observed)
            {
              now = s124_now_ns ();
              owner->dequeue_to_submit_ns += now - stage_started;
              sm->dequeue_to_submit_ns[owner_index] += now - stage_started;
            }
          owner->packets++;
          owner->bytes += length;
          if (sm->path_mode == S124_PATH_FULL)
            {
              s124_atomic_add_u64 (&sm->submit_packets, 1);
              s124_atomic_add_u64 (&sm->submit_bytes, length);
            }
          owner->observe_current = 0;
        }
      s124_atomic_add_u64 (&sm->worker_packets, 1);
      s124_atomic_add_u64 (&sm->worker_bytes, length);
      vlib_buffer_free_one (vm, from[i]);
    }
  s124_atomic_add_u64 (&sm->node_invocations, 1);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (s124_vpn_tun_worker_node) = {
  .name = "s124-vpn-tun-worker",
  .function = s124_vpn_tun_worker_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

static clib_error_t *
s124_enable (vlib_main_t *vm, int fd, u32 owner_count, const char *lib_path)
{
  s124_main_t *sm = &s124_main;
  clib_file_t file = { 0 };
  int flags;
  s124_path_mode_t path_mode = (s124_path_mode_t) sm->path_mode;
  s124_observe_mode_t observe_mode = (s124_observe_mode_t) sm->observe_mode;
  u32 frame_queue_index = sm->frame_queue_index;
  s124_api_t api = { 0 };
  if (sm->enabled)
    return clib_error_return (0, "S124 VPN TUN is already enabled");
  if (fd < 0 || owner_count == 0 || owner_count > S124_MAX_WORKERS ||
      owner_count > vlib_num_workers ())
    return clib_error_return (0, "invalid S124 fd/worker count");
  if (path_mode == S124_PATH_FULL && s124_load_hev (lib_path) < 0)
    return clib_error_return (0, "S124 HEV load failed: %s", sm->error);
  if (path_mode == S124_PATH_FULL)
    api = sm->api;
  memset (sm, 0, sizeof (*sm));
  sm->fd = -1;
  sm->file_index = ~0;
  sm->frame_queue_index = frame_queue_index;
  sm->api = api;
  sm->path_mode = path_mode;
  sm->observe_mode = observe_mode;
  if (path_mode == S124_PATH_FULL && !sm->api.handle)
    return clib_error_return (0, "S124 HEV API was lost during reset");
  sm->rx_buf = clib_mem_alloc_aligned (S124_RX_BUF_SIZE,
                                       CLIB_CACHE_LINE_BYTES);
  if (!sm->rx_buf)
    return clib_error_return (0, "S124 TUN rx allocation failed");
  flags = fcntl (fd, F_GETFL, 0);
  if (flags >= 0)
    (void) fcntl (fd, F_SETFL, flags | O_NONBLOCK);
  sm->fd = fd;
  sm->owner_count = owner_count;
  memset (sm->owners, 0, sizeof (sm->owners));
  for (u32 i = 0; i < owner_count; i++)
    {
      sm->owners[i].main = sm;
      sm->owners[i].owner_index = i;
      if (path_mode == S124_PATH_MEMCPY_CAL)
        {
          sm->owners[i].memcpy_scratch =
            clib_mem_alloc_aligned (S124_MAX_PACKET_LEN,
                                    CLIB_CACHE_LINE_BYTES);
          if (!sm->owners[i].memcpy_scratch)
            {
              for (u32 j = 0; j < i; j++)
                clib_mem_free (sm->owners[j].memcpy_scratch);
              clib_mem_free (sm->rx_buf);
              sm->rx_buf = 0;
              return clib_error_return (0,
                                        "S124 memcpy calibration allocation failed");
            }
        }
    }
  file.read_function = s124_fd_read_ready;
  file.file_descriptor = fd;
  file.polling_thread_index = 0;
  file.private_data = (uword) sm;
  file.description = format (0, "s124 VPN TUN fd %d", fd);
  sm->file_index = clib_file_add (&file_main, &file);
  sm->enabled = 1;
  return 0;
}

static clib_error_t *
s124_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                        vlib_cli_command_t *cmd)
{
  int fd = -1;
  u32 owner_count = vlib_num_workers ();
  u8 *lib_path = NULL;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fd %d", &fd))
        ;
      else if (unformat (input, "workers %u", &owner_count))
        ;
      else if (unformat (input, "mode full"))
        s124_main.path_mode = S124_PATH_FULL;
      else if (unformat (input, "mode udp-reflect"))
        s124_main.path_mode = S124_PATH_UDP_REFLECT;
      else if (unformat (input, "mode ingress-only"))
        s124_main.path_mode = S124_PATH_INGRESS_ONLY;
      else if (unformat (input, "mode memcpy-cal"))
        s124_main.path_mode = S124_PATH_MEMCPY_CAL;
      else if (unformat (input, "observe off"))
        s124_main.observe_mode = S124_OBSERVE_OFF;
      else if (unformat (input, "observe sample64"))
        s124_main.observe_mode = S124_OBSERVE_SAMPLE64;
      else if (unformat (input, "observe full"))
        s124_main.observe_mode = S124_OBSERVE_FULL;
      else if (unformat (input, "lib %s", &lib_path))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  clib_error_t *error = s124_enable (vm, fd, owner_count,
                                     (const char *) lib_path);
  vec_free (lib_path);
  return error;
}

VLIB_CLI_COMMAND (s124_enable_command, static) = {
  .path = "s124-vpn-tun enable",
  .short_help = "s124-vpn-tun enable fd <n> workers <n> "
                "[mode full|udp-reflect|ingress-only|memcpy-cal] "
                "[observe off|sample64|full] lib <path>",
  .function = s124_enable_command_fn,
};

static clib_error_t *
s124_observe_command_fn (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
  s124_observe_mode_t observe_mode;
  (void) vm;
  (void) cmd;
  if (unformat (input, "off"))
    observe_mode = S124_OBSERVE_OFF;
  else if (unformat (input, "sample64"))
    observe_mode = S124_OBSERVE_SAMPLE64;
  else if (unformat (input, "full"))
    observe_mode = S124_OBSERVE_FULL;
  else
    return clib_error_return (0, "expected off, sample64 or full");
  __atomic_store_n (&s124_main.observe_mode, (u8) observe_mode,
                    __ATOMIC_RELEASE);
  return 0;
}

VLIB_CLI_COMMAND (s124_observe_command, static) = {
  .path = "s124-vpn-tun observe",
  .short_help = "s124-vpn-tun observe off|sample64|full",
  .function = s124_observe_command_fn,
};

static clib_error_t *
s124_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                      vlib_cli_command_t *cmd)
{
  s124_main_t *sm = &s124_main;
  (void) input;
  (void) cmd;
  vlib_cli_output (vm,
                   "s124-vpn-tun enabled %u fd %d owners %u ingress %llu/%llu "
                   "worker %llu/%llu submit %llu/%llu errors %llu output %llu/%llu "
                   "output-errors %llu parse-errors %llu foreign-packets %llu "
                   "foreign-bytes %llu congestion-drops %llu "
                   "owner-start-errors %llu owner-mismatch %llu",
                   sm->enabled, sm->fd, sm->owner_count, sm->ingress_packets,
                   sm->ingress_bytes, s124_atomic_load_u64 (&sm->worker_packets),
                   s124_atomic_load_u64 (&sm->worker_bytes),
                   s124_atomic_load_u64 (&sm->submit_packets),
                   s124_atomic_load_u64 (&sm->submit_bytes),
                   s124_atomic_load_u64 (&sm->submit_errors),
                   s124_atomic_load_u64 (&sm->output_packets),
                   s124_atomic_load_u64 (&sm->output_bytes),
                   s124_atomic_load_u64 (&sm->output_errors),
                   sm->ingress_parse_errors, sm->ingress_foreign_packets,
                   sm->ingress_foreign_bytes, sm->ingress_congestion_drops,
                   sm->owner_start_errors,
                   s124_atomic_load_u64 (&sm->worker_owner_mismatch));
  vlib_cli_output (
    vm,
    "s124-vpn-tun-stage mode %u observe %u observed-packets %llu "
    "tun-read-calls %llu tun-read-bytes %llu tun-read-eagain %llu tun-read-errors %llu "
    "tun-read-ns %llu buffer-alloc-calls %llu buffer-alloc-errors %llu "
    "buffer-alloc-ns %llu ingress-copy-ns %llu ingress-copy-bytes %llu "
    "parse-packets %llu parse-errors %llu parse-ns %llu "
    "parse-error-bytes %llu parse-error-last-len %u "
    "parse-error-last-version %u parse-error-last-proto %u "
    "foreign-packets %llu foreign-bytes %llu "
    "foreign-last-len %u foreign-last-version %u foreign-last-proto %u "
    "tcp-input-last-len %u tcp-input-last-src-port %u "
    "tcp-input-last-dst-port %u tcp-input-last-flags %u "
    "tcp-input-last-src-ip %u tcp-input-last-dst-ip %u "
    "tcp-input-last-seq %u tcp-input-last-ack %u "
    "tcp-input-last-ip-checksum %u tcp-input-last-tcp-checksum %u "
    "tcp-input-checksum-checks %llu tcp-input-checksum-errors %llu "
    "udp-input-checksum-checks %llu udp-input-checksum-errors %llu "
    "tcp-input-syn-packets %llu tcp-input-syn-ack-packets %llu "
    "tcp-input-ack-packets %llu tcp-input-data-packets %llu "
    "tcp-output-last-len %u tcp-output-last-src-port %u "
    "tcp-output-last-dst-port %u tcp-output-last-flags %u "
    "tcp-output-last-src-ip %u tcp-output-last-dst-ip %u "
    "tcp-output-last-seq %u tcp-output-last-ack %u "
    "tcp-output-last-ip-checksum %u tcp-output-last-tcp-checksum %u "
    "tcp-output-checksum-checks %llu tcp-output-checksum-errors %llu "
    "udp-output-checksum-checks %llu udp-output-checksum-errors %llu "
    "tcp-output-syn-packets %llu tcp-output-syn-ack-packets %llu "
    "tcp-output-ack-packets %llu tcp-output-data-packets %llu "
    "enqueue-calls %llu enqueue-packets %llu enqueue-drops %llu "
    "enqueue-ns %llu queue-depth-samples %llu tcp-copy-metric %u",
    sm->path_mode, sm->observe_mode, (unsigned long long) sm->observed_packets,
    (unsigned long long) sm->tun_read_calls,
    (unsigned long long) sm->tun_read_bytes,
    (unsigned long long) sm->tun_read_eagain,
    (unsigned long long) sm->tun_read_errors,
    (unsigned long long) sm->tun_read_ns,
    (unsigned long long) sm->buffer_alloc_calls,
    (unsigned long long) sm->buffer_alloc_errors,
    (unsigned long long) sm->buffer_alloc_ns,
    (unsigned long long) sm->ingress_copy_ns,
    (unsigned long long) sm->ingress_copy_bytes,
    (unsigned long long) sm->ingress_parse_success,
    (unsigned long long) sm->ingress_parse_errors,
    (unsigned long long) sm->parse_ns,
    (unsigned long long) sm->ingress_parse_error_bytes,
    sm->parse_error_last_len,
    sm->parse_error_last_version,
    sm->parse_error_last_proto,
    (unsigned long long) sm->ingress_foreign_packets,
    (unsigned long long) sm->ingress_foreign_bytes,
    sm->foreign_last_len,
    sm->foreign_last_version,
    sm->foreign_last_proto,
    sm->tcp_input_last_len,
    sm->tcp_input_last_src_port,
    sm->tcp_input_last_dst_port,
    sm->tcp_input_last_flags,
    sm->tcp_input_last_src_ip,
    sm->tcp_input_last_dst_ip,
    sm->tcp_input_last_seq,
    sm->tcp_input_last_ack,
    sm->tcp_input_last_ip_checksum,
    sm->tcp_input_last_tcp_checksum,
    (unsigned long long) sm->tcp_input_checksum_checks,
    (unsigned long long) sm->tcp_input_checksum_errors,
    (unsigned long long) sm->udp_input_checksum_checks,
    (unsigned long long) sm->udp_input_checksum_errors,
    (unsigned long long) sm->tcp_input_syn_packets,
    (unsigned long long) sm->tcp_input_syn_ack_packets,
    (unsigned long long) sm->tcp_input_ack_packets,
    (unsigned long long) sm->tcp_input_data_packets,
    sm->tcp_output_last_len,
    sm->tcp_output_last_src_port,
    sm->tcp_output_last_dst_port,
    sm->tcp_output_last_flags,
    sm->tcp_output_last_src_ip,
    sm->tcp_output_last_dst_ip,
    sm->tcp_output_last_seq,
    sm->tcp_output_last_ack,
    sm->tcp_output_last_ip_checksum,
    sm->tcp_output_last_tcp_checksum,
    (unsigned long long) s124_atomic_load_u64 (&sm->tcp_output_checksum_checks),
    (unsigned long long) s124_atomic_load_u64 (&sm->tcp_output_checksum_errors),
    (unsigned long long) s124_atomic_load_u64 (&sm->udp_output_checksum_checks),
    (unsigned long long) s124_atomic_load_u64 (&sm->udp_output_checksum_errors),
    (unsigned long long) s124_atomic_load_u64 (&sm->tcp_output_syn_packets),
    (unsigned long long) s124_atomic_load_u64 (&sm->tcp_output_syn_ack_packets),
    (unsigned long long) s124_atomic_load_u64 (&sm->tcp_output_ack_packets),
    (unsigned long long) s124_atomic_load_u64 (&sm->tcp_output_data_packets),
    (unsigned long long) sm->enqueue_calls,
    (unsigned long long) sm->enqueue_packets,
    (unsigned long long) sm->ingress_congestion_drops,
    (unsigned long long) sm->enqueue_ns,
    (unsigned long long) sm->queue_depth_samples,
    sm->api.tcp_copy_metrics != NULL);
  vlib_cli_output (
    vm,
    "s124-vpn-tun-memcpy packets %llu bytes %llu ns %llu errors %llu",
    (unsigned long long) s124_atomic_load_u64 (&sm->memcpy_cal_packets),
    (unsigned long long) s124_atomic_load_u64 (&sm->memcpy_cal_bytes),
    (unsigned long long) s124_atomic_load_u64 (&sm->memcpy_cal_ns),
    (unsigned long long) s124_atomic_load_u64 (&sm->memcpy_cal_errors));
  vlib_cli_output (
    vm,
    "s124-vpn-tun-output callback-calls %llu pbuf-bytes %llu callback-ns %llu write-calls %llu "
    "write-bytes %llu write-ns %llu output-copy-bytes 0 partial-writes %llu eagain %llu eintr %llu "
    "other-errors %llu reflect-packets %llu reflect-errors %llu reflect-ns %llu "
    "ingress-only-packets %llu",
    (unsigned long long) s124_atomic_load_u64 (&sm->output_callback_calls),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_pbuf_bytes),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_callback_ns),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_write_calls),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_write_bytes),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_write_ns),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_partial_writes),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_eagain),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_eintr),
    (unsigned long long) s124_atomic_load_u64 (&sm->output_other_errors),
    (unsigned long long) s124_atomic_load_u64 (&sm->reflect_packets),
    (unsigned long long) s124_atomic_load_u64 (&sm->reflect_errors),
    (unsigned long long) s124_atomic_load_u64 (&sm->reflect_ns),
    (unsigned long long) s124_atomic_load_u64 (&sm->ingress_only_packets));
  for (u32 i = 0; i < sm->owner_count; i++)
    vlib_cli_output (vm, "s124-owner %u started %u packets %llu bytes %llu "
                         "submit-errors %llu udp-errors %llu tcp-errors %llu "
                         "queue-depth-max %llu dequeue-packets %llu queue-wait-ns %llu "
                         "dequeue-to-submit-ns %llu submit-total-ns %llu "
                         "udp-echo-stack-ns %llu tcp-echo-stack-ns %llu "
                         "worker-pthread %lu",
                     i, sm->owners[i].started, sm->owners[i].packets,
                     sm->owners[i].bytes, sm->owners[i].submit_errors,
                     sm->owners[i].udp_echo_errors, sm->owners[i].tcp_echo_errors,
                     sm->owners[i].queue_depth_max, sm->owners[i].dequeue_packets,
                     sm->owners[i].queue_wait_ns,
                     sm->owners[i].dequeue_to_submit_ns,
                     sm->owners[i].submit_total_ns,
                     sm->owners[i].udp_echo_stack_ns,
                     sm->owners[i].tcp_echo_stack_ns,
                     sm->worker_pthread[i]);
  if (sm->api.perf_metrics || sm->api.tcp_copy_metrics ||
      sm->api.runtime_identity || sm->api.lwip_identity)
    for (u32 i = 0; i < sm->owner_count; i++)
      if (sm->owners[i].context)
        {
          vlib_cli_output (vm, "s124-owner-perf %u submit-pbuf-alloc-ns %llu "
                               "submit-pbuf-allocs %llu submit-pbuf-frees %llu "
                               "submit-copy-ns %llu submit-copy-bytes %llu "
                               "udp-pbuf-alloc-ns %llu udp-pbuf-allocs %llu "
                               "udp-pbuf-frees %llu udp-copy-ns %llu "
                               "udp-copy-bytes %llu tcp-write-ns %llu "
                               "tcp-write-bytes %llu tcp-write-calls %llu "
                               "tcp-copy-ns %llu tcp-copy-bytes %llu "
                               "tcp-copy-metric %u",
                           i, (unsigned long long) sm->owners[i].perf.submit_pbuf_alloc_ns,
                           (unsigned long long) sm->owners[i].perf.submit_pbuf_allocs,
                           (unsigned long long) sm->owners[i].perf.submit_pbuf_frees,
                           (unsigned long long) sm->owners[i].perf.submit_copy_ns,
                           (unsigned long long) sm->owners[i].perf.submit_copy_bytes,
                           (unsigned long long) sm->owners[i].perf.udp_echo_pbuf_alloc_ns,
                           (unsigned long long) sm->owners[i].perf.udp_echo_pbuf_allocs,
                           (unsigned long long) sm->owners[i].perf.udp_echo_pbuf_frees,
                           (unsigned long long) sm->owners[i].perf.udp_echo_copy_ns,
                           (unsigned long long) sm->owners[i].perf.udp_echo_copy_bytes,
                           (unsigned long long) sm->owners[i].perf.tcp_write_ns,
                           (unsigned long long) sm->owners[i].perf.tcp_write_copy_bytes,
                           (unsigned long long) sm->owners[i].perf.tcp_write_calls,
                           (unsigned long long) sm->owners[i].tcp_copy_ns,
                           (unsigned long long) sm->owners[i].tcp_copy_bytes,
                           sm->api.tcp_copy_metrics != NULL);
          if (sm->api.runtime_identity)
            {
              vlib_cli_output (
                vm,
                "s124-owner-runtime %u sessions %llu tcp-sessions %llu "
                "udp-sessions %llu max-sessions %llu "
                "packet-credit-limit %llu packet-credit-used %llu "
                "packet-credit-high-water %llu pbuf-credit-limit %llu "
                "pbuf-credit-used %llu pbuf-credit-high-water %llu "
                "session-credit-limit %llu session-credit-used %llu "
                "session-credit-high-water %llu protected-credit-limit %llu "
                "protected-credit-used %llu protected-credit-high-water %llu "
                "credit-rejects %llu "
                "last-limit-error %d",
                i,
                (unsigned long long) sm->owners[i].runtime_identity.session_count,
                (unsigned long long) sm->owners[i].runtime_identity.tcp_session_count,
                (unsigned long long) sm->owners[i].runtime_identity.udp_session_count,
                (unsigned long long) sm->owners[i].runtime_identity.max_session_count,
                (unsigned long long) sm->owners[i].runtime_identity.credit_limit[0],
                (unsigned long long) sm->owners[i].runtime_identity.credit_used[0],
                (unsigned long long) sm->owners[i].runtime_identity.credit_high_water[0],
                (unsigned long long) sm->owners[i].runtime_identity.credit_limit[1],
                (unsigned long long) sm->owners[i].runtime_identity.credit_used[1],
                (unsigned long long) sm->owners[i].runtime_identity.credit_high_water[1],
                (unsigned long long) sm->owners[i].runtime_identity.credit_limit[2],
                (unsigned long long) sm->owners[i].runtime_identity.credit_used[2],
                (unsigned long long) sm->owners[i].runtime_identity.credit_high_water[2],
                (unsigned long long) sm->owners[i].runtime_identity.credit_limit[3],
                (unsigned long long) sm->owners[i].runtime_identity.credit_used[3],
                (unsigned long long) sm->owners[i].runtime_identity.credit_high_water[3],
                (unsigned long long) sm->owners[i].runtime_identity.credit_rejects[0] +
                sm->owners[i].runtime_identity.credit_rejects[1] +
                sm->owners[i].runtime_identity.credit_rejects[2] +
                sm->owners[i].runtime_identity.credit_rejects[3],
                sm->owners[i].runtime_identity.last_limit_error);
            }
          if (sm->api.lwip_identity)
            {
              vlib_cli_output (
                vm,
                "s124-owner-lwip %u tcp-pcb-used %llu tcp-pcb-free %llu "
                "tcp-listen-used %llu tcp-listen-free %llu "
                "tcp-seg-used %llu tcp-seg-free %llu pbuf-used %llu "
                "pbuf-free %llu pbuf-payload-used %llu pbuf-payload-free %llu "
                "udp-pcb-used %llu udp-pcb-free %llu",
                i,
                (unsigned long long) sm->owners[i].lwip_identity.tcp_pcb_pool_used,
                (unsigned long long) sm->owners[i].lwip_identity.tcp_pcb_pool_free,
                (unsigned long long) sm->owners[i].lwip_identity.tcp_pcb_listen_pool_used,
                (unsigned long long) sm->owners[i].lwip_identity.tcp_pcb_listen_pool_free,
                (unsigned long long) sm->owners[i].lwip_identity.tcp_seg_pool_used,
                (unsigned long long) sm->owners[i].lwip_identity.tcp_seg_pool_free,
                (unsigned long long) sm->owners[i].lwip_identity.pbuf_pool_used,
                (unsigned long long) sm->owners[i].lwip_identity.pbuf_pool_free,
                (unsigned long long) sm->owners[i].lwip_identity.pbuf_payload_pool_used,
                (unsigned long long) sm->owners[i].lwip_identity.pbuf_payload_pool_free,
                (unsigned long long) sm->owners[i].lwip_identity.udp_pcb_pool_used,
                (unsigned long long) sm->owners[i].lwip_identity.udp_pcb_pool_free);
            }
        }
  if (sm->error[0])
    vlib_cli_output (vm, "s124-vpn-tun error %s", sm->error);
  return 0;
}

VLIB_CLI_COMMAND (s124_show_command, static) = {
  .path = "show s124-vpn-tun",
  .short_help = "show s124-vpn-tun",
  .function = s124_show_command_fn,
};

/*
 * Paired-observe probes must not call the full diagnostic command.  The full
 * command asks HEV for pool/credit identity on every owner; under load that
 * cross-thread diagnostic can take long enough to contaminate the interval
 * being measured.  Keep this test-only snapshot to VPP-owned counters only.
 */
static clib_error_t *
s124_show_lite_command_fn (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *cmd)
{
  s124_main_t *sm = &s124_main;
  (void) input;
  (void) cmd;

  vlib_cli_output (
    vm,
    "s124-vpn-tun-lite enabled %u ingress %llu/%llu worker %llu/%llu "
    "submit %llu/%llu errors %llu output %llu/%llu output-errors %llu",
    sm->enabled, sm->ingress_packets, sm->ingress_bytes,
    s124_atomic_load_u64 (&sm->worker_packets),
    s124_atomic_load_u64 (&sm->worker_bytes),
    s124_atomic_load_u64 (&sm->submit_packets),
    s124_atomic_load_u64 (&sm->submit_bytes),
    s124_atomic_load_u64 (&sm->submit_errors),
    s124_atomic_load_u64 (&sm->output_packets),
    s124_atomic_load_u64 (&sm->output_bytes),
    s124_atomic_load_u64 (&sm->output_errors));

  vlib_cli_output (
    vm,
    "s124-vpn-tun-stage mode %u observe %u observed-packets %llu "
    "tun-read-calls %llu tun-read-ns %llu buffer-alloc-ns %llu "
    "ingress-copy-ns %llu ingress-copy-bytes %llu parse-packets %llu "
    "parse-ns %llu enqueue-packets %llu enqueue-drops %llu enqueue-ns %llu",
    sm->path_mode, sm->observe_mode,
    (unsigned long long) sm->observed_packets,
    (unsigned long long) sm->tun_read_calls,
    (unsigned long long) sm->tun_read_ns,
    (unsigned long long) sm->buffer_alloc_ns,
    (unsigned long long) sm->ingress_copy_ns,
    (unsigned long long) sm->ingress_copy_bytes,
    (unsigned long long) sm->ingress_parse_success,
    (unsigned long long) sm->parse_ns,
    (unsigned long long) sm->enqueue_packets,
    (unsigned long long) sm->ingress_congestion_drops,
    (unsigned long long) sm->enqueue_ns);

  for (u32 i = 0; i < sm->owner_count; i++)
    vlib_cli_output (vm, "s124-owner %u packets %llu bytes %llu "
                         "submit-errors %llu queue-depth-max %llu "
                         "dequeue-packets %llu queue-wait-ns %llu",
                     i, sm->owners[i].packets, sm->owners[i].bytes,
                     sm->owners[i].submit_errors, sm->owners[i].queue_depth_max,
                     sm->owners[i].dequeue_packets, sm->owners[i].queue_wait_ns);
  return 0;
}

VLIB_CLI_COMMAND (s124_show_lite_command, static) = {
  .path = "show s124-vpn-tun-lite",
  .short_help = "show s124-vpn-tun-lite",
  .function = s124_show_lite_command_fn,
};

static clib_error_t *
s124_init (vlib_main_t *vm)
{
  s124_main.frame_queue_index =
    vlib_frame_queue_main_init (s124_vpn_tun_worker_node.index, 0);
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (s124_init);
