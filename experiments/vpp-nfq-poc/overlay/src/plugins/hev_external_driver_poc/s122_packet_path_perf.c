/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-122 Android real-device packet-path performance probe.
 *
 * This is deliberately a test-only extension of the S121 packet seam.  It
 * keeps the existing copy-based contract and measures the complete worker
 * path around it.  The current first fixture is a persistent owner-local
 * lwIP UDP listener with a synchronous echo; TCP is added as a separate
 * fixture once the arm64 UDP instrumentation is running.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/threads.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define S122_MAX_PACKET_LEN 2048U
#define S122_MAX_PAYLOAD_LEN 1400U
#define S122_UDP_LISTEN_PORT 49154U
#define S122_TCP_LISTEN_PORT 49155U
#define S122_CLIENT_PORT 40001U
#define S122_TCP_CLIENT_PORT 40002U
#define S122_TCP_CLIENT_ISN 0x12200000U
#define S122_OUTPUT_SLOTS 8U
#define S122_SERVER_IP 0x0a000001U
#define S122_CLIENT_IP 0x0a000002U

typedef struct s122_packet_path_perf_main s122_packet_path_perf_main_t;

typedef void (*s122_output_fn) (void *data, const void *packet, size_t length);
typedef void (*s122_recv_fn) (void *data, uintptr_t config_identity,
                              uintptr_t session_identity,
                              unsigned int transport, const void *payload,
                              size_t length);

typedef struct
{
  s122_output_fn output;
  void *data;
} s122_callbacks_t;

typedef struct
{
  uintptr_t identity;
  uint16_t tcp_listen_port;
  uint16_t udp_listen_port;
  s122_recv_fn recv;
  void *recv_data;
  const void *tcp_connector;
  const void *udp_connector;
  uint8_t tcp_ip_type;
  uint8_t udp_ip_type;
} s122_session_config_t;

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
} s122_owner_config_t;

typedef void *(*s122_create_with_config_fn) (
    const s122_callbacks_t *callbacks, const s122_owner_config_t *config);
typedef void (*s122_owner_config_default_fn) (s122_owner_config_t *config);
typedef int (*s122_configure_fn) (void *context,
                                  const s122_session_config_t *config);
typedef int (*s122_start_fn) (void *context);
typedef int (*s122_submit_fn) (void *context, const void *packet,
                               size_t length);
typedef int (*s122_udp_echo_fn) (void *context, uintptr_t session_identity,
                                 const void *payload, size_t length);
typedef int (*s122_tcp_echo_fn) (void *context, uintptr_t session_identity,
                                 const void *payload, size_t length);
typedef void (*s122_destroy_fn) (void *context);

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
} s122_hev_perf_metrics_t;

typedef void (*s122_perf_metrics_fn) (void *context,
                                      s122_hev_perf_metrics_t *metrics);

typedef enum
{
  S122_ARM_FULL,
  S122_ARM_PREBUILT,
  S122_ARM_BUILDER,
  S122_ARM_MEMCPY,
} s122_arm_t;

typedef struct
{
  void *handle;
  s122_create_with_config_fn create_with_config;
  s122_owner_config_default_fn owner_config_default;
  s122_configure_fn configure;
  s122_start_fn start;
  s122_submit_fn submit;
  s122_udp_echo_fn udp_echo;
  s122_tcp_echo_fn tcp_echo;
  s122_perf_metrics_fn perf_metrics;
  s122_destroy_fn destroy;
} s122_api_t;

struct s122_packet_path_perf_main
{
  s122_api_t api;
  void *context;
  vlib_main_t *worker_vm;
  u32 frame_queue_index;
  u32 target_thread;
  u32 pending_buffer;
  u32 pending;
  u32 active;
  u32 finished;
  u32 queue_error;
  u32 remaining;
  u32 burst;
  u32 payload_len;
  u32 packet_len;
  u32 request_count;
  u32 data_submit_calls;
  u32 handshake_submit_calls;
  u32 data_output_calls;
  u32 handshake_output_calls;
  u32 node_invocations;
  u32 submit_calls;
  u32 recv_calls;
  u32 echo_calls;
  u32 output_calls;
  u32 ingress_buffers_allocated;
  u32 ingress_buffers_freed;
  u32 egress_buffers_allocated;
  u32 egress_buffers_freed;
  u32 output_valid;
  u32 output_buffer_count;
  u32 output_buffers[S122_OUTPUT_SLOTS];
  u8 prebuilt_packet[S122_MAX_PACKET_LEN];
  u32 prebuilt_len;
  u8 protocol;
  s122_arm_t arm;
  u8 in_handshake;
  u8 tcp_handshake_done;
  u8 reserved;
  u32 tcp_client_seq;
  u32 tcp_server_seq;
  u32 tcp_server_ack;
  u32 tcp_last_output_seq;
  u32 tcp_last_output_ack;
  u8 tcp_last_output_flags;
  u8 tcp_last_output_reserved[3];
  size_t vpp_to_pbuf_copy_bytes;
  size_t pbuf_to_vpp_copy_bytes;
  size_t protocol_payload_bytes;
  size_t output_bytes;
  uint64_t submit_ns;
  uint64_t recv_ns;
  uint64_t output_alloc_ns;
  uint64_t output_copy_ns;
  uint64_t output_total_ns;
  uint64_t handshake_ns;
  uint64_t build_ns;
  uint64_t memcpy_ns;
  size_t memcpy_bytes;
  s122_hev_perf_metrics_t hev_metrics;
  uint64_t started_ns;
  uint64_t finished_ns;
  unsigned long setup_pthread;
  unsigned long worker_pthread;
  unsigned long recv_pthread;
  unsigned long output_pthread;
  int submit_result;
  int echo_result;
  u8 *lib_path;
  char error[256];
};

static s122_packet_path_perf_main_t s122_packet_path_perf_main;

static uint64_t
s122_now_ns (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void
s122_set_error (const char *message)
{
  snprintf (s122_packet_path_perf_main.error,
            sizeof (s122_packet_path_perf_main.error), "%s", message);
}

static int
s122_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol)
    {
      snprintf (s122_packet_path_perf_main.error,
                sizeof (s122_packet_path_perf_main.error), "dlsym(%s): %s",
                name, dlerror ());
      return -1;
    }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static void
s122_load_optional_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (symbol)
    memcpy (destination, &symbol, sizeof (symbol));
}

static int
s122_load_hev (const char *path)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  void *handle;

  if (tm->api.handle)
    return 0;
  if (!path || !path[0])
    {
      s122_set_error ("S122_HEV_LIB is empty; pass `lib <path>`");
      return -1;
    }
  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      snprintf (tm->error, sizeof (tm->error), "dlopen(%s): %s", path,
                dlerror ());
      return -1;
    }

#define S122_LOAD(field, symbol)                                            \
  if (s122_load_symbol (handle, symbol, &tm->api.field) < 0)                 \
    goto load_failed
  S122_LOAD (create_with_config, "flow_stack_owner_create_with_config");
  S122_LOAD (owner_config_default, "hev_socks5_owner_config_default");
  S122_LOAD (configure, "flow_stack_owner_configure_sessions");
  S122_LOAD (start, "flow_stack_owner_start");
  S122_LOAD (submit, "flow_stack_owner_submit");
  S122_LOAD (udp_echo, "flow_stack_owner_udp_echo");
  S122_LOAD (tcp_echo, "flow_stack_owner_tcp_echo");
  s122_load_optional_symbol (handle, "flow_stack_owner_perf_metrics",
                             &tm->api.perf_metrics);
  S122_LOAD (destroy, "flow_stack_owner_destroy");
#undef S122_LOAD

  tm->api.handle = handle;
  fprintf (stderr, "s122_perf stage=hev-loaded lib=%s\n", path);
  return 0;

load_failed:
  dlclose (handle);
  memset (&tm->api, 0, sizeof (tm->api));
  return -1;
}

static uint16_t
s122_checksum (const void *data, size_t length)
{
  const u8 *bytes = data;
  uint32_t sum = 0;
  while (length > 1)
    {
      sum += ((uint16_t) bytes[0] << 8) | bytes[1];
      bytes += 2;
      length -= 2;
    }
  if (length)
    sum += (uint16_t) bytes[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t) ~sum;
}

static uint16_t
s122_l4_checksum (const u8 *packet, size_t packet_len, u8 protocol)
{
  u8 pseudo[12];
  u32 payload_len = (u32) packet_len - 20U;
  uint32_t sum = 0;
  const u8 *bytes;
  size_t length;

  clib_memcpy_fast (pseudo, packet + 12, 8);
  pseudo[8] = 0;
  pseudo[9] = protocol;
  pseudo[10] = (u8) (payload_len >> 8);
  pseudo[11] = (u8) payload_len;
  bytes = pseudo;
  length = sizeof (pseudo);
  while (length > 1)
    {
      sum += ((uint16_t) bytes[0] << 8) | bytes[1];
      bytes += 2;
      length -= 2;
    }
  bytes = packet + 20;
  length = payload_len;
  while (length > 1)
    {
      sum += ((uint16_t) bytes[0] << 8) | bytes[1];
      bytes += 2;
      length -= 2;
    }
  if (length)
    sum += (uint16_t) bytes[0] << 8;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (uint16_t) ~sum;
}

static int
s122_build_udp_packet (u8 *packet, size_t payload_len)
{
  size_t packet_len = 20U + 8U + payload_len;
  u16 ip_total = (u16) packet_len;
  u16 udp_total = (u16) (8U + payload_len);
  /* This fixture writes the wire bytes explicitly below.  Do not apply
   * clib_host_to_net_u16() first: on little-endian Android that would swap
   * the integer and then the byte-wise write would swap it a second time. */
  u16 source_port = S122_CLIENT_PORT;
  u16 destination_port = S122_UDP_LISTEN_PORT;

  if (!packet || payload_len > S122_MAX_PAYLOAD_LEN)
    return -1;
  clib_memset (packet, 0, packet_len);
  packet[0] = 0x45;
  packet[2] = (u8) (ip_total >> 8);
  packet[3] = (u8) ip_total;
  packet[4] = 0;
  packet[5] = 1;
  packet[8] = 64;
  packet[9] = 17;
  packet[12] = 10;
  packet[13] = 0;
  packet[14] = 0;
  packet[15] = 2;
  packet[16] = 10;
  packet[17] = 0;
  packet[18] = 0;
  packet[19] = 1;
  packet[10] = 0;
  packet[11] = 0;
  {
    u16 checksum = s122_checksum (packet, 20);
    packet[10] = (u8) (checksum >> 8);
    packet[11] = (u8) checksum;
  }
  packet[20] = (u8) (source_port >> 8);
  packet[21] = (u8) source_port;
  packet[22] = (u8) (destination_port >> 8);
  packet[23] = (u8) destination_port;
  packet[24] = (u8) (udp_total >> 8);
  packet[25] = (u8) udp_total;
  packet[26] = 0;
  packet[27] = 0;
  for (size_t i = 0; i < payload_len; i++)
    packet[28 + i] = (u8) ('A' + (i % 26));
  {
    u16 checksum = s122_l4_checksum (packet, packet_len, 17);
    packet[26] = (u8) (checksum >> 8);
    packet[27] = (u8) checksum;
  }
  return (int) packet_len;
}

static void
s122_put_u32 (u8 *dst, u32 value)
{
  dst[0] = (u8) (value >> 24);
  dst[1] = (u8) (value >> 16);
  dst[2] = (u8) (value >> 8);
  dst[3] = (u8) value;
}

static u32
s122_get_u32 (const u8 *src)
{
  return ((u32) src[0] << 24) | ((u32) src[1] << 16) |
         ((u32) src[2] << 8) | src[3];
}

static u16
s122_checksum_replace_word (u16 checksum, u16 old_word, u16 new_word)
{
  u32 sum = ((u32) (~checksum & 0xffffU)) +
            ((u32) (~old_word & 0xffffU)) + new_word;
  while (sum >> 16)
    sum = (sum & 0xffffU) + (sum >> 16);
  return (u16) ~sum;
}

static void
s122_patch_tcp_sequence (u8 *packet, u32 seq, u32 ack)
{
  u16 checksum;
  u16 old_word;
  u16 new_word;

  if (!packet)
    return;
  if (s122_get_u32 (packet + 24) == seq && s122_get_u32 (packet + 28) == ack)
    return;
  checksum = ((u16) packet[36] << 8) | packet[37];
  old_word = ((u16) packet[24] << 8) | packet[25];
  new_word = (u16) (seq >> 16);
  checksum = s122_checksum_replace_word (checksum, old_word, new_word);
  packet[24] = (u8) (new_word >> 8);
  packet[25] = (u8) new_word;
  old_word = ((u16) packet[26] << 8) | packet[27];
  new_word = (u16) seq;
  checksum = s122_checksum_replace_word (checksum, old_word, new_word);
  packet[26] = (u8) (new_word >> 8);
  packet[27] = (u8) new_word;
  old_word = ((u16) packet[28] << 8) | packet[29];
  new_word = (u16) (ack >> 16);
  checksum = s122_checksum_replace_word (checksum, old_word, new_word);
  packet[28] = (u8) (new_word >> 8);
  packet[29] = (u8) new_word;
  old_word = ((u16) packet[30] << 8) | packet[31];
  new_word = (u16) ack;
  checksum = s122_checksum_replace_word (checksum, old_word, new_word);
  packet[30] = (u8) (new_word >> 8);
  packet[31] = (u8) new_word;
  packet[36] = (u8) (checksum >> 8);
  packet[37] = (u8) checksum;
}

static int
s122_build_tcp_packet (u8 *packet, size_t payload_len, u8 flags, u32 seq,
                       u32 ack)
{
  size_t tcp_header_len = (flags & 0x02U) ? 24U : 20U;
  size_t packet_len = 20U + tcp_header_len + payload_len;
  u16 ip_total = (u16) packet_len;
  u16 source_port = S122_TCP_CLIENT_PORT;
  u16 destination_port = S122_TCP_LISTEN_PORT;
  u16 tcp_flags = (u16) (((tcp_header_len / 4U) << 12) | flags);

  if (!packet || payload_len > S122_MAX_PAYLOAD_LEN ||
      packet_len > S122_MAX_PACKET_LEN)
    return -1;
  clib_memset (packet, 0, packet_len);
  packet[0] = 0x45;
  packet[2] = (u8) (ip_total >> 8);
  packet[3] = (u8) ip_total;
  packet[4] = 0;
  packet[5] = 2;
  packet[8] = 64;
  packet[9] = 6;
  packet[12] = 10;
  packet[15] = 2;
  packet[16] = 10;
  packet[19] = 1;
  {
    u16 checksum = s122_checksum (packet, 20);
    packet[10] = (u8) (checksum >> 8);
    packet[11] = (u8) checksum;
  }
  packet[20] = (u8) (source_port >> 8);
  packet[21] = (u8) source_port;
  packet[22] = (u8) (destination_port >> 8);
  packet[23] = (u8) destination_port;
  s122_put_u32 (packet + 24, seq);
  s122_put_u32 (packet + 28, ack);
  packet[32] = (u8) (tcp_flags >> 8);
  packet[33] = (u8) tcp_flags;
  packet[34] = 0xff;
  packet[35] = 0xff;
  packet[36] = 0;
  packet[37] = 0;
  packet[38] = 0;
  packet[39] = 0;
  if (flags & 0x02U)
    {
      /* Advertise an MSS that keeps the largest S122 payload in one lwIP
       * segment.  The option is part of the real SYN path, not a bypass. */
      packet[40] = 2;
      packet[41] = 4;
      packet[42] = 0x05;
      packet[43] = 0xb4; /* 1460 */
    }
  for (size_t i = 0; i < payload_len; i++)
    packet[tcp_header_len + 20U + i] = (u8) ('A' + (i % 26));
  {
    u16 checksum = s122_l4_checksum (packet, packet_len, 6);
    packet[36] = (u8) (checksum >> 8);
    packet[37] = (u8) checksum;
  }
  return (int) packet_len;
}

static void
s122_release_outputs (vlib_main_t *vm)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  for (u32 i = 0; i < tm->output_buffer_count; i++)
    {
      vlib_buffer_free_one (vm, tm->output_buffers[i]);
      tm->egress_buffers_freed++;
    }
  tm->output_buffer_count = 0;
}

static void
s122_output (void *data, const void *packet, size_t length)
{
  s122_packet_path_perf_main_t *tm = data;
  uint64_t started = s122_now_ns ();
  uint64_t copied;
  u32 buffer;
  vlib_buffer_t *b;

  tm->output_pthread = (unsigned long) pthread_self ();
  tm->output_calls++;
  if (tm->in_handshake)
    tm->handshake_output_calls++;
  else
    tm->data_output_calls++;
  tm->output_bytes += length;
  tm->pbuf_to_vpp_copy_bytes += length;
  if (!tm->worker_vm || !packet || !length || length > S122_MAX_PACKET_LEN ||
      tm->output_buffer_count >= S122_OUTPUT_SLOTS)
    {
      if (tm->output_buffer_count >= S122_OUTPUT_SLOTS)
        s122_set_error ("too many synchronous outputs");
      else
        s122_set_error ("invalid output");
      tm->queue_error = 1;
      return;
    }
  if (vlib_buffer_alloc (tm->worker_vm, &buffer, 1) != 1)
    {
      tm->queue_error = 1;
      s122_set_error ("could not allocate VPP egress buffer");
      return;
    }
  copied = s122_now_ns ();
  b = vlib_get_buffer (tm->worker_vm, buffer);
  b->current_length = length;
  clib_memcpy_fast (vlib_buffer_get_current (b), packet, length);
  tm->output_alloc_ns += copied - started;
  tm->output_copy_ns += s122_now_ns () - copied;
  tm->output_total_ns += s122_now_ns () - started;
  tm->output_buffers[tm->output_buffer_count++] = buffer;
  tm->egress_buffers_allocated++;
  if (length >= 28 && ((const u8 *) packet)[0] == 0x45 &&
      ((const u8 *) packet)[9] == tm->protocol)
    {
      tm->output_valid++;
      if (tm->protocol == 6 && length >= 40)
        {
          const u8 *bytes = packet;
          u32 ihl = (u32) (bytes[0] & 0x0fU) * 4U;
          if (ihl >= 20U && length >= ihl + 20U)
            {
              tm->tcp_last_output_seq = s122_get_u32 (bytes + ihl + 4U);
              tm->tcp_last_output_ack = s122_get_u32 (bytes + ihl + 8U);
              tm->tcp_last_output_flags = bytes[ihl + 13U];
              if ((tm->tcp_last_output_flags & 0x12U) == 0x12U)
                {
                  tm->tcp_server_seq = tm->tcp_last_output_seq;
                  tm->tcp_server_ack = tm->tcp_last_output_ack;
                }
            }
        }
    }
}

static void
s122_recv (void *data, uintptr_t config_identity, uintptr_t session_identity,
           unsigned int transport, const void *payload, size_t length)
{
  s122_packet_path_perf_main_t *tm = data;
  uint64_t started = s122_now_ns ();
  (void) config_identity;
  tm->recv_pthread = (unsigned long) pthread_self ();
  tm->recv_calls++;
  tm->protocol_payload_bytes += length;
  if (transport != (tm->protocol == 6 ? 1U : 2U) || !payload || !length ||
      !tm->context)
    {
      tm->queue_error = 1;
      s122_set_error ("unexpected HEV/lwIP receive callback");
      return;
    }
  if (tm->protocol == 6)
    tm->echo_result = tm->api.tcp_echo (tm->context, session_identity, payload,
                                        length);
  else
    tm->echo_result = tm->api.udp_echo (tm->context, session_identity, payload,
                                        length);
  tm->echo_calls++;
  tm->recv_ns += s122_now_ns () - started;
  if (tm->echo_result < 0)
    {
      tm->queue_error = 1;
      s122_set_error (tm->protocol == 6 ? "lwIP TCP echo failed" :
                                         "lwIP UDP echo failed");
    }
}

static int
s122_submit_packet (vlib_main_t *vm, const u8 *packet, u32 length,
                    int data_packet)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  vlib_buffer_t *b;
  u32 buffer;
  uint64_t started;

  if (!packet || !length || length > S122_MAX_PACKET_LEN ||
      vlib_buffer_alloc (vm, &buffer, 1) != 1)
    {
      tm->queue_error = 1;
      s122_set_error ("could not allocate S122 ingress buffer");
      return -1;
    }
  b = vlib_get_buffer (vm, buffer);
  b->current_length = length;
  clib_memcpy_fast (vlib_buffer_get_current (b), packet, length);
  tm->output_buffer_count = 0;
  tm->in_handshake = data_packet ? 0 : 1;
  started = s122_now_ns ();
  tm->submit_result = tm->api.submit (tm->context,
                                      vlib_buffer_get_current (b), length);
  tm->submit_ns += s122_now_ns () - started;
  tm->submit_calls++;
  if (data_packet)
    tm->data_submit_calls++;
  else
    tm->handshake_submit_calls++;
  tm->vpp_to_pbuf_copy_bytes += length;
  tm->ingress_buffers_allocated++;
  if (tm->submit_result < 0)
    {
      tm->queue_error = 1;
      s122_set_error ("flow_stack_owner_submit failed");
    }
  vlib_buffer_free_one (vm, buffer);
  tm->ingress_buffers_freed++;
  s122_release_outputs (vm);
  return tm->submit_result;
}

static int
s122_memcpy_packet (vlib_main_t *vm, const u8 *packet, u32 length)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  vlib_buffer_t *b;
  u32 buffer;
  uint64_t started;

  if (!packet || !length || length > S122_MAX_PACKET_LEN ||
      vlib_buffer_alloc (vm, &buffer, 1) != 1)
    {
      tm->queue_error = 1;
      s122_set_error ("could not allocate S122 memcpy buffer");
      return -1;
    }
  b = vlib_get_buffer (vm, buffer);
  b->current_length = length;
  started = s122_now_ns ();
  clib_memcpy_fast (vlib_buffer_get_current (b), packet, length);
  tm->memcpy_ns += s122_now_ns () - started;
  tm->memcpy_bytes += length;
  tm->ingress_buffers_allocated++;
  vlib_buffer_free_one (vm, buffer);
  tm->ingress_buffers_freed++;
  return 0;
}

static int
s122_tcp_handshake (vlib_main_t *vm)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  u8 packet[S122_MAX_PACKET_LEN];
  uint64_t started = s122_now_ns ();
  u32 syn_seq = S122_TCP_CLIENT_ISN;
  int length;

  tm->tcp_client_seq = syn_seq;
  tm->tcp_server_seq = 0;
  tm->tcp_server_ack = 0;
  length = s122_build_tcp_packet (packet, 0, 0x02, syn_seq, 0);
  if (length < 0 || s122_submit_packet (vm, packet, (u32) length, 0) < 0 ||
      tm->tcp_last_output_flags != 0x12U)
    {
      tm->queue_error = 1;
      s122_set_error ("TCP SYN did not produce SYN-ACK");
      return -1;
    }
  tm->tcp_client_seq = syn_seq + 1U;
  tm->tcp_server_seq += 1U;
  length = s122_build_tcp_packet (packet, 0, 0x10, tm->tcp_client_seq,
                                  tm->tcp_server_seq);
  if (length < 0 || s122_submit_packet (vm, packet, (u32) length, 0) < 0)
    {
      tm->queue_error = 1;
      s122_set_error ("TCP ACK failed");
      return -1;
    }
  tm->tcp_handshake_done = 1;
  tm->handshake_ns += s122_now_ns () - started;
  return 0;
}

static const char *
s122_arm_name (s122_arm_t arm)
{
  switch (arm)
    {
    case S122_ARM_PREBUILT:
      return "prebuilt";
    case S122_ARM_BUILDER:
      return "builder";
    case S122_ARM_MEMCPY:
      return "memcpy";
    case S122_ARM_FULL:
    default:
      return "full";
    }
}

static int
s122_prepare_packet (s122_packet_path_perf_main_t *tm, u32 seq, u32 ack)
{
  uint64_t started = s122_now_ns ();
  int built;

  if (tm->protocol == 6)
    built = s122_build_tcp_packet (tm->prebuilt_packet, tm->payload_len, 0x18,
                                   seq, ack);
  else
    built = s122_build_udp_packet (tm->prebuilt_packet, tm->payload_len);
  tm->build_ns += s122_now_ns () - started;
  if (built < 0 || built != (int) tm->packet_len)
    {
      s122_set_error ("could not prepare S122 packet");
      return -1;
    }
  tm->prebuilt_len = (u32) built;
  return 0;
}

static void s122_finish_owner (void);

static int
s122_start_owner (vlib_main_t *vm)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  s122_callbacks_t callbacks = {
    .output = s122_output,
    .data = tm,
  };
  s122_session_config_t config;
  s122_owner_config_t owner_config;

  tm->worker_vm = vm;
  tm->setup_pthread = (unsigned long) pthread_self ();
  tm->active = 1;
  tm->finished = 0;
  tm->started_ns = s122_now_ns ();

  /* The builder and memcpy arms deliberately stop before HEV.  They share
   * the same VPP worker and packet size, but have no protocol-stack cost. */
  if (tm->arm == S122_ARM_BUILDER)
    return 0;
  if (tm->arm == S122_ARM_MEMCPY)
    return s122_prepare_packet (tm, 0, 0);

  tm->api.owner_config_default (&owner_config);
  owner_config.inflight_pbuf_credit_limit = 2;
  tm->context = tm->api.create_with_config (&callbacks, &owner_config);
  if (!tm->context)
    {
      s122_set_error ("flow stack owner create failed");
      return -1;
    }
  clib_memset (&config, 0, sizeof (config));
  config.identity = 0x122;
  if (tm->protocol == 6)
    config.tcp_listen_port = S122_TCP_LISTEN_PORT;
  else
    config.udp_listen_port = S122_UDP_LISTEN_PORT;
  config.recv = s122_recv;
  config.recv_data = tm;
  config.tcp_ip_type = 0;
  config.udp_ip_type = 0;
  if (tm->api.configure (tm->context, &config) < 0 ||
      tm->api.start (tm->context) < 0)
    {
      s122_set_error ("flow stack owner configure/start failed");
      tm->api.destroy (tm->context);
      tm->context = NULL;
      return -1;
    }
  if (tm->protocol == 6 && s122_tcp_handshake (vm) < 0)
    {
      s122_finish_owner ();
      return -1;
    }
  if (tm->arm == S122_ARM_PREBUILT &&
      s122_prepare_packet (tm, tm->tcp_client_seq, tm->tcp_server_seq) < 0)
    {
      s122_finish_owner ();
      return -1;
    }
  return 0;
}

static void
s122_finish_owner (void)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  if (!tm->queue_error && tm->arm != S122_ARM_BUILDER &&
      tm->arm != S122_ARM_MEMCPY &&
      (tm->data_submit_calls != tm->request_count ||
       tm->recv_calls != tm->request_count ||
       tm->echo_calls != tm->request_count ||
       tm->data_output_calls != tm->request_count))
    {
      tm->queue_error = 1;
      s122_set_error ("packet-path count mismatch");
    }
  if (tm->api.perf_metrics && tm->context)
    tm->api.perf_metrics (tm->context, &tm->hev_metrics);
  if (tm->context)
    tm->api.destroy (tm->context);
  tm->context = NULL;
  tm->active = 0;
  tm->finished = 1;
  tm->finished_ns = s122_now_ns ();
  fprintf (stderr,
           "s122_perf stage=finished arm=%s protocol=%s result=%s count=%u "
           "payload=%u burst=%u submit=%u data-submit=%u handshake-submit=%u "
           "recv=%u echo=%u output=%u data-output=%u handshake-output=%u "
           "copies=%lu/%lu "
           "protocol-bytes=%lu submit-ns=%llu recv-ns=%llu "
           "output-alloc-ns=%llu output-copy-ns=%llu output-total-ns=%llu "
           "handshake-ns=%llu build-ns=%llu memcpy-ns=%llu memcpy-bytes=%lu "
           "hev-submit-alloc-ns=%llu hev-submit-copy-ns=%llu "
           "hev-submit-copy-bytes=%llu hev-submit-pbuf=%llu/%llu "
           "hev-udp-alloc-ns=%llu hev-udp-copy-ns=%llu "
           "hev-udp-copy-bytes=%llu hev-udp-pbuf=%llu/%llu "
           "hev-tcp-write-ns=%llu hev-tcp-write-bytes=%llu "
           "hev-tcp-write-calls=%llu elapsed-ns=%llu threads setup=%lu "
           "worker=%lu recv=%lu output=%lu\n",
           s122_arm_name (tm->arm), tm->protocol == 6 ? "tcp" : "udp",
           tm->queue_error ? "FAIL" : "PASS",
           tm->request_count, tm->payload_len, tm->burst, tm->submit_calls,
           tm->data_submit_calls, tm->handshake_submit_calls, tm->recv_calls,
           tm->echo_calls, tm->output_calls, tm->data_output_calls,
           tm->handshake_output_calls,
           (unsigned long) tm->vpp_to_pbuf_copy_bytes,
           (unsigned long) tm->pbuf_to_vpp_copy_bytes,
           (unsigned long) tm->protocol_payload_bytes,
           (unsigned long long) tm->submit_ns,
           (unsigned long long) tm->recv_ns,
           (unsigned long long) tm->output_alloc_ns,
           (unsigned long long) tm->output_copy_ns,
           (unsigned long long) tm->output_total_ns,
           (unsigned long long) tm->handshake_ns,
           (unsigned long long) tm->build_ns,
           (unsigned long long) tm->memcpy_ns,
           (unsigned long) tm->memcpy_bytes,
           (unsigned long long) tm->hev_metrics.submit_pbuf_alloc_ns,
           (unsigned long long) tm->hev_metrics.submit_copy_ns,
           (unsigned long long) tm->hev_metrics.submit_copy_bytes,
           (unsigned long long) tm->hev_metrics.submit_pbuf_allocs,
           (unsigned long long) tm->hev_metrics.submit_pbuf_frees,
           (unsigned long long) tm->hev_metrics.udp_echo_pbuf_alloc_ns,
           (unsigned long long) tm->hev_metrics.udp_echo_copy_ns,
           (unsigned long long) tm->hev_metrics.udp_echo_copy_bytes,
           (unsigned long long) tm->hev_metrics.udp_echo_pbuf_allocs,
           (unsigned long long) tm->hev_metrics.udp_echo_pbuf_frees,
           (unsigned long long) tm->hev_metrics.tcp_write_ns,
           (unsigned long long) tm->hev_metrics.tcp_write_copy_bytes,
           (unsigned long long) tm->hev_metrics.tcp_write_calls,
           (unsigned long long) (tm->finished_ns - tm->started_ns),
           tm->setup_pthread, tm->worker_pthread, tm->recv_pthread,
           tm->output_pthread);
}

static int
s122_enqueue_next (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  u16 target = (u16) tm->target_thread;
  u32 buffer;

  if (vlib_buffer_alloc (vm, &buffer, 1) != 1)
    {
      tm->queue_error = 1;
      s122_set_error ("could not allocate S122 trigger buffer");
      return -1;
    }
  if (vlib_buffer_enqueue_to_thread (vm, node, tm->frame_queue_index, &buffer,
                                     &target, 1, 1) != 1)
    {
      vlib_buffer_free_one (vm, buffer);
      tm->queue_error = 1;
      s122_set_error ("could not enqueue S122 trigger buffer");
      return -1;
    }
  return 0;
}

VLIB_NODE_FN (s122_packet_path_perf_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  u16 target;
  (void) frame;
  if (!tm->pending)
    return 0;
  target = (u16) tm->target_thread;
  if (vlib_buffer_enqueue_to_thread (vm, node, tm->frame_queue_index,
                                     &tm->pending_buffer,
                                     &target, 1, 1) != 1)
    {
      vlib_buffer_free_one (vm, tm->pending_buffer);
      tm->queue_error = 1;
      s122_set_error ("could not enqueue initial S122 buffer");
    }
  tm->pending = 0;
  return 1;
}

VLIB_REGISTER_NODE (s122_packet_path_perf_trigger_node) = {
  .name = "s122-packet-path-perf-trigger",
  .function = s122_packet_path_perf_trigger_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (s122_packet_path_perf_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 work = tm->remaining < tm->burst ? tm->remaining : tm->burst;

  tm->worker_vm = vm;
  tm->worker_pthread = (unsigned long) pthread_self ();
  for (u32 i = 0; i < frame->n_vectors; i++)
    vlib_buffer_free_one (vm, from[i]);
  if (!tm->active && !tm->finished && s122_start_owner (vm) < 0)
    tm->queue_error = 1;
  if (!tm->active || tm->queue_error)
    return frame->n_vectors;

  for (u32 i = 0; i < work; i++)
    {
      u8 packet[S122_MAX_PACKET_LEN];
      int built;

      if (tm->arm == S122_ARM_BUILDER)
        {
          uint64_t started = s122_now_ns ();
          if (tm->protocol == 6)
            built = s122_build_tcp_packet (packet, tm->payload_len, 0x18,
                                           tm->tcp_client_seq,
                                           tm->tcp_server_seq);
          else
            built = s122_build_udp_packet (packet, tm->payload_len);
          tm->build_ns += s122_now_ns () - started;
        }
      else if (tm->arm == S122_ARM_MEMCPY)
        {
          built = (int) tm->prebuilt_len;
          if (s122_memcpy_packet (vm, tm->prebuilt_packet,
                                  tm->prebuilt_len) < 0)
            built = -1;
        }
      else if (tm->arm == S122_ARM_PREBUILT)
        {
          if (tm->protocol == 6)
            s122_patch_tcp_sequence (tm->prebuilt_packet,
                                     tm->tcp_client_seq,
                                     tm->tcp_server_seq);
          built = (int) tm->prebuilt_len;
          if (s122_submit_packet (vm, tm->prebuilt_packet,
                                  tm->prebuilt_len, 1) < 0)
            built = -1;
        }
      else
        {
          uint64_t started = s122_now_ns ();
          if (tm->protocol == 6)
            built = s122_build_tcp_packet (packet, tm->payload_len, 0x18,
                                           tm->tcp_client_seq,
                                           tm->tcp_server_seq);
          else
            built = s122_build_udp_packet (packet, tm->payload_len);
          tm->build_ns += s122_now_ns () - started;
          if (built == (int) tm->packet_len &&
              s122_submit_packet (vm, packet, tm->packet_len, 1) < 0)
            built = -1;
        }
      if (built != (int) tm->packet_len)
        {
          tm->queue_error = 1;
          if (!tm->error[0])
            s122_set_error ("could not build or submit packet");
          break;
        }
      if (tm->arm == S122_ARM_BUILDER)
        tm->data_submit_calls++;
      else if (tm->arm == S122_ARM_MEMCPY)
        tm->data_submit_calls++;
      if (tm->protocol == 6 && tm->arm != S122_ARM_MEMCPY)
        {
          /* The server echoed this payload synchronously.  ACK its bytes on
           * the next synthetic client segment so lwIP's send window does not
           * fill during a long TCP run. */
          tm->tcp_client_seq += tm->payload_len;
          tm->tcp_server_seq += tm->payload_len;
        }
      if (tm->queue_error)
        break;
    }
  tm->remaining -= work;
  if (tm->queue_error || tm->remaining == 0)
    {
      s122_finish_owner ();
    }
  else if (s122_enqueue_next (vm, node) < 0)
    {
      s122_finish_owner ();
    }
  tm->node_invocations++;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (s122_packet_path_perf_worker_node) = {
  .name = "s122-packet-path-perf-worker",
  .function = s122_packet_path_perf_worker_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

static clib_error_t *
s122_packet_path_perf_run_command_fn (vlib_main_t *vm,
                                      unformat_input_t *input,
                                      vlib_cli_command_t *cmd)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  u32 target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  u32 payload_len = 64;
  u32 count = 1;
  u32 burst = 1;
  u8 protocol = 17;
  s122_arm_t arm = S122_ARM_FULL;
  u8 *lib_path = NULL;
  const char *env_path;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "target-thread %u", &target_thread))
        ;
      else if (unformat (input, "payload %u", &payload_len))
        ;
      else if (unformat (input, "count %u", &count))
        ;
      else if (unformat (input, "burst %u", &burst))
        ;
      else if (unformat (input, "protocol tcp"))
        protocol = 6;
      else if (unformat (input, "protocol udp"))
        protocol = 17;
      else if (unformat (input, "arm full"))
        arm = S122_ARM_FULL;
      else if (unformat (input, "arm prebuilt"))
        arm = S122_ARM_PREBUILT;
      else if (unformat (input, "arm builder"))
        arm = S122_ARM_BUILDER;
      else if (unformat (input, "arm memcpy"))
        arm = S122_ARM_MEMCPY;
      else if (unformat (input, "lib %s", &lib_path))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  if (!target_thread || target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "target-thread must be a worker in 1..%u",
                              vlib_get_n_threads () - 1);
  if (!payload_len || payload_len > S122_MAX_PAYLOAD_LEN)
    return clib_error_return (0, "payload must be in 1..%u",
                              S122_MAX_PAYLOAD_LEN);
  if (!count || count > 10000000U)
    return clib_error_return (0, "count must be in 1..10000000");
  if (!burst || burst > count)
    return clib_error_return (0, "burst must be in 1..count");
  if (tm->pending || tm->active)
    return clib_error_return (0, "S122 packet path is already active");
  env_path = getenv ("S122_HEV_LIB");
  if (!lib_path && env_path)
    lib_path = format (0, "%s%c", env_path, 0);
  if (arm == S122_ARM_FULL || arm == S122_ARM_PREBUILT)
    {
      if (s122_load_hev ((const char *) lib_path) < 0)
        {
          clib_error_t *error = clib_error_return (0, "HEV load failed: %s",
                                                   tm->error);
          vec_free (lib_path);
          return error;
        }
    }
  vec_free (lib_path);
  if (vlib_buffer_alloc (vm, &tm->pending_buffer, 1) != 1)
    return clib_error_return (0, "could not allocate S122 trigger buffer");
  tm->target_thread = target_thread;
  tm->protocol = protocol;
  tm->arm = arm;
  tm->payload_len = payload_len;
  tm->packet_len = (protocol == 6 ? 40U : 28U) + payload_len;
  tm->request_count = count;
  tm->remaining = count;
  tm->burst = burst;
  tm->pending = 1;
  tm->finished = 0;
  tm->active = 0;
  tm->queue_error = 0;
  tm->output_buffer_count = 0;
  clib_memset (tm->output_buffers, 0, sizeof (tm->output_buffers));
  tm->tcp_handshake_done = 0;
  tm->tcp_client_seq = 0;
  tm->tcp_server_seq = 0;
  tm->tcp_server_ack = 0;
  tm->tcp_last_output_seq = 0;
  tm->tcp_last_output_ack = 0;
  tm->tcp_last_output_flags = 0;
  tm->prebuilt_len = 0;
  tm->submit_calls = 0;
  tm->data_submit_calls = 0;
  tm->handshake_submit_calls = 0;
  tm->recv_calls = 0;
  tm->echo_calls = 0;
  tm->output_calls = 0;
  tm->data_output_calls = 0;
  tm->handshake_output_calls = 0;
  tm->ingress_buffers_allocated = 0;
  tm->ingress_buffers_freed = 0;
  tm->egress_buffers_allocated = 0;
  tm->egress_buffers_freed = 0;
  tm->output_valid = 0;
  tm->node_invocations = 0;
  tm->vpp_to_pbuf_copy_bytes = 0;
  tm->pbuf_to_vpp_copy_bytes = 0;
  tm->protocol_payload_bytes = 0;
  tm->submit_ns = 0;
  tm->recv_ns = 0;
  tm->output_alloc_ns = 0;
  tm->output_copy_ns = 0;
  tm->output_total_ns = 0;
  tm->handshake_ns = 0;
  tm->build_ns = 0;
  tm->memcpy_ns = 0;
  tm->memcpy_bytes = 0;
  clib_memset (&tm->hev_metrics, 0, sizeof (tm->hev_metrics));
  tm->error[0] = 0;
  vlib_node_set_interrupt_pending (vm,
                                   s122_packet_path_perf_trigger_node.index);
  vlib_cli_output (vm,
                   "s122-packet-path-perf queued arm %s protocol %s "
                   "target-thread %u "
                   "payload %u count %u burst %u",
                   s122_arm_name (arm), protocol == 6 ? "tcp" : "udp",
                   target_thread, payload_len, count, burst);
  return 0;
}

VLIB_CLI_COMMAND (s122_packet_path_perf_run_command, static) = {
  .path = "s122-packet-path-perf run",
  .short_help =
      "s122-packet-path-perf run [arm full|prebuilt|builder|memcpy] "
      "[protocol udp|tcp] target-thread <worker> payload <bytes> count <n> "
      "burst <n> [lib <path>]",
  .function = s122_packet_path_perf_run_command_fn,
};

static clib_error_t *
s122_packet_path_perf_show_command_fn (vlib_main_t *vm,
                                       unformat_input_t *input,
                                       vlib_cli_command_t *cmd)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  (void) input;
  (void) cmd;
  vlib_cli_output (
      vm,
      "s122-packet-path-perf arm %s protocol %s active %u pending %u finished %u "
      "remaining %u submit %u data-submit %u handshake-submit %u recv %u "
      "echo %u output %u data-output %u handshake-output %u queue-error %u",
      s122_arm_name (tm->arm), tm->protocol == 6 ? "tcp" : "udp", tm->active,
      tm->pending, tm->finished, tm->remaining, tm->submit_calls,
      tm->data_submit_calls, tm->handshake_submit_calls, tm->recv_calls,
      tm->echo_calls, tm->output_calls, tm->data_output_calls,
      tm->handshake_output_calls, tm->queue_error);
  vlib_cli_output (
      vm,
      "s122-packet-path-perf copies=%lu/%lu protocol-bytes=%lu "
      "submit-ns=%llu recv-ns=%llu output-copy-ns=%llu build-ns=%llu "
      "memcpy-ns=%llu memcpy-bytes=%lu "
      "hev-submit-copy-ns=%llu hev-submit-copy-bytes=%llu "
      "hev-udp-copy-ns=%llu hev-udp-copy-bytes=%llu "
      "hev-tcp-write-ns=%llu hev-tcp-write-bytes=%llu handshake-ns=%llu "
      "elapsed-ns=%llu "
      "threads worker=%lu recv=%lu output=%lu",
      (unsigned long) tm->vpp_to_pbuf_copy_bytes,
      (unsigned long) tm->pbuf_to_vpp_copy_bytes,
      (unsigned long) tm->protocol_payload_bytes,
      (unsigned long long) tm->submit_ns,
      (unsigned long long) tm->recv_ns,
      (unsigned long long) tm->output_copy_ns,
      (unsigned long long) tm->build_ns,
      (unsigned long long) tm->memcpy_ns,
      (unsigned long) tm->memcpy_bytes,
      (unsigned long long) tm->hev_metrics.submit_copy_ns,
      (unsigned long long) tm->hev_metrics.submit_copy_bytes,
      (unsigned long long) tm->hev_metrics.udp_echo_copy_ns,
      (unsigned long long) tm->hev_metrics.udp_echo_copy_bytes,
      (unsigned long long) tm->hev_metrics.tcp_write_ns,
      (unsigned long long) tm->hev_metrics.tcp_write_copy_bytes,
      (unsigned long long) tm->handshake_ns,
      (unsigned long long) (tm->finished && tm->finished_ns >= tm->started_ns
                                 ? tm->finished_ns - tm->started_ns
                                 : 0),
      tm->worker_pthread, tm->recv_pthread, tm->output_pthread);
  if (tm->error[0])
    vlib_cli_output (vm, "s122-packet-path-perf error %s", tm->error);
  return 0;
}

VLIB_CLI_COMMAND (s122_packet_path_perf_show_command, static) = {
  .path = "show s122-packet-path-perf",
  .short_help = "show s122-packet-path-perf",
  .function = s122_packet_path_perf_show_command_fn,
};

static clib_error_t *
s122_packet_path_perf_init (vlib_main_t *vm)
{
  s122_packet_path_perf_main_t *tm = &s122_packet_path_perf_main;
  clib_memset (tm, 0, sizeof (*tm));
  tm->frame_queue_index =
      vlib_frame_queue_main_init (s122_packet_path_perf_worker_node.index, 0);
  tm->output_buffer_count = 0;
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (s122_packet_path_perf_init);
