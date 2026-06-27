/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_tun_poc_h
#define included_tun_poc_h

#include <vlib/vlib.h>
#include <vlib/file.h>

#define TUN_POC_MAX_THREAD_HITS 64

typedef enum
{
  TUN_POC_MODE_COUNT_ONLY,
  TUN_POC_MODE_REFLECT_ICMP,
  TUN_POC_MODE_FORWARD_FD,
  TUN_POC_MODE_HANDOFF_PROBE,
  TUN_POC_MODE_HANDOFF_FORWARD_FD,
} tun_poc_mode_t;

typedef struct
{
  u8 enabled;
  tun_poc_mode_t mode;
  int fd;
  int shim_fd;
  int resolver_fd;
  u32 file_index;
  u32 shim_file_index;
  u8 block_ip4_dst_set;
  u32 block_ip4_dst;
  u8 block_ip6_dst_set;
  u8 block_ip6_dst[16];
  u8 *rx_buf;
  u32 handoff_frame_queue_index;
  u32 handoff_target_thread;

  u64 rx_packets;
  u64 rx_bytes;
  u64 tx_packets;
  u64 tx_bytes;
  u64 shim_rx_packets;
  u64 shim_rx_bytes;
  u64 shim_tx_packets;
  u64 shim_tx_bytes;
  u64 blocked_packets;
  u64 blocked_bytes;
  u64 short_packets;
  u64 non_ipv4;
  u64 non_icmp;
  u64 non_echo;
  u64 parse_errors;
  u64 read_errors;
  u64 write_errors;
  u64 shim_read_errors;
  u64 shim_write_errors;
  u64 handoff_enqueued_packets;
  u64 handoff_enqueued_bytes;
  u64 handoff_congestion_drops;
  u64 handoff_alloc_errors;
  u64 worker_probe_packets;
  u64 worker_probe_bytes;
  u64 tuple_parsed_packets;
  u64 tuple_parse_errors;
  u64 tuple_non_tcp_udp;
  u8 last_tuple_valid;
  u8 last_tuple_ip_version;
  u8 last_tuple_protocol;
  u16 last_tuple_src_port;
  u16 last_tuple_dst_port;
  u32 last_tuple_ip4_src;
  u32 last_tuple_ip4_dst;
  u8 last_tuple_ip6_src[16];
  u8 last_tuple_ip6_dst[16];
  u8 resolver_enabled;
  i32 last_owner_uid;
  u64 resolver_queries;
  u64 resolver_hits;
  u64 resolver_errors;
  u64 main_fd_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 shim_fd_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 rx_node_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 worker_probe_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 overflow_thread_hits;
  u32 last_main_fd_thread_index;
  u32 last_shim_fd_thread_index;
  u32 last_rx_node_thread_index;
  u32 last_worker_probe_thread_index;
} tun_poc_main_t;

extern tun_poc_main_t tun_poc_main;

clib_error_t *tun_poc_enable (vlib_main_t *vm, int fd, tun_poc_mode_t mode,
			      int shim_fd, u8 block_ip4_dst_set,
			      u32 block_ip4_dst);
void tun_poc_disable (void);
u8 *format_tun_poc_mode (u8 *s, va_list *args);

#endif /* included_tun_poc_h */
