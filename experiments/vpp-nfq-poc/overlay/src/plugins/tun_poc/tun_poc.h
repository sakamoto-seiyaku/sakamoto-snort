/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_tun_poc_h
#define included_tun_poc_h

#include <vlib/vlib.h>
#include <vlib/file.h>

#define TUN_POC_MAX_THREAD_HITS 64
#define TUN_POC_MAX_DIRECT_WORKERS 64
#define TUN_POC_DIRECT_SEEN_KEYS 64
#define TUN_POC_FRAGMENT_MAX_ENTRIES 64
#define TUN_POC_FRAGMENT_MAX_RANGES 32

typedef enum
{
  TUN_POC_MODE_COUNT_ONLY,
  TUN_POC_MODE_REFLECT_ICMP,
  TUN_POC_MODE_FORWARD_FD,
  TUN_POC_MODE_HANDOFF_PROBE,
  TUN_POC_MODE_HANDOFF_FORWARD_FD,
  TUN_POC_MODE_DIRECT_OWNER,
  TUN_POC_MODE_DIRECT_OWNER_FAULT,
  TUN_POC_MODE_DIRECT_OWNER_RETURN,
  TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER,
  TUN_POC_MODE_FRAGMENT_OWNER,
} tun_poc_mode_t;

typedef struct
{
  u32 start;
  u32 end;
  u8 valid;
} tun_poc_fragment_range_t;

typedef struct
{
  u8 valid;
  u8 version;
  u8 protocol;
  u8 first_seen;
  u8 last_seen;
  u8 flow_owner_valid;
  u32 fragment_id;
  u32 owner;
  u32 flow_owner;
  u64 key_hash;
  f64 last_seen_time;
  u32 range_count;
  u32 final_end;
  u8 transitioned;
  tun_poc_fragment_range_t ranges[TUN_POC_FRAGMENT_MAX_RANGES];
} tun_poc_fragment_entry_t;

typedef struct
{
  u8 enabled;
  tun_poc_mode_t mode;
  int fd;
  int shim_fd;
  int resolver_fd;
  u32 file_index;
  u32 shim_file_index;
  u32 polling_thread_index;
  u32 shim_polling_thread_index;
  u8 block_ip4_dst_set;
  u32 block_ip4_dst;
  u8 block_ip6_dst_set;
  u8 block_ip6_dst[16];
  u8 *rx_buf;
  u32 handoff_frame_queue_index;
  u32 handoff_target_thread;
  u32 redirect_frame_queue_index;
  u32 redirect_target_thread;
  u8 redirect_enabled;

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
  u32 direct_worker_count;
  u64 direct_enqueued_packets;
  u64 direct_enqueued_bytes;
  u64 direct_congestion_drops;
  u64 direct_alloc_errors;
  u64 direct_parse_errors;
  u64 direct_owner_guard_pass;
  u64 direct_owner_guard_mismatch;
  u64 direct_corrective_handoffs;
  u64 direct_corrective_drops;
  u64 direct_second_mismatch_drops;
  u64 direct_fault_injected;
  u64 direct_fault_single_completed;
  u64 direct_return_enqueued_packets;
  u64 direct_return_enqueued_bytes;
  u64 direct_return_congestion_drops;
  u64 direct_return_worker_packets;
  u64 direct_return_worker_bytes;
  u64 direct_return_tx_packets;
  u64 direct_return_tx_bytes;
  u64 fragment_packets;
  u64 fragment_bytes;
  u64 fragment_first_packets;
  u64 fragment_nonfirst_packets;
  u64 fragment_last_packets;
  u64 fragment_malformed;
  u64 fragment_capacity_drops;
  u64 fragment_timeout_drops;
  u64 fragment_overlap_drops;
  u64 fragment_duplicate_drops;
  u64 fragment_owner_guard_pass;
  u64 fragment_owner_guard_mismatch;
  u64 fragment_flow_owner_transitions;
  u64 fragment_reassembly_success;
  u64 fragment_terminal_drops;
  u64 fragment_table_evictions;
  u64 fragment_owner_mask;
  tun_poc_fragment_entry_t fragment_entries[TUN_POC_FRAGMENT_MAX_ENTRIES];
  u32 fragment_cursor;
  f64 fragment_timeout_seconds;
  u32 completion_target_thread;
  u32 completion_fault_budget;
  u32 completion_frame_queue_index;
  u64 completion_enqueued_packets;
  u64 completion_enqueued_bytes;
  u64 completion_processed_packets;
  u64 completion_processed_bytes;
  u64 completion_eagain_drops;
  u64 completion_terminal_drops;
  u64 direct_reverse_matches;
  u64 direct_reverse_owner_mismatch;
  u64 direct_reverse_projection_matches;
  u64 direct_reverse_projection_mismatch;
  u64 direct_target_worker_mask;
  u64 direct_worker_packets[TUN_POC_MAX_DIRECT_WORKERS];
  u64 direct_worker_bytes[TUN_POC_MAX_DIRECT_WORKERS];
  u64 direct_seen_canonical_hash[TUN_POC_DIRECT_SEEN_KEYS];
  u64 direct_seen_direction_hash[TUN_POC_DIRECT_SEEN_KEYS];
  u32 direct_seen_owner[TUN_POC_DIRECT_SEEN_KEYS];
  u32 direct_seen_cursor;
  u8 direct_seen_valid[TUN_POC_DIRECT_SEEN_KEYS];
  u64 redirect_enqueued_packets;
  u64 redirect_enqueued_bytes;
  u64 redirect_congestion_drops;
  u64 redirect_worker_packets;
  u64 redirect_worker_bytes;
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
  u8 owner_cache_enabled;
  u8 owner_cache_valid;
  u8 owner_cache_ip_version;
  u8 owner_cache_protocol;
  u16 owner_cache_src_port;
  u16 owner_cache_dst_port;
  u32 owner_cache_ip4_src;
  u32 owner_cache_ip4_dst;
  u8 owner_cache_ip6_src[16];
  u8 owner_cache_ip6_dst[16];
  i32 owner_cache_uid;
  u8 block_owner_uid_set;
  i32 block_owner_uid;
  u64 resolver_queries;
  u64 resolver_hits;
  u64 resolver_errors;
  u64 owner_cache_hits;
  u64 owner_cache_misses;
  u64 owner_cache_stores;
  u64 uid_blocked_packets;
  u64 uid_blocked_bytes;
  /* A2-5 POC-only per-session admission ledger.  These flags keep the
   * durable stage/key events one-to-one with the fresh tuple used by the
   * runner; they are not production counters. */
  u8 ledger_policy_logged;
  u8 ledger_admitted_logged;
  u8 pending_owner_policy_valid;
  u8 pending_owner_cache_enabled;
  u8 pending_block_owner_uid_set;
  i32 pending_block_owner_uid;
  u64 main_fd_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 shim_fd_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 rx_node_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 worker_probe_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 worker_redirect_thread_hits[TUN_POC_MAX_THREAD_HITS];
  u64 overflow_thread_hits;
  u32 last_main_fd_thread_index;
  u32 last_shim_fd_thread_index;
  u32 last_rx_node_thread_index;
  u32 last_worker_probe_thread_index;
  u32 last_worker_redirect_thread_index;
} tun_poc_main_t;

extern tun_poc_main_t tun_poc_main;

clib_error_t *tun_poc_enable (vlib_main_t *vm, int fd, tun_poc_mode_t mode,
			      int shim_fd, u8 block_ip4_dst_set,
			      u32 block_ip4_dst, u32 polling_thread_index);
void tun_poc_disable (void);
u8 *format_tun_poc_mode (u8 *s, va_list *args);

#endif /* included_tun_poc_h */
