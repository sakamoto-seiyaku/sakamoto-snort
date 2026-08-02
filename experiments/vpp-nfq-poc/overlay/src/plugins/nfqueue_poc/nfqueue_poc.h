/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_poc_h
#define included_nfqueue_poc_h

#include <vlib/vlib.h>
#include <vlib/file.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>

#define NFQUEUE_POC_ASYNC_LEASE_CAPACITY 64
#define NFQUEUE_POC_TWO_LANE_COUNT 2
#define NFQUEUE_POC_LANE_MATRIX_MAX 4

typedef enum
{
  NFQUEUE_POC_MODE_ACCEPT_ALL,
  NFQUEUE_POC_MODE_DROP_ALL,
  NFQUEUE_POC_MODE_DROP_RATIO,
  NFQUEUE_POC_MODE_BLOCK_IP6_DST,
  NFQUEUE_POC_MODE_ALLOW_UID,
  NFQUEUE_POC_MODE_BLOCK_UID,
  NFQUEUE_POC_MODE_ASYNC_LEASE,
  NFQUEUE_POC_MODE_TWO_LANE,
  NFQUEUE_POC_MODE_LANE_MATRIX,
} nfqueue_poc_mode_t;

typedef enum
{
  NFQUEUE_POC_FAMILY_IP4,
  NFQUEUE_POC_FAMILY_IP6,
} nfqueue_poc_family_t;

typedef struct
{
  u8 enabled;
  u8 unbind_existing;
  u16 queue_num;
  nfqueue_poc_mode_t mode;
  nfqueue_poc_family_t family;
  u32 drop_ratio;
  u32 block_uid;
  u32 queue_maxlen;
  u32 async_ingress_delay_ms;
  u8 two_lane_stale_fault;
  u8 two_lane_count;
  u8 two_lane_polling_contexts;
  u64 two_lane_seen[NFQUEUE_POC_LANE_MATRIX_MAX];
  u64 two_lane_accepted[NFQUEUE_POC_LANE_MATRIX_MAX];
  u64 two_lane_dropped[NFQUEUE_POC_LANE_MATRIX_MAX];
  u64 two_lane_owner_hits[NFQUEUE_POC_LANE_MATRIX_MAX];
  u64 two_lane_worker_hits[NFQUEUE_POC_LANE_MATRIX_MAX];
  u64 two_lane_stale_completions;
  u64 two_lane_out_of_order;
  u64 two_lane_verdict_errors;
  void *two_lane_state;
  u8 block_ip6_dst[16];
  u8 *event_log_path;
  FILE *event_log_file;

  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  int fd;
  u32 file_index;
  u8 *rx_buf;

  u64 seen;
  u64 accepted;
  u64 dropped;
  u64 missing_id;
  u64 handle_errors;
  u64 recv_errors;
  u64 enobufs;
  u64 payload_missing;
  u64 parse_errors;
  u64 rule_match;
  u64 rule_miss;
  u64 event_write_errors;
  u8 async_duplicate_fault;
  u8 async_stale_fault;
  u8 async_missing_fault;
  u8 async_shutdown_fault;
  u8 async_missing_id_fault;
  u32 async_delay_ms;
  u64 async_lane_generation;
  u64 async_ingress_leases;
  u64 async_worker_dispatches;
  u64 async_completion_intents;
  u64 async_terminal_outcomes;
  u64 async_duplicate_completions;
  u64 async_stale_completions;
  u64 async_missing_completions;
  u64 async_missing_id_verdicts;
  u64 async_deadline_drops;
  u64 async_shutdown_drops;
  u64 async_overload_drops;
  u64 async_worker_backpressure_drops;
  u64 async_verdict_errors;
  u32 async_last_verdict_errno;
  u64 async_pipe_errors;
  u64 async_out_of_order;
  u64 async_pending_peak;
  u32 async_completion_file_index;
  void *async_state;
} nfqueue_poc_main_t;

extern nfqueue_poc_main_t nfqueue_poc_main;

clib_error_t *nfqueue_poc_enable (vlib_main_t *vm, u16 queue_num,
				  nfqueue_poc_family_t family,
				  nfqueue_poc_mode_t mode, u32 drop_ratio,
				  u32 lane_count, u32 polling_contexts,
				  u32 queue_maxlen,
				  u32 async_ingress_delay_ms,
				  u32 block_uid,
				  const u8 *block_ip6_dst,
				  const char *event_log_path,
				  u8 unbind_existing,
				  u8 async_duplicate_fault,
				  u8 async_stale_fault,
				  u8 async_missing_fault,
				  u8 async_missing_id_fault,
				  u8 async_shutdown_fault,
				  u32 async_delay_ms);
void nfqueue_poc_disable (void);
u8 *format_nfqueue_poc_mode (u8 *s, va_list *args);
u8 *format_nfqueue_poc_family (u8 *s, va_list *args);

#endif /* included_nfqueue_poc_h */
