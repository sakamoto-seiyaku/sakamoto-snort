/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_poc_h
#define included_nfqueue_poc_h

#include <vlib/vlib.h>
#include <vlib/file.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>

typedef enum
{
  NFQUEUE_POC_MODE_ACCEPT_ALL,
  NFQUEUE_POC_MODE_DROP_ALL,
  NFQUEUE_POC_MODE_DROP_RATIO,
  NFQUEUE_POC_MODE_BLOCK_IP6_DST,
  NFQUEUE_POC_MODE_BLOCK_UID,
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
} nfqueue_poc_main_t;

extern nfqueue_poc_main_t nfqueue_poc_main;

clib_error_t *nfqueue_poc_enable (vlib_main_t *vm, u16 queue_num,
				  nfqueue_poc_family_t family,
				  nfqueue_poc_mode_t mode, u32 drop_ratio,
				  u32 block_uid,
				  const u8 *block_ip6_dst,
				  const char *event_log_path,
				  u8 unbind_existing);
void nfqueue_poc_disable (void);
u8 *format_nfqueue_poc_mode (u8 *s, va_list *args);
u8 *format_nfqueue_poc_family (u8 *s, va_list *args);

#endif /* included_nfqueue_poc_h */
