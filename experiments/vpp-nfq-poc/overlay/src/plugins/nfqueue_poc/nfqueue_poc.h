/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_poc_h
#define included_nfqueue_poc_h

#include <vlib/vlib.h>
#include <vlib/file.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

typedef enum
{
  NFQUEUE_POC_MODE_ACCEPT_ALL,
  NFQUEUE_POC_MODE_DROP_ALL,
  NFQUEUE_POC_MODE_DROP_RATIO,
} nfqueue_poc_mode_t;

typedef struct
{
  u8 enabled;
  u8 unbind_existing;
  u16 queue_num;
  nfqueue_poc_mode_t mode;
  u32 drop_ratio;

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
} nfqueue_poc_main_t;

extern nfqueue_poc_main_t nfqueue_poc_main;

clib_error_t *nfqueue_poc_enable (vlib_main_t *vm, u16 queue_num,
				  nfqueue_poc_mode_t mode, u32 drop_ratio,
				  u8 unbind_existing);
void nfqueue_poc_disable (void);
u8 *format_nfqueue_poc_mode (u8 *s, va_list *args);

#endif /* included_nfqueue_poc_h */
