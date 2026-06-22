/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_tun_poc_h
#define included_tun_poc_h

#include <vlib/vlib.h>
#include <vlib/file.h>

typedef enum
{
  TUN_POC_MODE_COUNT_ONLY,
  TUN_POC_MODE_REFLECT_ICMP,
  TUN_POC_MODE_FORWARD_FD,
} tun_poc_mode_t;

typedef struct
{
  u8 enabled;
  tun_poc_mode_t mode;
  int fd;
  int shim_fd;
  u32 file_index;
  u32 shim_file_index;
  u8 *rx_buf;

  u64 rx_packets;
  u64 rx_bytes;
  u64 tx_packets;
  u64 tx_bytes;
  u64 shim_rx_packets;
  u64 shim_rx_bytes;
  u64 shim_tx_packets;
  u64 shim_tx_bytes;
  u64 short_packets;
  u64 non_ipv4;
  u64 non_icmp;
  u64 non_echo;
  u64 parse_errors;
  u64 read_errors;
  u64 write_errors;
  u64 shim_read_errors;
  u64 shim_write_errors;
} tun_poc_main_t;

extern tun_poc_main_t tun_poc_main;

clib_error_t *tun_poc_enable (vlib_main_t *vm, int fd,
			      tun_poc_mode_t mode, int shim_fd);
void tun_poc_disable (void);
u8 *format_tun_poc_mode (u8 *s, va_list *args);

#endif /* included_tun_poc_h */
