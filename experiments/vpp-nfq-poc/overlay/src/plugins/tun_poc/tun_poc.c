/* SPDX-License-Identifier: Apache-2.0 */

#include <tun_poc/tun_poc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>

#define TUN_POC_RX_BUF_SIZE 65536

typedef struct __attribute__ ((packed))
{
  u8 version_ihl;
  u8 tos;
  u16 total_length;
  u16 id;
  u16 frag_off;
  u8 ttl;
  u8 protocol;
  u16 checksum;
  u32 src;
  u32 dst;
} tun_poc_ip4_header_t;

typedef struct __attribute__ ((packed))
{
  u8 type;
  u8 code;
  u16 checksum;
  u16 ident;
  u16 sequence;
} tun_poc_icmp_header_t;

tun_poc_main_t tun_poc_main = {
  .fd = -1,
  .shim_fd = -1,
  .file_index = ~0,
  .shim_file_index = ~0,
};

u8 *
format_tun_poc_mode (u8 *s, va_list *args)
{
  tun_poc_mode_t mode = va_arg (*args, tun_poc_mode_t);

  switch (mode)
    {
    case TUN_POC_MODE_COUNT_ONLY:
      return format (s, "count-only");
    case TUN_POC_MODE_REFLECT_ICMP:
      return format (s, "reflect-icmp");
    case TUN_POC_MODE_FORWARD_FD:
      return format (s, "forward-fd");
    }

  return format (s, "unknown");
}

static clib_error_t *
tun_poc_set_nonblocking (int fd, const char *name)
{
  int flags;

  flags = fcntl (fd, F_GETFL, 0);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return clib_error_return_unix (0, "set %s nonblocking", name);

  return 0;
}

static int
tun_poc_write_packet (int fd, const u8 *packet, ssize_t packet_len,
		      u64 *packets, u64 *bytes, u64 *errors)
{
  ssize_t written;

  written = write (fd, packet, packet_len);
  if (written != packet_len)
    {
      (*errors)++;
      return -1;
    }

  (*packets)++;
  (*bytes) += packet_len;
  return 0;
}

static u16
tun_poc_checksum (const u8 *data, uword len)
{
  u32 sum = 0;

  while (len > 1)
    {
      sum += ((u16) data[0] << 8) | data[1];
      data += 2;
      len -= 2;
    }

  if (len)
    sum += ((u16) data[0] << 8);

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return htons ((u16) ~sum);
}

static void
tun_poc_reflect_icmp4 (tun_poc_main_t *tm, u8 *packet, ssize_t packet_len)
{
  tun_poc_ip4_header_t *ip4;
  tun_poc_icmp_header_t *icmp;
  uword ihl;
  uword total_len;
  u32 tmp_addr;

  if (packet_len < (ssize_t) (sizeof (*ip4) + sizeof (*icmp)))
    {
      tm->short_packets++;
      return;
    }

  ip4 = (tun_poc_ip4_header_t *) packet;
  if ((ip4->version_ihl >> 4) != 4)
    {
      tm->non_ipv4++;
      return;
    }

  ihl = (ip4->version_ihl & 0x0f) * 4;
  total_len = ntohs (ip4->total_length);
  if (ihl < sizeof (*ip4) || total_len < ihl + sizeof (*icmp) ||
      total_len > (uword) packet_len)
    {
      tm->parse_errors++;
      return;
    }

  if (ip4->protocol != IPPROTO_ICMP)
    {
      tm->non_icmp++;
      return;
    }

  icmp = (tun_poc_icmp_header_t *) (packet + ihl);
  if (icmp->type != 8 || icmp->code != 0)
    {
      tm->non_echo++;
      return;
    }

  icmp->type = 0;
  icmp->checksum = 0;
  icmp->checksum = tun_poc_checksum ((u8 *) icmp, total_len - ihl);

  tmp_addr = ip4->src;
  ip4->src = ip4->dst;
  ip4->dst = tmp_addr;
  ip4->ttl = 64;
  ip4->checksum = 0;
  ip4->checksum = tun_poc_checksum ((u8 *) ip4, ihl);

  (void) tun_poc_write_packet (tm->fd, packet, total_len, &tm->tx_packets,
			       &tm->tx_bytes, &tm->write_errors);
}

static clib_error_t *
tun_poc_main_fd_read_ready (clib_file_t *f)
{
  tun_poc_main_t *tm = (tun_poc_main_t *) f->private_data;

  while (1)
    {
      ssize_t rv = read (tm->fd, tm->rx_buf, TUN_POC_RX_BUF_SIZE);
      if (rv > 0)
	{
	  tm->rx_packets++;
	  tm->rx_bytes += rv;
	  if (tm->mode == TUN_POC_MODE_REFLECT_ICMP)
	    tun_poc_reflect_icmp4 (tm, tm->rx_buf, rv);
	  else if (tm->mode == TUN_POC_MODE_FORWARD_FD)
	    (void) tun_poc_write_packet (tm->shim_fd, tm->rx_buf, rv,
					 &tm->shim_tx_packets,
					 &tm->shim_tx_bytes,
					 &tm->shim_write_errors);
	  continue;
	}

      if (rv == 0)
	return clib_error_return (0, "tun fd closed");

      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return 0;

      if (errno == EINTR)
	continue;

      tm->read_errors++;
      return clib_error_return_unix (0, "tun read");
    }
}

static clib_error_t *
tun_poc_shim_fd_read_ready (clib_file_t *f)
{
  tun_poc_main_t *tm = &tun_poc_main;

  (void) f;

  while (1)
    {
      ssize_t rv = read (tm->shim_fd, tm->rx_buf, TUN_POC_RX_BUF_SIZE);
      if (rv > 0)
	{
	  tm->shim_rx_packets++;
	  tm->shim_rx_bytes += rv;
	  (void) tun_poc_write_packet (tm->fd, tm->rx_buf, rv,
				       &tm->tx_packets, &tm->tx_bytes,
				       &tm->write_errors);
	  continue;
	}

      if (rv == 0)
	return clib_error_return (0, "tun shim fd closed");

      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return 0;

      if (errno == EINTR)
	continue;

      tm->shim_read_errors++;
      return clib_error_return_unix (0, "tun shim read");
    }
}

clib_error_t *
tun_poc_enable (vlib_main_t *vm, int fd, tun_poc_mode_t mode, int shim_fd)
{
  tun_poc_main_t *tm = &tun_poc_main;
  clib_file_t template = { 0 };
  clib_error_t *err;

  (void) vm;

  if (tm->enabled)
    return clib_error_return (0, "tun_poc already enabled on fd %d", tm->fd);
  if (fd < 0)
    return clib_error_return (0, "fd must be non-negative");
  if (mode == TUN_POC_MODE_FORWARD_FD && shim_fd < 0)
    return clib_error_return (0, "forward-fd mode requires shim-fd");
  if (mode == TUN_POC_MODE_FORWARD_FD && shim_fd == fd)
    return clib_error_return (0, "shim-fd must differ from fd");

  err = tun_poc_set_nonblocking (fd, "tun fd");
  if (err)
    return err;

  if (mode == TUN_POC_MODE_FORWARD_FD)
    {
      err = tun_poc_set_nonblocking (shim_fd, "tun shim fd");
      if (err)
	return err;
    }

  tm->rx_buf =
    clib_mem_alloc_aligned (TUN_POC_RX_BUF_SIZE, CLIB_CACHE_LINE_BYTES);
  if (!tm->rx_buf)
    return clib_error_return (0, "failed to allocate rx buffer");

  tm->fd = fd;
  tm->shim_fd = shim_fd;
  tm->mode = mode;
  tm->rx_packets = 0;
  tm->rx_bytes = 0;
  tm->tx_packets = 0;
  tm->tx_bytes = 0;
  tm->shim_rx_packets = 0;
  tm->shim_rx_bytes = 0;
  tm->shim_tx_packets = 0;
  tm->shim_tx_bytes = 0;
  tm->short_packets = 0;
  tm->non_ipv4 = 0;
  tm->non_icmp = 0;
  tm->non_echo = 0;
  tm->parse_errors = 0;
  tm->read_errors = 0;
  tm->write_errors = 0;
  tm->shim_read_errors = 0;
  tm->shim_write_errors = 0;

  template.read_function = tun_poc_main_fd_read_ready;
  template.file_descriptor = tm->fd;
  template.private_data = (uword) tm;
  template.description = format (0, "tun-poc fd %d", fd);
  tm->file_index = clib_file_add (&file_main, &template);

  if (mode == TUN_POC_MODE_FORWARD_FD)
    {
      clib_memset (&template, 0, sizeof (template));
      template.read_function = tun_poc_shim_fd_read_ready;
      template.file_descriptor = tm->shim_fd;
      template.private_data = (uword) tm;
      template.description = format (0, "tun-poc shim fd %d", shim_fd);
      tm->shim_file_index = clib_file_add (&file_main, &template);
    }

  tm->enabled = 1;

  return 0;
}

void
tun_poc_disable (void)
{
  tun_poc_main_t *tm = &tun_poc_main;

  if (tm->enabled)
    {
      clib_file_del_by_index (&file_main, tm->file_index);
      if (tm->shim_file_index != ~0)
	clib_file_del_by_index (&file_main, tm->shim_file_index);
      tm->enabled = 0;
    }

  if (tm->rx_buf)
    {
      clib_mem_free (tm->rx_buf);
      tm->rx_buf = 0;
    }

  tm->fd = -1;
  tm->shim_fd = -1;
  tm->file_index = ~0;
  tm->shim_file_index = ~0;
}

static clib_error_t *
tun_poc_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  tun_poc_mode_t mode = TUN_POC_MODE_REFLECT_ICMP;
  int fd = -1;
  int shim_fd = -1;

  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fd %d", &fd))
	;
      else if (unformat (input, "shim-fd %d", &shim_fd))
	;
      else if (unformat (input, "mode count-only"))
	mode = TUN_POC_MODE_COUNT_ONLY;
      else if (unformat (input, "mode reflect-icmp"))
	mode = TUN_POC_MODE_REFLECT_ICMP;
      else if (unformat (input, "mode forward-fd"))
	mode = TUN_POC_MODE_FORWARD_FD;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  return tun_poc_enable (vm, fd, mode, shim_fd);
}

VLIB_CLI_COMMAND (tun_poc_enable_command, static) = {
  .path = "tun-poc enable",
  .short_help =
    "tun-poc enable fd <n> [mode count-only|reflect-icmp|forward-fd] "
    "[shim-fd <n>]",
  .function = tun_poc_enable_command_fn,
};

static clib_error_t *
tun_poc_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;

  tun_poc_disable ();
  return 0;
}

VLIB_CLI_COMMAND (tun_poc_disable_command, static) = {
  .path = "tun-poc disable",
  .short_help = "tun-poc disable",
  .function = tun_poc_disable_command_fn,
};

static clib_error_t *
tun_poc_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  tun_poc_main_t *tm = &tun_poc_main;

  (void) input;
  (void) cmd;

  vlib_cli_output (vm, "enabled %u fd %d shim-fd %d mode %U", tm->enabled,
		   tm->fd, tm->shim_fd, format_tun_poc_mode, tm->mode);
  vlib_cli_output (vm, "rx %llu bytes %llu tx %llu bytes %llu",
		   tm->rx_packets, tm->rx_bytes, tm->tx_packets, tm->tx_bytes);
  vlib_cli_output (vm,
		   "shim-rx %llu bytes %llu shim-tx %llu bytes %llu",
		   tm->shim_rx_packets, tm->shim_rx_bytes,
		   tm->shim_tx_packets, tm->shim_tx_bytes);
  vlib_cli_output (vm,
		   "short %llu non-ipv4 %llu non-icmp %llu non-echo %llu",
		   tm->short_packets, tm->non_ipv4, tm->non_icmp,
		   tm->non_echo);
  vlib_cli_output (
    vm,
    "parse-errors %llu read-errors %llu write-errors %llu "
    "shim-read-errors %llu shim-write-errors %llu",
    tm->parse_errors, tm->read_errors, tm->write_errors,
    tm->shim_read_errors, tm->shim_write_errors);
  return 0;
}

VLIB_CLI_COMMAND (tun_poc_show_command, static) = {
  .path = "show tun-poc",
  .short_help = "show tun-poc",
  .function = tun_poc_show_command_fn,
};
