/* SPDX-License-Identifier: Apache-2.0 */

#include <nfqueue_poc/nfqueue_poc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define NFQUEUE_POC_RX_BUF_SIZE 65536

nfqueue_poc_main_t nfqueue_poc_main = {
  .fd = -1,
};

u8 *
format_nfqueue_poc_mode (u8 *s, va_list *args)
{
  nfqueue_poc_mode_t mode = va_arg (*args, nfqueue_poc_mode_t);

  switch (mode)
    {
    case NFQUEUE_POC_MODE_ACCEPT_ALL:
      return format (s, "accept-all");
    case NFQUEUE_POC_MODE_DROP_ALL:
      return format (s, "drop-all");
    case NFQUEUE_POC_MODE_DROP_RATIO:
      return format (s, "drop-ratio");
    }

  return format (s, "unknown");
}

static u32
nfqueue_poc_choose_verdict (nfqueue_poc_main_t *nm)
{
  switch (nm->mode)
    {
    case NFQUEUE_POC_MODE_ACCEPT_ALL:
      return NF_ACCEPT;
    case NFQUEUE_POC_MODE_DROP_ALL:
      return NF_DROP;
    case NFQUEUE_POC_MODE_DROP_RATIO:
      if (nm->drop_ratio == 0)
	return NF_ACCEPT;
      if (nm->drop_ratio >= 100)
	return NF_DROP;
      return ((nm->seen * nm->drop_ratio) % 100) < nm->drop_ratio ?
	       NF_DROP :
	       NF_ACCEPT;
    }

  return NF_DROP;
}

static int
nfqueue_poc_packet_cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data)
{
  nfqueue_poc_main_t *nm = data;
  struct nfqnl_msg_packet_hdr *ph;
  u32 id = 0;
  u32 verdict;

  (void) nfmsg;

  nm->seen++;

  ph = nfq_get_msg_packet_hdr (nfa);
  if (ph)
    id = ntohl (ph->packet_id);
  else
    {
      nm->missing_id++;
      return 0;
    }

  verdict = nfqueue_poc_choose_verdict (nm);
  if (verdict == NF_ACCEPT)
    nm->accepted++;
  else
    nm->dropped++;

  return nfq_set_verdict (qh, id, verdict, 0, 0);
}

static clib_error_t *
nfqueue_poc_fd_read_ready (clib_file_t *f)
{
  nfqueue_poc_main_t *nm = (nfqueue_poc_main_t *) f->private_data;

  while (1)
    {
      int rv = recv (nm->fd, nm->rx_buf, NFQUEUE_POC_RX_BUF_SIZE,
		     MSG_DONTWAIT);
      if (rv >= 0)
	{
	  if (nfq_handle_packet (nm->handle, (char *) nm->rx_buf, rv) < 0)
	    nm->handle_errors++;
	  continue;
	}

      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return 0;

      if (errno == EINTR)
	continue;

      if (errno == ENOBUFS)
	{
	  nm->enobufs++;
	  continue;
	}

      nm->recv_errors++;
      return clib_error_return_unix (0, "nfqueue recv");
    }
}

static clib_error_t *
nfqueue_poc_configure_queue (struct nfq_q_handle *queue)
{
  if (nfq_set_mode (queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    return clib_error_return_unix (0, "nfq_set_mode NFQNL_COPY_PACKET");

  if (nfq_set_queue_maxlen (queue, 4096) < 0)
    return clib_error_return_unix (0, "nfq_set_queue_maxlen");

#ifdef NFQA_CFG_F_UID_GID
  if (nfq_set_queue_flags (queue, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID) < 0)
    clib_warning ("nfqueue_poc: kernel did not enable UID/GID attrs");
#endif

  return 0;
}

clib_error_t *
nfqueue_poc_enable (vlib_main_t *vm, u16 queue_num, nfqueue_poc_mode_t mode,
		    u32 drop_ratio, u8 unbind_existing)
{
  nfqueue_poc_main_t *nm = &nfqueue_poc_main;
  clib_file_t template = { 0 };
  clib_error_t *err = 0;
  int flags;

  (void) vm;

  if (nm->enabled)
    return clib_error_return (0, "nfqueue_poc already enabled on queue %u",
			      nm->queue_num);

  nm->handle = nfq_open ();
  if (!nm->handle)
    return clib_error_return_unix (0, "nfq_open");

  if (unbind_existing)
    (void) nfq_unbind_pf (nm->handle, AF_INET);

  if (nfq_bind_pf (nm->handle, AF_INET) < 0)
    {
      err = clib_error_return_unix (0, "nfq_bind_pf AF_INET");
      goto error;
    }

  nm->queue =
    nfq_create_queue (nm->handle, queue_num, nfqueue_poc_packet_cb, nm);
  if (!nm->queue)
    {
      err = clib_error_return_unix (0, "nfq_create_queue %u", queue_num);
      goto error;
    }

  err = nfqueue_poc_configure_queue (nm->queue);
  if (err)
    goto error;

  nm->fd = nfq_fd (nm->handle);
  flags = fcntl (nm->fd, F_GETFL, 0);
  if (flags < 0 || fcntl (nm->fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      err = clib_error_return_unix (0, "set nfqueue fd nonblocking");
      goto error;
    }

  nm->rx_buf = clib_mem_alloc_aligned (NFQUEUE_POC_RX_BUF_SIZE,
				       CLIB_CACHE_LINE_BYTES);
  if (!nm->rx_buf)
    {
      err = clib_error_return (0, "failed to allocate rx buffer");
      goto error;
    }

  nm->queue_num = queue_num;
  nm->mode = mode;
  nm->drop_ratio = drop_ratio;
  nm->unbind_existing = unbind_existing;
  nm->seen = 0;
  nm->accepted = 0;
  nm->dropped = 0;
  nm->missing_id = 0;
  nm->handle_errors = 0;
  nm->recv_errors = 0;
  nm->enobufs = 0;

  template.read_function = nfqueue_poc_fd_read_ready;
  template.file_descriptor = nm->fd;
  template.private_data = (uword) nm;
  template.description = format (0, "nfqueue-poc queue %u", queue_num);
  nm->file_index = clib_file_add (&file_main, &template);
  nm->enabled = 1;

  return 0;

error:
  nfqueue_poc_disable ();
  return err;
}

void
nfqueue_poc_disable (void)
{
  nfqueue_poc_main_t *nm = &nfqueue_poc_main;

  if (nm->enabled)
    {
      clib_file_del_by_index (&file_main, nm->file_index);
      nm->enabled = 0;
    }

  if (nm->queue)
    {
      nfq_destroy_queue (nm->queue);
      nm->queue = 0;
    }

  if (nm->handle)
    {
      nfq_close (nm->handle);
      nm->handle = 0;
    }

  if (nm->rx_buf)
    {
      clib_mem_free (nm->rx_buf);
      nm->rx_buf = 0;
    }

  nm->fd = -1;
  nm->file_index = ~0;
}

static clib_error_t *
nfqueue_poc_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  nfqueue_poc_mode_t mode = NFQUEUE_POC_MODE_ACCEPT_ALL;
  u32 queue_num = 42;
  u32 drop_ratio = 50;
  u8 unbind_existing = 0;

  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &queue_num))
	;
      else if (unformat (input, "mode accept-all"))
	mode = NFQUEUE_POC_MODE_ACCEPT_ALL;
      else if (unformat (input, "mode drop-all"))
	mode = NFQUEUE_POC_MODE_DROP_ALL;
      else if (unformat (input, "mode drop-ratio %u", &drop_ratio))
	mode = NFQUEUE_POC_MODE_DROP_RATIO;
      else if (unformat (input, "unbind-existing"))
	unbind_existing = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (queue_num > 65535)
    return clib_error_return (0, "queue must be 0..65535");
  if (drop_ratio > 100)
    return clib_error_return (0, "drop ratio must be 0..100");

  return nfqueue_poc_enable (vm, (u16) queue_num, mode, drop_ratio,
			     unbind_existing);
}

VLIB_CLI_COMMAND (nfqueue_poc_enable_command, static) = {
  .path = "nfqueue-poc enable",
  .short_help = "nfqueue-poc enable [queue <n>] "
		"[mode accept-all|drop-all|drop-ratio <n>] "
		"[unbind-existing]",
  .function = nfqueue_poc_enable_command_fn,
};

static clib_error_t *
nfqueue_poc_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;

  nfqueue_poc_disable ();
  return 0;
}

VLIB_CLI_COMMAND (nfqueue_poc_disable_command, static) = {
  .path = "nfqueue-poc disable",
  .short_help = "nfqueue-poc disable",
  .function = nfqueue_poc_disable_command_fn,
};

static clib_error_t *
nfqueue_poc_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  nfqueue_poc_main_t *nm = &nfqueue_poc_main;

  (void) input;
  (void) cmd;

  vlib_cli_output (vm, "enabled %u queue %u mode %U drop-ratio %u fd %d",
		   nm->enabled, nm->queue_num, format_nfqueue_poc_mode,
		   nm->mode, nm->drop_ratio, nm->fd);
  vlib_cli_output (vm, "seen %llu accept %llu drop %llu missing-id %llu",
		   nm->seen, nm->accepted, nm->dropped, nm->missing_id);
  vlib_cli_output (vm, "handle-errors %llu recv-errors %llu enobufs %llu",
		   nm->handle_errors, nm->recv_errors, nm->enobufs);
  return 0;
}

VLIB_CLI_COMMAND (nfqueue_poc_show_command, static) = {
  .path = "show nfqueue-poc",
  .short_help = "show nfqueue-poc",
  .function = nfqueue_poc_show_command_fn,
};
