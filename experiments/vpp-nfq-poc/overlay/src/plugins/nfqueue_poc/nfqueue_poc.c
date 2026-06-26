/* SPDX-License-Identifier: Apache-2.0 */

#include <nfqueue_poc/nfqueue_poc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
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
    case NFQUEUE_POC_MODE_BLOCK_IP6_DST:
      return format (s, "block-ip6-dst");
    case NFQUEUE_POC_MODE_ALLOW_UID:
      return format (s, "allow-uid");
    case NFQUEUE_POC_MODE_BLOCK_UID:
      return format (s, "block-uid");
    }

  return format (s, "unknown");
}

u8 *
format_nfqueue_poc_family (u8 *s, va_list *args)
{
  nfqueue_poc_family_t family = va_arg (*args, nfqueue_poc_family_t);

  switch (family)
    {
    case NFQUEUE_POC_FAMILY_IP4:
      return format (s, "ip4");
    case NFQUEUE_POC_FAMILY_IP6:
      return format (s, "ip6");
    }

  return format (s, "unknown");
}

static int
nfqueue_poc_address_family (nfqueue_poc_family_t family)
{
  return family == NFQUEUE_POC_FAMILY_IP6 ? AF_INET6 : AF_INET;
}

typedef struct
{
  int payload_len;
  u8 ip_version;
  u8 proto;
  u8 uid_known;
  u32 uid;
  u8 dst_valid;
  u8 dst[16];
} nfqueue_poc_packet_facts_t;

static void
nfqueue_poc_collect_facts (struct nfq_data *nfa,
			   nfqueue_poc_packet_facts_t *facts)
{
  unsigned char *payload = 0;

  clib_memset (facts, 0, sizeof (*facts));
  facts->payload_len = nfq_get_payload (nfa, &payload);
  if (nfq_get_uid (nfa, &facts->uid))
    facts->uid_known = 1;

  if (facts->payload_len < 1 || !payload)
    return;

  facts->ip_version = payload[0] >> 4;
  if (facts->ip_version == 4 && facts->payload_len >= 20)
    {
      facts->proto = payload[9];
      clib_memcpy (facts->dst, payload + 16, 4);
      facts->dst_valid = 1;
    }
  else if (facts->ip_version == 6 && facts->payload_len >= 40)
    {
      facts->proto = payload[6];
      clib_memcpy (facts->dst, payload + 24, 16);
      facts->dst_valid = 1;
    }
}

static const char *
nfqueue_poc_family_name (const nfqueue_poc_packet_facts_t *facts)
{
  if (facts->ip_version == 4)
    return "ipv4";
  if (facts->ip_version == 6)
    return "ipv6";
  return "unknown";
}

static void
nfqueue_poc_format_dst (const nfqueue_poc_packet_facts_t *facts, char *buf,
			size_t len)
{
  int af;

  buf[0] = 0;
  if (!facts->dst_valid)
    return;

  af = facts->ip_version == 6 ? AF_INET6 : AF_INET;
  if (!inet_ntop (af, facts->dst, buf, len))
    buf[0] = 0;
}

static void
nfqueue_poc_write_event (nfqueue_poc_main_t *nm, u32 id,
			 const nfqueue_poc_packet_facts_t *facts,
			 u32 verdict, const char *reason,
			 const char *rule_id)
{
  char dst[INET6_ADDRSTRLEN];
  int rv;

  if (!nm->event_log_file)
    return;

  nfqueue_poc_format_dst (facts, dst, sizeof (dst));

  rv = fprintf (nm->event_log_file,
		"{\"type\":\"packet\",\"mode\":\"nfq\",\"queue\":%u,"
		"\"packetId\":%u,\"family\":\"%s\",\"proto\":%u,"
		"\"payloadLen\":%d,\"uidKnown\":%s,",
		nm->queue_num, id, nfqueue_poc_family_name (facts),
		facts->proto, facts->payload_len,
		facts->uid_known ? "true" : "false");
  if (rv < 0)
    {
      nm->event_write_errors++;
      return;
    }

  if (facts->uid_known)
    rv = fprintf (nm->event_log_file, "\"uid\":%u,", facts->uid);
  else
    rv = fprintf (nm->event_log_file, "\"uid\":null,");
  if (rv < 0)
    {
      nm->event_write_errors++;
      return;
    }

  if (dst[0])
    rv = fprintf (nm->event_log_file, "\"dstIp\":\"%s\",", dst);
  else
    rv = fprintf (nm->event_log_file, "\"dstIp\":null,");
  if (rv < 0)
    {
      nm->event_write_errors++;
      return;
    }

  rv = fprintf (nm->event_log_file,
		"\"verdict\":\"%s\",\"reason\":\"%s\",\"ruleId\":",
		verdict == NF_ACCEPT ? "allow" : "block", reason);
  if (rv < 0)
    {
      nm->event_write_errors++;
      return;
    }

  if (rule_id)
    rv = fprintf (nm->event_log_file, "\"%s\"}\n", rule_id);
  else
    rv = fprintf (nm->event_log_file, "null}\n");
  if (rv < 0 || fflush (nm->event_log_file) != 0)
    nm->event_write_errors++;
}

static u32
nfqueue_poc_block_ip6_dst_verdict (
  nfqueue_poc_main_t *nm, const nfqueue_poc_packet_facts_t *facts,
  const char **reason, const char **rule_id)
{
  if (facts->payload_len < 0)
    {
      nm->payload_missing++;
      nm->rule_miss++;
      *reason = "default_allow_no_payload";
      return NF_ACCEPT;
    }

  if (facts->ip_version != 6 || !facts->dst_valid)
    {
      nm->parse_errors++;
      nm->rule_miss++;
      *reason = "default_allow_parse_error";
      return NF_ACCEPT;
    }

  if (memcmp (facts->dst, nm->block_ip6_dst, 16) == 0)
    {
      nm->rule_match++;
      *reason = "exact_ip6_dst";
      *rule_id = "block-ip6-dst";
      return NF_DROP;
    }

  nm->rule_miss++;
  *reason = "default_allow";
  return NF_ACCEPT;
}

static u32
nfqueue_poc_choose_verdict (nfqueue_poc_main_t *nm,
			    const nfqueue_poc_packet_facts_t *facts,
			    const char **reason, const char **rule_id)
{
  *rule_id = 0;

  switch (nm->mode)
    {
    case NFQUEUE_POC_MODE_ACCEPT_ALL:
      *reason = "mode_accept_all";
      return NF_ACCEPT;
    case NFQUEUE_POC_MODE_DROP_ALL:
      *reason = "mode_drop_all";
      return NF_DROP;
    case NFQUEUE_POC_MODE_DROP_RATIO:
      if (nm->drop_ratio == 0)
	{
	  *reason = "mode_drop_ratio_allow";
	  return NF_ACCEPT;
	}
      if (nm->drop_ratio >= 100)
	{
	  *reason = "mode_drop_ratio_drop";
	  return NF_DROP;
	}
      if (((nm->seen * nm->drop_ratio) % 100) < nm->drop_ratio)
	{
	  *reason = "mode_drop_ratio_drop";
	  return NF_DROP;
	}
      *reason = "mode_drop_ratio_allow";
      return NF_ACCEPT;
    case NFQUEUE_POC_MODE_BLOCK_IP6_DST:
      return nfqueue_poc_block_ip6_dst_verdict (nm, facts, reason, rule_id);
    case NFQUEUE_POC_MODE_ALLOW_UID:
      if (facts->uid_known && facts->uid == nm->block_uid)
	{
	  nm->rule_match++;
	  *reason = "uid_allow";
	  *rule_id = "allow-uid";
	  return NF_ACCEPT;
	}
      nm->rule_miss++;
      *reason = facts->uid_known ? "default_allow_uid_miss" :
				   "default_allow_uid_unknown";
      return NF_ACCEPT;
    case NFQUEUE_POC_MODE_BLOCK_UID:
      if (facts->uid_known && facts->uid == nm->block_uid)
	{
	  nm->rule_match++;
	  *reason = "uid_block";
	  *rule_id = "block-uid";
	  return NF_DROP;
	}
      nm->rule_miss++;
      *reason = facts->uid_known ? "default_allow_uid_miss" :
				   "default_allow_uid_unknown";
      return NF_ACCEPT;
    }

  *reason = "unknown_mode_drop";
  return NF_DROP;
}

static int
nfqueue_poc_packet_cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data)
{
  nfqueue_poc_main_t *nm = data;
  struct nfqnl_msg_packet_hdr *ph;
  nfqueue_poc_packet_facts_t facts;
  const char *reason = "unknown";
  const char *rule_id = 0;
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

  nfqueue_poc_collect_facts (nfa, &facts);
  verdict = nfqueue_poc_choose_verdict (nm, &facts, &reason, &rule_id);
  if (verdict == NF_ACCEPT)
    nm->accepted++;
  else
    nm->dropped++;

  nfqueue_poc_write_event (nm, id, &facts, verdict, reason, rule_id);

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
nfqueue_poc_enable (vlib_main_t *vm, u16 queue_num,
		    nfqueue_poc_family_t family, nfqueue_poc_mode_t mode,
		    u32 drop_ratio, u32 block_uid, const u8 *block_ip6_dst,
		    const char *event_log_path, u8 unbind_existing)
{
  nfqueue_poc_main_t *nm = &nfqueue_poc_main;
  clib_file_t template = { 0 };
  clib_error_t *err = 0;
  int af = nfqueue_poc_address_family (family);
  int flags;

  (void) vm;

  if (nm->enabled)
    return clib_error_return (0, "nfqueue_poc already enabled on queue %u",
			      nm->queue_num);

  nm->handle = nfq_open ();
  if (!nm->handle)
    return clib_error_return_unix (0, "nfq_open");

  if (unbind_existing)
    (void) nfq_unbind_pf (nm->handle, af);

  if (nfq_bind_pf (nm->handle, af) < 0)
    {
      err = clib_error_return_unix (
	0, "nfq_bind_pf %U", format_nfqueue_poc_family, family);
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

  if (event_log_path)
    {
      nm->event_log_file = fopen (event_log_path, "w");
      if (!nm->event_log_file)
	{
	  err = clib_error_return_unix (0, "open event log %s",
					event_log_path);
	  goto error;
	}
      nm->event_log_path = format (0, "%s%c", event_log_path, 0);
    }

  nm->queue_num = queue_num;
  nm->mode = mode;
  nm->family = family;
  nm->drop_ratio = drop_ratio;
  nm->block_uid = block_uid;
  if (block_ip6_dst)
    clib_memcpy (nm->block_ip6_dst, block_ip6_dst, sizeof (nm->block_ip6_dst));
  else
    clib_memset (nm->block_ip6_dst, 0, sizeof (nm->block_ip6_dst));
  nm->unbind_existing = unbind_existing;
  nm->seen = 0;
  nm->accepted = 0;
  nm->dropped = 0;
  nm->missing_id = 0;
  nm->handle_errors = 0;
  nm->recv_errors = 0;
  nm->enobufs = 0;
  nm->payload_missing = 0;
  nm->parse_errors = 0;
  nm->rule_match = 0;
  nm->rule_miss = 0;
  nm->event_write_errors = 0;

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

  if (nm->event_log_file)
    {
      fclose (nm->event_log_file);
      nm->event_log_file = 0;
    }

  if (nm->event_log_path)
    {
      vec_free (nm->event_log_path);
      nm->event_log_path = 0;
    }

  nm->fd = -1;
  nm->file_index = ~0;
}

static clib_error_t *
nfqueue_poc_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  clib_error_t *err;
  nfqueue_poc_mode_t mode = NFQUEUE_POC_MODE_ACCEPT_ALL;
  nfqueue_poc_family_t family = NFQUEUE_POC_FAMILY_IP4;
  u32 queue_num = 42;
  u32 drop_ratio = 50;
  u32 block_uid = 0;
  u8 unbind_existing = 0;
  u8 *block_ip6_dst_text = 0;
  u8 *event_log_path = 0;
  u8 block_ip6_dst[16] = { 0 };
  u8 block_ip6_dst_set = 0;

  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &queue_num))
	;
      else if (unformat (input, "family ip4") ||
	       unformat (input, "family ipv4"))
	family = NFQUEUE_POC_FAMILY_IP4;
      else if (unformat (input, "family ip6") ||
	       unformat (input, "family ipv6"))
	family = NFQUEUE_POC_FAMILY_IP6;
      else if (unformat (input, "mode accept-all"))
	mode = NFQUEUE_POC_MODE_ACCEPT_ALL;
      else if (unformat (input, "mode drop-all"))
	mode = NFQUEUE_POC_MODE_DROP_ALL;
      else if (unformat (input, "mode drop-ratio %u", &drop_ratio))
	mode = NFQUEUE_POC_MODE_DROP_RATIO;
      else if (unformat (input, "mode block-ip6-dst %s",
			 &block_ip6_dst_text))
	{
	  if (inet_pton (AF_INET6, (char *) block_ip6_dst_text,
			 block_ip6_dst) != 1)
	    {
	      vec_free (block_ip6_dst_text);
	      return clib_error_return (0, "invalid IPv6 address");
	    }
	  vec_free (block_ip6_dst_text);
	  block_ip6_dst_text = 0;
	  family = NFQUEUE_POC_FAMILY_IP6;
	  mode = NFQUEUE_POC_MODE_BLOCK_IP6_DST;
	  block_ip6_dst_set = 1;
	}
      else if (unformat (input, "mode block-uid %u", &block_uid))
	mode = NFQUEUE_POC_MODE_BLOCK_UID;
      else if (unformat (input, "mode allow-uid %u", &block_uid))
	mode = NFQUEUE_POC_MODE_ALLOW_UID;
      else if (unformat (input, "unbind-existing"))
	unbind_existing = 1;
      else if (unformat (input, "event-log %s", &event_log_path))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (queue_num > 65535)
    return clib_error_return (0, "queue must be 0..65535");
  if (drop_ratio > 100)
    return clib_error_return (0, "drop ratio must be 0..100");
  if (mode == NFQUEUE_POC_MODE_BLOCK_IP6_DST && !block_ip6_dst_set)
    return clib_error_return (0, "block-ip6-dst requires an IPv6 address");

  err = nfqueue_poc_enable (
    vm, (u16) queue_num, family, mode, drop_ratio, block_uid,
    block_ip6_dst_set ? block_ip6_dst : 0, (char *) event_log_path,
    unbind_existing);
  vec_free (event_log_path);
  return err;
}

VLIB_CLI_COMMAND (nfqueue_poc_enable_command, static) = {
  .path = "nfqueue-poc enable",
  .short_help = "nfqueue-poc enable [queue <n>] "
		"[family ip4|ip6] "
		"[mode accept-all|drop-all|drop-ratio <n>|"
		"block-ip6-dst <addr>|allow-uid <uid>|block-uid <uid>] "
		"[event-log <path>] "
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

  vlib_cli_output (
    vm, "enabled %u queue %u family %U mode %U drop-ratio %u block-uid %u fd %d",
    nm->enabled, nm->queue_num, format_nfqueue_poc_family, nm->family,
    format_nfqueue_poc_mode, nm->mode, nm->drop_ratio, nm->block_uid, nm->fd);
  vlib_cli_output (vm, "seen %llu accept %llu drop %llu missing-id %llu",
		   nm->seen, nm->accepted, nm->dropped, nm->missing_id);
  vlib_cli_output (vm, "handle-errors %llu recv-errors %llu enobufs %llu",
		   nm->handle_errors, nm->recv_errors, nm->enobufs);
  vlib_cli_output (
    vm, "payload-missing %llu parse-errors %llu rule-match %llu rule-miss %llu",
    nm->payload_missing, nm->parse_errors, nm->rule_match, nm->rule_miss);
  vlib_cli_output (vm, "event-log %s event-write-errors %llu",
		   nm->event_log_path ? (char *) nm->event_log_path : "-",
		   nm->event_write_errors);
  return 0;
}

VLIB_CLI_COMMAND (nfqueue_poc_show_command, static) = {
  .path = "show nfqueue-poc",
  .short_help = "show nfqueue-poc",
  .function = nfqueue_poc_show_command_fn,
};
