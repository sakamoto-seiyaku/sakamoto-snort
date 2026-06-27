/* SPDX-License-Identifier: Apache-2.0 */

#include <tun_poc/tun_poc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vlib/buffer_node.h>
#include <vlib/threads.h>

#define TUN_POC_RX_BUF_SIZE 65536
#define TUN_POC_HANDOFF_BURST 32

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

typedef struct __attribute__ ((packed))
{
  u16 src_port;
  u16 dst_port;
} tun_poc_l4_ports_t;

tun_poc_main_t tun_poc_main = {
  .fd = -1,
  .shim_fd = -1,
  .resolver_fd = -1,
  .file_index = ~0,
  .shim_file_index = ~0,
  .handoff_frame_queue_index = ~0,
  .handoff_target_thread = ~0,
  .redirect_frame_queue_index = ~0,
  .redirect_target_thread = ~0,
};

extern vlib_node_registration_t tun_poc_rx_handoff_node;
extern vlib_node_registration_t tun_poc_worker_probe_node;
extern vlib_node_registration_t tun_poc_worker_redirect_node;

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
    case TUN_POC_MODE_HANDOFF_PROBE:
      return format (s, "handoff-probe");
    case TUN_POC_MODE_HANDOFF_FORWARD_FD:
      return format (s, "handoff-forward-fd");
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

static void
tun_poc_note_thread_hit (u64 *hits, u32 *last_thread_index, u64 *overflow)
{
  u32 thread_index = vlib_get_thread_index ();

  *last_thread_index = thread_index;
  if (thread_index < TUN_POC_MAX_THREAD_HITS)
    hits[thread_index]++;
  else
    (*overflow)++;
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

static u8
tun_poc_should_block_static_dst (tun_poc_main_t *tm, const u8 *packet,
				 ssize_t packet_len)
{
  const tun_poc_ip4_header_t *ip4;
  uword ihl;
  uword total_len;
  u8 version;

  if (!tm->block_ip4_dst_set && !tm->block_ip6_dst_set)
    return 0;

  if (packet_len < 1)
    {
      tm->short_packets++;
      return 0;
    }

  version = packet[0] >> 4;
  if (version == 6 && tm->block_ip6_dst_set)
    {
      if (packet_len < 40)
	{
	  tm->short_packets++;
	  return 0;
	}
      return memcmp (packet + 24, tm->block_ip6_dst, 16) == 0;
    }

  if (version != 4 || !tm->block_ip4_dst_set)
    return 0;

  if (packet_len < (ssize_t) sizeof (*ip4))
    {
      tm->short_packets++;
      return 0;
    }
  ip4 = (const tun_poc_ip4_header_t *) packet;

  ihl = (ip4->version_ihl & 0x0f) * 4;
  total_len = ntohs (ip4->total_length);
  if (ihl < sizeof (*ip4) || total_len < ihl ||
      total_len > (uword) packet_len)
    {
      tm->parse_errors++;
      return 0;
    }

  return ip4->dst == tm->block_ip4_dst;
}

static void
tun_poc_record_l4_tuple (tun_poc_main_t *tm, const u8 *packet,
			 ssize_t packet_len)
{
  const tun_poc_ip4_header_t *ip4;
  const tun_poc_l4_ports_t *ports;
  uword l4_offset;
  uword total_len;
  u8 version;
  u8 protocol;

  if (packet_len < 1)
    {
      tm->tuple_parse_errors++;
      return;
    }

  version = packet[0] >> 4;
  if (version == 4)
    {
      if (packet_len < (ssize_t) sizeof (*ip4))
	{
	  tm->tuple_parse_errors++;
	  return;
	}

      ip4 = (const tun_poc_ip4_header_t *) packet;
      l4_offset = (ip4->version_ihl & 0x0f) * 4;
      total_len = ntohs (ip4->total_length);
      protocol = ip4->protocol;
      if (l4_offset < sizeof (*ip4) ||
	  total_len < l4_offset + sizeof (*ports) ||
	  total_len > (uword) packet_len)
	{
	  tm->tuple_parse_errors++;
	  return;
	}

      if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
	{
	  tm->tuple_non_tcp_udp++;
	  return;
	}

      ports = (const tun_poc_l4_ports_t *) (packet + l4_offset);
      tm->last_tuple_valid = 1;
      tm->last_tuple_ip_version = 4;
      tm->last_tuple_protocol = protocol;
      tm->last_tuple_src_port = ntohs (ports->src_port);
      tm->last_tuple_dst_port = ntohs (ports->dst_port);
      tm->last_tuple_ip4_src = ip4->src;
      tm->last_tuple_ip4_dst = ip4->dst;
      tm->tuple_parsed_packets++;
      return;
    }

  if (version == 6)
    {
      if (packet_len < 40 + (ssize_t) sizeof (*ports))
	{
	  tm->tuple_parse_errors++;
	  return;
	}

      protocol = packet[6];
      if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
	{
	  tm->tuple_non_tcp_udp++;
	  return;
	}

      ports = (const tun_poc_l4_ports_t *) (packet + 40);
      tm->last_tuple_valid = 1;
      tm->last_tuple_ip_version = 6;
      tm->last_tuple_protocol = protocol;
      tm->last_tuple_src_port = ntohs (ports->src_port);
      tm->last_tuple_dst_port = ntohs (ports->dst_port);
      clib_memcpy (tm->last_tuple_ip6_src, packet + 8,
		   sizeof (tm->last_tuple_ip6_src));
      clib_memcpy (tm->last_tuple_ip6_dst, packet + 24,
		   sizeof (tm->last_tuple_ip6_dst));
      tm->tuple_parsed_packets++;
      return;
    }

  tm->tuple_parse_errors++;
}

static u8
tun_poc_owner_cache_lookup (tun_poc_main_t *tm)
{
  if (!tm->owner_cache_enabled || !tm->owner_cache_valid ||
      !tm->last_tuple_valid)
    return 0;

  if (tm->owner_cache_ip_version != tm->last_tuple_ip_version ||
      tm->owner_cache_protocol != tm->last_tuple_protocol ||
      tm->owner_cache_src_port != tm->last_tuple_src_port ||
      tm->owner_cache_dst_port != tm->last_tuple_dst_port)
    return 0;

  if (tm->last_tuple_ip_version == 4)
    {
      if (tm->owner_cache_ip4_src != tm->last_tuple_ip4_src ||
	  tm->owner_cache_ip4_dst != tm->last_tuple_ip4_dst)
	return 0;
    }
  else if (tm->last_tuple_ip_version == 6)
    {
      if (memcmp (tm->owner_cache_ip6_src, tm->last_tuple_ip6_src,
		  sizeof (tm->owner_cache_ip6_src)) ||
	  memcmp (tm->owner_cache_ip6_dst, tm->last_tuple_ip6_dst,
		  sizeof (tm->owner_cache_ip6_dst)))
	return 0;
    }
  else
    return 0;

  tm->last_owner_uid = tm->owner_cache_uid;
  tm->owner_cache_hits++;
  return 1;
}

static void
tun_poc_owner_cache_store (tun_poc_main_t *tm, i32 uid)
{
  if (!tm->owner_cache_enabled || !tm->last_tuple_valid || uid < 0)
    return;

  tm->owner_cache_valid = 1;
  tm->owner_cache_ip_version = tm->last_tuple_ip_version;
  tm->owner_cache_protocol = tm->last_tuple_protocol;
  tm->owner_cache_src_port = tm->last_tuple_src_port;
  tm->owner_cache_dst_port = tm->last_tuple_dst_port;
  tm->owner_cache_ip4_src = tm->last_tuple_ip4_src;
  tm->owner_cache_ip4_dst = tm->last_tuple_ip4_dst;
  clib_memcpy (tm->owner_cache_ip6_src, tm->last_tuple_ip6_src,
	       sizeof (tm->owner_cache_ip6_src));
  clib_memcpy (tm->owner_cache_ip6_dst, tm->last_tuple_ip6_dst,
	       sizeof (tm->owner_cache_ip6_dst));
  tm->owner_cache_uid = uid;
  tm->owner_cache_stores++;
}

static void
tun_poc_query_owner_resolver (tun_poc_main_t *tm)
{
  char src[INET6_ADDRSTRLEN] = { 0 };
  char dst[INET6_ADDRSTRLEN] = { 0 };
  char query[256];
  char response[64];
  struct pollfd pfd = { 0 };
  int query_len;
  int uid;
  ssize_t rv;

  if (!tm->resolver_enabled || tm->resolver_fd < 0 || !tm->last_tuple_valid)
    return;

  if (tm->owner_cache_enabled)
    {
      if (tun_poc_owner_cache_lookup (tm))
	return;
      tm->owner_cache_misses++;
    }

  if (tm->last_tuple_ip_version == 4)
    {
      if (!inet_ntop (AF_INET, &tm->last_tuple_ip4_src, src, sizeof (src)) ||
	  !inet_ntop (AF_INET, &tm->last_tuple_ip4_dst, dst, sizeof (dst)))
	{
	  tm->resolver_errors++;
	  return;
	}
    }
  else if (tm->last_tuple_ip_version == 6)
    {
      if (!inet_ntop (AF_INET6, tm->last_tuple_ip6_src, src, sizeof (src)) ||
	  !inet_ntop (AF_INET6, tm->last_tuple_ip6_dst, dst, sizeof (dst)))
	{
	  tm->resolver_errors++;
	  return;
	}
    }
  else
    return;

  query_len = snprintf (query, sizeof (query),
			"resolve ip%u proto %u %s %u %s %u\n",
			tm->last_tuple_ip_version, tm->last_tuple_protocol, src,
			tm->last_tuple_src_port, dst,
			tm->last_tuple_dst_port);
  if (query_len <= 0 || query_len >= (int) sizeof (query))
    {
      tm->resolver_errors++;
      return;
    }

  tm->resolver_queries++;
  rv = write (tm->resolver_fd, query, query_len);
  if (rv != query_len)
    {
      tm->resolver_errors++;
      return;
    }

  pfd.fd = tm->resolver_fd;
  pfd.events = POLLIN;
  if (poll (&pfd, 1, 500) <= 0 || !(pfd.revents & POLLIN))
    {
      tm->resolver_errors++;
      return;
    }

  rv = read (tm->resolver_fd, response, sizeof (response) - 1);
  if (rv <= 0)
    {
      tm->resolver_errors++;
      return;
    }
  response[rv] = 0;

  if (sscanf (response, "uid %d", &uid) != 1)
    {
      tm->resolver_errors++;
      return;
    }

  tm->last_owner_uid = uid;
  tm->resolver_hits++;
  tun_poc_owner_cache_store (tm, uid);
}

static void
tun_poc_process_worker_packet (tun_poc_main_t *tm, const u8 *packet,
			       u32 packet_len)
{
  tun_poc_record_l4_tuple (tm, packet, packet_len);
  tun_poc_query_owner_resolver (tm);

  if (tm->block_owner_uid_set && tm->last_owner_uid == tm->block_owner_uid)
    {
      tm->uid_blocked_packets++;
      tm->uid_blocked_bytes += packet_len;
      tm->blocked_packets++;
      tm->blocked_bytes += packet_len;
      return;
    }

  if (tm->mode == TUN_POC_MODE_HANDOFF_FORWARD_FD)
    {
      if (tun_poc_should_block_static_dst (tm, packet, packet_len))
	{
	  tm->blocked_packets++;
	  tm->blocked_bytes += packet_len;
	  return;
	}
      (void) tun_poc_write_packet (tm->shim_fd, packet, packet_len,
				   &tm->shim_tx_packets,
				   &tm->shim_tx_bytes,
				   &tm->shim_write_errors);
    }
}

static clib_error_t *
tun_poc_main_fd_read_ready (clib_file_t *f)
{
  tun_poc_main_t *tm = (tun_poc_main_t *) f->private_data;

  tun_poc_note_thread_hit (tm->main_fd_thread_hits,
			   &tm->last_main_fd_thread_index,
			   &tm->overflow_thread_hits);

  if (tm->mode == TUN_POC_MODE_HANDOFF_PROBE ||
      tm->mode == TUN_POC_MODE_HANDOFF_FORWARD_FD)
    {
      vlib_node_set_interrupt_pending (vlib_get_main (),
				       tun_poc_rx_handoff_node.index);
      return 0;
    }

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
	    {
	      if (tun_poc_should_block_static_dst (tm, tm->rx_buf, rv))
		{
		  tm->blocked_packets++;
		  tm->blocked_bytes += rv;
		  continue;
		}
	      (void) tun_poc_write_packet (tm->shim_fd, tm->rx_buf, rv,
					   &tm->shim_tx_packets,
					   &tm->shim_tx_bytes,
					   &tm->shim_write_errors);
	    }
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

VLIB_NODE_FN (tun_poc_rx_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  tun_poc_main_t *tm = &tun_poc_main;
  u32 processed = 0;
  uword buffer_size = vlib_buffer_get_default_data_size (vm);

  (void) frame;

  tun_poc_note_thread_hit (tm->rx_node_thread_hits,
			   &tm->last_rx_node_thread_index,
			   &tm->overflow_thread_hits);

  if (!tm->enabled ||
      (tm->mode != TUN_POC_MODE_HANDOFF_PROBE &&
       tm->mode != TUN_POC_MODE_HANDOFF_FORWARD_FD))
    return 0;

  while (processed < TUN_POC_HANDOFF_BURST)
    {
      u32 bi = ~0;
      vlib_buffer_t *b;
      u16 target_thread;
      ssize_t rv;
      u32 n_enq;

      rv = read (tm->fd, tm->rx_buf, TUN_POC_RX_BUF_SIZE);
      if (rv > 0)
	{
	  tm->rx_packets++;
	  tm->rx_bytes += rv;

	  if ((uword) rv > buffer_size)
	    {
	      tm->parse_errors++;
	      processed++;
	      continue;
	    }

	  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	    {
	      tm->handoff_alloc_errors++;
	      processed++;
	      continue;
	    }

	  b = vlib_get_buffer (vm, bi);
	  b->flags = 0;
	  b->current_data = 0;
	  b->current_length = rv;
	  clib_memcpy_fast (vlib_buffer_get_current (b), tm->rx_buf, rv);

	  target_thread = (u16) tm->handoff_target_thread;
	  n_enq = vlib_buffer_enqueue_to_thread (
	    vm, node, tm->handoff_frame_queue_index, &bi, &target_thread, 1,
	    1 /* drop on congestion */);
	  if (n_enq == 1)
	    {
	      tm->handoff_enqueued_packets++;
	      tm->handoff_enqueued_bytes += rv;
	    }
	  else
	    tm->handoff_congestion_drops++;

	  processed++;
	  continue;
	}

      if (rv == 0)
	return processed;

      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return processed;

      if (errno == EINTR)
	continue;

      tm->read_errors++;
      return processed;
    }

  return processed;
}

VLIB_REGISTER_NODE (tun_poc_rx_handoff_node) = {
  .name = "tun-poc-rx-handoff",
  .function = tun_poc_rx_handoff_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (tun_poc_worker_probe_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  tun_poc_main_t *tm = &tun_poc_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 *to_free = 0;

  tun_poc_note_thread_hit (tm->worker_probe_thread_hits,
			   &tm->last_worker_probe_thread_index,
			   &tm->overflow_thread_hits);

  for (u32 i = 0; i < n_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u8 *packet = vlib_buffer_get_current (b);
      u32 packet_len = vlib_buffer_length_in_chain (vm, b);

      tm->worker_probe_packets++;
      tm->worker_probe_bytes += packet_len;
      if (tm->redirect_enabled &&
	  tm->redirect_target_thread != vlib_get_thread_index ())
	{
	  u16 target_thread = (u16) tm->redirect_target_thread;
	  u32 bi = from[i];
	  u32 n_enq;

	  n_enq = vlib_buffer_enqueue_to_thread (
	    vm, node, tm->redirect_frame_queue_index, &bi, &target_thread, 1,
	    1 /* drop on congestion */);
	  if (n_enq == 1)
	    {
	      tm->redirect_enqueued_packets++;
	      tm->redirect_enqueued_bytes += packet_len;
	      continue;
	    }

	  tm->redirect_congestion_drops++;
	  vec_add1 (to_free, from[i]);
	  continue;
	}

      tun_poc_process_worker_packet (tm, packet, packet_len);
      vec_add1 (to_free, from[i]);
    }

  if (vec_len (to_free) > 0)
    vlib_buffer_free (vm, to_free, vec_len (to_free));
  vec_free (to_free);
  return n_left;
}

VLIB_REGISTER_NODE (tun_poc_worker_probe_node) = {
  .name = "tun-poc-worker-probe",
  .function = tun_poc_worker_probe_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (tun_poc_worker_redirect_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  tun_poc_main_t *tm = &tun_poc_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  (void) node;

  tun_poc_note_thread_hit (tm->worker_redirect_thread_hits,
			   &tm->last_worker_redirect_thread_index,
			   &tm->overflow_thread_hits);

  for (u32 i = 0; i < n_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u8 *packet = vlib_buffer_get_current (b);
      u32 packet_len = vlib_buffer_length_in_chain (vm, b);

      tm->redirect_worker_packets++;
      tm->redirect_worker_bytes += packet_len;
      tun_poc_process_worker_packet (tm, packet, packet_len);
    }

  vlib_buffer_free (vm, from, n_left);
  return n_left;
}

VLIB_REGISTER_NODE (tun_poc_worker_redirect_node) = {
  .name = "tun-poc-worker-redirect",
  .function = tun_poc_worker_redirect_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

static clib_error_t *
tun_poc_handoff_init (vlib_main_t *vm)
{
  tun_poc_main_t *tm = &tun_poc_main;

  (void) vm;

  tm->handoff_frame_queue_index =
    vlib_frame_queue_main_init (tun_poc_worker_probe_node.index, 0);
  tm->redirect_frame_queue_index =
    vlib_frame_queue_main_init (tun_poc_worker_redirect_node.index, 0);
  return 0;
}

VLIB_INIT_FUNCTION (tun_poc_handoff_init);

static clib_error_t *
tun_poc_shim_fd_read_ready (clib_file_t *f)
{
  tun_poc_main_t *tm = &tun_poc_main;

  (void) f;
  tun_poc_note_thread_hit (tm->shim_fd_thread_hits,
			   &tm->last_shim_fd_thread_index,
			   &tm->overflow_thread_hits);

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
tun_poc_enable (vlib_main_t *vm, int fd, tun_poc_mode_t mode, int shim_fd,
		u8 block_ip4_dst_set, u32 block_ip4_dst)
{
  tun_poc_main_t *tm = &tun_poc_main;
  clib_file_t template = { 0 };
  clib_error_t *err;

  (void) vm;

  if (tm->enabled)
    return clib_error_return (0, "tun_poc already enabled on fd %d", tm->fd);
  if (fd < 0)
    return clib_error_return (0, "fd must be non-negative");
  if ((mode == TUN_POC_MODE_FORWARD_FD ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD) &&
      shim_fd < 0)
    return clib_error_return (0, "%U mode requires shim-fd",
			      format_tun_poc_mode, mode);
  if ((mode == TUN_POC_MODE_FORWARD_FD ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD) &&
      shim_fd == fd)
    return clib_error_return (0, "shim-fd must differ from fd");
  if ((mode == TUN_POC_MODE_HANDOFF_PROBE ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD) &&
      tm->handoff_frame_queue_index == ~0)
    return clib_error_return (0, "handoff frame queue is not initialized");
  if ((mode == TUN_POC_MODE_HANDOFF_PROBE ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD) &&
      tm->redirect_frame_queue_index == ~0)
    return clib_error_return (0, "redirect frame queue is not initialized");

  err = tun_poc_set_nonblocking (fd, "tun fd");
  if (err)
    return err;

  if (mode == TUN_POC_MODE_FORWARD_FD ||
      mode == TUN_POC_MODE_HANDOFF_FORWARD_FD)
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
  tm->resolver_fd = -1;
  tm->mode = mode;
  tm->block_ip4_dst_set = block_ip4_dst_set;
  tm->block_ip4_dst = block_ip4_dst;
  tm->block_ip6_dst_set = 0;
  clib_memset (tm->block_ip6_dst, 0, sizeof (tm->block_ip6_dst));
  tm->handoff_target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  tm->redirect_target_thread = ~0;
  tm->redirect_enabled = 0;
  tm->rx_packets = 0;
  tm->rx_bytes = 0;
  tm->tx_packets = 0;
  tm->tx_bytes = 0;
  tm->shim_rx_packets = 0;
  tm->shim_rx_bytes = 0;
  tm->shim_tx_packets = 0;
  tm->shim_tx_bytes = 0;
  tm->blocked_packets = 0;
  tm->blocked_bytes = 0;
  tm->short_packets = 0;
  tm->non_ipv4 = 0;
  tm->non_icmp = 0;
  tm->non_echo = 0;
  tm->parse_errors = 0;
  tm->read_errors = 0;
  tm->write_errors = 0;
  tm->shim_read_errors = 0;
  tm->shim_write_errors = 0;
  tm->handoff_enqueued_packets = 0;
  tm->handoff_enqueued_bytes = 0;
  tm->handoff_congestion_drops = 0;
  tm->handoff_alloc_errors = 0;
  tm->redirect_enqueued_packets = 0;
  tm->redirect_enqueued_bytes = 0;
  tm->redirect_congestion_drops = 0;
  tm->redirect_worker_packets = 0;
  tm->redirect_worker_bytes = 0;
  tm->worker_probe_packets = 0;
  tm->worker_probe_bytes = 0;
  tm->tuple_parsed_packets = 0;
  tm->tuple_parse_errors = 0;
  tm->tuple_non_tcp_udp = 0;
  tm->last_tuple_valid = 0;
  tm->last_tuple_ip_version = 0;
  tm->last_tuple_protocol = 0;
  tm->last_tuple_src_port = 0;
  tm->last_tuple_dst_port = 0;
  tm->last_tuple_ip4_src = 0;
  tm->last_tuple_ip4_dst = 0;
  clib_memset (tm->last_tuple_ip6_src, 0, sizeof (tm->last_tuple_ip6_src));
  clib_memset (tm->last_tuple_ip6_dst, 0, sizeof (tm->last_tuple_ip6_dst));
  tm->resolver_enabled = 0;
  tm->last_owner_uid = -1;
  tm->owner_cache_enabled = 0;
  tm->owner_cache_valid = 0;
  tm->owner_cache_ip_version = 0;
  tm->owner_cache_protocol = 0;
  tm->owner_cache_src_port = 0;
  tm->owner_cache_dst_port = 0;
  tm->owner_cache_ip4_src = 0;
  tm->owner_cache_ip4_dst = 0;
  clib_memset (tm->owner_cache_ip6_src, 0,
	       sizeof (tm->owner_cache_ip6_src));
  clib_memset (tm->owner_cache_ip6_dst, 0,
	       sizeof (tm->owner_cache_ip6_dst));
  tm->owner_cache_uid = -1;
  tm->block_owner_uid_set = 0;
  tm->block_owner_uid = -1;
  tm->resolver_queries = 0;
  tm->resolver_hits = 0;
  tm->resolver_errors = 0;
  tm->owner_cache_hits = 0;
  tm->owner_cache_misses = 0;
  tm->owner_cache_stores = 0;
  tm->uid_blocked_packets = 0;
  tm->uid_blocked_bytes = 0;
  tm->overflow_thread_hits = 0;
  tm->last_main_fd_thread_index = ~0;
  tm->last_shim_fd_thread_index = ~0;
  tm->last_rx_node_thread_index = ~0;
  tm->last_worker_probe_thread_index = ~0;
  tm->last_worker_redirect_thread_index = ~0;
  clib_memset (tm->main_fd_thread_hits, 0, sizeof (tm->main_fd_thread_hits));
  clib_memset (tm->shim_fd_thread_hits, 0, sizeof (tm->shim_fd_thread_hits));
  clib_memset (tm->rx_node_thread_hits, 0, sizeof (tm->rx_node_thread_hits));
  clib_memset (tm->worker_probe_thread_hits, 0,
	       sizeof (tm->worker_probe_thread_hits));
  clib_memset (tm->worker_redirect_thread_hits, 0,
	       sizeof (tm->worker_redirect_thread_hits));

  template.read_function = tun_poc_main_fd_read_ready;
  template.file_descriptor = tm->fd;
  template.private_data = (uword) tm;
  template.description = format (0, "tun-poc fd %d", fd);
  tm->file_index = clib_file_add (&file_main, &template);

  if (mode == TUN_POC_MODE_FORWARD_FD ||
      mode == TUN_POC_MODE_HANDOFF_FORWARD_FD)
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
  tm->resolver_fd = -1;
  tm->file_index = ~0;
  tm->shim_file_index = ~0;
  tm->redirect_enabled = 0;
  tm->redirect_target_thread = ~0;
}

static clib_error_t *
tun_poc_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  tun_poc_mode_t mode = TUN_POC_MODE_REFLECT_ICMP;
  int fd = -1;
  int shim_fd = -1;
  int resolver_fd = -1;
  int block_owner_uid = -1;
  u8 *block_ip4_dst_text = 0;
  u8 *block_ip6_dst_text = 0;
  u32 block_ip4_dst = 0;
  u8 block_ip6_dst[16] = { 0 };
  u8 block_ip4_dst_set = 0;
  u8 block_ip6_dst_set = 0;
  u8 owner_cache_enabled = 0;
  u32 handoff_target_thread = ~0;
  u32 redirect_target_thread = ~0;

  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fd %d", &fd))
	;
      else if (unformat (input, "shim-fd %d", &shim_fd))
	;
      else if (unformat (input, "resolver-fd %d", &resolver_fd))
	;
      else if (unformat (input, "block-owner-uid %d", &block_owner_uid))
	;
      else if (unformat (input, "owner-cache"))
	owner_cache_enabled = 1;
      else if (unformat (input, "mode count-only"))
	mode = TUN_POC_MODE_COUNT_ONLY;
      else if (unformat (input, "mode reflect-icmp"))
	mode = TUN_POC_MODE_REFLECT_ICMP;
      else if (unformat (input, "mode forward-fd"))
	mode = TUN_POC_MODE_FORWARD_FD;
      else if (unformat (input, "mode handoff-probe"))
	mode = TUN_POC_MODE_HANDOFF_PROBE;
      else if (unformat (input, "mode handoff-forward-fd"))
	mode = TUN_POC_MODE_HANDOFF_FORWARD_FD;
      else if (unformat (input, "target-thread %u", &handoff_target_thread))
	;
      else if (unformat (input, "redirect-thread %u",
			 &redirect_target_thread))
	;
      else if (unformat (input, "block-ip4-dst %s", &block_ip4_dst_text))
	{
	  if (inet_pton (AF_INET, (char *) block_ip4_dst_text,
			 &block_ip4_dst) != 1)
	    {
	      vec_free (block_ip4_dst_text);
	      return clib_error_return (0, "invalid IPv4 address");
	    }
	  vec_free (block_ip4_dst_text);
	  block_ip4_dst_text = 0;
	  block_ip4_dst_set = 1;
	}
      else if (unformat (input, "block-ip6-dst %s", &block_ip6_dst_text))
	{
	  if (inet_pton (AF_INET6, (char *) block_ip6_dst_text,
			 block_ip6_dst) != 1)
	    {
	      vec_free (block_ip6_dst_text);
	      return clib_error_return (0, "invalid IPv6 address");
	    }
	  vec_free (block_ip6_dst_text);
	  block_ip6_dst_text = 0;
	  block_ip6_dst_set = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if ((mode == TUN_POC_MODE_HANDOFF_PROBE ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD) &&
      handoff_target_thread != ~0 &&
      handoff_target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "target-thread %u is outside VPP thread "
				 "range 0..%u",
			      handoff_target_thread, vlib_get_n_threads () - 1);
  if (redirect_target_thread != ~0 &&
      mode != TUN_POC_MODE_HANDOFF_PROBE &&
      mode != TUN_POC_MODE_HANDOFF_FORWARD_FD)
    return clib_error_return (0, "redirect-thread requires handoff mode");
  if (redirect_target_thread != ~0 &&
      redirect_target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "redirect-thread %u is outside VPP thread "
				 "range 0..%u",
			      redirect_target_thread,
			      vlib_get_n_threads () - 1);

  clib_error_t *err =
    tun_poc_enable (vm, fd, mode, shim_fd, block_ip4_dst_set, block_ip4_dst);
  if (!err && handoff_target_thread != ~0)
    tun_poc_main.handoff_target_thread = handoff_target_thread;
  if (!err && redirect_target_thread != ~0)
    {
      tun_poc_main.redirect_enabled = 1;
      tun_poc_main.redirect_target_thread = redirect_target_thread;
    }
  if (!err && resolver_fd >= 0)
    {
	  tun_poc_main.resolver_fd = resolver_fd;
	  tun_poc_main.resolver_enabled = 1;
	}
  if (!err && owner_cache_enabled)
    tun_poc_main.owner_cache_enabled = 1;
  if (!err && block_owner_uid >= 0)
    {
      tun_poc_main.block_owner_uid_set = 1;
      tun_poc_main.block_owner_uid = block_owner_uid;
    }
  if (!err && block_ip6_dst_set)
    {
      tun_poc_main.block_ip6_dst_set = 1;
      clib_memcpy (tun_poc_main.block_ip6_dst, block_ip6_dst,
		   sizeof (tun_poc_main.block_ip6_dst));
    }
  return err;
}

VLIB_CLI_COMMAND (tun_poc_enable_command, static) = {
  .path = "tun-poc enable",
  .short_help =
    "tun-poc enable fd <n> "
    "[mode count-only|reflect-icmp|forward-fd|handoff-probe|"
    "handoff-forward-fd] "
    "[shim-fd <n>] [resolver-fd <n>] [target-thread <n>] "
    "[redirect-thread <n>] "
    "[block-owner-uid <uid>] [owner-cache] [block-ip4-dst <addr>] "
    "[block-ip6-dst <addr>]",
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
  char block_dst[INET_ADDRSTRLEN] = "-";
  char block_dst6[INET6_ADDRSTRLEN] = "-";
  char tuple_src[INET6_ADDRSTRLEN] = "-";
  char tuple_dst[INET6_ADDRSTRLEN] = "-";

  (void) input;
  (void) cmd;

  if (tm->block_ip4_dst_set &&
      !inet_ntop (AF_INET, &tm->block_ip4_dst, block_dst,
		  sizeof (block_dst)))
    block_dst[0] = '-';
  if (tm->block_ip6_dst_set &&
      !inet_ntop (AF_INET6, tm->block_ip6_dst, block_dst6,
		  sizeof (block_dst6)))
    block_dst6[0] = '-';
  if (tm->last_tuple_valid && tm->last_tuple_ip_version == 4)
    {
      if (!inet_ntop (AF_INET, &tm->last_tuple_ip4_src, tuple_src,
		      sizeof (tuple_src)))
	tuple_src[0] = '-';
      if (!inet_ntop (AF_INET, &tm->last_tuple_ip4_dst, tuple_dst,
		      sizeof (tuple_dst)))
	tuple_dst[0] = '-';
    }
  else if (tm->last_tuple_valid && tm->last_tuple_ip_version == 6)
    {
      if (!inet_ntop (AF_INET6, tm->last_tuple_ip6_src, tuple_src,
		      sizeof (tuple_src)))
	tuple_src[0] = '-';
      if (!inet_ntop (AF_INET6, tm->last_tuple_ip6_dst, tuple_dst,
		      sizeof (tuple_dst)))
	tuple_dst[0] = '-';
    }

  vlib_cli_output (vm, "enabled %u fd %d shim-fd %d mode %U", tm->enabled,
		   tm->fd, tm->shim_fd, format_tun_poc_mode, tm->mode);
  vlib_cli_output (vm, "rx %llu bytes %llu tx %llu bytes %llu",
		   tm->rx_packets, tm->rx_bytes, tm->tx_packets, tm->tx_bytes);
  vlib_cli_output (vm,
		   "shim-rx %llu bytes %llu shim-tx %llu bytes %llu",
		   tm->shim_rx_packets, tm->shim_rx_bytes,
		   tm->shim_tx_packets, tm->shim_tx_bytes);
  vlib_cli_output (vm, "blocked %llu bytes %llu block-ip4-dst %s",
		   tm->blocked_packets, tm->blocked_bytes, block_dst);
  vlib_cli_output (vm, "block-ip6-dst %s", block_dst6);
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
  vlib_cli_output (
    vm,
    "handoff target-thread %u fq %u enqueued %llu bytes %llu "
    "congestion-drops %llu alloc-errors %llu worker-packets %llu bytes %llu",
    tm->handoff_target_thread, tm->handoff_frame_queue_index,
    tm->handoff_enqueued_packets, tm->handoff_enqueued_bytes,
    tm->handoff_congestion_drops, tm->handoff_alloc_errors,
    tm->worker_probe_packets, tm->worker_probe_bytes);
  vlib_cli_output (
    vm,
    "redirect enabled %u target-thread %u fq %u enqueued %llu bytes %llu "
    "congestion-drops %llu worker-packets %llu bytes %llu",
    tm->redirect_enabled, tm->redirect_target_thread,
    tm->redirect_frame_queue_index, tm->redirect_enqueued_packets,
    tm->redirect_enqueued_bytes, tm->redirect_congestion_drops,
    tm->redirect_worker_packets, tm->redirect_worker_bytes);
  vlib_cli_output (
    vm,
    "tuple parsed %llu errors %llu non-tcp-udp %llu last-valid %u",
    tm->tuple_parsed_packets, tm->tuple_parse_errors, tm->tuple_non_tcp_udp,
    tm->last_tuple_valid);
  if (tm->last_tuple_valid && tm->last_tuple_ip_version == 6)
    vlib_cli_output (vm, "last-tuple ip6 proto %u [%s]:%u -> [%s]:%u",
		     tm->last_tuple_protocol, tuple_src,
		     tm->last_tuple_src_port, tuple_dst,
		     tm->last_tuple_dst_port);
  else
    vlib_cli_output (vm, "last-tuple ip%u proto %u %s:%u -> %s:%u",
		     tm->last_tuple_ip_version, tm->last_tuple_protocol,
		     tuple_src, tm->last_tuple_src_port, tuple_dst,
		     tm->last_tuple_dst_port);
  vlib_cli_output (
    vm,
    "resolver enabled %u fd %d queries %llu hits %llu errors %llu "
    "last-uid %d",
    tm->resolver_enabled, tm->resolver_fd, tm->resolver_queries,
    tm->resolver_hits, tm->resolver_errors, tm->last_owner_uid);
  vlib_cli_output (
    vm,
    "owner-cache enabled %u valid %u hits %llu misses %llu stores %llu uid %d",
    tm->owner_cache_enabled, tm->owner_cache_valid, tm->owner_cache_hits,
    tm->owner_cache_misses, tm->owner_cache_stores, tm->owner_cache_uid);
  vlib_cli_output (
    vm, "uid-block enabled %u uid %d packets %llu bytes %llu",
    tm->block_owner_uid_set, tm->block_owner_uid, tm->uid_blocked_packets,
    tm->uid_blocked_bytes);
  vlib_cli_output (
    vm,
    "thread-hits main last %u t0 %llu t1 %llu t2 %llu t3 %llu overflow %llu",
    tm->last_main_fd_thread_index, tm->main_fd_thread_hits[0],
    tm->main_fd_thread_hits[1], tm->main_fd_thread_hits[2],
    tm->main_fd_thread_hits[3], tm->overflow_thread_hits);
  vlib_cli_output (
    vm, "thread-hits shim last %u t0 %llu t1 %llu t2 %llu t3 %llu",
    tm->last_shim_fd_thread_index, tm->shim_fd_thread_hits[0],
    tm->shim_fd_thread_hits[1], tm->shim_fd_thread_hits[2],
    tm->shim_fd_thread_hits[3]);
  vlib_cli_output (
    vm, "thread-hits rx-node last %u t0 %llu t1 %llu t2 %llu t3 %llu",
    tm->last_rx_node_thread_index, tm->rx_node_thread_hits[0],
    tm->rx_node_thread_hits[1], tm->rx_node_thread_hits[2],
    tm->rx_node_thread_hits[3]);
  vlib_cli_output (
    vm,
    "thread-hits worker-probe last %u t0 %llu t1 %llu t2 %llu t3 %llu",
    tm->last_worker_probe_thread_index, tm->worker_probe_thread_hits[0],
    tm->worker_probe_thread_hits[1], tm->worker_probe_thread_hits[2],
    tm->worker_probe_thread_hits[3]);
  vlib_cli_output (
    vm,
    "thread-hits worker-redirect last %u t0 %llu t1 %llu t2 %llu t3 %llu",
    tm->last_worker_redirect_thread_index,
    tm->worker_redirect_thread_hits[0],
    tm->worker_redirect_thread_hits[1],
    tm->worker_redirect_thread_hits[2],
    tm->worker_redirect_thread_hits[3]);
  return 0;
}

VLIB_CLI_COMMAND (tun_poc_show_command, static) = {
  .path = "show tun-poc",
  .short_help = "show tun-poc",
  .function = tun_poc_show_command_fn,
};
