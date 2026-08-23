/* SPDX-License-Identifier: Apache-2.0 */

#include <tun_poc/tun_poc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vlib/buffer_node.h>
#include <vlib/threads.h>

#define TUN_POC_RX_BUF_SIZE 65536
#define TUN_POC_HANDOFF_BURST 32

#define TUN_POC_PROCESS_CONSUMED 0
#define TUN_POC_PROCESS_REQUEUED 1
#define TUN_POC_PROCESS_COMPLETION 2

#define TUN_POC_FRAGMENT_CLASSIFY_ERROR 0
#define TUN_POC_FRAGMENT_CLASSIFY_NON_FRAGMENT 1
#define TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT 2
#define TUN_POC_OPAQUE_FRAGMENT  (1u << 0)
#define TUN_POC_OPAQUE_FRAGMENT_TRANSITION (1u << 1)
#define TUN_POC_OPAQUE_FRAGMENT_FIRST (1u << 2)
#define TUN_POC_OPAQUE_OWNER_ONLY (1u << 3)

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

typedef struct
{
  u8 version;
  u8 protocol;
  u8 addr_len;
  u16 src_port;
  u16 dst_port;
  u8 src[16];
  u8 dst[16];
} tun_poc_direct_tuple_t;

typedef struct
{
  u8 version;
  u8 protocol;
  u8 is_fragment;
  u8 malformed;
  u8 first;
  u8 more;
  u8 addr_len;
  u32 fragment_id;
  u32 offset;
  u32 payload_len;
  u8 src[16];
  u8 dst[16];
} tun_poc_fragment_info_t;

static u8 tun_poc_parse_direct_tuple (const u8 *packet, u32 packet_len,
				      tun_poc_direct_tuple_t *tuple);

/* A2-5 is deliberately a one-flow, fresh-session POC.  Keep the admission
 * ledger at the actual UID policy and shim write seam rather than deriving it
 * from aggregate `show tun-poc` counters.  The stage is passed by the Android
 * launcher into the VPP child environment and the canonical key matches the
 * AppA TrafficAdapter envelope (family|protocol|source-port|destination).
 */
static const char *
tun_poc_ledger_stage (tun_poc_main_t *tm)
{
  if (tm && tm->ledger_stage_id[0])
    return tm->ledger_stage_id;
  const char *stage = getenv ("SAKAMOTO_A2_STAGE_ID");
  return stage && stage[0] ? stage : "unknown";
}

static u8
tun_poc_a25_stage (tun_poc_main_t *tm)
{
  const char *stage = tun_poc_ledger_stage (tm);
  return (tm && tm->strict_owner_pending) || strncmp (stage, "A2-5", 4) == 0;
}

static void
tun_poc_ledger_log (tun_poc_main_t *tm, const char *event,
			    const char *decision, int uid,
			    const tun_poc_direct_tuple_t *tuple)
{
  char dst[INET6_ADDRSTRLEN] = "?";
  const char *family;
  const char *protocol;

  if (!tm || !event || !tuple || !tuple->version)
    return;
  family = tuple->version == 6 ? "ip6" : "ip4";
  protocol = tuple->protocol == IPPROTO_TCP ? "tcp" :
             tuple->protocol == IPPROTO_UDP ? "udp" : "other";
  if (tuple->version == 6)
    {
      (void) inet_ntop (AF_INET6, tuple->dst, dst, sizeof (dst));
    }
  else
    {
      (void) inet_ntop (AF_INET, tuple->dst, dst, sizeof (dst));
    }
  fprintf (stderr,
           "tun-poc ledger event=%s stage-id=%s flow-id=%s|%s|%s|%u "
           "canonical-key=%s|%s|%u|%s:%u uid=%d decision=%s\n",
           event, tun_poc_ledger_stage (tm), tun_poc_ledger_stage (tm), family,
           protocol, (unsigned) tuple->src_port, family, protocol,
           (unsigned) tuple->src_port, dst, (unsigned) tuple->dst_port, uid,
           decision ? decision : "");
}

tun_poc_main_t tun_poc_main = {
  .fd = -1,
  .shim_fd = -1,
  .resolver_fd = -1,
  .file_index = ~0,
  .shim_file_index = ~0,
  .polling_thread_index = 0,
  .shim_polling_thread_index = 0,
  .handoff_frame_queue_index = ~0,
  .handoff_target_thread = ~0,
  .redirect_frame_queue_index = ~0,
  .redirect_target_thread = ~0,
  .completion_frame_queue_index = ~0,
  .completion_target_thread = 0,
  .last_owner_uid = -1,
  .owner_cache_uid = -1,
  .block_owner_uid = -1,
  .pending_block_owner_uid = -1,
};

extern vlib_node_registration_t tun_poc_rx_handoff_node;
extern vlib_node_registration_t tun_poc_worker_probe_node;
extern vlib_node_registration_t tun_poc_worker_redirect_node;
extern vlib_node_registration_t tun_poc_completion_node;

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
    case TUN_POC_MODE_DIRECT_OWNER:
      return format (s, "direct-owner");
    case TUN_POC_MODE_DIRECT_OWNER_FAULT:
      return format (s, "direct-owner-fault");
    case TUN_POC_MODE_DIRECT_OWNER_RETURN:
      return format (s, "direct-owner-return");
    case TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER:
      return format (s, "direct-owner-single-writer");
    case TUN_POC_MODE_FRAGMENT_OWNER:
      return format (s, "fragment-owner");
    }

  return format (s, "unknown");
}

static inline u8
tun_poc_is_direct_owner_mode (tun_poc_mode_t mode)
{
  return mode == TUN_POC_MODE_DIRECT_OWNER ||
         mode == TUN_POC_MODE_DIRECT_OWNER_FAULT ||
         mode == TUN_POC_MODE_DIRECT_OWNER_RETURN ||
         mode == TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER ||
         mode == TUN_POC_MODE_FRAGMENT_OWNER;
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
tun_poc_parse_direct_tuple (const u8 *packet, u32 packet_len,
			    tun_poc_direct_tuple_t *tuple)
{
  const tun_poc_ip4_header_t *ip4;
  const tun_poc_l4_ports_t *ports;
  uword l4_offset;
  uword total_len;
  u8 version;

  clib_memset (tuple, 0, sizeof (*tuple));
  if (packet_len < 1)
    return 0;

  version = packet[0] >> 4;
  if (version == 4)
    {
      if (packet_len < sizeof (*ip4))
	return 0;

      ip4 = (const tun_poc_ip4_header_t *) packet;
      l4_offset = (ip4->version_ihl & 0x0f) * 4;
      total_len = ntohs (ip4->total_length);
      if (l4_offset < sizeof (*ip4) ||
	  total_len < l4_offset + sizeof (*ports) ||
	  total_len > packet_len)
	return 0;
      if (ip4->protocol != IPPROTO_TCP && ip4->protocol != IPPROTO_UDP)
	return 0;

      ports = (const tun_poc_l4_ports_t *) (packet + l4_offset);
      tuple->version = 4;
      tuple->protocol = ip4->protocol;
      tuple->addr_len = 4;
      tuple->src_port = ntohs (ports->src_port);
      tuple->dst_port = ntohs (ports->dst_port);
      clib_memcpy (tuple->src, &ip4->src, 4);
      clib_memcpy (tuple->dst, &ip4->dst, 4);
      return 1;
    }

  if (version == 6)
    {
      if (packet_len < 40 + sizeof (*ports))
	return 0;
      if (packet[6] != IPPROTO_TCP && packet[6] != IPPROTO_UDP)
	return 0;

      ports = (const tun_poc_l4_ports_t *) (packet + 40);
      tuple->version = 6;
      tuple->protocol = packet[6];
      tuple->addr_len = 16;
      tuple->src_port = ntohs (ports->src_port);
      tuple->dst_port = ntohs (ports->dst_port);
      clib_memcpy (tuple->src, packet + 8, 16);
      clib_memcpy (tuple->dst, packet + 24, 16);
      return 1;
    }

  return 0;
}

static u64
tun_poc_hash_bytes (u64 hash, const u8 *data, uword len)
{
  while (len--)
    {
      hash ^= *data++;
      hash *= 1099511628211ULL;
    }
  return hash;
}

static u8
tun_poc_parse_fragment_info (const u8 *packet, u32 packet_len,
			      tun_poc_fragment_info_t *info)
{
  u8 version;

  clib_memset (info, 0, sizeof (*info));
  if (packet_len < 1)
    return TUN_POC_FRAGMENT_CLASSIFY_ERROR;

  version = packet[0] >> 4;
  if (version == 4)
    {
      const tun_poc_ip4_header_t *ip4;
      u32 ihl;
      u32 total_len;
      u16 frag_off;

      if (packet_len < sizeof (*ip4))
	return TUN_POC_FRAGMENT_CLASSIFY_ERROR;
      ip4 = (const tun_poc_ip4_header_t *) packet;
      ihl = (ip4->version_ihl & 0x0f) * 4;
      total_len = ntohs (ip4->total_length);
      if (ihl < sizeof (*ip4) || total_len < ihl || total_len > packet_len)
	{
	  info->malformed = 1;
	  return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
	}
      frag_off = ntohs (ip4->frag_off);
      info->version = 4;
      info->protocol = ip4->protocol;
      info->addr_len = 4;
      info->fragment_id = ntohs (ip4->id);
      clib_memcpy (info->src, &ip4->src, 4);
      clib_memcpy (info->dst, &ip4->dst, 4);
      if ((frag_off & 0x3fff) == 0)
	return TUN_POC_FRAGMENT_CLASSIFY_NON_FRAGMENT;

      info->offset = (u32) (frag_off & 0x1fff) * 8;
      info->payload_len = total_len - ihl;
      info->first = info->offset == 0;
      info->more = (frag_off & 0x2000) != 0;
      clib_memcpy (info->src, &ip4->src, 4);
      clib_memcpy (info->dst, &ip4->dst, 4);
      if (info->payload_len == 0 || info->offset + info->payload_len > 65535 ||
	  (info->more && (info->payload_len & 7)))
	info->malformed = 1;
      return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
    }

  if (version == 6)
    {
      u8 next_header;
      u32 cursor = 40;
      u32 total_len;

      if (packet_len < 40)
	return TUN_POC_FRAGMENT_CLASSIFY_ERROR;
      total_len = 40 + ntohs (*(const u16 *) (packet + 4));
      if (total_len > packet_len)
	{
	  info->malformed = 1;
	  return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
	}
      next_header = packet[6];
      info->version = 6;
      info->protocol = next_header;
      info->addr_len = 16;
      clib_memcpy (info->src, packet + 8, 16);
      clib_memcpy (info->dst, packet + 24, 16);

      /* Walk the bounded extension chain until the Fragment header. */
      for (u32 depth = 0; depth < 8; depth++)
	{
	  u32 ext_len;
	  if (next_header == IPPROTO_FRAGMENT)
	    {
	      u16 off_flags;
	      if (cursor + 8 > total_len)
		{
		  info->malformed = 1;
		  return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
		}
	      off_flags = ntohs (*(const u16 *) (packet + cursor + 2));
	      info->version = 6;
	      info->protocol = packet[cursor];
	      info->addr_len = 16;
	      info->fragment_id = ntohl (*(const u32 *) (packet + cursor + 4));
	      info->offset = (u32) ((off_flags >> 3) & 0x1fff) * 8;
	      info->payload_len = total_len - cursor - 8;
	      info->first = info->offset == 0;
	      info->more = (off_flags & 1) != 0;
	      if (info->payload_len == 0 || info->offset + info->payload_len > 0x1fffffff ||
		  (info->more && (info->payload_len & 7)))
		info->malformed = 1;
	      return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
	    }
	  if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING ||
	      next_header == IPPROTO_DSTOPTS)
	    {
	      if (cursor + 2 > total_len)
		{
		  info->malformed = 1;
		  return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
		}
	      ext_len = ((u32) packet[cursor + 1] + 1) * 8;
	    }
	  else if (next_header == IPPROTO_AH)
	    {
	      if (cursor + 2 > total_len)
		{
		  info->malformed = 1;
		  return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
		}
	      ext_len = ((u32) packet[cursor + 1] + 2) * 4;
	    }
	  else
	    return TUN_POC_FRAGMENT_CLASSIFY_NON_FRAGMENT;
	  if (ext_len < 8 || cursor + ext_len > total_len)
	    {
	      info->malformed = 1;
	      return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
	    }
	  next_header = packet[cursor];
	  cursor += ext_len;
	}
      info->malformed = 1;
      return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
    }

  return TUN_POC_FRAGMENT_CLASSIFY_ERROR;
}

static u64
tun_poc_fragment_key_hash (const tun_poc_fragment_info_t *info)
{
  u8 key[1 + 1 + 4 + 16 + 16];
  u8 *p = key;

  *p++ = info->version;
  *p++ = info->protocol;
  *p++ = (u8) (info->fragment_id >> 24);
  *p++ = (u8) (info->fragment_id >> 16);
  *p++ = (u8) (info->fragment_id >> 8);
  *p++ = (u8) info->fragment_id;
  clib_memcpy (p, info->src, info->addr_len);
  p += info->addr_len;
  clib_memcpy (p, info->dst, info->addr_len);
  p += info->addr_len;
  return tun_poc_hash_bytes (1469598103934665603ULL, key, p - key);
}

static u64
tun_poc_hash_direct_tuple (const tun_poc_direct_tuple_t *tuple, u8 canonical)
{
  u8 key[1 + 1 + 16 + 2 + 16 + 2];
  const u8 *first_addr = tuple->src;
  const u8 *second_addr = tuple->dst;
  u16 first_port = tuple->src_port;
  u16 second_port = tuple->dst_port;
  u8 *p = key;
  int address_order;

  if (canonical)
    {
      address_order = memcmp (tuple->src, tuple->dst, tuple->addr_len);
      if (address_order > 0 ||
	  (address_order == 0 && tuple->src_port > tuple->dst_port))
	{
	  first_addr = tuple->dst;
	  second_addr = tuple->src;
	  first_port = tuple->dst_port;
	  second_port = tuple->src_port;
	}
    }

  *p++ = tuple->version;
  *p++ = tuple->protocol;
  clib_memcpy (p, first_addr, tuple->addr_len);
  p += tuple->addr_len;
  *p++ = (u8) (first_port >> 8);
  *p++ = (u8) first_port;
  clib_memcpy (p, second_addr, tuple->addr_len);
  p += tuple->addr_len;
  *p++ = (u8) (second_port >> 8);
  *p++ = (u8) second_port;

  return tun_poc_hash_bytes (1469598103934665603ULL, key,
			     (uword) (p - key));
}

static u8
tun_poc_direct_owner_for_packet (tun_poc_main_t *tm, const u8 *packet,
				 u32 packet_len, u32 *owner, u64 *canonical_hash,
				 u64 *direction_hash)
{
  tun_poc_direct_tuple_t tuple;

  if (!tun_poc_parse_direct_tuple (packet, packet_len, &tuple) ||
      tm->direct_worker_count == 0)
    return 0;

  *canonical_hash = tun_poc_hash_direct_tuple (&tuple, 1);
  *direction_hash = tun_poc_hash_direct_tuple (&tuple, 0);
  *owner = (u32) (*canonical_hash % tm->direct_worker_count);
  return 1;
}

static u8
tun_poc_ip_owner_for_packet (tun_poc_main_t *tm,
			       const tun_poc_fragment_info_t *info,
			       u32 *owner, u64 *canonical_hash,
			       u64 *direction_hash)
{
  u8 key[1 + 1 + 4 + 16 + 16];
  u8 *p = key;

  if (tm->direct_worker_count == 0 || info->addr_len == 0)
    return 0;
  *p++ = info->version;
  *p++ = info->protocol;
  clib_memcpy (p, info->src, info->addr_len);
  p += info->addr_len;
  clib_memcpy (p, info->dst, info->addr_len);
  p += info->addr_len;
  *canonical_hash = tun_poc_hash_bytes (1469598103934665603ULL, key,
					      p - key);
  *direction_hash = *canonical_hash;
  *owner = (u32) (*canonical_hash % tm->direct_worker_count);
  return 1;
}

static u8
tun_poc_fragment_ranges_complete (const tun_poc_fragment_entry_t *entry)
{
  u32 covered = 0;
  u8 progressed;

  if (!entry->first_seen || !entry->last_seen || entry->final_end == 0)
    return 0;

  do
    {
      progressed = 0;
      for (u32 i = 0; i < TUN_POC_FRAGMENT_MAX_RANGES; i++)
	{
	  const tun_poc_fragment_range_t *range = &entry->ranges[i];
	  if (!range->valid || range->start > covered || range->end <= covered)
	    continue;
	  covered = range->end;
	  progressed = 1;
	}
    }
  while (progressed && covered < entry->final_end);

  return covered >= entry->final_end;
}

static void
tun_poc_fragment_expire (tun_poc_main_t *tm, f64 now)
{
  if (tm->fragment_timeout_seconds <= 0)
    return;

  for (u32 i = 0; i < TUN_POC_FRAGMENT_MAX_ENTRIES; i++)
    {
      tun_poc_fragment_entry_t *entry = &tm->fragment_entries[i];
      if (!entry->valid || now - entry->last_seen_time <
	      tm->fragment_timeout_seconds)
	continue;
      entry->valid = 0;
      tm->fragment_timeout_drops++;
      tm->fragment_terminal_drops++;
    }
}

static u8
tun_poc_fragment_owner_for_packet (tun_poc_main_t *tm, const u8 *packet,
				    u32 packet_len, u32 *owner,
				    u64 *canonical_hash, u64 *direction_hash,
				    u8 *is_fragment, u8 *owner_only, u8 *is_first,
				    u8 *transitioned)
{
  tun_poc_fragment_info_t info;
  u8 kind;
  f64 now;
  u64 key_hash;
  u32 slot = ~0;
  tun_poc_fragment_entry_t *entry;

  *is_fragment = 0;
  *owner_only = 0;
  *is_first = 0;
  *transitioned = 0;
  kind = tun_poc_parse_fragment_info (packet, packet_len, &info);
  if (kind == TUN_POC_FRAGMENT_CLASSIFY_ERROR)
    return 0;
  if (kind == TUN_POC_FRAGMENT_CLASSIFY_NON_FRAGMENT)
	{
	  if (tun_poc_direct_owner_for_packet (tm, packet, packet_len, owner,
						 canonical_hash, direction_hash))
	    return 1;
	  if (!tun_poc_ip_owner_for_packet (tm, &info, owner, canonical_hash,
					      direction_hash))
	    return 0;
	  *owner_only = 1;
	  return 1;
	}

  tm->fragment_packets++;
  tm->fragment_bytes += packet_len;
  if (info.malformed)
    {
      tm->fragment_malformed++;
      tm->fragment_terminal_drops++;
      return 0;
    }

  *is_fragment = 1;
  *is_first = info.first;
  if (info.first)
    tm->fragment_first_packets++;
  else
    tm->fragment_nonfirst_packets++;
  if (!info.more)
    tm->fragment_last_packets++;

  now = vlib_time_now (vlib_get_main ());
  tun_poc_fragment_expire (tm, now);
  key_hash = tun_poc_fragment_key_hash (&info);
  *canonical_hash = key_hash;
  *direction_hash = key_hash;

  for (u32 i = 0; i < TUN_POC_FRAGMENT_MAX_ENTRIES; i++)
    {
      tun_poc_fragment_entry_t *candidate = &tm->fragment_entries[i];
      if (candidate->valid && candidate->key_hash == key_hash &&
	  candidate->version == info.version &&
	  candidate->protocol == info.protocol &&
	  candidate->fragment_id == info.fragment_id)
	{
	  slot = i;
	  break;
	}
      if (slot == ~0 && !candidate->valid)
	slot = i;
    }

  if (slot == ~0)
    {
      tm->fragment_capacity_drops++;
      tm->fragment_terminal_drops++;
      return 0;
    }

  entry = &tm->fragment_entries[slot];
  if (!entry->valid)
    {
      clib_memset (entry, 0, sizeof (*entry));
      entry->valid = 1;
      entry->version = info.version;
      entry->protocol = info.protocol;
      entry->fragment_id = info.fragment_id;
      entry->key_hash = key_hash;
      entry->owner = (u32) (key_hash % tm->direct_worker_count);
    }
  entry->last_seen_time = now;

  for (u32 i = 0; i < TUN_POC_FRAGMENT_MAX_RANGES; i++)
    {
      tun_poc_fragment_range_t *range = &entry->ranges[i];
      if (!range->valid)
	continue;
      if (range->start == info.offset &&
	  range->end == info.offset + info.payload_len)
	{
	  tm->fragment_duplicate_drops++;
	  tm->fragment_terminal_drops++;
	  return 0;
	}
      if (info.offset < range->end &&
	  info.offset + info.payload_len > range->start)
	{
	  tm->fragment_overlap_drops++;
	  tm->fragment_terminal_drops++;
	  return 0;
	}
    }

  if (entry->range_count >= TUN_POC_FRAGMENT_MAX_RANGES)
    {
      tm->fragment_capacity_drops++;
      tm->fragment_terminal_drops++;
      return 0;
    }
  for (u32 i = 0; i < TUN_POC_FRAGMENT_MAX_RANGES; i++)
    if (!entry->ranges[i].valid)
      {
	entry->ranges[i].valid = 1;
	entry->ranges[i].start = info.offset;
	entry->ranges[i].end = info.offset + info.payload_len;
	entry->range_count++;
	break;
      }

  if (info.first)
    {
      tun_poc_direct_tuple_t tuple;
      if (tun_poc_parse_direct_tuple (packet, packet_len, &tuple))
	{
	  *canonical_hash = tun_poc_hash_direct_tuple (&tuple, 1);
	  *direction_hash = tun_poc_hash_direct_tuple (&tuple, 0);
	  entry->flow_owner =
	    (u32) (*canonical_hash % tm->direct_worker_count);
	  entry->flow_owner_valid = 1;
	}
      entry->first_seen = 1;
    }
  if (!info.more)
    {
      entry->last_seen = 1;
      entry->final_end = info.offset + info.payload_len;
    }

  if (entry->flow_owner_valid && !entry->transitioned &&
      tun_poc_fragment_ranges_complete (entry))
    {
      entry->transitioned = 1;
      tm->fragment_flow_owner_transitions++;
      tm->fragment_reassembly_success++;
      *transitioned = 1;
    }

  *owner = entry->transitioned && entry->flow_owner_valid ?
	entry->flow_owner : entry->owner;
  if (*owner < TUN_POC_MAX_DIRECT_WORKERS)
    tm->fragment_owner_mask |= 1ULL << *owner;
  return TUN_POC_FRAGMENT_CLASSIFY_FRAGMENT;
}

static void
tun_poc_direct_note_reverse_projection (tun_poc_main_t *tm, const u8 *packet,
					 u32 packet_len, u32 owner)
{
  tun_poc_direct_tuple_t tuple;
  u8 address[16];
  u16 port;
  u64 reverse_hash;
  u32 reverse_owner;

  if (!tun_poc_parse_direct_tuple (packet, packet_len, &tuple))
    return;

  clib_memcpy (address, tuple.src, sizeof (address));
  clib_memcpy (tuple.src, tuple.dst, sizeof (tuple.src));
  clib_memcpy (tuple.dst, address, sizeof (tuple.dst));
  port = tuple.src_port;
  tuple.src_port = tuple.dst_port;
  tuple.dst_port = port;
  reverse_hash = tun_poc_hash_direct_tuple (&tuple, 1);
  reverse_owner = (u32) (reverse_hash % tm->direct_worker_count);
  if (reverse_owner == owner)
    tm->direct_reverse_projection_matches++;
  else
    tm->direct_reverse_projection_mismatch++;
}

static void
tun_poc_direct_note_key (tun_poc_main_t *tm, u32 owner, u64 canonical_hash,
			 u64 direction_hash)
{
  for (u32 i = 0; i < TUN_POC_DIRECT_SEEN_KEYS; i++)
    {
      if (!tm->direct_seen_valid[i] ||
	  tm->direct_seen_canonical_hash[i] != canonical_hash)
	continue;
      if (tm->direct_seen_direction_hash[i] != direction_hash)
	{
	  tm->direct_reverse_matches++;
	  if (tm->direct_seen_owner[i] != owner)
	    tm->direct_reverse_owner_mismatch++;
	}
      break;
    }

  u32 slot = tm->direct_seen_cursor++ % TUN_POC_DIRECT_SEEN_KEYS;
  tm->direct_seen_valid[slot] = 1;
  tm->direct_seen_canonical_hash[slot] = canonical_hash;
  tm->direct_seen_direction_hash[slot] = direction_hash;
  tm->direct_seen_owner[slot] = owner;
  tm->direct_target_worker_mask |= 1ULL << owner;
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

static i32
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
    return -1;

  if (tm->owner_cache_enabled)
    {
      if (tun_poc_owner_cache_lookup (tm))
	return tm->last_owner_uid;
      tm->owner_cache_misses++;
    }

  if (tm->last_tuple_ip_version == 4)
    {
      if (!inet_ntop (AF_INET, &tm->last_tuple_ip4_src, src, sizeof (src)) ||
	  !inet_ntop (AF_INET, &tm->last_tuple_ip4_dst, dst, sizeof (dst)))
	{
	  tm->resolver_errors++;
	  return -1;
	}
    }
  else if (tm->last_tuple_ip_version == 6)
    {
      if (!inet_ntop (AF_INET6, tm->last_tuple_ip6_src, src, sizeof (src)) ||
	  !inet_ntop (AF_INET6, tm->last_tuple_ip6_dst, dst, sizeof (dst)))
	{
	  tm->resolver_errors++;
	  return -1;
	}
    }
  else
    return -1;

  query_len = snprintf (query, sizeof (query),
			"resolve ip%u proto %u %s %u %s %u\n",
			tm->last_tuple_ip_version, tm->last_tuple_protocol, src,
			tm->last_tuple_src_port, dst,
			tm->last_tuple_dst_port);
  if (query_len <= 0 || query_len >= (int) sizeof (query))
    {
	  tm->resolver_errors++;
	  return -1;
    }

  tm->resolver_queries++;
  rv = write (tm->resolver_fd, query, query_len);
  if (rv != query_len)
    {
	  tm->resolver_errors++;
	  return -1;
    }

  pfd.fd = tm->resolver_fd;
  pfd.events = POLLIN;
  if (poll (&pfd, 1, 500) <= 0 || !(pfd.revents & POLLIN))
    {
	  tm->resolver_errors++;
	  return -1;
    }

  rv = read (tm->resolver_fd, response, sizeof (response) - 1);
  if (rv <= 0)
    {
      tm->resolver_errors++;
      return -1;
    }
  response[rv] = 0;

  if (sscanf (response, "uid %d", &uid) != 1)
    {
      tm->resolver_errors++;
      return -1;
    }

  tm->last_owner_uid = uid;
  tm->resolver_hits++;
  tun_poc_owner_cache_store (tm, uid);
  return uid;
}

static u8
tun_poc_process_worker_packet (tun_poc_main_t *tm, vlib_main_t *vm,
			       vlib_node_runtime_t *node, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  const u8 *packet = vlib_buffer_get_current (b);
  u32 packet_len = vlib_buffer_length_in_chain (vm, b);
  u8 fragment_marker = tm->mode == TUN_POC_MODE_FRAGMENT_OWNER &&
			       (b->opaque[3] & TUN_POC_OPAQUE_FRAGMENT);
  u8 owner_only_marker = tm->mode == TUN_POC_MODE_FRAGMENT_OWNER &&
					 (b->opaque[3] & TUN_POC_OPAQUE_OWNER_ONLY);
  u8 owner_metadata_marker = fragment_marker || owner_only_marker;
  i32 packet_owner_uid = tm->last_owner_uid;

  if (tun_poc_is_direct_owner_mode (tm->mode))
    {
      u32 owner = ~0;
      u32 actual_thread = vlib_get_thread_index ();
      u32 actual_owner = actual_thread > 0 ? actual_thread - 1 : ~0;
      u64 canonical_hash = 0;
      u64 direction_hash = 0;

	  if (owner_metadata_marker)
	owner = b->opaque[2];
      else if (!tun_poc_direct_owner_for_packet (tm, packet, packet_len, &owner,
						   &canonical_hash,
						   &direction_hash))
	{
	  tm->direct_parse_errors++;
	  return 0;
	}

      if (actual_owner < TUN_POC_MAX_DIRECT_WORKERS)
	{
	  if (!fragment_marker)
	    {
	      tm->direct_worker_packets[actual_owner]++;
	      tm->direct_worker_bytes[actual_owner] += packet_len;
	    }
	  else if (actual_owner == owner)
	    tm->fragment_owner_guard_pass++;
	  else
	    tm->fragment_owner_guard_mismatch++;
	}
	if ((tm->mode == TUN_POC_MODE_DIRECT_OWNER_RETURN ||
	     tm->mode == TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER) && b->opaque[1])
	  {
	    tm->direct_return_worker_packets++;
	    tm->direct_return_worker_bytes += packet_len;
	  }
	if (!fragment_marker && tm->mode == TUN_POC_MODE_DIRECT_OWNER_FAULT &&
	    b->opaque[0] == 4 && actual_owner == owner)
	  {
	    /* The second fault is deliberately injected after the corrective
	     * enqueue. This is the bounded DROP branch of the Owner Guard POC. */
	    tm->direct_owner_guard_mismatch++;
	    tm->direct_second_mismatch_drops++;
	    return 0;
	  }

	if (fragment_marker)
	  {
	    if (actual_owner != owner)
	      return 0;
	  }
	else if (actual_owner == owner)
	  {
	tm->direct_owner_guard_pass++;
	if (tm->mode == TUN_POC_MODE_DIRECT_OWNER_FAULT && b->opaque[0] == 3)
	  tm->direct_fault_single_completed++;
	  }
      else
	{
	  tm->direct_owner_guard_mismatch++;
	  if (tm->mode == TUN_POC_MODE_DIRECT_OWNER_FAULT &&
	      (b->opaque[0] == 1 || b->opaque[0] == 2))
	    {
	      u16 target_thread = (u16) (owner + 1);
	      u32 n_enq;

	      b->opaque[0] += 2;
	      n_enq = vlib_buffer_enqueue_to_thread (
		vm, node, tm->handoff_frame_queue_index, &bi, &target_thread, 1,
		1 /* drop on congestion */);
	      if (n_enq == 1)
		{
		  tm->direct_corrective_handoffs++;
		  return 1;
		}

	      tm->direct_corrective_drops++;
	    }
	  return 0;
	}
    }

  if (fragment_marker)
    {
      tm->last_tuple_valid = 0;
      tm->last_owner_uid = -1;
      if (b->opaque[3] & TUN_POC_OPAQUE_FRAGMENT_FIRST)
	tun_poc_record_l4_tuple (tm, packet, packet_len);
    }
	else if (!owner_only_marker)
	tun_poc_record_l4_tuple (tm, packet, packet_len);
	if ((!fragment_marker && !owner_only_marker) ||
	    (b->opaque[3] & TUN_POC_OPAQUE_FRAGMENT_FIRST))
	  {
	    /* A fresh A2-5 tuple must not inherit a previous flow's owner while
	     * Android's asynchronous owner lookup is still pending. */
	    tm->last_owner_uid = -1;
	    packet_owner_uid = tun_poc_query_owner_resolver (tm);
  }

  if (tun_poc_a25_stage (tm) && tm->resolver_enabled &&
      packet_owner_uid < 0)
    {
      /* The first packet only submits the Android lookup.  Conservatively
       * hold it at the policy seam; a later packet with the same fresh tuple
       * observes the completed UID and is the sole allow/drop decision. */
      tm->blocked_packets++;
      tm->blocked_bytes += packet_len;
      return 0;
    }

  if (tm->block_owner_uid_set && packet_owner_uid == tm->block_owner_uid)
    {
      tm->uid_blocked_packets++;
      tm->uid_blocked_bytes += packet_len;
      tm->blocked_packets++;
      tm->blocked_bytes += packet_len;
      return 0;
    }

  if (tm->mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
      tun_poc_is_direct_owner_mode (tm->mode))
    {
      if (tun_poc_should_block_static_dst (tm, packet, packet_len))
	{
	  tm->blocked_packets++;
	  tm->blocked_bytes += packet_len;
	  return 0;
	}
	  if (tm->mode == TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER)
	    {
	      u16 target_thread = (u16) tm->completion_target_thread;
	      u32 n_enq = vlib_buffer_enqueue_to_thread (
		vm, node, tm->completion_frame_queue_index, &bi, &target_thread, 1,
		1 /* drop on congestion */);
	      if (n_enq == 1)
		{
		  tm->completion_enqueued_packets++;
		  tm->completion_enqueued_bytes += packet_len;
		  return TUN_POC_PROCESS_COMPLETION;
		}
	      tm->completion_eagain_drops++;
	      tm->completion_terminal_drops++;
	      return TUN_POC_PROCESS_CONSUMED;
	    }
          if ((tm->mode == TUN_POC_MODE_DIRECT_OWNER_RETURN ||
               tm->mode == TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER ||
               tm->mode == TUN_POC_MODE_FRAGMENT_OWNER) &&
              b->opaque[1])
	    {
	      (void) tun_poc_write_packet (tm->fd, packet, packet_len,
					   &tm->direct_return_tx_packets,
					   &tm->direct_return_tx_bytes,
					   &tm->write_errors);
	    }
	      else
	    {
	      tun_poc_direct_tuple_t admitted_tuple;
	      int write_result = tun_poc_write_packet (
		tm->shim_fd, packet, packet_len, &tm->shim_tx_packets,
		&tm->shim_tx_bytes, &tm->shim_write_errors);
	      if (write_result == 0 && !tm->ledger_admitted_logged)
		{
		  if (tun_poc_parse_direct_tuple (packet, packet_len,
					   &admitted_tuple))
		    {
		      tun_poc_ledger_log (tm, "TRANSPORT_ADMITTED", "ALLOW",
					  tm->last_owner_uid, &admitted_tuple);
		      tm->ledger_admitted_logged = 1;
		    }
		}
	    }
    }

	      return TUN_POC_PROCESS_CONSUMED;
}

static clib_error_t *
tun_poc_main_fd_read_ready (clib_file_t *f)
{
  tun_poc_main_t *tm = (tun_poc_main_t *) f->private_data;

  tun_poc_note_thread_hit (tm->main_fd_thread_hits,
			   &tm->last_main_fd_thread_index,
			   &tm->overflow_thread_hits);

  if (tm->mode == TUN_POC_MODE_HANDOFF_PROBE ||
      tm->mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
      tun_poc_is_direct_owner_mode (tm->mode))
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
       tm->mode != TUN_POC_MODE_HANDOFF_FORWARD_FD &&
       !tun_poc_is_direct_owner_mode (tm->mode)))
    return 0;

  while (processed < TUN_POC_HANDOFF_BURST)
    {
      u32 bi = ~0;
      vlib_buffer_t *b;
      u16 target_thread;
      u32 direct_owner = ~0;
      u64 direct_canonical_hash = 0;
      u64 direct_direction_hash = 0;
      u8 fragment_packet = 0;
      u8 owner_only = 0;
      u8 fragment_first = 0;
      u8 fragment_transition = 0;
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

          if (tm->mode == TUN_POC_MODE_FRAGMENT_OWNER)
	    {
	      if (!tun_poc_fragment_owner_for_packet (
		    tm, tm->rx_buf, (u32) rv, &direct_owner,
		    &direct_canonical_hash, &direct_direction_hash,
		    &fragment_packet, &owner_only, &fragment_first,
		    &fragment_transition))
		{
		  tm->direct_parse_errors++;
		  processed++;
		  continue;
		}
	      if (!fragment_packet && !owner_only)
		{
		  tun_poc_direct_note_key (tm, direct_owner, direct_canonical_hash,
					   direct_direction_hash);
		  tun_poc_direct_note_reverse_projection (tm, tm->rx_buf, (u32) rv,
							 direct_owner);
		}
	    }
	  else if (tun_poc_is_direct_owner_mode (tm->mode))
	    {
	      if (!tun_poc_direct_owner_for_packet (
		    tm, tm->rx_buf, (u32) rv, &direct_owner,
		    &direct_canonical_hash, &direct_direction_hash))
		{
		  tm->direct_parse_errors++;
		  processed++;
		  continue;
		}
      tun_poc_direct_note_key (tm, direct_owner, direct_canonical_hash,
				       direct_direction_hash);
      tun_poc_direct_note_reverse_projection (tm, tm->rx_buf, (u32) rv,
						       direct_owner);
	    }

	  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	    {
          if (tun_poc_is_direct_owner_mode (tm->mode))
		tm->direct_alloc_errors++;
	      else
		tm->handoff_alloc_errors++;
	      processed++;
	      continue;
	    }

	  b = vlib_get_buffer (vm, bi);
	  b->flags = 0;
	  b->opaque[2] = (fragment_packet || owner_only) ? direct_owner : 0;
	  b->opaque[3] = fragment_packet ? TUN_POC_OPAQUE_FRAGMENT :
			 owner_only ? TUN_POC_OPAQUE_OWNER_ONLY : 0;
	  if (fragment_packet && fragment_first)
	    b->opaque[3] |= TUN_POC_OPAQUE_FRAGMENT_FIRST;
	  if (fragment_packet && fragment_transition)
	    b->opaque[3] |= TUN_POC_OPAQUE_FRAGMENT_TRANSITION;
	  b->opaque[1] = 0; /* primary TUN ingress lane */
	  b->current_data = 0;
	  b->current_length = rv;
	  clib_memcpy_fast (vlib_buffer_get_current (b), tm->rx_buf, rv);

      target_thread = tun_poc_is_direct_owner_mode (tm->mode)
                       ? (u16) (direct_owner + 1)
			   : (u16) tm->handoff_target_thread;
      if (tm->mode == TUN_POC_MODE_DIRECT_OWNER_FAULT &&
	  tm->direct_fault_injected < 2)
	    {
	      b->opaque[0] = (u32) (1 + tm->direct_fault_injected);
	      tm->direct_fault_injected++;
	      target_thread = (u16) (((direct_owner + 1) %
				      tm->direct_worker_count) + 1);
	    }
	  else
	    b->opaque[0] = 0;
	  n_enq = vlib_buffer_enqueue_to_thread (
	    vm, node, tm->handoff_frame_queue_index, &bi, &target_thread, 1,
	    1 /* drop on congestion */);
	  if (n_enq == 1)
	    {
		if (tun_poc_is_direct_owner_mode (tm->mode))
		{
		  tm->direct_enqueued_packets++;
		  tm->direct_enqueued_bytes += rv;
		}
	      else
		{
		  tm->handoff_enqueued_packets++;
		  tm->handoff_enqueued_bytes += rv;
		}
	    }
	  else
	    {
      if (tun_poc_is_direct_owner_mode (tm->mode))
		tm->direct_congestion_drops++;
	      else
		tm->handoff_congestion_drops++;
	    }

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

      if (!tun_poc_process_worker_packet (tm, vm, node, from[i]))
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
  u32 *to_free = 0;

  tun_poc_note_thread_hit (tm->worker_redirect_thread_hits,
			   &tm->last_worker_redirect_thread_index,
			   &tm->overflow_thread_hits);

  for (u32 i = 0; i < n_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 packet_len = vlib_buffer_length_in_chain (vm, b);

      tm->redirect_worker_packets++;
      tm->redirect_worker_bytes += packet_len;
      if (!tun_poc_process_worker_packet (tm, vm, node, from[i]))
	vec_add1 (to_free, from[i]);
    }

  if (vec_len (to_free) > 0)
    vlib_buffer_free (vm, to_free, vec_len (to_free));
  vec_free (to_free);
  return n_left;
}

VLIB_REGISTER_NODE (tun_poc_worker_redirect_node) = {
  .name = "tun-poc-worker-redirect",
  .function = tun_poc_worker_redirect_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (tun_poc_completion_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  tun_poc_main_t *tm = &tun_poc_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  (void) node;

  for (u32 i = 0; i < n_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 packet_len = vlib_buffer_length_in_chain (vm, b);

      tm->completion_processed_packets++;
      tm->completion_processed_bytes += packet_len;

      /* Fault injection models a bounded non-blocking write failure at the
       * single completion owner. The buffer has a terminal outcome here. */
      if (tm->completion_fault_budget > 0)
	{
	  tm->completion_fault_budget--;
	  tm->completion_eagain_drops++;
	  tm->completion_terminal_drops++;
	  vlib_buffer_free_one (vm, from[i]);
	  continue;
	}

      if (b->opaque[1])
	{
	  if (tun_poc_write_packet (tm->fd, vlib_buffer_get_current (b),
				     packet_len, &tm->direct_return_tx_packets,
				     &tm->direct_return_tx_bytes,
				     &tm->write_errors) < 0)
	    {
	      tm->completion_eagain_drops++;
	      tm->completion_terminal_drops++;
	    }
	}
      else if (tun_poc_write_packet (tm->shim_fd, vlib_buffer_get_current (b),
					 packet_len, &tm->shim_tx_packets,
					 &tm->shim_tx_bytes,
					 &tm->shim_write_errors) < 0)
	{
	  tm->completion_eagain_drops++;
	  tm->completion_terminal_drops++;
	}

      vlib_buffer_free_one (vm, from[i]);
    }

  return n_left;
}

VLIB_REGISTER_NODE (tun_poc_completion_node) = {
  .name = "tun-poc-completion",
  .function = tun_poc_completion_node_fn,
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
  tm->completion_frame_queue_index =
    vlib_frame_queue_main_init (tun_poc_completion_node.index, 0);
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
          if (tm->mode == TUN_POC_MODE_DIRECT_OWNER_RETURN ||
              tm->mode == TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER ||
              tm->mode == TUN_POC_MODE_FRAGMENT_OWNER)
	    {
	      vlib_main_t *vm = vlib_get_main ();
	      vlib_node_runtime_t *node =
		vlib_node_get_runtime (vm, tun_poc_rx_handoff_node.index);
	      u32 bi = ~0;
	      u32 owner = ~0;
	      u64 canonical_hash = 0;
	      u64 direction_hash = 0;
	      u8 fragment_packet = 0;
	      u8 owner_only = 0;
	      u8 fragment_first = 0;
	      u8 fragment_transition = 0;

	      if (tm->mode == TUN_POC_MODE_FRAGMENT_OWNER)
		{
		  if (!tun_poc_fragment_owner_for_packet (
			  tm, tm->rx_buf, (u32) rv, &owner, &canonical_hash,
			  &direction_hash, &fragment_packet, &owner_only,
			  &fragment_first, &fragment_transition))
		    {
		      tm->direct_parse_errors++;
		      continue;
		    }
		}
	      else if (!tun_poc_direct_owner_for_packet (
			 tm, tm->rx_buf, (u32) rv, &owner, &canonical_hash,
			 &direction_hash))
		{
		  tm->direct_parse_errors++;
		  continue;
		}
	      if (!fragment_packet && !owner_only)
		{
		  tun_poc_direct_note_key (tm, owner, canonical_hash,
					   direction_hash);
		  tun_poc_direct_note_reverse_projection (tm, tm->rx_buf, (u32) rv,
							 owner);
		}
	      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
		{
		  tm->direct_alloc_errors++;
		  continue;
		}

	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	      b->flags = 0;
	      b->opaque[0] = 0;
	      b->opaque[2] = (fragment_packet || owner_only) ? owner : 0;
	      b->opaque[3] = fragment_packet ? TUN_POC_OPAQUE_FRAGMENT :
			       owner_only ? TUN_POC_OPAQUE_OWNER_ONLY : 0;
	      if (fragment_packet && fragment_first)
		b->opaque[3] |= TUN_POC_OPAQUE_FRAGMENT_FIRST;
	      if (fragment_packet && fragment_transition)
		b->opaque[3] |= TUN_POC_OPAQUE_FRAGMENT_TRANSITION;
	      b->opaque[1] = 1; /* transport-return ingress lane */
	      b->current_data = 0;
	      b->current_length = rv;
	      clib_memcpy_fast (vlib_buffer_get_current (b), tm->rx_buf, rv);

	      u16 target_thread = (u16) (owner + 1);
	      u32 n_enq = vlib_buffer_enqueue_to_thread (
		vm, node, tm->handoff_frame_queue_index, &bi, &target_thread, 1,
		1 /* drop on congestion */);
	      if (n_enq == 1)
		{
		  tm->direct_return_enqueued_packets++;
		  tm->direct_return_enqueued_bytes += rv;
		  tm->direct_enqueued_packets++;
		  tm->direct_enqueued_bytes += rv;
		}
	      else
		{
		  tm->direct_return_congestion_drops++;
		  tm->direct_congestion_drops++;
		  vlib_buffer_free_one (vm, bi);
		}
	      continue;
	    }
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
		 u8 block_ip4_dst_set, u32 block_ip4_dst,
		 u32 polling_thread_index)
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
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
       tun_poc_is_direct_owner_mode (mode)) &&
      shim_fd < 0)
    return clib_error_return (0, "%U mode requires shim-fd",
			      format_tun_poc_mode, mode);
  if ((mode == TUN_POC_MODE_FORWARD_FD ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
       tun_poc_is_direct_owner_mode (mode)) &&
      shim_fd == fd)
    return clib_error_return (0, "shim-fd must differ from fd");
  if ((mode == TUN_POC_MODE_HANDOFF_PROBE ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
       tun_poc_is_direct_owner_mode (mode)) &&
      tm->handoff_frame_queue_index == ~0)
    return clib_error_return (0, "handoff frame queue is not initialized");
  if ((mode == TUN_POC_MODE_HANDOFF_PROBE ||
       mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
       tun_poc_is_direct_owner_mode (mode)) &&
      tm->redirect_frame_queue_index == ~0)
    return clib_error_return (0, "redirect frame queue is not initialized");
  if (tun_poc_is_direct_owner_mode (mode) &&
      vlib_num_workers () < 2)
    return clib_error_return (0,
			      "direct-owner requires at least two VPP workers");
  if (tun_poc_is_direct_owner_mode (mode) &&
      vlib_num_workers () > TUN_POC_MAX_DIRECT_WORKERS)
    return clib_error_return (0, "direct-owner worker count exceeds %u",
			      TUN_POC_MAX_DIRECT_WORKERS);
  if (polling_thread_index != ~0 &&
      polling_thread_index >= vlib_get_n_threads ())
    return clib_error_return (0, "polling-thread %u is outside VPP thread "
			      "range 0..%u", polling_thread_index,
			      vlib_get_n_threads () - 1);

  err = tun_poc_set_nonblocking (fd, "tun fd");
  if (err)
    return err;

  if (mode == TUN_POC_MODE_FORWARD_FD ||
      mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
      tun_poc_is_direct_owner_mode (mode))
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
  tm->polling_thread_index = polling_thread_index == ~0
				 ? vlib_get_thread_index ()
				 : polling_thread_index;
  tm->shim_polling_thread_index = tm->polling_thread_index;
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
  tm->direct_worker_count = vlib_num_workers ();
  tm->direct_enqueued_packets = 0;
  tm->direct_enqueued_bytes = 0;
  tm->direct_congestion_drops = 0;
  tm->direct_alloc_errors = 0;
  tm->direct_parse_errors = 0;
  tm->direct_owner_guard_pass = 0;
  tm->direct_owner_guard_mismatch = 0;
  tm->direct_corrective_handoffs = 0;
  tm->direct_corrective_drops = 0;
  tm->direct_second_mismatch_drops = 0;
  tm->direct_fault_injected = 0;
  tm->direct_fault_single_completed = 0;
  tm->direct_return_enqueued_packets = 0;
  tm->direct_return_enqueued_bytes = 0;
  tm->direct_return_congestion_drops = 0;
  tm->direct_return_worker_packets = 0;
  tm->direct_return_worker_bytes = 0;
  tm->direct_return_tx_packets = 0;
  tm->direct_return_tx_bytes = 0;
  tm->fragment_packets = 0;
  tm->fragment_bytes = 0;
  tm->fragment_first_packets = 0;
  tm->fragment_nonfirst_packets = 0;
  tm->fragment_last_packets = 0;
  tm->fragment_malformed = 0;
  tm->fragment_capacity_drops = 0;
  tm->fragment_timeout_drops = 0;
  tm->fragment_overlap_drops = 0;
  tm->fragment_duplicate_drops = 0;
  tm->fragment_owner_guard_pass = 0;
  tm->fragment_owner_guard_mismatch = 0;
  tm->fragment_flow_owner_transitions = 0;
  tm->fragment_reassembly_success = 0;
  tm->fragment_terminal_drops = 0;
  tm->fragment_table_evictions = 0;
  tm->fragment_owner_mask = 0;
  tm->fragment_cursor = 0;
  tm->fragment_timeout_seconds = 5.0;
  clib_memset (tm->fragment_entries, 0, sizeof (tm->fragment_entries));
  tm->completion_target_thread = 0;
  tm->completion_fault_budget = 0;
  tm->completion_enqueued_packets = 0;
  tm->completion_enqueued_bytes = 0;
  tm->completion_processed_packets = 0;
  tm->completion_processed_bytes = 0;
  tm->completion_eagain_drops = 0;
  tm->completion_terminal_drops = 0;
  tm->direct_reverse_matches = 0;
  tm->direct_reverse_owner_mismatch = 0;
  tm->direct_reverse_projection_matches = 0;
  tm->direct_reverse_projection_mismatch = 0;
  tm->direct_target_worker_mask = 0;
  tm->direct_seen_cursor = 0;
  clib_memset (tm->direct_worker_packets, 0,
	       sizeof (tm->direct_worker_packets));
  clib_memset (tm->direct_worker_bytes, 0, sizeof (tm->direct_worker_bytes));
  clib_memset (tm->direct_seen_canonical_hash, 0,
	       sizeof (tm->direct_seen_canonical_hash));
  clib_memset (tm->direct_seen_direction_hash, 0,
	       sizeof (tm->direct_seen_direction_hash));
  clib_memset (tm->direct_seen_owner, 0, sizeof (tm->direct_seen_owner));
  clib_memset (tm->direct_seen_valid, 0, sizeof (tm->direct_seen_valid));
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
  tm->ledger_policy_logged = 0;
  tm->ledger_admitted_logged = 0;
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
  template.polling_thread_index = tm->polling_thread_index;
  template.private_data = (uword) tm;
  template.description = format (0, "tun-poc fd %d", fd);
  tm->file_index = clib_file_add (&file_main, &template);

  if (mode == TUN_POC_MODE_FORWARD_FD ||
      mode == TUN_POC_MODE_HANDOFF_FORWARD_FD ||
      tun_poc_is_direct_owner_mode (mode))
    {
      clib_memset (&template, 0, sizeof (template));
      template.read_function = tun_poc_shim_fd_read_ready;
      template.file_descriptor = tm->shim_fd;
      template.polling_thread_index = tm->shim_polling_thread_index;
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
  u32 polling_thread_index = ~0;
  u32 completion_eagain_budget = 0;

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
      else if (unformat (input, "mode direct-owner-fault"))
	mode = TUN_POC_MODE_DIRECT_OWNER_FAULT;
      else if (unformat (input, "mode direct-owner-return"))
	mode = TUN_POC_MODE_DIRECT_OWNER_RETURN;
      else if (unformat (input, "mode direct-owner-single-writer"))
	mode = TUN_POC_MODE_DIRECT_OWNER_SINGLE_WRITER;
      else if (unformat (input, "mode fragment-owner"))
	mode = TUN_POC_MODE_FRAGMENT_OWNER;
      else if (unformat (input, "mode direct-owner"))
	mode = TUN_POC_MODE_DIRECT_OWNER;
      else if (unformat (input, "completion-eagain %u",
				 &completion_eagain_budget))
	;
      else if (unformat (input, "target-thread %u", &handoff_target_thread))
	;
      else if (unformat (input, "redirect-thread %u",
			 &redirect_target_thread))
		;
      else if (unformat (input, "polling-thread %u", &polling_thread_index))
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
    tun_poc_enable (vm, fd, mode, shim_fd, block_ip4_dst_set, block_ip4_dst,
			 polling_thread_index);
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
  if (!err)
    tun_poc_main.completion_fault_budget = completion_eagain_budget;
  return err;
}

VLIB_CLI_COMMAND (tun_poc_enable_command, static) = {
  .path = "tun-poc enable",
  .short_help =
    "tun-poc enable fd <n> "
    "[mode count-only|reflect-icmp|forward-fd|handoff-probe|"
    "handoff-forward-fd|direct-owner|direct-owner-fault|direct-owner-return|"
    "direct-owner-single-writer|fragment-owner] [completion-eagain <n>] "
    "[shim-fd <n>] [resolver-fd <n>] [target-thread <n>] "
    "[redirect-thread <n>] [polling-thread <n>] "
    "[block-owner-uid <uid>] [owner-cache] [block-ip4-dst <addr>] "
    "[block-ip6-dst <addr>]",
  .function = tun_poc_enable_command_fn,
};

static clib_error_t *
tun_poc_stage_command_fn (vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *cmd)
{
  u8 *stage = 0;

  (void) cmd;
  if (!unformat (input, "%s", &stage) || !stage || !stage[0])
    {
      vec_free (stage);
      return clib_error_return (0, "stage is required");
    }

  snprintf (tun_poc_main.ledger_stage_id,
            sizeof (tun_poc_main.ledger_stage_id), "%s", (char *) stage);
  /*
   * Admission is a per-stage ledger fact.  The Android VPN can emit a
   * startup/control packet before the runner installs its registered stage;
   * if that packet consumes the one-shot guard, the first real transport
   * packet in the stage has no durable TRANSPORT_ADMITTED evidence.  Reset
   * only the stage-scoped admission guard here; packet counters and resolver
   * state remain session-scoped.
   */
  tun_poc_main.ledger_admitted_logged = 0;
  tun_poc_main.strict_owner_pending =
    strncmp ((char *) stage, "A2-5", 4) == 0;
  vec_free (stage);
  vlib_cli_output (vm, "stage %s strict-owner-pending %u",
                   tun_poc_main.ledger_stage_id,
                   tun_poc_main.strict_owner_pending);
  return 0;
}

VLIB_CLI_COMMAND (tun_poc_stage_command, static) = {
  .path = "tun-poc stage",
  .short_help = "tun-poc stage <stage-id>",
  .function = tun_poc_stage_command_fn,
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
  u32 direct_target_workers = 0;

  (void) input;
  (void) cmd;

  for (u32 i = 0; i < TUN_POC_MAX_DIRECT_WORKERS; i++)
    if (tm->direct_target_worker_mask & (1ULL << i))
      direct_target_workers++;

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
  vlib_cli_output (vm, "polling-thread main %u shim %u",
		   tm->polling_thread_index, tm->shim_polling_thread_index);
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
    "direct workers %u target-workers %u enqueued %llu bytes %llu "
    "congestion-drops %llu alloc-errors %llu parse-errors %llu",
    tm->direct_worker_count, direct_target_workers,
    tm->direct_enqueued_packets, tm->direct_enqueued_bytes,
    tm->direct_congestion_drops, tm->direct_alloc_errors,
    tm->direct_parse_errors);
  vlib_cli_output (
    vm,
    "direct owner-guard pass %llu mismatch %llu reverse-matches %llu "
    "reverse-owner-mismatch %llu reverse-projection-matches %llu "
    "reverse-projection-mismatch %llu corrective-handoff %llu "
    "corrective-drop %llu second-mismatch-drop %llu fault-injected %llu "
    "single-completed %llu",
    tm->direct_owner_guard_pass, tm->direct_owner_guard_mismatch,
    tm->direct_reverse_matches, tm->direct_reverse_owner_mismatch,
    tm->direct_reverse_projection_matches,
    tm->direct_reverse_projection_mismatch, tm->direct_corrective_handoffs,
    tm->direct_corrective_drops, tm->direct_second_mismatch_drops,
    tm->direct_fault_injected, tm->direct_fault_single_completed);
  vlib_cli_output (
    vm,
    "direct worker-hits t0 %llu t1 %llu t2 %llu t3 %llu "
    "bytes t0 %llu t1 %llu t2 %llu t3 %llu",
    tm->direct_worker_packets[0], tm->direct_worker_packets[1],
    tm->direct_worker_packets[2], tm->direct_worker_packets[3],
    tm->direct_worker_bytes[0], tm->direct_worker_bytes[1],
    tm->direct_worker_bytes[2], tm->direct_worker_bytes[3]);
  vlib_cli_output (
    vm,
    "direct return enqueued %llu bytes %llu congestion-drops %llu "
    "worker-packets %llu bytes %llu tx %llu bytes %llu",
    tm->direct_return_enqueued_packets, tm->direct_return_enqueued_bytes,
    tm->direct_return_congestion_drops, tm->direct_return_worker_packets,
    tm->direct_return_worker_bytes, tm->direct_return_tx_packets,
    tm->direct_return_tx_bytes);
  vlib_cli_output (
    vm,
    "fragment packets %llu bytes %llu first %llu nonfirst %llu last %llu",
    tm->fragment_packets, tm->fragment_bytes, tm->fragment_first_packets,
    tm->fragment_nonfirst_packets, tm->fragment_last_packets);
  vlib_cli_output (
    vm,
    "fragment malformed %llu capacity-drops %llu timeout-drops %llu "
    "overlap-drops %llu duplicate-drops %llu terminal-drops %llu evictions %llu",
    tm->fragment_malformed, tm->fragment_capacity_drops,
    tm->fragment_timeout_drops, tm->fragment_overlap_drops,
    tm->fragment_duplicate_drops, tm->fragment_terminal_drops,
    tm->fragment_table_evictions);
  vlib_cli_output (
    vm,
    "fragment owner-guard pass %llu mismatch %llu transitions %llu "
    "reassembly-success %llu owner-mask 0x%llx",
    tm->fragment_owner_guard_pass, tm->fragment_owner_guard_mismatch,
    tm->fragment_flow_owner_transitions, tm->fragment_reassembly_success,
    tm->fragment_owner_mask);
  vlib_cli_output (
    vm,
    "completion target-thread %u fq %u enqueued %llu bytes %llu "
    "processed %llu bytes %llu eagain-drops %llu terminal-drops %llu",
    tm->completion_target_thread, tm->completion_frame_queue_index,
    tm->completion_enqueued_packets, tm->completion_enqueued_bytes,
    tm->completion_processed_packets, tm->completion_processed_bytes,
    tm->completion_eagain_drops, tm->completion_terminal_drops);
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
  vlib_cli_output (vm, "a2-5 strict-owner-pending %u stage %s",
                   tm->strict_owner_pending,
                   tm->ledger_stage_id[0] ? tm->ledger_stage_id : "environment");
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
