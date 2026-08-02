/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Throwaway Android NFQUEUE balance instrument.  This deliberately lives in
 * the POC plugin and has no production API. Phase P2a keeps every socket on
 * VPP main; P2b optionally binds a lane fd to a worker to measure execution
 * topology before any corrective handoff is attempted.
 */

#define _GNU_SOURCE

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vlib/threads.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <sched.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define NFQB_MAX_LANES 4
#define NFQB_FLOW_CAPACITY 4096
#define NFQB_RX_SIZE 65536
#define NFQB_COPY_RANGE 256
#define NFQB_MAGIC 0x4e465142u
#define NFQB_DRAIN_BUDGET 64
#define NFQB_HASH_SEED 0x1234ULL
#define NFQB_HASH_VERSION 1

typedef struct
{
  u8 valid;
  u8 first_lane;
  u8 lane_mask;
  u8 canonical_owner;
  u32 epoch;
  u32 flow_id;
  u32 last_sequence;
  u64 packets;
} nfqb_flow_t;

typedef struct nfqb_main nfqb_main_t;

typedef struct
{
  nfqb_main_t *bm;
  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  u32 file_index;
  u32 callback_thread_index;
  u32 expected_thread_index;
  u32 callback_tid;
  i32 callback_cpu;
  u32 first_callback_tid;
  i32 first_callback_cpu;
  u16 queue_num;
  u8 index;
  int fd;
  u64 callback_calls;
  u64 recv_calls;
  u64 recv_bytes;
  u64 recv_eagain;
  u64 recv_enobufs;
  u64 recv_eintr;
  u64 recv_errors;
  u64 drain_budget_yields;
  u64 handle_errors;
  u64 packet_callbacks;
  u64 marked_packets;
  u64 missing_id;
  u64 missing_marker;
  u64 flow_inserts;
  u64 flow_table_full;
  u64 sequence_duplicates;
  u64 sequence_reorders;
  u64 sequence_gaps;
  u64 projected_local_packets;
  u64 projected_handoff_packets;
  u64 callback_thread_mismatches;
  u64 callback_tid_changes;
  u64 callback_cpu_changes;
  u64 verdict_calls;
  u64 verdict_errors;
  u64 verdict_eagain;
  u64 verdict_enobufs;
  nfqb_flow_t flows[NFQB_FLOW_CAPACITY];
} nfqb_lane_t;

struct nfqb_main
{
  u8 enabled;
  u8 lanes;
  u8 owners;
  u8 worker_polling;
  u16 base_queue;
  u32 queue_maxlen;
  nfqb_lane_t lane[NFQB_MAX_LANES];
};

static nfqb_main_t nfqb_main;

typedef struct
{
  u8 src[4];
  u8 dst[4];
  u16 src_port;
  u16 dst_port;
  u8 proto;
  u8 valid;
  u32 epoch;
  u32 flow_id;
  u32 sequence;
  u8 marked;
} nfqb_packet_t;

static_always_inline u32
nfqb_read_be_u32 (const u8 *p)
{
  u32 value;

  clib_memcpy (&value, p, sizeof (value));
  return clib_net_to_host_u32 (value);
}

static void
nfqb_parse_packet (struct nfq_data *nfa, nfqb_packet_t *packet)
{
  unsigned char *payload = 0;
  int length;
  u32 ihl;
  const u8 *udp_payload;

  clib_memset (packet, 0, sizeof (*packet));
  length = nfq_get_payload (nfa, &payload);
  if (length < 28 || !payload || (payload[0] >> 4) != 4)
    return;

  ihl = (payload[0] & 0x0f) * 4;
  if (ihl < 20 || length < (int) ihl + 8 || payload[9] != IPPROTO_UDP)
    return;

  clib_memcpy (packet->src, payload + 12, 4);
  clib_memcpy (packet->dst, payload + 16, 4);
  packet->proto = payload[9];
  packet->src_port = clib_net_to_host_u16 (*(u16 *) (payload + ihl));
  packet->dst_port = clib_net_to_host_u16 (*(u16 *) (payload + ihl + 2));
  packet->valid = 1;

  if (length < (int) ihl + 8 + 16)
    return;
  udp_payload = payload + ihl + 8;
  if (nfqb_read_be_u32 (udp_payload) != NFQB_MAGIC)
    return;
  packet->epoch = nfqb_read_be_u32 (udp_payload + 4);
  packet->flow_id = nfqb_read_be_u32 (udp_payload + 8);
  packet->sequence = nfqb_read_be_u32 (udp_payload + 12);
  packet->marked = 1;
}

static u64
nfqb_canonical_hash (const nfqb_packet_t *packet)
{
  const u8 *left = packet->src;
  const u8 *right = packet->dst;
  u16 left_port = packet->src_port;
  u16 right_port = packet->dst_port;
  u8 left_address[16] = { 0 };
  u8 right_address[16] = { 0 };
  u8 key[1 + 1 + 16 + 1 + 16 + 2 + 2];
  u8 *p = key;
  u64 hash = 14695981039346656037ULL ^ NFQB_HASH_SEED;

  if (memcmp (left, right, 4) > 0 ||
      (memcmp (left, right, 4) == 0 && left_port > right_port))
    {
      left = packet->dst;
      right = packet->src;
      left_port = packet->dst_port;
      right_port = packet->src_port;
    }

  *p++ = packet->proto;
  clib_memcpy (left_address, left, 4);
  clib_memcpy (right_address, right, 4);
  *p++ = 0; /* Flow::AddressFamily::Ipv4 */
  for (u32 i = 0; i < sizeof (left_address); i++)
    *p++ = left_address[i];
  *p++ = 0; /* Flow::AddressFamily::Ipv4 */
  for (u32 i = 0; i < sizeof (right_address); i++)
    *p++ = right_address[i];
  *p++ = (u8) (left_port >> 8);
  *p++ = (u8) left_port;
  *p++ = (u8) (right_port >> 8);
  *p++ = (u8) right_port;
  for (u32 i = 0; i < sizeof (key); i++)
    {
      hash ^= key[i];
      hash *= 1099511628211ULL;
    }
  return hash;
}

static u32
nfqb_canonical_owner (const nfqb_main_t *bm, const nfqb_packet_t *packet)
{
  return (u32) (nfqb_canonical_hash (packet) % bm->owners);
}

static nfqb_flow_t *
nfqb_get_flow (nfqb_lane_t *lane, const nfqb_packet_t *packet,
	       u8 canonical_owner)
{
  u32 start = (packet->flow_id * 2654435761u + packet->epoch) &
	      (NFQB_FLOW_CAPACITY - 1);

  for (u32 probe = 0; probe < NFQB_FLOW_CAPACITY; probe++)
    {
      nfqb_flow_t *flow =
	&lane->flows[(start + probe) & (NFQB_FLOW_CAPACITY - 1)];

      if (!flow->valid)
	{
	  flow->valid = 1;
	  flow->first_lane = lane->index;
	  flow->lane_mask = (u8) (1u << lane->index);
	  flow->canonical_owner = canonical_owner;
	  flow->epoch = packet->epoch;
	  flow->flow_id = packet->flow_id;
	  flow->last_sequence = packet->sequence;
	  flow->packets = 0;
	  lane->flow_inserts++;
	  return flow;
	}
      if (flow->epoch == packet->epoch && flow->flow_id == packet->flow_id)
	return flow;
    }

  lane->flow_table_full++;
  return 0;
}

static void
nfqb_record_marked_packet (nfqb_lane_t *lane, const nfqb_packet_t *packet)
{
  nfqb_main_t *bm = lane->bm;
  u8 owner = (u8) nfqb_canonical_owner (bm, packet);
  nfqb_flow_t *flow = nfqb_get_flow (lane, packet, owner);

  lane->marked_packets++;
  if ((lane->index % bm->owners) == owner)
    lane->projected_local_packets++;
  else
    lane->projected_handoff_packets++;

  if (!flow)
    return;

  if (flow->packets > 0)
    {
      if (packet->sequence == flow->last_sequence)
	lane->sequence_duplicates++;
      else if (packet->sequence < flow->last_sequence)
	lane->sequence_reorders++;
      else if (packet->sequence > flow->last_sequence + 1)
	lane->sequence_gaps += packet->sequence - flow->last_sequence - 1;

      if (packet->sequence > flow->last_sequence)
	flow->last_sequence = packet->sequence;
    }

  flow->lane_mask |= (u8) (1u << lane->index);
  flow->packets++;
}

static int
nfqb_packet_cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
  nfqb_lane_t *lane = data;
  struct nfqnl_msg_packet_hdr *header;
  nfqb_packet_t packet;
  u32 packet_id;

  (void) nfmsg;
  lane->packet_callbacks++;
  header = nfq_get_msg_packet_hdr (nfa);
  if (!header)
    {
      lane->missing_id++;
      return 0;
    }

  packet_id = clib_net_to_host_u32 (header->packet_id);
  nfqb_parse_packet (nfa, &packet);
  if (packet.marked)
    nfqb_record_marked_packet (lane, &packet);
  else
    lane->missing_marker++;

  lane->verdict_calls++;
  if (nfq_set_verdict (qh, packet_id, NF_ACCEPT, 0, 0) < 0)
    {
      lane->verdict_errors++;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
	lane->verdict_eagain++;
      else if (errno == ENOBUFS)
	lane->verdict_enobufs++;
    }
  return 0;
}

static clib_error_t *
nfqb_read_ready (clib_file_t *f)
{
  nfqb_lane_t *lane = (nfqb_lane_t *) f->private_data;
  u8 buffer[NFQB_RX_SIZE];

  lane->callback_calls++;
  lane->callback_thread_index = vlib_get_thread_index ();
  lane->callback_tid = (u32) syscall (SYS_gettid);
  lane->callback_cpu = sched_getcpu ();
  if (lane->first_callback_tid == 0)
    {
      lane->first_callback_tid = lane->callback_tid;
      lane->first_callback_cpu = lane->callback_cpu;
    }
  else
    {
      if (lane->callback_tid != lane->first_callback_tid)
	lane->callback_tid_changes++;
      if (lane->callback_cpu != lane->first_callback_cpu)
	lane->callback_cpu_changes++;
    }
  if (lane->callback_thread_index != lane->expected_thread_index)
    lane->callback_thread_mismatches++;

  for (u32 drained = 0; drained < NFQB_DRAIN_BUDGET; drained++)
    {
      int rv;

      lane->recv_calls++;
      rv = recv (lane->fd, buffer, sizeof (buffer), MSG_DONTWAIT);
      if (rv >= 0)
	{
	  lane->recv_bytes += (u64) rv;
	  if (nfq_handle_packet (lane->handle, (char *) buffer, rv) < 0)
	    {
	      lane->handle_errors++;
	      return clib_error_return (0,
				"nfqueue-balance handle failed lane %u",
				lane->index);
	    }
	  continue;
	}
      if (errno == EAGAIN || errno == EWOULDBLOCK)
	{
	  lane->recv_eagain++;
	  return 0;
	}
      if (errno == EINTR)
	{
	  lane->recv_eintr++;
	  continue;
	}
      if (errno == ENOBUFS)
	{
	  lane->recv_enobufs++;
	  return 0;
	}
      lane->recv_errors++;
      return clib_error_return_unix (0, "nfqueue-balance recv lane %u",
				      lane->index);
    }
  lane->drain_budget_yields++;
  return 0;
}

static void
nfqb_stop (nfqb_main_t *bm)
{
  vlib_main_t *vm;

  if (!bm->enabled)
    return;

  vm = vlib_get_main ();
  if (vlib_num_workers ())
    vlib_worker_thread_barrier_sync (vm);
  for (u32 i = 0; i < NFQB_MAX_LANES; i++)
    {
      nfqb_lane_t *lane = &bm->lane[i];

      if (lane->file_index != ~0)
	{
	  clib_file_del_by_index (&file_main, lane->file_index);
	  lane->file_index = ~0;
	}
      if (lane->queue)
	{
	  nfq_destroy_queue (lane->queue);
	  lane->queue = 0;
	}
      if (lane->handle)
	{
	  nfq_close (lane->handle);
	  lane->handle = 0;
	}
      lane->fd = -1;
    }
  bm->enabled = 0;
  if (vlib_num_workers ())
    vlib_worker_thread_barrier_release (vm);
}

static clib_error_t *
nfqb_start (nfqb_main_t *bm, u16 base_queue, u8 lanes, u8 owners,
	    u32 queue_maxlen, u8 worker_polling)
{
  clib_error_t *error = 0;

  if (bm->enabled)
    return clib_error_return (0, "nfqueue-balance-poc already enabled");
  if (lanes < 1 || lanes > NFQB_MAX_LANES)
    return clib_error_return (0, "lanes must be 1..%u", NFQB_MAX_LANES);
  if (owners < 1 || owners > NFQB_MAX_LANES)
    return clib_error_return (0, "owners must be 1..%u", NFQB_MAX_LANES);
  if ((u32) base_queue + lanes - 1 > 65535)
    return clib_error_return (0, "queue range exceeds 65535");
  if (worker_polling && owners > vlib_num_workers ())
    return clib_error_return (0, "worker polling needs at least %u workers",
			      owners);

  clib_memset (bm, 0, sizeof (*bm));
  bm->enabled = 1;
  bm->lanes = lanes;
  bm->owners = owners;
  bm->worker_polling = worker_polling;
  bm->base_queue = base_queue;
  bm->queue_maxlen = queue_maxlen;
  for (u32 i = 0; i < NFQB_MAX_LANES; i++)
    {
      bm->lane[i].bm = bm;
      bm->lane[i].index = (u8) i;
      bm->lane[i].file_index = ~0;
      bm->lane[i].fd = -1;
      bm->lane[i].callback_cpu = -1;
      bm->lane[i].first_callback_cpu = -1;
      bm->lane[i].expected_thread_index =
	worker_polling ? 1 + (i % owners) : 0;
    }

  for (u32 i = 0; i < lanes; i++)
    {
      nfqb_lane_t *lane = &bm->lane[i];
      clib_file_t file = { 0 };
      int flags;

      lane->queue_num = (u16) (base_queue + i);
      lane->handle = nfq_open ();
      if (!lane->handle)
	{
	  error = clib_error_return_unix (0, "nfq_open lane %u", i);
	  goto fail;
	}
      if (nfq_bind_pf (lane->handle, AF_INET) < 0)
	{
	  error = clib_error_return_unix (0, "nfq_bind_pf lane %u", i);
	  goto fail;
	}
      lane->queue = nfq_create_queue (lane->handle, lane->queue_num,
				      nfqb_packet_cb, lane);
      if (!lane->queue)
	{
	  error = clib_error_return_unix (0, "nfq_create_queue lane %u", i);
	  goto fail;
	}
      if (nfq_set_mode (lane->queue, NFQNL_COPY_PACKET, NFQB_COPY_RANGE) < 0 ||
	  nfq_set_queue_maxlen (lane->queue, queue_maxlen) < 0)
	{
	  error = clib_error_return_unix (0, "configure queue lane %u", i);
	  goto fail;
	}

      lane->fd = nfq_fd (lane->handle);
      flags = fcntl (lane->fd, F_GETFL, 0);
      if (flags < 0 || fcntl (lane->fd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
	  error = clib_error_return_unix (0, "nonblocking lane %u", i);
	  goto fail;
	}

      file.read_function = nfqb_read_ready;
      file.file_descriptor = lane->fd;
      file.private_data = (uword) lane;
      file.polling_thread_index = lane->expected_thread_index;
      file.dont_close = 1;
      file.description = format (0, "nfqueue-balance-poc lane %u", i);
      lane->file_index = clib_file_add (&file_main, &file);
    }
  return 0;

fail:
  nfqb_stop (bm);
  return error;
}

static clib_error_t *
nfqb_start_command (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  u32 base_queue = 60;
  u32 lanes = 2;
  u32 owners = 2;
  u32 queue_maxlen = 4096;
  u8 worker_polling = 0;

  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &base_queue))
	;
      else if (unformat (input, "lanes %u", &lanes))
	;
      else if (unformat (input, "owners %u", &owners))
	;
      else if (unformat (input, "queue-maxlen %u", &queue_maxlen))
	;
      else if (unformat (input, "polling workers"))
	worker_polling = 1;
      else if (unformat (input, "polling main"))
	worker_polling = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  if (base_queue > 65535 || lanes > 255 || owners > 255 || queue_maxlen == 0)
    return clib_error_return (0, "invalid numeric argument");
  return nfqb_start (&nfqb_main, (u16) base_queue, (u8) lanes, (u8) owners,
		     queue_maxlen, worker_polling);
}

VLIB_CLI_COMMAND (nfqb_start_cli, static) = {
  .path = "nfqueue-balance-poc start",
  .short_help = "nfqueue-balance-poc start [queue <n>] [lanes <1..4>] "
		"[owners <1..4>] [queue-maxlen <n>] [polling main|workers]",
  .function = nfqb_start_command,
};

static clib_error_t *
nfqb_stop_command (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;
  nfqb_stop (&nfqb_main);
  return 0;
}

VLIB_CLI_COMMAND (nfqb_stop_cli, static) = {
  .path = "nfqueue-balance-poc stop",
  .short_help = "nfqueue-balance-poc stop",
  .function = nfqb_stop_command,
};

static clib_error_t *
nfqb_show_command (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  nfqb_main_t *bm = &nfqb_main;
  u64 packets = 0;
  u64 marked_packets = 0;
  u64 missing_id = 0;
  u64 missing_marker = 0;
  u64 unique_flows = 0;
  u64 flow_table_full = 0;
  u64 migration_flows = 0;
  u64 migration_packets = 0;
  u64 migration_owner_mismatches = 0;
  u64 sequence_duplicates = 0;
  u64 sequence_reorders = 0;
  u64 sequence_gaps = 0;
  u64 projected_local_packets = 0;
  u64 projected_handoff_packets = 0;
  u64 projected_local_flows = 0;
  u64 projected_handoff_flows = 0;
  u64 verdicts = 0;
  nfqb_packet_t golden = {
    .src = { 192, 0, 2, 1 },
    .dst = { 198, 51, 100, 2 },
    .src_port = 12345,
    .dst_port = 443,
    .proto = IPPROTO_UDP,
    .valid = 1,
  };
  nfqb_packet_t golden_reverse = golden;
  u8 golden_address[4];
  u16 golden_port;

  (void) input;
  (void) cmd;
  if (!bm->enabled)
    {
      vlib_cli_output (vm, "nfqb enabled 0");
      return 0;
    }
  if (vlib_num_workers ())
    vlib_worker_thread_barrier_sync (vm);
  for (u32 lane_index = 0; lane_index < bm->lanes; lane_index++)
    {
      nfqb_lane_t *lane = &bm->lane[lane_index];

      packets += lane->packet_callbacks;
      marked_packets += lane->marked_packets;
      missing_id += lane->missing_id;
      missing_marker += lane->missing_marker;
      flow_table_full += lane->flow_table_full;
      sequence_duplicates += lane->sequence_duplicates;
      sequence_reorders += lane->sequence_reorders;
      sequence_gaps += lane->sequence_gaps;
      projected_local_packets += lane->projected_local_packets;
      projected_handoff_packets += lane->projected_handoff_packets;
      verdicts += lane->verdict_calls - lane->verdict_errors;

      for (u32 flow_index = 0; flow_index < NFQB_FLOW_CAPACITY;
	   flow_index++)
	{
	  nfqb_flow_t *flow = &lane->flows[flow_index];
	  u64 migrated = 0;

	  if (!flow->valid)
	    continue;
	  for (u32 earlier = 0; earlier < lane_index; earlier++)
	    {
	      nfqb_lane_t *other = &bm->lane[earlier];
	      u32 start = (flow->flow_id * 2654435761u + flow->epoch) &
			  (NFQB_FLOW_CAPACITY - 1);

	      for (u32 probe = 0; probe < NFQB_FLOW_CAPACITY; probe++)
		{
		  nfqb_flow_t *candidate =
		    &other->flows[(start + probe) & (NFQB_FLOW_CAPACITY - 1)];
		  if (!candidate->valid)
		    break;
		  if (candidate->epoch == flow->epoch &&
		      candidate->flow_id == flow->flow_id)
		    {
		      migrated = flow->packets;
		      break;
		    }
		}
	      if (migrated)
		break;
	    }
	  if (migrated)
	    {
	      migration_packets += migrated;
	      continue;
	    }
	  unique_flows++;
	  if ((lane_index % bm->owners) == flow->canonical_owner)
	    projected_local_flows++;
	  else
	    projected_handoff_flows++;
	  for (u32 later = lane_index + 1; later < bm->lanes; later++)
	    {
	      nfqb_lane_t *other = &bm->lane[later];
	      u8 found_later = 0;
	      u32 start = (flow->flow_id * 2654435761u + flow->epoch) &
			  (NFQB_FLOW_CAPACITY - 1);

	      for (u32 probe = 0; probe < NFQB_FLOW_CAPACITY; probe++)
		{
		  nfqb_flow_t *candidate =
		    &other->flows[(start + probe) & (NFQB_FLOW_CAPACITY - 1)];
		  if (!candidate->valid)
		    break;
		  if (candidate->epoch == flow->epoch &&
		      candidate->flow_id == flow->flow_id)
		    {
		      migration_flows++;
		      if (candidate->canonical_owner != flow->canonical_owner)
			migration_owner_mismatches++;
		      found_later = 1;
		      break;
		    }
		}
	      if (found_later)
		break;
	    }
	}
    }

  vlib_cli_output (
    vm, "nfqb enabled %u topology %s queue %u lanes %u owners %u "
	"packets %llu marked %llu verdict-debt %llu missing-id %llu "
	"missing-marker %llu",
    bm->enabled, bm->worker_polling ? "worker-callback" : "main-callback",
    bm->base_queue, bm->lanes, bm->owners, packets, marked_packets,
    packets >= verdicts ? packets - verdicts : 0, missing_id, missing_marker);
  vlib_cli_output (
    vm, "nfqb flows %llu table-full %llu migration-flows %llu "
	"migration-packets %llu migration-owner-mismatches %llu "
	"duplicates %llu reorders %llu gaps %llu",
    unique_flows, flow_table_full, migration_flows,
    migration_packets, migration_owner_mismatches, sequence_duplicates,
    sequence_reorders, sequence_gaps);
  vlib_cli_output (
    vm, "nfqb projection local-packets %llu handoff-packets %llu "
	"local-flows %llu handoff-flows %llu",
    projected_local_packets, projected_handoff_packets,
    projected_local_flows, projected_handoff_flows);
  clib_memcpy (golden_address, golden_reverse.src, 4);
  clib_memcpy (golden_reverse.src, golden_reverse.dst, 4);
  clib_memcpy (golden_reverse.dst, golden_address, 4);
  golden_port = golden_reverse.src_port;
  golden_reverse.src_port = golden_reverse.dst_port;
  golden_reverse.dst_port = golden_port;
  vlib_cli_output (vm, "nfqb golden version %u seed %llu hash %llu "
		       "reverse-hash %llu",
		   NFQB_HASH_VERSION, NFQB_HASH_SEED,
		   nfqb_canonical_hash (&golden),
		   nfqb_canonical_hash (&golden_reverse));
  for (u32 i = 0; i < bm->lanes; i++)
    {
      nfqb_lane_t *lane = &bm->lane[i];
      vlib_cli_output (
	vm, "nfqb lane %u queue %u packets %llu marked %llu flows %llu "
	    "callbacks %llu recv-calls %llu recv-bytes %llu eagain %llu "
	    "eintr %llu enobufs %llu recv-errors %llu drain-yields %llu "
	    "handle-errors %llu "
	    "verdict-calls %llu verdict-errors %llu verdict-eagain %llu "
	    "verdict-enobufs %llu thread %u expected-thread %u "
	    "thread-mismatches %llu tid %u cpu %d first-tid %u first-cpu %d "
	    "tid-changes %llu cpu-changes %llu",
	i, lane->queue_num, lane->packet_callbacks, lane->marked_packets,
	lane->flow_inserts, lane->callback_calls, lane->recv_calls,
	lane->recv_bytes, lane->recv_eagain, lane->recv_eintr,
	lane->recv_enobufs, lane->recv_errors, lane->drain_budget_yields,
	lane->handle_errors,
	lane->verdict_calls, lane->verdict_errors, lane->verdict_eagain,
	lane->verdict_enobufs, lane->callback_thread_index,
	lane->expected_thread_index, lane->callback_thread_mismatches,
	lane->callback_tid, lane->callback_cpu, lane->first_callback_tid,
	lane->first_callback_cpu, lane->callback_tid_changes,
	lane->callback_cpu_changes);
    }
  if (vlib_num_workers ())
    vlib_worker_thread_barrier_release (vm);
  return 0;
}

VLIB_CLI_COMMAND (nfqb_show_cli, static) = {
  .path = "show nfqueue-balance-poc",
  .short_help = "show nfqueue-balance-poc",
  .function = nfqb_show_command,
};
