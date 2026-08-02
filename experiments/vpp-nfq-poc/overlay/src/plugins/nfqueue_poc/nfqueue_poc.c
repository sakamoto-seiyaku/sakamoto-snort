/* SPDX-License-Identifier: Apache-2.0 */

#include <nfqueue_poc/nfqueue_poc.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define NFQUEUE_POC_RX_BUF_SIZE 65536
/* The POC only parses the network-layer header; do not copy full packets. */
#define NFQUEUE_POC_COPY_RANGE 512
#define NFQUEUE_POC_ASYNC_WORKERS 2

typedef enum
{
  NFQUEUE_POC_ASYNC_LEASE_FREE,
  NFQUEUE_POC_ASYNC_LEASE_PENDING,
  NFQUEUE_POC_ASYNC_LEASE_PROCESSING,
  NFQUEUE_POC_ASYNC_LEASE_COMPLETE,
} nfqueue_poc_async_lease_state_t;

nfqueue_poc_main_t nfqueue_poc_main = {
  .fd = -1,
  .async_completion_file_index = ~0,
};

static clib_error_t *nfqueue_poc_async_start (nfqueue_poc_main_t *nm);
static void nfqueue_poc_async_stop (nfqueue_poc_main_t *nm);
static clib_error_t *nfqueue_poc_async_completion_read_ready (clib_file_t *f);
static clib_error_t *nfqueue_poc_configure_queue (struct nfq_q_handle *queue,
						 u32 queue_maxlen);
static clib_error_t *nfqueue_poc_two_lane_start (nfqueue_poc_main_t *nm,
						 u16 base_queue);
static void nfqueue_poc_two_lane_stop (nfqueue_poc_main_t *nm);
static clib_error_t *nfqueue_poc_two_lane_fd_read_ready (clib_file_t *f);

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
    case NFQUEUE_POC_MODE_ASYNC_LEASE:
      return format (s, "async-lease");
    case NFQUEUE_POC_MODE_TWO_LANE:
      return format (s, "two-lane");
    case NFQUEUE_POC_MODE_LANE_MATRIX:
      return format (s, "lane-matrix");
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
  u8 src_valid;
  u8 dst_valid;
  u8 ports_valid;
  u8 reserved;
  u16 src_port;
  u16 dst_port;
  u8 src[16];
  u8 dst[16];
} nfqueue_poc_packet_facts_t;

typedef struct
{
  nfqueue_poc_main_t *nm;
  u8 lane_index;
  u16 queue_num;
  struct nfq_handle *handle;
  struct nfq_q_handle *queue;
  int fd;
  u32 file_index;
  u64 lane_generation;
} nfqueue_poc_two_lane_t;

typedef struct
{
  nfqueue_poc_two_lane_t lanes[NFQUEUE_POC_LANE_MATRIX_MAX];
} nfqueue_poc_two_lane_state_t;

typedef struct
{
  u64 lane_generation;
  u16 queue_num;
  u16 reserved;
  u32 packet_id;
  u32 slot;
  u64 sequence;
  u32 verdict;
  u8 state;
  u8 verdict_sent;
  u8 result_refs;
  u8 reserved2;
  nfqueue_poc_packet_facts_t facts;
} nfqueue_poc_async_lease_t;

typedef struct
{
  u64 lane_generation;
  u16 queue_num;
  u16 kind;
  u32 packet_id;
  u32 slot;
  u32 verdict;
  u64 sequence;
} nfqueue_poc_async_result_t;

typedef struct
{
  pthread_mutex_t lock;
  pthread_cond_t cond;
  u8 stopping;
  u8 duplicate_injected;
  u8 stale_injected;
  u8 missing_injected;
  u32 head;
  u32 tail;
  u32 queue_count;
  u32 used_count;
  u64 next_sequence;
  u64 last_completion_sequence;
  int completion_pipe[2];
  pthread_t workers[NFQUEUE_POC_ASYNC_WORKERS];
  nfqueue_poc_async_lease_t leases[NFQUEUE_POC_ASYNC_LEASE_CAPACITY];
  nfqueue_poc_main_t *nm;
} nfqueue_poc_async_state_t;

#define NFQUEUE_POC_ASYNC_RESULT_NORMAL 0
#define NFQUEUE_POC_ASYNC_RESULT_DEADLINE 1

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
      u32 ihl = (payload[0] & 0x0f) * 4;
      if (ihl < 20 || facts->payload_len < (int) ihl)
	return;
      facts->proto = payload[9];
      clib_memcpy (facts->src, payload + 12, 4);
      clib_memcpy (facts->dst, payload + 16, 4);
      facts->src_valid = 1;
      facts->dst_valid = 1;
      if ((facts->proto == IPPROTO_TCP || facts->proto == IPPROTO_UDP) &&
	  facts->payload_len >= (int) ihl + 4)
	{
	  facts->src_port = clib_net_to_host_u16 (*(u16 *) (payload + ihl));
	  facts->dst_port = clib_net_to_host_u16 (*(u16 *) (payload + ihl + 2));
	  facts->ports_valid = 1;
	}
    }
  else if (facts->ip_version == 6 && facts->payload_len >= 40)
    {
      facts->proto = payload[6];
      clib_memcpy (facts->src, payload + 8, 16);
      clib_memcpy (facts->dst, payload + 24, 16);
      facts->src_valid = 1;
      facts->dst_valid = 1;
      if ((facts->proto == IPPROTO_TCP || facts->proto == IPPROTO_UDP) &&
	  facts->payload_len >= 44)
	{
	  facts->src_port = clib_net_to_host_u16 (*(u16 *) (payload + 40));
	  facts->dst_port = clib_net_to_host_u16 (*(u16 *) (payload + 42));
	  facts->ports_valid = 1;
	}
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
    case NFQUEUE_POC_MODE_ASYNC_LEASE:
      *reason = "async_base_accept";
      return NF_ACCEPT;
    case NFQUEUE_POC_MODE_TWO_LANE:
      *reason = "two_lane_base_accept";
      return NF_ACCEPT;
    case NFQUEUE_POC_MODE_LANE_MATRIX:
      *reason = "lane_matrix_base_accept";
      return NF_ACCEPT;
    }

  *reason = "unknown_mode_drop";
  return NF_DROP;
}

static void
nfqueue_poc_async_write_result (nfqueue_poc_async_state_t *state,
				const nfqueue_poc_async_result_t *result)
{
  ssize_t rv;

  do
    rv = write (state->completion_pipe[1], result, sizeof (*result));
  while (rv < 0 && errno == EINTR);

  if (rv != (ssize_t) sizeof (*result))
    __atomic_fetch_add (&state->nm->async_pipe_errors, 1, __ATOMIC_RELAXED);
  else
    __atomic_fetch_add (&state->nm->async_completion_intents, 1,
				__ATOMIC_RELAXED);
}

static void *
nfqueue_poc_async_worker (void *arg)
{
  nfqueue_poc_async_state_t *state = arg;
  nfqueue_poc_main_t *nm = state->nm;

  while (1)
    {
      nfqueue_poc_async_lease_t *lease;
      nfqueue_poc_async_result_t result = { 0 };
      u64 sequence;
      u32 delay_ms;
      u8 missing = 0;
      u8 stale = 0;
      u8 duplicate = 0;
      const char *reason = 0;
      const char *rule_id = 0;

      pthread_mutex_lock (&state->lock);
      while (state->queue_count == 0 && !state->stopping)
	pthread_cond_wait (&state->cond, &state->lock);
      if (state->queue_count == 0 && state->stopping)
	{
	  pthread_mutex_unlock (&state->lock);
	  break;
	}

      lease = &state->leases[state->head];
      state->head = (state->head + 1) % NFQUEUE_POC_ASYNC_LEASE_CAPACITY;
      state->queue_count--;
      lease->state = NFQUEUE_POC_ASYNC_LEASE_PROCESSING;
      nm->async_worker_dispatches++;
      sequence = lease->sequence;
      delay_ms = nm->async_delay_ms ? nm->async_delay_ms : 5;

      /* Faults are assigned to distinct ingress sequence numbers so one run
       * proves stale, duplicate, and deadline handling independently. */
      if (nm->async_missing_fault && sequence == 1 && !state->missing_injected)
	{
	  state->missing_injected = 1;
	  missing = 1;
	  nm->async_missing_completions++;
	}
      if (nm->async_stale_fault && sequence == 2 && !state->stale_injected)
	{
	  state->stale_injected = 1;
	  stale = 1;
	}
      if (nm->async_duplicate_fault && sequence == 3 &&
	  !state->duplicate_injected)
	{
	  state->duplicate_injected = 1;
	  duplicate = 1;
	}

      lease->verdict = nfqueue_poc_choose_verdict (nm, &lease->facts,
						      &reason, &rule_id);
      lease->result_refs = (u8) (1 + stale + duplicate);
      lease->verdict_sent = 0;
      result.lane_generation = lease->lane_generation;
      result.queue_num = lease->queue_num;
      result.packet_id = lease->packet_id;
      result.slot = lease->slot;
      result.verdict = lease->verdict;
      result.sequence = lease->sequence;
      pthread_mutex_unlock (&state->lock);

      /* Even sequence numbers finish first, making completion reordering
       * observable without changing the owner-selection key. */
      usleep ((useconds_t) delay_ms * (sequence & 1 ? 3 : 1) * 1000);

      if (state->stopping && nm->async_shutdown_fault)
	continue;

      if (missing)
	{
	  usleep ((useconds_t) delay_ms * 2 * 1000);
	  result.kind = NFQUEUE_POC_ASYNC_RESULT_DEADLINE;
	  nfqueue_poc_async_write_result (state, &result);
	  continue;
	}

      if (stale)
	{
	  nfqueue_poc_async_result_t stale_result = result;
	  stale_result.lane_generation++;
	  nfqueue_poc_async_write_result (state, &stale_result);
	}

      nfqueue_poc_async_write_result (state, &result);
      if (duplicate)
	nfqueue_poc_async_write_result (state, &result);
    }

  return 0;
}

static void
nfqueue_poc_async_free_lease (nfqueue_poc_async_state_t *state,
			      nfqueue_poc_async_lease_t *lease)
{
  lease->state = NFQUEUE_POC_ASYNC_LEASE_FREE;
  lease->verdict_sent = 0;
  lease->result_refs = 0;
  if (state->used_count > 0)
    state->used_count--;
}

static void
nfqueue_poc_async_handle_result (nfqueue_poc_main_t *nm,
				 const nfqueue_poc_async_result_t *result)
{
  nfqueue_poc_async_state_t *state = nm->async_state;
  nfqueue_poc_async_lease_t *lease;
  u32 verdict;

  pthread_mutex_lock (&state->lock);
  if (result->slot >= NFQUEUE_POC_ASYNC_LEASE_CAPACITY)
    {
      nm->async_stale_completions++;
      pthread_mutex_unlock (&state->lock);
      return;
    }

  lease = &state->leases[result->slot];
  if (result->lane_generation != nm->async_lane_generation ||
      result->queue_num != nm->queue_num ||
      lease->lane_generation != result->lane_generation)
    {
      nm->async_stale_completions++;
      if (lease->result_refs > 0)
	lease->result_refs--;
      pthread_mutex_unlock (&state->lock);
      return;
    }

  if (lease->state == NFQUEUE_POC_ASYNC_LEASE_FREE ||
      lease->verdict_sent)
    {
      nm->async_duplicate_completions++;
      if (lease->result_refs > 0)
	lease->result_refs--;
      if (lease->state != NFQUEUE_POC_ASYNC_LEASE_FREE &&
	  lease->result_refs == 0)
	nfqueue_poc_async_free_lease (state, lease);
      pthread_mutex_unlock (&state->lock);
      return;
    }

  if (state->last_completion_sequence != 0 &&
      result->sequence < state->last_completion_sequence)
    nm->async_out_of_order++;
  if (result->sequence > state->last_completion_sequence)
    state->last_completion_sequence = result->sequence;

  verdict = result->kind == NFQUEUE_POC_ASYNC_RESULT_DEADLINE ? NF_DROP :
								 result->verdict;
  if (nfq_set_verdict (nm->queue, result->packet_id, verdict, 0, 0) < 0)
    {
      nm->async_verdict_errors++;
      nm->async_last_verdict_errno = errno;
    }
  else
    {
      if (verdict == NF_ACCEPT)
	nm->accepted++;
      else
	nm->dropped++;
      nm->async_terminal_outcomes++;
      if (result->kind == NFQUEUE_POC_ASYNC_RESULT_DEADLINE)
	nm->async_deadline_drops++;
    }

  lease->verdict_sent = 1;
  if (lease->result_refs > 0)
    lease->result_refs--;
  if (lease->result_refs == 0)
    nfqueue_poc_async_free_lease (state, lease);
  pthread_mutex_unlock (&state->lock);
}

static clib_error_t *
nfqueue_poc_async_completion_read_ready (clib_file_t *f)
{
  nfqueue_poc_main_t *nm = (nfqueue_poc_main_t *) f->private_data;
  nfqueue_poc_async_state_t *state = nm->async_state;
  nfqueue_poc_async_result_t result;
  ssize_t rv;

  while (1)
    {
      rv = read (state->completion_pipe[0], &result, sizeof (result));
      if (rv == (ssize_t) sizeof (result))
	{
	  nfqueue_poc_async_handle_result (nm, &result);
	  continue;
	}
      if (rv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
	return 0;
      if (rv < 0 && errno == EINTR)
	continue;
      if (rv == 0)
	return clib_error_return (0, "async completion pipe closed");
      nm->async_pipe_errors++;
      return 0;
    }
}

static clib_error_t *
nfqueue_poc_async_start (nfqueue_poc_main_t *nm)
{
  nfqueue_poc_async_state_t *state;
  clib_file_t template = { 0 };
  u32 i;

  state = clib_mem_alloc_aligned (sizeof (*state), CLIB_CACHE_LINE_BYTES);
  if (!state)
return clib_error_return (0, "failed to allocate async PacketLease state");
  clib_memset (state, 0, sizeof (*state));
  state->completion_pipe[0] = -1;
  state->completion_pipe[1] = -1;
  state->nm = nm;
  if (pthread_mutex_init (&state->lock, 0) != 0 ||
      pthread_cond_init (&state->cond, 0) != 0 ||
      pipe (state->completion_pipe) < 0)
    {
      clib_mem_free (state);
      return clib_error_return_unix (0, "initialize async PacketLease state");
    }
  (void) fcntl (state->completion_pipe[0], F_SETFL,
		fcntl (state->completion_pipe[0], F_GETFL, 0) | O_NONBLOCK);

  for (i = 0; i < NFQUEUE_POC_ASYNC_WORKERS; i++)
    if (pthread_create (&state->workers[i], 0, nfqueue_poc_async_worker,
				state) != 0)
      {
	state->stopping = 1;
	pthread_cond_broadcast (&state->cond);
	for (u32 j = 0; j < i; j++)
	  pthread_join (state->workers[j], 0);
	close (state->completion_pipe[0]);
	close (state->completion_pipe[1]);
	pthread_cond_destroy (&state->cond);
	pthread_mutex_destroy (&state->lock);
	clib_mem_free (state);
	return clib_error_return (0, "start async PacketLease worker");
      }

  nm->async_state = state;
  template.read_function = nfqueue_poc_async_completion_read_ready;
  template.file_descriptor = state->completion_pipe[0];
  template.private_data = (uword) nm;
  template.description = format (0, "nfqueue-poc async completion");
  nm->async_completion_file_index = clib_file_add (&file_main, &template);
  return 0;
}

static void
nfqueue_poc_async_stop (nfqueue_poc_main_t *nm)
{
  nfqueue_poc_async_state_t *state = nm->async_state;

  if (!state)
return;
  if (nm->async_completion_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->async_completion_file_index);
      nm->async_completion_file_index = ~0;
    }

  pthread_mutex_lock (&state->lock);
  state->stopping = 1;
  pthread_cond_broadcast (&state->cond);
  pthread_mutex_unlock (&state->lock);
  for (u32 i = 0; i < NFQUEUE_POC_ASYNC_WORKERS; i++)
    pthread_join (state->workers[i], 0);

  /* Drain completions already produced before closing the original lane. */
  while (1)
    {
      nfqueue_poc_async_result_t result;
      ssize_t rv = read (state->completion_pipe[0], &result, sizeof (result));
      if (rv != (ssize_t) sizeof (result))
	break;
      nfqueue_poc_async_handle_result (nm, &result);
    }

  pthread_mutex_lock (&state->lock);
  for (u32 i = 0; i < NFQUEUE_POC_ASYNC_LEASE_CAPACITY; i++)
    {
      nfqueue_poc_async_lease_t *lease = &state->leases[i];
      if (lease->state == NFQUEUE_POC_ASYNC_LEASE_FREE ||
	  lease->verdict_sent)
	continue;
      if (nfq_set_verdict (nm->queue, lease->packet_id, NF_DROP, 0, 0) < 0)
	{
	  nm->async_verdict_errors++;
	  nm->async_last_verdict_errno = errno;
	}
      else
	{
	 nm->dropped++;
	 nm->async_shutdown_drops++;
	 nm->async_terminal_outcomes++;
	}
      lease->verdict_sent = 1;
      nfqueue_poc_async_free_lease (state, lease);
    }
  pthread_mutex_unlock (&state->lock);

  close (state->completion_pipe[0]);
  close (state->completion_pipe[1]);
  pthread_cond_destroy (&state->cond);
  pthread_mutex_destroy (&state->lock);
  clib_mem_free (state);
  nm->async_state = 0;
}

static int
nfqueue_poc_async_enqueue (nfqueue_poc_main_t *nm, struct nfq_q_handle *qh,
			   u32 id, const nfqueue_poc_packet_facts_t *facts)
{
  nfqueue_poc_async_state_t *state = nm->async_state;
  nfqueue_poc_async_lease_t *lease;

  pthread_mutex_lock (&state->lock);
  if (nm->async_missing_id_fault && nm->async_missing_id_verdicts == 0)
    {
      nm->missing_id++;
      nm->async_missing_id_verdicts++;
      nm->dropped++;
      nm->async_terminal_outcomes++;
      (void) nfq_set_verdict (qh, id, NF_DROP, 0, 0);
      pthread_mutex_unlock (&state->lock);
      return 0;
    }
  if (state->used_count >= NFQUEUE_POC_ASYNC_LEASE_CAPACITY ||
      state->leases[state->tail].state != NFQUEUE_POC_ASYNC_LEASE_FREE)
    {
      nm->async_overload_drops++;
      nm->async_worker_backpressure_drops++;
      nm->dropped++;
      nm->async_terminal_outcomes++;
      (void) nfq_set_verdict (qh, id, NF_DROP, 0, 0);
      pthread_mutex_unlock (&state->lock);
      return 0;
    }

  lease = &state->leases[state->tail];
  clib_memset (lease, 0, sizeof (*lease));
  lease->lane_generation = nm->async_lane_generation;
  lease->queue_num = nm->queue_num;
  lease->packet_id = id;
  lease->slot = state->tail;
  lease->sequence = ++state->next_sequence;
  lease->facts = *facts;
  lease->state = NFQUEUE_POC_ASYNC_LEASE_PENDING;
  state->tail = (state->tail + 1) % NFQUEUE_POC_ASYNC_LEASE_CAPACITY;
  state->queue_count++;
  state->used_count++;
  nm->async_ingress_leases++;
  if (state->used_count > nm->async_pending_peak)
    nm->async_pending_peak = state->used_count;
  pthread_cond_signal (&state->cond);
  pthread_mutex_unlock (&state->lock);
  return 0;
}

static u32
nfqueue_poc_two_lane_owner (nfqueue_poc_main_t *nm,
			    const nfqueue_poc_packet_facts_t *facts)
{
  const u8 *left = facts->src;
  const u8 *right = facts->dst;
  u16 left_port = facts->src_port;
  u16 right_port = facts->dst_port;
  u32 width = facts->ip_version == 6 ? 16 : 4;
  u32 hash = 2166136261u;

  /* Direction-independent key: queue/lane is deliberately absent. */
  if (facts->src_valid && facts->dst_valid &&
      memcmp (left, right, width) > 0)
    {
      left = facts->dst;
      right = facts->src;
      left_port = facts->dst_port;
      right_port = facts->src_port;
    }
  hash ^= facts->ip_version;
  hash *= 16777619u;
  hash ^= facts->proto;
  hash *= 16777619u;
  for (u32 i = 0; i < width; i++)
    {
      hash ^= left[i];
      hash *= 16777619u;
    }
  for (u32 i = 0; i < width; i++)
    {
      hash ^= right[i];
      hash *= 16777619u;
    }
  hash ^= left_port;
  hash *= 16777619u;
  hash ^= right_port;
  hash *= 16777619u;
  return hash % (nm->two_lane_count ? nm->two_lane_count :
			 NFQUEUE_POC_TWO_LANE_COUNT);
}

static int
nfqueue_poc_two_lane_packet_cb (struct nfq_q_handle *qh,
				struct nfgenmsg *nfmsg, struct nfq_data *nfa,
				void *data)
{
  nfqueue_poc_two_lane_t *lane = data;
  nfqueue_poc_main_t *nm = lane->nm;
  struct nfqnl_msg_packet_hdr *ph;
  nfqueue_poc_packet_facts_t facts;
  const char *reason = "two_lane_owner";
  const char *rule_id = "two-lane-owner";
  u32 id;
  u32 owner;
  u32 verdict = NF_ACCEPT;

  (void) nfmsg;
  lane->lane_generation = nm->async_lane_generation;
  nm->seen++;
  nm->two_lane_seen[lane->lane_index]++;
  ph = nfq_get_msg_packet_hdr (nfa);
  if (!ph)
    {
      nm->missing_id++;
      return 0;
    }
  id = ntohl (ph->packet_id);
  nfqueue_poc_collect_facts (nfa, &facts);
  owner = nfqueue_poc_two_lane_owner (nm, &facts);
  nm->two_lane_owner_hits[owner]++;
  nm->two_lane_worker_hits[owner]++;

  /* The stale injection is a completion identity check only. The valid
   * completion still owns and sends the single verdict for this packet. */
  if (nm->two_lane_stale_fault && lane->lane_index == 0 &&
      nm->two_lane_seen[lane->lane_index] == 1)
    nm->two_lane_stale_completions++;

  nfqueue_poc_write_event (nm, id, &facts, verdict, reason, rule_id);
  if (nfq_set_verdict (qh, id, verdict, 0, 0) < 0)
    nm->two_lane_verdict_errors++;
  else
    {
      nm->accepted++;
      nm->two_lane_accepted[lane->lane_index]++;
    }
  return 0;
}

static clib_error_t *
nfqueue_poc_two_lane_fd_read_ready (clib_file_t *f)
{
  nfqueue_poc_two_lane_t *lane = (nfqueue_poc_two_lane_t *) f->private_data;
  nfqueue_poc_main_t *nm = lane->nm;
  u8 buf[NFQUEUE_POC_RX_BUF_SIZE];

  while (1)
    {
      int rv = recv (lane->fd, buf, sizeof (buf), MSG_DONTWAIT);
      if (rv >= 0)
	{
	  if (nfq_handle_packet (lane->handle, (char *) buf, rv) < 0)
	    nm->handle_errors++;
	  continue;
	}
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
	return 0;
      if (errno == ENOBUFS)
	{
	  nm->enobufs++;
	  return 0;
	}
      nm->recv_errors++;
      return clib_error_return_unix (0, "nfqueue two-lane recv");
    }
}

static clib_error_t *
nfqueue_poc_two_lane_start (nfqueue_poc_main_t *nm, u16 base_queue)
{
  nfqueue_poc_two_lane_state_t *state;
  clib_file_t template;
  int af = nfqueue_poc_address_family (nm->family);

  state = clib_mem_alloc_aligned (sizeof (*state), CLIB_CACHE_LINE_BYTES);
  if (!state)
    return clib_error_return (0, "failed to allocate two-lane state");
  clib_memset (state, 0, sizeof (*state));
  nm->two_lane_state = state;
  for (u32 i = 0; i < nm->two_lane_count; i++)
    {
      nfqueue_poc_two_lane_t *lane = &state->lanes[i];
      clib_error_t *err;
      int flags;

      lane->nm = nm;
      lane->lane_index = i;
      lane->queue_num = base_queue + i;
      lane->file_index = ~0;
      lane->handle = nfq_open ();
      if (!lane->handle)
	return clib_error_return_unix (0, "nfq_open two-lane %u", i);
      if (nm->unbind_existing)
	(void) nfq_unbind_pf (lane->handle, af);
      if (nfq_bind_pf (lane->handle, af) < 0)
	return clib_error_return_unix (0, "nfq_bind_pf two-lane %u", i);
      lane->queue = nfq_create_queue (lane->handle, lane->queue_num,
					      nfqueue_poc_two_lane_packet_cb, lane);
      if (!lane->queue)
	return clib_error_return (0, "nfq_create_queue two-lane %u", i);
      err = nfqueue_poc_configure_queue (lane->queue, nm->queue_maxlen);
      if (err)
	return err;
      lane->fd = nfq_fd (lane->handle);
      flags = fcntl (lane->fd, F_GETFL, 0);
      if (flags < 0 || fcntl (lane->fd, F_SETFL, flags | O_NONBLOCK) < 0)
	return clib_error_return_unix (0, "set two-lane fd nonblocking");
      clib_memset (&template, 0, sizeof (template));
      template.read_function = nfqueue_poc_two_lane_fd_read_ready;
      template.file_descriptor = lane->fd;
      template.private_data = (uword) lane;
      template.description = format (0, "nfqueue-poc two-lane %u", i);
      lane->file_index = clib_file_add (&file_main, &template);
    }
  return 0;
}

static void
nfqueue_poc_two_lane_stop (nfqueue_poc_main_t *nm)
{
  nfqueue_poc_two_lane_state_t *state = nm->two_lane_state;

  if (!state)
    return;
  for (u32 i = 0; i < nm->two_lane_count; i++)
    {
      nfqueue_poc_two_lane_t *lane = &state->lanes[i];
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
  clib_mem_free (state);
  nm->two_lane_state = 0;
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

  if (nm->mode == NFQUEUE_POC_MODE_ASYNC_LEASE &&
      nm->async_ingress_delay_ms)
    usleep ((useconds_t) nm->async_ingress_delay_ms * 1000);

  nfqueue_poc_collect_facts (nfa, &facts);

  if (nm->mode == NFQUEUE_POC_MODE_ASYNC_LEASE)
    return nfqueue_poc_async_enqueue (nm, qh, id, &facts);

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
	  /* Leave the read-ready callback so a kernel drop cannot spin this thread. */
	  return 0;
	}

      nm->recv_errors++;
      return clib_error_return_unix (0, "nfqueue recv");
    }
}

static clib_error_t *
nfqueue_poc_configure_queue (struct nfq_q_handle *queue, u32 queue_maxlen)
{
  if (nfq_set_mode (queue, NFQNL_COPY_PACKET, NFQUEUE_POC_COPY_RANGE) < 0)
    return clib_error_return_unix (0, "nfq_set_mode NFQNL_COPY_PACKET");

  if (nfq_set_queue_maxlen (queue, queue_maxlen ? queue_maxlen : 4096) < 0)
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
		    u32 drop_ratio, u32 lane_count, u32 polling_contexts,
		    u32 queue_maxlen, u32 async_ingress_delay_ms,
		    u32 block_uid,
		    const u8 *block_ip6_dst,
		    const char *event_log_path, u8 unbind_existing,
		    u8 async_duplicate_fault, u8 async_stale_fault,
		    u8 async_missing_fault, u8 async_missing_id_fault,
		    u8 async_shutdown_fault, u32 async_delay_ms)
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

  if (mode == NFQUEUE_POC_MODE_TWO_LANE ||
      mode == NFQUEUE_POC_MODE_LANE_MATRIX)
    {
      if (mode == NFQUEUE_POC_MODE_TWO_LANE)
	lane_count = NFQUEUE_POC_TWO_LANE_COUNT;
      if (lane_count < NFQUEUE_POC_TWO_LANE_COUNT ||
	  lane_count > NFQUEUE_POC_LANE_MATRIX_MAX)
	return clib_error_return (0, "lane count must be 2..%u",
				  NFQUEUE_POC_LANE_MATRIX_MAX);
      if (polling_contexts == 0 || polling_contexts > lane_count)
	return clib_error_return (0, "polling contexts must be 1..lane-count");
      nm->queue_num = queue_num;
      nm->mode = mode;
      nm->family = family;
      nm->queue_maxlen = queue_maxlen ? queue_maxlen : 4096;
      nm->async_lane_generation++;
      if (nm->async_lane_generation == 0)
	nm->async_lane_generation = 1;
      nm->unbind_existing = unbind_existing;
      nm->two_lane_count = (u8) lane_count;
      nm->two_lane_polling_contexts = (u8) polling_contexts;
      nm->two_lane_stale_fault = async_stale_fault;
      clib_memset (nm->two_lane_seen, 0, sizeof (nm->two_lane_seen));
      clib_memset (nm->two_lane_accepted, 0,
		   sizeof (nm->two_lane_accepted));
      clib_memset (nm->two_lane_dropped, 0,
		   sizeof (nm->two_lane_dropped));
      clib_memset (nm->two_lane_owner_hits, 0,
		   sizeof (nm->two_lane_owner_hits));
      clib_memset (nm->two_lane_worker_hits, 0,
		   sizeof (nm->two_lane_worker_hits));
      nm->two_lane_stale_completions = 0;
      nm->two_lane_out_of_order = 0;
      nm->two_lane_verdict_errors = 0;
      nm->seen = nm->accepted = nm->dropped = nm->missing_id = 0;
      nm->handle_errors = nm->recv_errors = nm->enobufs = 0;
      nm->fd = -1;
      nm->file_index = ~0;
      if (block_ip6_dst)
	clib_memcpy (nm->block_ip6_dst, block_ip6_dst,
		     sizeof (nm->block_ip6_dst));
      else
	clib_memset (nm->block_ip6_dst, 0, sizeof (nm->block_ip6_dst));
      if (event_log_path)
	{
	  nm->event_log_file = fopen (event_log_path, "w");
	  if (!nm->event_log_file)
	    return clib_error_return_unix (0, "open event log %s",
					   event_log_path);
	  nm->event_log_path = format (0, "%s%c", event_log_path, 0);
	}
      nm->enabled = 1;
      err = nfqueue_poc_two_lane_start (nm, queue_num);
      if (err)
	{
	  nfqueue_poc_disable ();
	  return err;
	}
      return 0;
    }

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

  err = nfqueue_poc_configure_queue (nm->queue, queue_maxlen);
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
  nm->queue_maxlen = queue_maxlen ? queue_maxlen : 4096;
  nm->async_ingress_delay_ms = async_ingress_delay_ms;
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
  nm->async_duplicate_fault = async_duplicate_fault;
  nm->async_stale_fault = async_stale_fault;
  nm->async_missing_fault = async_missing_fault;
  nm->async_missing_id_fault = async_missing_id_fault;
  nm->async_shutdown_fault = async_shutdown_fault;
  nm->async_delay_ms = async_delay_ms ? async_delay_ms : 5;
  nm->async_lane_generation++;
  if (nm->async_lane_generation == 0)
    nm->async_lane_generation = 1;
  nm->async_ingress_leases = 0;
  nm->async_worker_dispatches = 0;
  nm->async_completion_intents = 0;
  nm->async_terminal_outcomes = 0;
  nm->async_duplicate_completions = 0;
  nm->async_stale_completions = 0;
  nm->async_missing_completions = 0;
  nm->async_missing_id_verdicts = 0;
  nm->async_deadline_drops = 0;
  nm->async_shutdown_drops = 0;
  nm->async_overload_drops = 0;
  nm->async_worker_backpressure_drops = 0;
  nm->async_verdict_errors = 0;
  nm->async_pipe_errors = 0;
  nm->async_out_of_order = 0;
  nm->async_pending_peak = 0;
  nm->async_completion_file_index = ~0;

  template.read_function = nfqueue_poc_fd_read_ready;
  template.file_descriptor = nm->fd;
  template.private_data = (uword) nm;
  template.description = format (0, "nfqueue-poc queue %u", queue_num);
  nm->file_index = clib_file_add (&file_main, &template);
  nm->enabled = 1;

  if (mode == NFQUEUE_POC_MODE_ASYNC_LEASE)
    {
      err = nfqueue_poc_async_start (nm);
      if (err)
	{
	  nfqueue_poc_disable ();
	  return err;
	}
    }

  return 0;

error:
  nfqueue_poc_disable ();
  return err;
}

void
nfqueue_poc_disable (void)
{
  nfqueue_poc_main_t *nm = &nfqueue_poc_main;

  /* Keep the NFQUEUE netlink fd alive until every async lease has received a
   * terminal verdict.  clib_file_del_by_index may close the registered fd. */
  if (nm->async_state)
    nfqueue_poc_async_stop (nm);
  if (nm->two_lane_state)
    nfqueue_poc_two_lane_stop (nm);

  if (nm->enabled)
    {
      if (nm->file_index != ~0)
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
  nm->async_completion_file_index = ~0;
  nm->two_lane_count = 0;
  nm->two_lane_polling_contexts = 0;
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
  u32 lane_count = NFQUEUE_POC_TWO_LANE_COUNT;
  u32 polling_contexts = 1;
  u32 queue_maxlen = 4096;
  u32 async_ingress_delay_ms = 0;
  u32 block_uid = 0;
  u8 unbind_existing = 0;
  u8 *block_ip6_dst_text = 0;
  u8 *event_log_path = 0;
  u8 block_ip6_dst[16] = { 0 };
  u8 block_ip6_dst_set = 0;
  u8 async_duplicate_fault = 0;
  u8 async_stale_fault = 0;
  u8 async_missing_fault = 0;
  u8 async_missing_id_fault = 0;
  u8 async_shutdown_fault = 0;
  u32 async_delay_ms = 5;

  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &queue_num))
	;
      else if (unformat (input, "lanes %u", &lane_count))
	;
      else if (unformat (input, "polling-contexts %u", &polling_contexts))
	;
      else if (unformat (input, "queue-maxlen %u", &queue_maxlen))
	;
      else if (unformat (input, "async-ingress-delay-ms %u",
				 &async_ingress_delay_ms))
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
      else if (unformat (input, "mode async-lease"))
	mode = NFQUEUE_POC_MODE_ASYNC_LEASE;
      else if (unformat (input, "mode two-lane"))
	mode = NFQUEUE_POC_MODE_TWO_LANE;
      else if (unformat (input, "mode lane-matrix"))
	mode = NFQUEUE_POC_MODE_LANE_MATRIX;
      else if (unformat (input, "async-duplicate"))
	async_duplicate_fault = 1;
      else if (unformat (input, "async-stale"))
	async_stale_fault = 1;
      else if (unformat (input, "two-lane-stale"))
	async_stale_fault = 1;
      else if (unformat (input, "async-missing-id"))
	async_missing_id_fault = 1;
      else if (unformat (input, "async-missing"))
	async_missing_fault = 1;
      else if (unformat (input, "async-shutdown"))
	async_shutdown_fault = 1;
      else if (unformat (input, "async-delay-ms %u", &async_delay_ms))
	;
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
  if (queue_maxlen == 0)
    return clib_error_return (0, "queue maxlen must be greater than zero");
  if (mode == NFQUEUE_POC_MODE_LANE_MATRIX &&
      (lane_count < NFQUEUE_POC_TWO_LANE_COUNT ||
       lane_count > NFQUEUE_POC_LANE_MATRIX_MAX))
    return clib_error_return (0, "lane count must be 2..%u",
				      NFQUEUE_POC_LANE_MATRIX_MAX);
  if (mode == NFQUEUE_POC_MODE_LANE_MATRIX &&
      (polling_contexts == 0 || polling_contexts > lane_count))
    return clib_error_return (0, "polling contexts must be 1..lane-count");
  if (mode == NFQUEUE_POC_MODE_BLOCK_IP6_DST && !block_ip6_dst_set)
    return clib_error_return (0, "block-ip6-dst requires an IPv6 address");

  err = nfqueue_poc_enable (
    vm, (u16) queue_num, family, mode, drop_ratio, lane_count,
    polling_contexts, queue_maxlen,
    async_ingress_delay_ms, block_uid,
    block_ip6_dst_set ? block_ip6_dst : 0, (char *) event_log_path,
    unbind_existing, async_duplicate_fault, async_stale_fault,
    async_missing_fault, async_missing_id_fault, async_shutdown_fault,
    async_delay_ms);
  vec_free (event_log_path);
  return err;
}

VLIB_CLI_COMMAND (nfqueue_poc_enable_command, static) = {
  .path = "nfqueue-poc enable",
  .short_help = "nfqueue-poc enable [queue <n>] "
		"[queue-maxlen <n>] "
		"[lanes <2..4>] [polling-contexts <n>] "
		"[async-ingress-delay-ms <n>] "
		"[family ip4|ip6] "
		"[mode accept-all|drop-all|drop-ratio <n>|"
		"block-ip6-dst <addr>|allow-uid <uid>|block-uid <uid>|"
		"async-lease|two-lane|lane-matrix] "
		"[async-duplicate] [async-stale] [async-missing] "
		"[async-missing-id] [async-shutdown] [async-delay-ms <n>] "
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
    vm, "enabled %u queue %u family %U mode %U copy-range %u queue-maxlen %u "
       "drop-ratio %u block-uid %u fd %d",
    nm->enabled, nm->queue_num, format_nfqueue_poc_family, nm->family,
    format_nfqueue_poc_mode, nm->mode, NFQUEUE_POC_COPY_RANGE,
    nm->queue_maxlen, nm->drop_ratio, nm->block_uid, nm->fd);
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
  vlib_cli_output (
    vm, "async lane-generation %llu delay-ms %u ingress-delay-ms %u "
	       "faults duplicate %u stale %u "
	       "missing %u missing-id %u shutdown %u",
    nm->async_lane_generation, nm->async_delay_ms,
    nm->async_ingress_delay_ms,
    nm->async_duplicate_fault, nm->async_stale_fault,
    nm->async_missing_fault, nm->async_missing_id_fault,
    nm->async_shutdown_fault);
  vlib_cli_output (
    vm, "async leases ingress %llu worker-dispatches %llu completion-intents %llu "
       "terminal-outcomes %llu pending-peak %llu",
    nm->async_ingress_leases, nm->async_worker_dispatches,
    nm->async_completion_intents, nm->async_terminal_outcomes,
    nm->async_pending_peak);
  vlib_cli_output (
    vm, "async faults duplicate %llu stale %llu missing %llu missing-id %llu "
       "deadline %llu shutdown %llu overload %llu out-of-order %llu "
       "worker-backpressure %llu verdict-errors %llu last-verdict-errno %u "
       "pipe-errors %llu",
    nm->async_duplicate_completions, nm->async_stale_completions,
    nm->async_missing_completions, nm->async_missing_id_verdicts,
    nm->async_deadline_drops, nm->async_shutdown_drops,
    nm->async_overload_drops, nm->async_out_of_order,
    nm->async_worker_backpressure_drops,
    nm->async_verdict_errors, nm->async_last_verdict_errno,
    nm->async_pipe_errors);
  vlib_cli_output (
    vm, "two-lane lane0 seen %llu accepted %llu owner-hits %llu worker-hits %llu "
       "lane1 seen %llu accepted %llu owner-hits %llu worker-hits %llu",
    nm->two_lane_seen[0], nm->two_lane_accepted[0],
    nm->two_lane_owner_hits[0], nm->two_lane_worker_hits[0],
    nm->two_lane_seen[1], nm->two_lane_accepted[1],
    nm->two_lane_owner_hits[1], nm->two_lane_worker_hits[1]);
  vlib_cli_output (vm, "lane-matrix lanes %u polling-contexts %u",
                   nm->two_lane_count, nm->two_lane_polling_contexts);
  if (nm->two_lane_count > 2)
    vlib_cli_output (
      vm, "lane-matrix lane2 seen %llu accepted %llu owner-hits %llu worker-hits %llu "
          "lane3 seen %llu accepted %llu owner-hits %llu worker-hits %llu",
      nm->two_lane_seen[2], nm->two_lane_accepted[2],
      nm->two_lane_owner_hits[2], nm->two_lane_worker_hits[2],
      nm->two_lane_seen[3], nm->two_lane_accepted[3],
      nm->two_lane_owner_hits[3], nm->two_lane_worker_hits[3]);
  vlib_cli_output (
    vm, "two-lane stale-completions %llu out-of-order %llu verdict-errors %llu",
    nm->two_lane_stale_completions, nm->two_lane_out_of_order,
    nm->two_lane_verdict_errors);
  return 0;
}

VLIB_CLI_COMMAND (nfqueue_poc_show_command, static) = {
  .path = "show nfqueue-poc",
  .short_help = "show nfqueue-poc",
  .function = nfqueue_poc_show_command_fn,
};
