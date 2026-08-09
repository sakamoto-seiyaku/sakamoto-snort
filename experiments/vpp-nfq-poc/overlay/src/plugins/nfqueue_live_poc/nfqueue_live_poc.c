/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-73 — throwaway VPP-native NFQUEUE live-buffer closure probe.
 *
 * The netlink datagram is received straight into the VPP buffer's current
 * data span. libnetfilter_queue only projects pointers into that datagram;
 * the payload is never copied by this plugin. A worker frame queue moves the
 * buffer index. A fixed completion frame moves the index and full identity back
 * to the origin lane, which calls nfq_set_verdict and then returns the same
 * buffer through vlib_buffer_free_one(). Only bounded transport-fault paths
 * use the producer's direct fail-open settlement when no completion frame can
 * be published.
 */

#include <nfqueue_live_poc/nfqueue_live_poc.h>

#include <vlib/file.h>
#include <vlib/threads.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define NFQUEUE_LIVE_RING_CAPACITY 128u
#define NFQUEUE_LIVE_ACCEPT NF_ACCEPT
#define NFQUEUE_LIVE_FLAG_UID_KNOWN (1u << 0)
#define NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN (1u << 1)
#define NFQUEUE_LIVE_FLAG_STATE_SHIFT 2
#define NFQUEUE_LIVE_FLAG_STATE_MASK (7u << NFQUEUE_LIVE_FLAG_STATE_SHIFT)
#define NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED (1u << 5)
#define NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN (1u << 6)
#define NFQUEUE_LIVE_FLAG_OUTCOME_FAILED (1u << 7)

/* These are compile-time proof obligations, not mutable per-packet state:
 * this probe has no packet-copy, scratch-buffer, or heap-obligation path. */
#define NFQUEUE_LIVE_PACKET_COPY_PATHS 0u
#define NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS 0u
#define NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS 0u
#define NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS 0u
_Static_assert (NFQUEUE_LIVE_PACKET_COPY_PATHS == 0u,
                "S73 packet-copy path must remain absent");
_Static_assert (NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS == 0u,
                "S73 full-packet memcpy path must remain absent");
_Static_assert (NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS == 0u,
                "S73 scratch-buffer path must remain absent");
_Static_assert (NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS == 0u,
                "S73 per-packet heap obligation must remain absent");

typedef enum
{
  NFQUEUE_LIVE_STATE_FREE = 0,
  NFQUEUE_LIVE_STATE_LIVE = 1,
  NFQUEUE_LIVE_STATE_COMPLETION = 2,
  NFQUEUE_LIVE_STATE_ATTEMPTED = 3,
  NFQUEUE_LIVE_STATE_RETURNED = 4,
} nfqueue_live_state_t;

typedef struct
{
  nfqueue_live_main_t *nm;
  u32 buffer_index;
  u8 *base;
  u32 parse_length;
  u32 datagram_length;
  u32 callback_count;
  u8 truncated;
  u8 candidate;
  u8 verdict_settled;
  u8 metadata_initialized;
} nfqueue_live_datagram_t;

nfqueue_live_main_t nfqueue_live_main = {
  .netlink_fd = -1,
  .completion_fd = -1,
  .netlink_file_index = ~0,
  .completion_file_index = ~0,
  .worker_thread = 1,
};

extern vlib_node_registration_t nfqueue_live_ingress_process_node;
extern vlib_node_registration_t nfqueue_live_owner_node;

static_always_inline nfqueue_live_meta_t *
nfqueue_live_meta (vlib_buffer_t *b)
{
  return (nfqueue_live_meta_t *) b->opaque;
}

static_always_inline void
nfqueue_live_set_generation (nfqueue_live_meta_t *meta, u64 generation)
{
  meta->generation_lo = (u32) generation;
  meta->generation_hi = (u32) (generation >> 32);
}

static_always_inline nfqueue_live_state_t
nfqueue_live_state (const nfqueue_live_meta_t *meta)
{
  return (nfqueue_live_state_t) ((meta->flags & NFQUEUE_LIVE_FLAG_STATE_MASK) >>
                                 NFQUEUE_LIVE_FLAG_STATE_SHIFT);
}

static_always_inline void
nfqueue_live_set_state (nfqueue_live_meta_t *meta, nfqueue_live_state_t state)
{
  meta->flags = (meta->flags & ~NFQUEUE_LIVE_FLAG_STATE_MASK) |
                ((u8) state << NFQUEUE_LIVE_FLAG_STATE_SHIFT);
}

static_always_inline u8
nfqueue_live_index_push (nfqueue_live_index_ring_t *ring, u32 index)
{
  u32 tail = __atomic_load_n (&ring->tail, __ATOMIC_RELAXED);
  u32 next = (tail + 1) % NFQUEUE_LIVE_RING_CAPACITY;
  if (next == __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE))
    return 0;
  ring->indices[tail] = index;
  __atomic_store_n (&ring->tail, next, __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
nfqueue_live_index_pop (nfqueue_live_index_ring_t *ring, u32 *index)
{
  u32 head = __atomic_load_n (&ring->head, __ATOMIC_RELAXED);
  if (head == __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE))
    return 0;
  *index = ring->indices[head];
  __atomic_store_n (&ring->head, (head + 1) % NFQUEUE_LIVE_RING_CAPACITY,
                    __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
nfqueue_live_completion_push (nfqueue_live_completion_ring_t *ring,
                               const nfqueue_live_completion_t *entry)
{
  u32 tail = __atomic_load_n (&ring->tail, __ATOMIC_RELAXED);
  u32 next = (tail + 1) % NFQUEUE_LIVE_RING_CAPACITY;
  if (next == __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE))
    return 0;
  ring->entries[tail] = *entry;
  __atomic_store_n (&ring->tail, next, __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
nfqueue_live_completion_pop (nfqueue_live_completion_ring_t *ring,
                              nfqueue_live_completion_t *entry)
{
  u32 head = __atomic_load_n (&ring->head, __ATOMIC_RELAXED);
  if (head == __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE))
    return 0;
  *entry = ring->entries[head];
  __atomic_store_n (&ring->head, (head + 1) % NFQUEUE_LIVE_RING_CAPACITY,
                    __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u32
nfqueue_live_completion_free_slots (nfqueue_live_completion_ring_t *ring)
{
  u32 head = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE);
  u32 tail = __atomic_load_n (&ring->tail, __ATOMIC_RELAXED);
  return (head + NFQUEUE_LIVE_RING_CAPACITY - tail - 1) %
         NFQUEUE_LIVE_RING_CAPACITY;
}

static_always_inline void
nfqueue_live_completion_lock (nfqueue_live_main_t *nm)
{
  while (__atomic_exchange_n (&nm->completion_push_lock, 1,
                              __ATOMIC_ACQUIRE) != 0)
    ;
}

static_always_inline void
nfqueue_live_completion_unlock (nfqueue_live_main_t *nm)
{
  __atomic_store_n (&nm->completion_push_lock, 0, __ATOMIC_RELEASE);
}

static void
nfqueue_live_wake_completion (nfqueue_live_main_t *nm)
{
  u64 one = 1;
  if (write (nm->completion_fd, &one, sizeof (one)) == (ssize_t) sizeof (one))
    nm->completion_wake_writes++;
  else if (errno != EAGAIN && errno != EWOULDBLOCK)
    nm->completion_wake_errors++;
}

static u8
nfqueue_live_recover_packet_id (const u8 *base, u32 length, u32 *packet_id)
{
  const struct nlmsghdr *nlh;
  u32 message_length;
  u32 offset;

  if (!base || !packet_id || length < NLMSG_HDRLEN + sizeof (struct nfgenmsg))
    return 0;
  nlh = (const struct nlmsghdr *) base;
  if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof (struct nfgenmsg))
    return 0;
  message_length = clib_min ((u32) nlh->nlmsg_len, length);
  offset = NLMSG_HDRLEN + NLMSG_ALIGN (sizeof (struct nfgenmsg));
  while (offset + NLA_HDRLEN <= message_length)
    {
      const struct nlattr *attr = (const struct nlattr *) (base + offset);
      u32 attr_length = attr->nla_len;
      u32 aligned_length;

      if (attr_length < NLA_HDRLEN ||
          offset + attr_length > message_length)
        break;
      aligned_length = NLA_ALIGN (attr_length);
      if ((attr->nla_type & NLA_TYPE_MASK) == NFQA_PACKET_HDR &&
          attr_length >= NLA_HDRLEN + sizeof (struct nfqnl_msg_packet_hdr))
        {
          const struct nfqnl_msg_packet_hdr *header =
            (const struct nfqnl_msg_packet_hdr *) (base + offset + NLA_HDRLEN);
          *packet_id = ntohl (header->packet_id);
          return 1;
        }
      if (aligned_length == 0 || offset + aligned_length > message_length)
        break;
      offset += aligned_length;
    }
  return 0;
}

static void
nfqueue_live_record_last (nfqueue_live_main_t *nm,
                           const nfqueue_live_meta_t *meta,
                           u32 buffer_index, u8 *base)
{
  nm->last_buffer_index = buffer_index;
  nm->last_buffer_base = (uword) base;
  nm->last_datagram_length = meta->datagram_length;
  nm->last_payload_offset = meta->payload_offset;
  nm->last_payload_length = meta->payload_length;
  nm->last_original_length = meta->original_length;
  nm->last_captured_length = meta->payload_length;
  nm->last_hook = meta->hook;
  nm->last_uid = meta->uid;
  nm->last_uid_known = (meta->flags & NFQUEUE_LIVE_FLAG_UID_KNOWN) != 0;
  nm->last_ip_version = meta->ip_version;
}

static void
nfqueue_live_send_verdict (nfqueue_live_main_t *nm,
                           struct nfq_q_handle *queue, u32 packet_id,
                           u32 verdict)
{
  if (nfq_set_verdict (queue, packet_id, verdict, 0, 0) < 0)
    {
      nm->verdict_send_failures++;
      nm->last_verdict_errno = errno;
    }
  else
    {
      /* A successful send proves only that the local netlink socket accepted
       * the datagram. Kernel verdict acceptance remains OUTCOME_UNKNOWN. */
      nm->verdict_send_success++;
      nm->completion_outcome_unknown++;
    }
  nm->verdict_attempts++;
}

static void
nfqueue_live_return_buffer (nfqueue_live_main_t *nm, u32 buffer_index,
                            nfqueue_live_meta_t *meta)
{
  if (meta->completion_refs != 0 ||
      nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
  if (nm->outstanding != 0)
    nm->outstanding--;
  nm->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_release_unqueued (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  meta->completion_refs = 0;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
  nm->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_free_unowned (nfqueue_live_main_t *nm, u32 buffer_index)
{
  nm->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_settle_fail_open (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) == 0)
    {
      meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
      nfqueue_live_send_verdict (nm, nm->queue, meta->packet_id,
                                 NFQUEUE_LIVE_ACCEPT);
    }
  meta->completion_refs = 0;
  nm->fail_open_settlements++;
  nfqueue_live_return_buffer (nm, buffer_index, meta);
}

static_always_inline u8
nfqueue_live_completion_identity_matches (const nfqueue_live_meta_t *meta,
                                           const nfqueue_live_completion_t *entry)
{
  return entry->generation_lo == meta->generation_lo &&
         entry->generation_hi == meta->generation_hi &&
         entry->packet_id == meta->packet_id &&
         entry->obligation_nonce == meta->obligation_nonce;
}

static void
nfqueue_live_drop_completion_ref (nfqueue_live_main_t *nm, u32 buffer_index,
                                  nfqueue_live_meta_t *meta,
                                  const nfqueue_live_completion_t *entry)
{
  if (!entry->reference_held || meta->completion_refs == 0)
    return;
  meta->completion_refs--;
  if (meta->completion_refs == 0)
    nfqueue_live_return_buffer (nm, buffer_index, meta);
}

static void
nfqueue_live_complete_one (nfqueue_live_main_t *nm,
                           const nfqueue_live_completion_t *entry)
{
  vlib_buffer_t *buffer;
  nfqueue_live_meta_t *meta;

  buffer = vlib_get_buffer (nm->vm, entry->buffer_index);
  meta = nfqueue_live_meta (buffer);

  /* Check the full completion identity before touching verdict or reference
   * state. Generation alone is insufficient when a packet id is reused. */
  if (!nfqueue_live_completion_identity_matches (meta, entry) ||
      nfqueue_live_state (meta) < NFQUEUE_LIVE_STATE_COMPLETION)
    {
      nm->completion_stale++;
      nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
      return;
    }

  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) != 0)
    {
      nm->completion_duplicate++;
      nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
      return;
    }

  meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
  nfqueue_live_send_verdict (nm, nm->queue, meta->packet_id, entry->verdict);

  nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
}

static void
nfqueue_live_drain_completion_queue (nfqueue_live_main_t *nm)
{
  u64 value;
  nfqueue_live_completion_t entry;

  while (nm->completion_fd >= 0 &&
         read (nm->completion_fd, &value, sizeof (value)) == (ssize_t) sizeof (value))
    ;
  while (nfqueue_live_completion_pop (&nm->completion, &entry))
    {
      nm->completion_frames++;
      nfqueue_live_complete_one (nm, &entry);
    }
}

static clib_error_t *
nfqueue_live_completion_read_ready (clib_file_t *file)
{
  nfqueue_live_main_t *nm = (nfqueue_live_main_t *) file->private_data;
  nfqueue_live_drain_completion_queue (nm);
  return 0;
}

static void
nfqueue_live_direct_accept (nfqueue_live_main_t *nm,
                            struct nfq_q_handle *queue, u32 packet_id)
{
  nfqueue_live_send_verdict (nm, queue, packet_id, NFQUEUE_LIVE_ACCEPT);
}

static u32
nfqueue_live_next_obligation_nonce (nfqueue_live_main_t *nm)
{
  nm->next_obligation_nonce++;
  if (nm->next_obligation_nonce == 0)
    {
      nm->generation++;
      if (nm->generation == 0)
        nm->generation = 1;
      nm->next_obligation_nonce = 1;
    }
  return nm->next_obligation_nonce;
}

static int
nfqueue_live_packet_cb (struct nfq_q_handle *queue, struct nfgenmsg *message,
                        struct nfq_data *data, void *opaque)
{
  nfqueue_live_main_t *nm = (nfqueue_live_main_t *) opaque;
  nfqueue_live_datagram_t *datagram = nm->active_datagram;
  struct nfqnl_msg_packet_hdr *header;
  nfqueue_live_meta_t *meta;
  unsigned char *payload = 0;
  int payload_length;
  u32 cap_len;
  u32 packet_id;
  uword payload_address;
  uword begin;
  uword end;
  vlib_buffer_t *buffer;
  (void) message;

  if (!datagram)
    return 0;
  datagram->callback_count++;
  nm->callbacks++;
  header = nfq_get_msg_packet_hdr (data);
  if (!header)
    {
      nm->missing_ingress_identity++;
      return 0;
    }
  packet_id = ntohl (header->packet_id);
  if (datagram->callback_count != 1)
    {
      nm->multiple_message_rejects++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      datagram->verdict_settled = 1;
      return 0;
    }

  if (datagram->truncated)
    {
      nfqueue_live_direct_accept (nm, queue, packet_id);
      datagram->verdict_settled = 1;
      return 0;
    }

  payload_length = nfq_get_payload (data, &payload);
  if (payload_length <= 0 || !payload)
    {
      nm->malformed_payloads++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      datagram->verdict_settled = 1;
      return 0;
    }
  if (nfq_get_cap_len (data, &cap_len) < 0)
    {
      /* Some kernels omit NFQA_CAP_LEN for ordinary, non-GSO local traffic.
       * Keep the value sourced from libnetfilter_queue's captured payload
       * metadata; never inspect an L3 header to invent original_length. */
      nm->cap_len_missing++;
      cap_len = (u32) payload_length;
    }
  payload_address = (uword) payload;
  begin = (uword) datagram->base;
  end = begin + datagram->parse_length;
  if (payload_address < begin || payload_address > end ||
      (uword) payload_length > end - payload_address)
    {
      nm->malformed_payloads++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      datagram->verdict_settled = 1;
      return 0;
    }

  buffer = vlib_get_buffer (nm->vm, datagram->buffer_index);
  meta = nfqueue_live_meta (buffer);
  clib_memset (meta, 0, sizeof (*meta));
  datagram->metadata_initialized = 1;
  nfqueue_live_set_generation (meta, nm->generation);
  meta->packet_id = packet_id;
  meta->obligation_nonce = nfqueue_live_next_obligation_nonce (nm);
  meta->datagram_length = datagram->datagram_length;
  meta->payload_offset = (u32) (payload_address - begin);
  meta->payload_length = (u32) payload_length;
  meta->original_length = cap_len;
  meta->hook = header->hook;
  meta->completion_refs = 1;
  if (nfq_get_uid (data, &meta->uid))
    meta->flags |= NFQUEUE_LIVE_FLAG_UID_KNOWN;
  meta->flags |= NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN;
  meta->ip_version = payload[0] >> 4;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_LIVE);
  nm->inline_metadata_writes++;
  nm->payload_span_checks++;
  if (meta->payload_offset > meta->datagram_length ||
      meta->payload_length > meta->datagram_length - meta->payload_offset)
    {
      nm->payload_span_failures++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      datagram->verdict_settled = 1;
      return 0;
    }
  nm->payload_pointer_projections++;
  datagram->candidate = 1;
  return 0;
}

static clib_error_t *
nfqueue_live_netlink_read_ready (clib_file_t *file)
{
  nfqueue_live_main_t *nm = (nfqueue_live_main_t *) file->private_data;
  u32 buffer_index;
  vlib_buffer_t *buffer;
  u8 *base;
  u32 capacity;
  int received;
  nfqueue_live_datagram_t datagram;
  int handled;

  if (nm->quiescing)
    return 0;

  while (1)
    {
      if (vlib_buffer_alloc (nm->vm, &buffer_index, 1) != 1)
        {
          nm->ingress_alloc_failures++;
          return 0;
        }
      buffer = vlib_get_buffer (nm->vm, buffer_index);
      base = vlib_buffer_get_current (buffer);
      capacity = vlib_buffer_get_default_data_size (nm->vm);
      received = recv (nm->netlink_fd, base, capacity,
                       MSG_DONTWAIT | MSG_TRUNC);
      if (received < 0)
        {
          vlib_buffer_free_one (nm->vm, buffer_index);
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
          return clib_error_return_unix (0, "nfqueue-live recv");
        }
      if (received == 0)
        {
          vlib_buffer_free_one (nm->vm, buffer_index);
          continue;
        }
      nm->live_buffer_receives++;
      datagram.nm = nm;
      datagram.buffer_index = buffer_index;
      datagram.base = base;
      datagram.datagram_length = (u32) received;
      datagram.parse_length = clib_min ((u32) received, capacity);
      datagram.callback_count = 0;
      datagram.truncated = received > (int) capacity;
      datagram.candidate = 0;
      datagram.verdict_settled = 0;
      datagram.metadata_initialized = 0;
      if (datagram.truncated)
        nm->truncated_datagrams++;
      nm->active_datagram = &datagram;
      buffer->current_length = datagram.parse_length;
      nm->datagrams++;
      handled = nfq_handle_packet (nm->handle, (char *) base,
                                   (int) datagram.parse_length);
      nm->active_datagram = 0;
      if (handled < 0 || datagram.callback_count == 0)
        {
          u32 recovered_packet_id;
          if (datagram.candidate)
            {
              nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
              if (!datagram.verdict_settled)
                nfqueue_live_direct_accept (nm, nm->queue, meta->packet_id);
              nfqueue_live_release_unqueued (nm, buffer_index, meta);
            }
          else if (!datagram.verdict_settled &&
                   nfqueue_live_recover_packet_id (base, datagram.parse_length,
                                                   &recovered_packet_id))
            {
              /* MSG_TRUNC and parser failures still owe the kernel a verdict
               * whenever the packet id can be recovered from NFQA_PACKET_HDR. */
              nfqueue_live_direct_accept (nm, nm->queue, recovered_packet_id);
              datagram.verdict_settled = 1;
              nfqueue_live_free_unowned (nm, buffer_index);
            }
          else
            {
              if (!datagram.verdict_settled)
                nm->identity_unrecoverable++;
              if (datagram.metadata_initialized)
                nfqueue_live_release_unqueued (
                  nm, buffer_index, nfqueue_live_meta (buffer));
              else
                nfqueue_live_free_unowned (nm, buffer_index);
            }
        }
      else if (datagram.callback_count > 1)
        {
          nm->multiple_message_datagrams++;
          if (datagram.candidate)
            {
              nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
              if (!datagram.verdict_settled)
                nfqueue_live_direct_accept (nm, nm->queue, meta->packet_id);
              nfqueue_live_release_unqueued (nm, buffer_index, meta);
            }
          else
            nfqueue_live_free_unowned (nm, buffer_index);
        }
      else if (datagram.candidate)
        {
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          if (!nfqueue_live_index_push (&nm->ingress, buffer_index))
            {
              nm->ingress_overload++;
              nfqueue_live_direct_accept (nm, nm->queue, meta->packet_id);
              nfqueue_live_release_unqueued (nm, buffer_index, meta);
            }
          else
            {
              nm->outstanding++;
              nfqueue_live_record_last (nm, meta, buffer_index, base);
              vlib_process_signal_event (
                nm->vm, nfqueue_live_ingress_process_node.index, 0, 0);
            }
        }
      else
        {
          /* A single callback can reject itself (missing CAP_LEN, malformed
           * payload, or span failure). It still owns the allocated VPP buffer
           * and must release it after its direct verdict, if any. */
          if (datagram.metadata_initialized)
            nfqueue_live_release_unqueued (
              nm, buffer_index, nfqueue_live_meta (buffer));
          else
            nfqueue_live_free_unowned (nm, buffer_index);
        }
    }
}

VLIB_NODE_FN (nfqueue_live_owner_node) (vlib_main_t *vm,
                                        vlib_node_runtime_t *node,
                                        vlib_frame_t *frame)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  while (n_left != 0)
    {
      nfqueue_live_completion_t completion = { 0 };
      vlib_buffer_t *buffer = vlib_get_buffer (vm, from[0]);
      nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
      u32 buffer_index = from[0];
      u32 worker_thread = vlib_get_thread_index ();

      nm->handoff_count++;
      nm->last_worker_thread = worker_thread;
      if (worker_thread != nm->origin_lane)
        nm->owner_mismatch_count++;
      if (nfqueue_live_state (meta) != NFQUEUE_LIVE_STATE_LIVE)
        nm->owner_invalid_state++;
      nm->payload_span_checks++;
      if ((meta->flags & NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN) == 0 ||
          meta->payload_offset > meta->datagram_length ||
          meta->payload_length > meta->datagram_length - meta->payload_offset)
        {
          nm->payload_span_failures++;
          nfqueue_live_settle_fail_open (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
      completion.buffer_index = buffer_index;
      completion.generation_lo = meta->generation_lo;
      completion.generation_hi = meta->generation_hi;
      completion.packet_id = meta->packet_id;
      completion.obligation_nonce = meta->obligation_nonce;
      completion.verdict = NFQUEUE_LIVE_ACCEPT;
      completion.reference_held = 1;
      /* Fault-injection entries are reserved before publishing the primary
       * completion. This keeps a failed duplicate/stale publication from
       * creating an untracked reference or leaving the live buffer stranded. */
      u8 stale_requested = nm->inject_stale != 0;
      u8 duplicate_requested = nm->inject_duplicate != 0;
      u32 required_slots = 1 + stale_requested + duplicate_requested;
      u8 primary_pushed;
      u8 stale_pushed = 1;
      u8 duplicate_pushed = 1;
      nfqueue_live_completion_lock (nm);
      if (nfqueue_live_completion_free_slots (&nm->completion) < required_slots)
        {
          nfqueue_live_completion_unlock (nm);
          nm->completion_ring_overflow++;
          nm->inject_stale = 0;
          nm->inject_duplicate = 0;
          nfqueue_live_settle_fail_open (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }
      if (stale_requested)
        meta->completion_refs++;
      if (duplicate_requested)
        meta->completion_refs++;
      primary_pushed = nfqueue_live_completion_push (&nm->completion, &completion);
      if (!primary_pushed)
        {
          if (stale_requested)
            meta->completion_refs--;
          if (duplicate_requested)
            meta->completion_refs--;
          nfqueue_live_completion_unlock (nm);
          nm->completion_ring_overflow++;
          nfqueue_live_settle_fail_open (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }
      if (stale_requested)
        {
          nfqueue_live_completion_t stale = completion;
          stale.obligation_nonce++;
          if (stale.obligation_nonce == 0)
            stale.packet_id++;
          stale_pushed = nfqueue_live_completion_push (&nm->completion, &stale);
          if (!stale_pushed)
            meta->completion_refs--;
          nm->inject_stale = 0;
        }
      if (duplicate_requested)
        {
          nfqueue_live_completion_t duplicate = completion;
          duplicate_pushed =
            nfqueue_live_completion_push (&nm->completion, &duplicate);
          if (!duplicate_pushed)
            meta->completion_refs--;
          nm->inject_duplicate = 0;
        }
      nfqueue_live_completion_unlock (nm);
      if (!stale_pushed)
        nm->completion_ring_overflow++;
      if (!duplicate_pushed)
        nm->completion_ring_overflow++;
      nfqueue_live_wake_completion (nm);
      from++;
      n_left--;
    }
  (void) node;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nfqueue_live_owner_node) = {
  .name = "nfqueue-live-owner",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_NODE_FN (nfqueue_live_ingress_process_node) (vlib_main_t *vm,
                                                   vlib_node_runtime_t *node,
                                                   vlib_frame_t *frame)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 from[VLIB_FRAME_SIZE];
  u16 threads[VLIB_FRAME_SIZE];
  u32 count;
  u32 enqueued;
  (void) frame;

  while (1)
    {
      (void) vlib_process_wait_for_event (vm);
      (void) vlib_process_get_events (vm, 0);
      count = 0;
      while (count < VLIB_FRAME_SIZE &&
             nfqueue_live_index_pop (&nm->ingress, &from[count]))
        {
          threads[count] = (u16) nm->worker_thread;
          count++;
        }
      if (count == 0)
        continue;
      enqueued = vlib_buffer_enqueue_to_thread (
        vm, node, nm->frame_queue_index, from, threads, count, 1);
      while (enqueued < count)
        {
          vlib_buffer_t *buffer = vlib_get_buffer (vm, from[enqueued]);
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          nfqueue_live_completion_t completion = {
            .buffer_index = from[enqueued],
            .generation_lo = meta->generation_lo,
            .generation_hi = meta->generation_hi,
            .packet_id = meta->packet_id,
            .obligation_nonce = meta->obligation_nonce,
            .verdict = NFQUEUE_LIVE_ACCEPT,
            .reference_held = 1,
          };
          nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
          nfqueue_live_completion_lock (nm);
          u8 completion_pushed =
            nfqueue_live_completion_push (&nm->completion, &completion);
          nfqueue_live_completion_unlock (nm);
          if (!completion_pushed)
            {
              nm->completion_ring_overflow++;
              nfqueue_live_settle_fail_open (nm, from[enqueued], meta);
            }
          else
            nfqueue_live_wake_completion (nm);
          enqueued++;
        }
    }
}

VLIB_REGISTER_NODE (nfqueue_live_ingress_process_node) = {
  .name = "nfqueue-live-ingress-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 16,
};

static void
nfqueue_live_reset_runtime (nfqueue_live_main_t *nm)
{
  nm->ingress.head = 0;
  nm->ingress.tail = 0;
  nm->completion.head = 0;
  nm->completion.tail = 0;
  nm->completion_push_lock = 0;
  nm->outstanding = 0;
  nm->next_obligation_nonce = 0;
  nm->last_buffer_index = ~0;
  nm->last_buffer_base = 0;
  nm->last_worker_thread = ~0;
}

static void
nfqueue_live_drain_ingress_queue (nfqueue_live_main_t *nm)
{
  u32 buffer_index;
  while (nfqueue_live_index_pop (&nm->ingress, &buffer_index))
    {
      vlib_buffer_t *buffer = vlib_get_buffer (nm->vm, buffer_index);
      nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
      /* Quiesce no longer admits new packets; any item still in the
       * transport ring is settled fail-open before teardown. */
      nfqueue_live_settle_fail_open (nm, buffer_index, meta);
    }
}

static clib_error_t *
nfqueue_live_drain_bounded (nfqueue_live_main_t *nm)
{
  u32 attempt;
  for (attempt = 0; attempt < 200; attempt++)
    {
      nfqueue_live_drain_ingress_queue (nm);
      nfqueue_live_drain_completion_queue (nm);
      if (nm->outstanding == 0)
        return 0;
      /* Workers continue to run while the origin lane polls the completion
       * transport. The bound makes teardown failure explicit. */
      usleep (1000);
    }
  nfqueue_live_drain_ingress_queue (nm);
  nfqueue_live_drain_completion_queue (nm);
  if (nm->outstanding != 0)
    return clib_error_return (0,
                              "nfqueue-live bounded drain left %u obligations",
                              nm->outstanding);
  return 0;
}

static void
nfqueue_live_close (nfqueue_live_main_t *nm)
{
  if (nm->netlink_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->netlink_file_index);
      nm->netlink_file_index = ~0;
    }
  if (nm->completion_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->completion_file_index);
      nm->completion_file_index = ~0;
    }
  if (nm->queue)
    {
      nfq_destroy_queue (nm->queue);
      nm->queue = 0;
    }
  if (nm->handle)
    {
      nfq_unbind_pf (nm->handle, nm->family == 6 ? AF_INET6 : AF_INET);
      nfq_close (nm->handle);
      nm->handle = 0;
    }
  if (nm->completion_fd >= 0)
    {
      close (nm->completion_fd);
      nm->completion_fd = -1;
    }
  nm->netlink_fd = -1;
  nm->enabled = 0;
  nm->quiescing = 0;
}

static clib_error_t *
nfqueue_live_enable (vlib_main_t *vm, u16 queue_num, u8 family,
                    u8 inject_stale, u8 inject_duplicate)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_file_t file = { 0 };
  int af = family == 6 ? AF_INET6 : AF_INET;

  if (nm->enabled)
    return clib_error_return (0, "nfqueue-live-poc already enabled");
  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "start VPP with at least one worker");
  nfqueue_live_reset_runtime (nm);
  nm->vm = vm;
  nm->queue_num = queue_num;
  nm->family = family;
  nm->origin_lane = 0;
  nm->worker_thread = 1;
  nm->inject_stale = inject_stale;
  nm->inject_duplicate = inject_duplicate;
  nm->generation++;
  if (nm->generation == 0)
    nm->generation = 1;
  nm->handle = nfq_open ();
  if (!nm->handle)
    return clib_error_return_unix (0, "nfq_open");
  if (nfq_bind_pf (nm->handle, af) < 0)
    {
      nfq_close (nm->handle);
      nm->handle = 0;
      return clib_error_return_unix (0, "nfq_bind_pf");
    }
  nm->queue = nfq_create_queue (nm->handle, queue_num,
                                 nfqueue_live_packet_cb, nm);
  if (!nm->queue)
    {
      nfq_unbind_pf (nm->handle, af);
      nfq_close (nm->handle);
      nm->handle = 0;
      return clib_error_return_unix (0, "nfq_create_queue");
    }
  if (nfq_set_mode (nm->queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
      nfqueue_live_close (nm);
      return clib_error_return_unix (0, "nfq_set_mode");
    }
  if (nfq_set_queue_flags (nm->queue, NFQA_CFG_F_UID_GID,
                           NFQA_CFG_F_UID_GID) < 0)
    {
      nfqueue_live_close (nm);
      return clib_error_return_unix (0, "nfq_set_queue_flags uid/gid");
    }
  nm->netlink_fd = nfq_fd (nm->handle);
  (void) fcntl (nm->netlink_fd, F_SETFL,
                fcntl (nm->netlink_fd, F_GETFL, 0) | O_NONBLOCK);
  nm->completion_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (nm->completion_fd < 0)
    {
      nfqueue_live_close (nm);
      return clib_error_return_unix (0, "eventfd");
    }

  file.read_function = nfqueue_live_netlink_read_ready;
  file.file_descriptor = nm->netlink_fd;
  file.private_data = (uword) nm;
  file.description = format (0, "nfqueue-live-poc origin lane");
  nm->netlink_file_index = clib_file_add (&file_main, &file);
  file = (clib_file_t) { 0 };
  file.read_function = nfqueue_live_completion_read_ready;
  file.file_descriptor = nm->completion_fd;
  file.private_data = (uword) nm;
  file.description = format (0, "nfqueue-live-poc completion frame");
  nm->completion_file_index = clib_file_add (&file_main, &file);
  nm->enabled = 1;
  return 0;
}

static clib_error_t *
nfqueue_live_disable (void)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_error_t *error;
  if (!nm->enabled)
    return 0;
  nm->quiescing = 1;
  if (nm->netlink_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->netlink_file_index);
      nm->netlink_file_index = ~0;
    }
  error = nfqueue_live_drain_bounded (nm);
  if (error)
    return error;
  nfqueue_live_close (nm);
  return 0;
}

static clib_error_t *
nfqueue_live_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  u32 queue_num = 42;
  u8 family = 4;
  u8 stale = 0;
  u8 duplicate = 0;
  clib_error_t *error;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &queue_num))
        ;
      else if (unformat (input, "family ip4"))
        family = 4;
      else if (unformat (input, "family ip6") ||
               unformat (input, "family ipv6"))
        family = 6;
      else if (unformat (input, "inject-stale"))
        stale = 1;
      else if (unformat (input, "inject-duplicate"))
        duplicate = 1;
      else
        return clib_error_return (0, "unknown nfqueue-live-poc option");
    }
  error = nfqueue_live_enable (vm, (u16) queue_num, family, stale, duplicate);
  return error;
}

VLIB_CLI_COMMAND (nfqueue_live_enable_command, static) = {
  .path = "nfqueue-live-poc enable",
  .short_help = "nfqueue-live-poc enable queue <n> [family ip4|ip6] "
                "[inject-stale] [inject-duplicate]",
  .function = nfqueue_live_enable_command_fn,
};

static clib_error_t *
nfqueue_live_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;
  return nfqueue_live_disable ();
}

VLIB_CLI_COMMAND (nfqueue_live_disable_command, static) = {
  .path = "nfqueue-live-poc disable",
  .short_help = "nfqueue-live-poc disable",
  .function = nfqueue_live_disable_command_fn,
};

static clib_error_t *
nfqueue_live_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  (void) input;
  (void) cmd;
  vlib_cli_output (vm, "enabled %u family ip%u queue %u generation %llu",
                   nm->enabled, nm->family, nm->queue_num,
                   (unsigned long long) nm->generation);
  vlib_cli_output (vm, "buffer-data-size %u worker-thread %u origin-lane %u",
                   data_size, nm->last_worker_thread, nm->origin_lane);
  vlib_cli_output (vm, "datagrams %llu callbacks %llu multiple-message-datagrams %llu rejects %llu",
                   (unsigned long long) nm->datagrams,
                   (unsigned long long) nm->callbacks,
                   (unsigned long long) nm->multiple_message_datagrams,
                   (unsigned long long) nm->multiple_message_rejects);
  vlib_cli_output (vm, "live-buffer-receives %llu inline-metadata-writes %llu payload-pointer-projections %llu",
                   (unsigned long long) nm->live_buffer_receives,
                   (unsigned long long) nm->inline_metadata_writes,
                   (unsigned long long) nm->payload_pointer_projections);
  vlib_cli_output (vm, "last-buffer-index %u last-buffer-base 0x%llx datagram-length %u",
                   nm->last_buffer_index, (unsigned long long) nm->last_buffer_base,
                   nm->last_datagram_length);
  vlib_cli_output (vm, "nfqa-payload-offset %u nfqa-payload-length %u original-length %u captured-length %u",
                   nm->last_payload_offset, nm->last_payload_length,
                   nm->last_original_length, nm->last_captured_length);
  vlib_cli_output (vm, "hook %u ip-version %u uid-known %u uid %u",
                   nm->last_hook, nm->last_ip_version,
                   nm->last_uid_known, nm->last_uid);
  vlib_cli_output (vm, "payload-span-checks %llu payload-span-failures %llu packet-copies %llu",
                   (unsigned long long) nm->payload_span_checks,
                   (unsigned long long) nm->payload_span_failures,
                   (unsigned long long) NFQUEUE_LIVE_PACKET_COPY_PATHS);
  vlib_cli_output (vm, "scratch-rx-buffers %llu full-packet-memcpy %llu per-packet-heap-objects %llu",
                   (unsigned long long) NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS,
                   (unsigned long long) NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS,
                   (unsigned long long) NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS);
  vlib_cli_output (vm, "handoffs %llu owner-mismatches %llu owner-invalid-state %llu",
                   (unsigned long long) nm->handoff_count,
                   (unsigned long long) nm->owner_mismatch_count,
                   (unsigned long long) nm->owner_invalid_state);
  vlib_cli_output (vm, "completion-frames %llu stale %llu duplicate %llu ring-overflow %llu",
                   (unsigned long long) nm->completion_frames,
                   (unsigned long long) nm->completion_stale,
                   (unsigned long long) nm->completion_duplicate,
                   (unsigned long long) nm->completion_ring_overflow);
  vlib_cli_output (vm, "cap-len-missing %llu truncated-datagrams %llu fail-open-settlements %llu identity-unrecoverable %llu",
                   (unsigned long long) nm->cap_len_missing,
                   (unsigned long long) nm->truncated_datagrams,
                   (unsigned long long) nm->fail_open_settlements,
                   (unsigned long long) nm->identity_unrecoverable);
  vlib_cli_output (vm, "verdict-attempts %llu send-success %llu send-failures %llu outcome-unknown %llu",
                   (unsigned long long) nm->verdict_attempts,
                   (unsigned long long) nm->verdict_send_success,
                   (unsigned long long) nm->verdict_send_failures,
                   (unsigned long long) nm->completion_outcome_unknown);
  vlib_cli_output (vm, "native-buffer-returns %llu outstanding-obligations %u ingress-alloc-failures %llu",
                   (unsigned long long) nm->native_buffer_returns, nm->outstanding,
                   (unsigned long long) nm->ingress_alloc_failures);
  return 0;
}

VLIB_CLI_COMMAND (nfqueue_live_show_command, static) = {
  .path = "show nfqueue-live-poc",
  .short_help = "show nfqueue-live-poc",
  .function = nfqueue_live_show_command_fn,
};

static clib_error_t *
nfqueue_live_init (vlib_main_t *vm)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  nm->vm = vm;
  nm->frame_queue_index = vlib_frame_queue_main_init (
    nfqueue_live_owner_node.index, 0);
  nfqueue_live_reset_runtime (nm);
  return 0;
}

VLIB_INIT_FUNCTION (nfqueue_live_init);
