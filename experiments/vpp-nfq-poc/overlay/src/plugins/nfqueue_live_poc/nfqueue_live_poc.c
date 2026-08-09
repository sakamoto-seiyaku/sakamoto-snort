/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-73 — throwaway VPP-native NFQUEUE live-buffer closure probe.
 *
 * The netlink datagram is received straight into the VPP buffer's current
 * data span. libnetfilter_queue only projects pointers into that datagram;
 * the payload is never copied by this plugin. A worker frame queue moves the
 * buffer index. A fixed completion frame moves the index and generation back
 * to the origin lane, which alone calls nfq_set_verdict and then returns the
 * same buffer through vlib_buffer_free_one().
 */

#include <nfqueue_live_poc/nfqueue_live_poc.h>

#include <vlib/file.h>
#include <vlib/threads.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <string.h>
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
  u8 candidate;
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

static_always_inline u64
nfqueue_live_generation (const nfqueue_live_meta_t *meta)
{
  return ((u64) meta->generation_hi << 32) | meta->generation_lo;
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

static void
nfqueue_live_wake_completion (nfqueue_live_main_t *nm)
{
  u64 one = 1;
  if (write (nm->completion_fd, &one, sizeof (one)) == (ssize_t) sizeof (one))
    nm->completion_wake_writes++;
  else if (errno != EAGAIN && errno != EWOULDBLOCK)
    nm->completion_wake_errors++;
}

static u32
nfqueue_live_ipv4_original_length (const u8 *payload, u32 length)
{
  if (length < 20 || (payload[0] >> 4) != 4)
    return 0;
  if ((payload[0] & 0x0f) < 5)
    return 0;
  if (((u32) (payload[0] & 0x0f) * 4) > length)
    return 0;
  return ((u32) payload[2] << 8) | payload[3];
}

static u32
nfqueue_live_ipv6_original_length (const u8 *payload, u32 length)
{
  if (length < 40 || (payload[0] >> 4) != 6)
    return 0;
  return 40u + (((u32) payload[4] << 8) | payload[5]);
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
  nm->last_captured_length = meta->captured_length;
  nm->last_hook = meta->hook;
  nm->last_uid = meta->uid;
  nm->last_uid_known = (meta->flags & NFQUEUE_LIVE_FLAG_UID_KNOWN) != 0;
  nm->last_ip_version = meta->ip_version;
}

static void
nfqueue_live_return_buffer (nfqueue_live_main_t *nm, u32 buffer_index,
                            nfqueue_live_meta_t *meta)
{
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
  if (meta->completion_refs != 0)
    return;
  if (nm->outstanding != 0)
    nm->outstanding--;
  nm->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_complete_one (nfqueue_live_main_t *nm,
                            const nfqueue_live_completion_t *entry)
{
  vlib_buffer_t *buffer;
  nfqueue_live_meta_t *meta;
  u64 generation;
  int rc;

  buffer = vlib_get_buffer (nm->vm, entry->buffer_index);
  meta = nfqueue_live_meta (buffer);
  generation = ((u64) entry->generation_hi << 32) | entry->generation_lo;

  if (generation != nfqueue_live_generation (meta) ||
      nfqueue_live_state (meta) < NFQUEUE_LIVE_STATE_COMPLETION)
    {
      nm->completion_stale++;
      return;
    }

  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) != 0)
    {
      nm->completion_duplicate++;
      if (meta->completion_refs != 0)
        meta->completion_refs--;
      if (meta->completion_refs == 0)
        nfqueue_live_return_buffer (nm, entry->buffer_index, meta);
      return;
    }

  meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
  nm->verdict_attempts++;
  rc = nfq_set_verdict (nm->queue, meta->packet_id, entry->verdict, 0, 0);
  if (rc < 0)
    {
      meta->flags |= NFQUEUE_LIVE_FLAG_OUTCOME_FAILED;
      nm->verdict_send_failures++;
      nm->last_verdict_errno = errno;
    }
  else
    {
      /* A successful send() proves only that the local netlink socket accepted
       * the datagram. Kernel verdict acceptance remains OUTCOME_UNKNOWN. */
      meta->flags |= NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN;
      nm->verdict_send_success++;
      nm->completion_outcome_unknown++;
    }

  if (meta->completion_refs != 0)
    meta->completion_refs--;
  if (meta->completion_refs == 0)
    nfqueue_live_return_buffer (nm, entry->buffer_index, meta);
}

static clib_error_t *
nfqueue_live_completion_read_ready (clib_file_t *file)
{
  nfqueue_live_main_t *nm = (nfqueue_live_main_t *) file->private_data;
  u64 value;
  nfqueue_live_completion_t entry;

  while (read (nm->completion_fd, &value, sizeof (value)) == (ssize_t) sizeof (value))
    ;
  while (nfqueue_live_completion_pop (&nm->completion, &entry))
    {
      nm->completion_frames++;
      nfqueue_live_complete_one (nm, &entry);
    }
  return 0;
}

static void
nfqueue_live_direct_accept (nfqueue_live_main_t *nm,
                            struct nfq_q_handle *queue, u32 packet_id)
{
  if (nfq_set_verdict (queue, packet_id, NFQUEUE_LIVE_ACCEPT, 0, 0) < 0)
    {
      nm->verdict_send_failures++;
      nm->last_verdict_errno = errno;
    }
  else
    {
      nm->verdict_send_success++;
      nm->completion_outcome_unknown++;
    }
  nm->verdict_attempts++;
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
      return 0;
    }

  payload_length = nfq_get_payload (data, &payload);
  if (payload_length < 0 || !payload)
    {
      nm->malformed_payloads++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      return 0;
    }
  payload_address = (uword) payload;
  begin = (uword) datagram->base;
  end = begin + datagram->parse_length;
  if (payload_address < begin || payload_address > end ||
      (uword) payload_length > end - payload_address)
    {
      nm->malformed_payloads++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      return 0;
    }

  buffer = vlib_get_buffer (nm->vm, datagram->buffer_index);
  meta = nfqueue_live_meta (buffer);
  clib_memset (meta, 0, sizeof (*meta));
  nfqueue_live_set_generation (meta, nm->generation);
  meta->packet_id = packet_id;
  meta->datagram_length = datagram->datagram_length;
  meta->payload_offset = (u32) (payload_address - begin);
  meta->payload_length = (u32) payload_length;
  meta->captured_length = (u16) clib_min ((u32) payload_length, (u32) 0xffff);
  meta->origin_lane = nm->origin_lane;
  meta->hook = header->hook;
  meta->completion_refs = 1;
  if (nfq_get_uid (data, &meta->uid))
    meta->flags |= NFQUEUE_LIVE_FLAG_UID_KNOWN;
  meta->flags |= NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN;
  meta->ip_version = payload[0] >> 4;
  if (meta->ip_version == 4)
    meta->original_length = nfqueue_live_ipv4_original_length (payload,
                                                                (u32) payload_length);
  else if (meta->ip_version == 6)
    meta->original_length = nfqueue_live_ipv6_original_length (payload,
                                                                (u32) payload_length);
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_LIVE);
  nm->payload_span_checks++;
  if (meta->payload_offset + meta->payload_length > meta->datagram_length)
    {
      nm->payload_span_failures++;
      nfqueue_live_direct_accept (nm, queue, packet_id);
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
      return 0;
    }
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
      datagram.nm = nm;
      datagram.buffer_index = buffer_index;
      datagram.base = base;
      datagram.datagram_length = (u32) received;
      datagram.parse_length = clib_min ((u32) received, capacity);
      datagram.callback_count = 0;
      datagram.candidate = 0;
      nm->active_datagram = &datagram;
      buffer->current_length = datagram.parse_length;
      nm->datagrams++;
      handled = nfq_handle_packet (nm->handle, (char *) base,
                                   (int) datagram.parse_length);
      nm->active_datagram = 0;
      if (handled < 0 || datagram.callback_count == 0)
        vlib_buffer_free_one (nm->vm, buffer_index);
      else if (datagram.callback_count > 1)
        {
          nm->multiple_message_datagrams++;
          if (datagram.candidate)
            {
              nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
              nfqueue_live_direct_accept (nm, nm->queue, meta->packet_id);
            }
          vlib_buffer_free_one (nm->vm, buffer_index);
        }
      else if (datagram.candidate)
        {
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          if (!nfqueue_live_index_push (&nm->ingress, buffer_index))
            {
              nm->ingress_overload++;
              nfqueue_live_direct_accept (nm, nm->queue, meta->packet_id);
              vlib_buffer_free_one (nm->vm, buffer_index);
            }
          else
            {
              nm->outstanding++;
              nfqueue_live_record_last (nm, meta, buffer_index, base);
              vlib_process_signal_event (
                nm->vm, nfqueue_live_ingress_process_node.index, 0, 0);
            }
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
      if (worker_thread != meta->origin_lane)
        nm->owner_mismatch_count++;
      if (nfqueue_live_state (meta) != NFQUEUE_LIVE_STATE_LIVE)
        nm->owner_invalid_state++;
      nm->payload_span_checks++;
      if ((meta->flags & NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN) == 0 ||
          meta->payload_offset + meta->payload_length > meta->datagram_length)
        nm->payload_span_failures++;
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
      completion.buffer_index = buffer_index;
      completion.generation_lo = meta->generation_lo;
      completion.generation_hi = meta->generation_hi;
      completion.verdict = NFQUEUE_LIVE_ACCEPT;
      if (!nfqueue_live_completion_push (&nm->completion, &completion))
        nm->completion_ring_overflow++;
      if (nm->inject_stale)
        {
          nfqueue_live_completion_t stale = completion;
          stale.generation_lo++;
          if (stale.generation_lo == 0)
            stale.generation_hi++;
          if (!nfqueue_live_completion_push (&nm->completion, &stale))
            nm->completion_ring_overflow++;
          nm->inject_stale = 0;
        }
      if (nm->inject_duplicate)
        {
          nfqueue_live_completion_t duplicate = completion;
          meta->completion_refs++;
          if (!nfqueue_live_completion_push (&nm->completion, &duplicate))
            nm->completion_ring_overflow++;
          nm->inject_duplicate = 0;
        }
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
          nfqueue_live_completion_t completion = {
            .buffer_index = from[enqueued],
            .generation_lo = nfqueue_live_meta (vlib_get_buffer (vm, from[enqueued]))->generation_lo,
            .generation_hi = nfqueue_live_meta (vlib_get_buffer (vm, from[enqueued]))->generation_hi,
            .verdict = NFQUEUE_LIVE_ACCEPT,
          };
          nfqueue_live_completion_push (&nm->completion, &completion);
          enqueued++;
          nfqueue_live_wake_completion (nm);
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
  nm->outstanding = 0;
  nm->last_buffer_index = ~0;
  nm->last_buffer_base = 0;
  nm->last_worker_thread = ~0;
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
  if (!nm->enabled)
    return 0;
  nm->quiescing = 1;
  if (nm->outstanding != 0)
    return clib_error_return (0,
                              "cannot teardown with outstanding live buffer obligations");
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
                   (unsigned long long) nm->packet_copies);
  vlib_cli_output (vm, "scratch-rx-buffers %llu full-packet-memcpy %llu per-packet-heap-objects %llu",
                   (unsigned long long) nm->scratch_rx_buffers,
                   (unsigned long long) nm->full_packet_memcpy,
                   (unsigned long long) nm->per_packet_heap_objects);
  vlib_cli_output (vm, "handoffs %llu owner-mismatches %llu owner-invalid-state %llu",
                   (unsigned long long) nm->handoff_count,
                   (unsigned long long) nm->owner_mismatch_count,
                   (unsigned long long) nm->owner_invalid_state);
  vlib_cli_output (vm, "completion-frames %llu stale %llu duplicate %llu ring-overflow %llu",
                   (unsigned long long) nm->completion_frames,
                   (unsigned long long) nm->completion_stale,
                   (unsigned long long) nm->completion_duplicate,
                   (unsigned long long) nm->completion_ring_overflow);
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
