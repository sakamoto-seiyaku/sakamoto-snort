/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_end.h"
#include "product_flow_expiry.h"
#include "product_packet_graph.h"
#include <vlib/threads.h>
#include <vnet/buffer.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define PRODUCT_FLOW_END_WORKERS 2
enum { END_CONTROL_NONE, END_CONTROL_NOW, END_CONTROL_NEXT_PACKET };
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  product_flow_runtime_t *runtime;
  u64 generation;
  u64 allocated, consumers, terminals, early_frees, released;
  u64 alloc_callbacks, ordinary_frees;
  u32 trace_count;
  u32 early_next;
  struct
  {
    u64 generation, incarnation;
    u32 slot, batch;
    u16 udp_port;
    u8 kind, reason, early;
  } control;
} product_flow_end_owner_t;

static struct
{
  product_flow_end_owner_t owners[PRODUCT_FLOW_END_WORKERS];
  u32 buffers;
  u32 initialized;
} product_flow_end_main;
extern vlib_node_registration_t product_flow_consumer_node;
extern vlib_node_registration_t product_flow_end_control_node;

/* Slow control/fatal evidence only. This does not run on ordinary packets. */
static void
trace_capacity (vlib_main_t *vm, const char *event, u32 requested, u32 closed)
{
  product_flow_end_owner_t *owner =
    &product_flow_end_main.owners[vlib_get_worker_index (vm->thread_index)];
  u8 index = vlib_buffer_pool_get_default_for_numa (vm, vm->numa_node);
  vlib_buffer_pool_t *pool = vlib_get_buffer_pool (vm, index);
  u32 available;
  clib_spinlock_lock (&pool->lock);
  available = pool->n_avail;
  clib_spinlock_unlock (&pool->lock);
  struct timespec now;
  if (clock_gettime (CLOCK_MONOTONIC, &now))
    clib_panic ("FlowEnd capacity clock unavailable");
  product_flow_runtime_snapshot_t state = product_flow_runtime_snapshot (owner->runtime);
  fprintf (stderr, "s234 event=%s thread=%u owner=%u generation=%llu monotonic_ns=%llu requested=%u closed=%u pool=%u total=%u available=%u owner_cached=%u entry_bytes=%u buffer_bytes=%u data_bytes=%u entries=%u linked=%u ending=%u end_allocated=%llu end_released=%llu\n",
    event, vm->thread_index, vlib_get_worker_index (vm->thread_index),
    (unsigned long long) owner->generation,
    (unsigned long long) now.tv_sec * 1000000000ULL + now.tv_nsec,
    requested, closed, index, pool->n_buffers, available,
    pool->threads[vm->thread_index].n_cached,
    (u32) sizeof (product_flow_entry_t), (u32) sizeof (vlib_buffer_t), pool->data_size,
    state.active_entries, state.linked_entries, state.ending_entries,
    (unsigned long long) owner->allocated, (unsigned long long) owner->released);
}

_Static_assert (offsetof (vnet_buffer_opaque2_t, unused[4]) <=
                  PRODUCT_FLOW_END_DISCRIMINANT_OFFSET, "upstream unused tail");
_Static_assert (offsetof (vlib_buffer_t, opaque2) >= sizeof (vlib_buffer_template_t),
                "native free must preserve the discriminant and identity");

static product_flow_end_owner_t *
current_owner (vlib_main_t *vm)
{
  if (PREDICT_FALSE (!vm->thread_index ||
                    vm->thread_index > PRODUCT_FLOW_END_WORKERS ||
                    vm->thread_index != vlib_get_thread_index ()))
    clib_panic ("FlowEnd executed outside its owner worker");
  return &product_flow_end_main.owners[vlib_get_worker_index (vm->thread_index)];
}

static product_flow_end_metadata_t
metadata_load (const vlib_buffer_t *buffer)
{
  product_flow_end_metadata_t metadata;
  clib_memcpy_fast (&metadata, buffer->opaque2, sizeof (metadata));
  return metadata;
}

static const product_flow_entry_t *
validate_identity (vlib_main_t *vm, const product_flow_end_metadata_t *metadata)
{
  product_flow_end_owner_t *owner = current_owner (vm);
  if (PREDICT_FALSE (!owner->runtime || metadata->owner !=
                      vlib_get_worker_index (vm->thread_index) ||
                    metadata->generation != owner->generation))
    clib_panic ("FlowEnd owner/generation mismatch");
  const product_flow_entry_t *entry = product_flow_runtime_entry (
    owner->runtime, metadata->flow_index);
  if (PREDICT_FALSE (!entry || entry->linked ||
                    entry->incarnation != metadata->incarnation ||
                    entry->end_reason != metadata->end_reason ||
                    !entry->end_reason))
    clib_panic ("FlowEnd does not reference its allocated unlinked entry");
  return entry;
}

static void
validate_signal (vlib_main_t *vm, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (PREDICT_FALSE (!product_buffer_is_flow_end (b) || b->current_length ||
                    b->current_data || b->ref_count != 1 ||
                    (b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    clib_panic ("FlowEnd must be one exclusive empty native buffer");
  /* No AdapterObligation or borrowed first-packet platform state. */
  for (u32 i = 0; i < ARRAY_LEN (b->opaque); i++)
    if (PREDICT_FALSE (b->opaque[i]))
      clib_panic ("FlowEnd carries packet/adapter metadata");
  product_flow_end_metadata_t metadata = metadata_load (b);
  (void) validate_identity (vm, &metadata);
}

static void
trace_signal (vlib_main_t *vm, const char *event, u32 node, u32 bi,
               const product_flow_end_metadata_t *metadata,
               const product_flow_entry_t *entry)
{
  if (!metadata->trace)
    return;
  fprintf (stderr, "s225 event=%s node=%u thread=%u owner=%u generation=%llu buffer=%u slot=%u incarnation=%llu reason=%u linked=%u allocated=%u protocol=%u hash=%llu orig_packets=%llu reply_packets=%llu orig_bytes=%llu reply_bytes=%llu first_seen=%llu last_seen=%llu length=0 obligation=0\n",
    event, node, vm->thread_index, metadata->owner,
    (unsigned long long) metadata->generation, bi, metadata->flow_index,
    (unsigned long long) metadata->incarnation, metadata->end_reason,
    entry->linked, entry->in_use, entry->key.protocol,
    (unsigned long long) entry->canonical_hash,
    (unsigned long long) entry->side_packets[0],
    (unsigned long long) entry->side_packets[1],
    (unsigned long long) entry->side_bytes[0],
    (unsigned long long) entry->side_bytes[1],
    (unsigned long long) entry->first_seen,
    (unsigned long long) entry->last_seen);
}

static u32
buffers_allocated (vlib_main_t *vm, u8 pool_index, u32 *buffers, u32 count)
{
  (void) pool_index;
  for (u32 i = 0; i < count; i++)
    ((u8 *) vlib_get_buffer (vm, buffers[i])->opaque2)
      [PRODUCT_FLOW_END_DISCRIMINANT_OFFSET] &= ~PRODUCT_FLOW_END_DISCRIMINANT;
  if (vm->thread_index && vm->thread_index <= PRODUCT_FLOW_END_WORKERS)
    product_flow_end_main.owners[vlib_get_worker_index (vm->thread_index)]
      .alloc_callbacks += count;
  return count;
}

static u32
buffers_freed (vlib_main_t *vm, u8 pool_index, u32 *buffers, u32 count)
{
  (void) pool_index;
  u32 ended = 0;
  for (u32 i = 0; i < count; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffers[i]);
      if (!product_buffer_is_flow_end (b))
        {
          if (vm->thread_index && vm->thread_index <= PRODUCT_FLOW_END_WORKERS)
            product_flow_end_main.owners[vlib_get_worker_index (vm->thread_index)]
              .ordinary_frees++;
          continue;
        }
      /* vlib_buffer_pool_put runs only when the last reference is returned.
       * Its caller has already reset flags/opaque to the native template. */
      product_flow_end_metadata_t metadata = metadata_load (b);
      const product_flow_entry_t *entry = validate_identity (vm, &metadata);
      product_flow_end_owner_t *owner = current_owner (vm);
      trace_signal (vm, "free_callback", ~0, buffers[i], &metadata, entry);
      product_flow_entry_t expired_snapshot;
      int report_expiry = entry->deadline_us && entry->end_reason == PRODUCT_FLOW_END_EXPIRED;
      if (report_expiry) expired_snapshot = *entry;
      ((u8 *) b->opaque2)[PRODUCT_FLOW_END_DISCRIMINANT_OFFSET] &=
        ~PRODUCT_FLOW_END_DISCRIMINANT;
      if (PREDICT_FALSE (product_flow_runtime_release_end (
            owner->runtime, metadata.flow_index, metadata.generation,
            metadata.incarnation, metadata.end_reason) != PRODUCT_FLOW_ENTRY_STATUS_OK))
        clib_panic ("FlowEnd final release rejected");
      if (report_expiry)
        product_flow_expiry_released (vm, &expired_snapshot, metadata.flow_index);
      owner->released++;
      ended++;
      clib_atomic_fetch_sub_relax (&product_flow_end_main.buffers, 1);
    }
  if (ended) product_flow_expiry_changed (vm);
  return count;
}

static void
deliver_end (void *context, const product_flow_entry_t *entry, u32 slot,
              product_flow_end_reason_t reason)
{
  vlib_main_t *vm = vlib_get_main ();
  product_flow_end_owner_t *owner = current_owner (vm);
  if (PREDICT_FALSE (context != owner || entry->linked))
    clib_panic ("FlowEnd delivery before owner unlink");
  u32 bi;
  if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) != 1))
    {
      trace_capacity (vm, "allocator_returned_zero", 1, 0);
      fprintf (stderr, "s225 event=fatal_allocation_failure thread=%u owner=%u generation=%llu slot=%u incarnation=%llu reason=%u exit_code=70\n",
        vm->thread_index, vlib_get_worker_index (vm->thread_index),
        (unsigned long long) owner->generation, slot,
        (unsigned long long) entry->incarnation, reason);
      /* This is a checked resource failure, not memory corruption. The pinned
       * panic path aborts and enters system core capture, which can retain
       * NFQUEUE descriptors during dump collection. Terminate all threads
       * without that path so the OS releases native ownership promptly.
       * No END finalizers/normal verdicts are claimed for this OS reclamation;
       * the existing supervisor withdraws platform hooks/TUN and owns restart. */
      _exit (70);
    }
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  b->current_data = 0;
  b->current_length = 0;
  b->flags = 0;
  b->next_buffer = 0;
  clib_memset (b->opaque, 0, sizeof (b->opaque));
  product_flow_end_metadata_t metadata = {
    .generation = owner->generation, .incarnation = entry->incarnation,
    .flow_index = slot, .owner = vlib_get_worker_index (vm->thread_index),
    .end_reason = reason, .trace = owner->trace_count++ < 256,
    .early_free = owner->early_next,
    .is_flow_end = PRODUCT_FLOW_END_DISCRIMINANT,
  };
  owner->early_next = 0;
  clib_memcpy_fast (b->opaque2, &metadata, sizeof (metadata));
  owner->allocated++;
  clib_atomic_fetch_add_relax (&product_flow_end_main.buffers, 1);
  validate_signal (vm, bi);
  trace_signal (vm, "unlink_allocate", product_flow_consumer_node.index,
                bi, &metadata, entry);
  vlib_frame_t *frame = vlib_get_frame_to_node (vm, product_flow_consumer_node.index);
  ((u32 *) vlib_frame_vector_args (frame))[0] = bi;
  frame->n_vectors = 1;
  vlib_put_frame_to_node (vm, product_flow_consumer_node.index, frame);
}

clib_error_t *
product_flow_end_init (vlib_main_t *vm)
{
  if (product_flow_end_main.initialized ||
      vlib_buffer_set_alloc_free_callback (vm, buffers_allocated, buffers_freed))
    return clib_error_return (0, "Product FlowEnd buffer callbacks already owned");
  product_flow_end_main.initialized = 1;
  return 0;
}

int
product_flow_end_start (u64 generation, product_flow_runtime_t **runtimes,
                        u32 worker_count)
{
  if (!product_flow_end_main.initialized || !generation ||
      worker_count != PRODUCT_FLOW_END_WORKERS || product_flow_end_buffer_debt ())
    return 0;
  for (u32 i = 0; i < worker_count; i++)
    {
      product_flow_end_owner_t *owner = &product_flow_end_main.owners[i];
      clib_memset (owner, 0, sizeof (*owner));
      owner->runtime = runtimes[i];
      owner->generation = generation;
      if (product_flow_runtime_set_end_callback (runtimes[i], deliver_end, owner)
          != PRODUCT_FLOW_ENTRY_STATUS_OK)
        return 0;
    }
  return product_flow_expiry_bind (generation, runtimes);
}

u32
product_flow_end_buffer_debt (void)
{
  return clib_atomic_load_acq_n (&product_flow_end_main.buffers);
}

void
product_flow_end_unbind (void)
{
  if (PREDICT_FALSE (product_flow_end_buffer_debt ()))
    clib_panic ("cannot replace a runtime referenced by FlowEnd");
  (void) product_flow_expiry_bind (0, NULL);
  for (u32 i = 0; i < PRODUCT_FLOW_END_WORKERS; i++)
    product_flow_end_main.owners[i].runtime = 0;
}

int
product_flow_end_consume (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi)
{
  validate_signal (vm, bi);
  product_flow_end_owner_t *owner = current_owner (vm);
  product_flow_end_metadata_t metadata = metadata_load (vlib_get_buffer (vm, bi));
  const product_flow_entry_t *entry = validate_identity (vm, &metadata);
  owner->consumers++;
  trace_signal (vm, "consumer_end", node->node_index, bi, &metadata, entry);
  /* There are no DPI/telemetry attachments in the current product. This is
   * the shared post-conntrack consumer seam, not a parallel lifecycle arc. */
  if (metadata.early_free)
    {
      owner->early_frees++;
      trace_signal (vm, "consumer_early_free", node->node_index, bi, &metadata, entry);
      vlib_buffer_free (vm, &bi, 1);
      return 1;
    }
  return 0;
}

void
product_flow_end_terminal (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi)
{
  validate_signal (vm, bi);
  product_flow_end_owner_t *owner = current_owner (vm);
  product_flow_end_metadata_t metadata = metadata_load (vlib_get_buffer (vm, bi));
  owner->terminals++;
  trace_signal (vm, "terminal_end", node->node_index, bi, &metadata,
                validate_identity (vm, &metadata));
  vlib_buffer_free (vm, &bi, 1);
}

static void
run_control (vlib_main_t *vm)
{
  product_flow_end_owner_t *owner = current_owner (vm);
  u32 slot = owner->control.slot;
  u64 generation = owner->control.generation, incarnation = owner->control.incarnation;
  u8 reason = owner->control.reason;
  owner->early_next = owner->control.early;
  owner->control.kind = END_CONTROL_NONE;
  if (owner->control.batch)
    {
      /* One explicitly requested owner input invocation. No pending ENDs,
       * reserve buffers, retry, implicit expiry or recurring scan. The UDP
       * port limits controlled closes to the experiment's own endpoints. */
      u32 requested = owner->control.batch, closed = 0;
      u16 port = owner->control.udp_port;
      owner->control.batch = 0;
      trace_capacity (vm, "batch_begin", requested, 0);
      product_flow_runtime_snapshot_t state = product_flow_runtime_snapshot (owner->runtime);
      if (generation == state.generation)
        for (u32 index = 0; index < state.capacity && closed < requested; index++)
          {
            const product_flow_entry_t *entry = product_flow_runtime_entry (owner->runtime, index);
            if (!entry || !entry->linked || entry->key.kind != PRODUCT_OWNER_KEY_L4_PORTS ||
                entry->key.protocol != PRODUCT_FLOW_ENTRY_PROTOCOL_UDP ||
                (entry->key.transport.ports.a != port && entry->key.transport.ports.b != port))
              continue;
            if (product_flow_runtime_close (owner->runtime, index, generation,
                  entry->incarnation, PRODUCT_FLOW_END_CLOSED) != PRODUCT_FLOW_ENTRY_STATUS_OK)
              clib_panic ("owner-local controlled batch close rejected");
            closed++;
          }
      trace_capacity (vm, "batch_end", requested, closed);
      return;
    }
  product_flow_entry_status_t status = product_flow_runtime_close (
    owner->runtime, slot, generation, incarnation, reason);
  if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
    owner->early_next = 0;
  fprintf (stderr, "s225 event=controlled_close thread=%u owner=%u generation=%llu slot=%u incarnation=%llu reason=%u status=%u\n",
    vm->thread_index, vlib_get_worker_index (vm->thread_index),
    (unsigned long long) generation, slot, (unsigned long long) incarnation,
    reason, status);
}

void
product_flow_end_before_observe (vlib_main_t *vm)
{
  if (current_owner (vm)->control.kind == END_CONTROL_NEXT_PACKET)
    run_control (vm);
}

VLIB_NODE_FN (product_flow_end_control_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  (void) frame;
  vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  if (current_owner (vm)->control.kind == END_CONTROL_NOW)
    run_control (vm);
  return 0;
}
VLIB_REGISTER_NODE (product_flow_end_control_node) = {
  .name = "product-flow-end-control", .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

void
product_flow_end_quiesce (vlib_main_t *vm)
{
  product_flow_expiry_quiesce ();
  /* Caller holds the same lifecycle worker barrier used to quiesce ingress.
   * Cancel only commands which have not closed an entry. Live ENDs drain in
   * their existing graph before administrative FlowRuntime cleanup. */
  (void) vm;
  for (u32 i = 0; i < PRODUCT_FLOW_END_WORKERS; i++)
    {
      product_flow_end_main.owners[i].control.kind = END_CONTROL_NONE;
      vlib_main_t *worker_vm = vlib_get_main_by_index (vlib_get_worker_thread_index (i));
      vlib_node_set_state (worker_vm, product_flow_end_control_node.index,
                           VLIB_NODE_STATE_DISABLED);
    }
}

static clib_error_t *
close_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  (void) command;
  u32 worker = ~0, slot = ~0, early = 0, on_packet = 0, batch = 0, port = 0;
  u64 generation = 0, incarnation = 0;
  u32 reason = PRODUCT_FLOW_END_CLOSED;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "owner %u", &worker) ||
          unformat (input, "slot %u", &slot) ||
          unformat (input, "generation %llu", &generation) ||
          unformat (input, "incarnation %llu", &incarnation) ||
          unformat (input, "batch %u", &batch) ||
          unformat (input, "udp-port %u", &port)) ;
      else if (unformat (input, "early")) early = 1;
      else if (unformat (input, "on-packet")) on_packet = 1;
      else if (unformat (input, "expire")) reason = PRODUCT_FLOW_END_EXPIRED;
      else return clib_error_return (0, "invalid FlowEnd close argument");
    }
  if (worker >= PRODUCT_FLOW_END_WORKERS || !generation ||
      (!batch && (!incarnation || port)) ||
      (batch && (batch > 1024 || !port || port > 65535 || early ||
                 reason != PRODUCT_FLOW_END_CLOSED || incarnation || slot != ~0U)) ||
      !product_packet_graph_accepting ())
    return clib_error_return (0, "FlowEnd close requires owner/generation and slot/incarnation or batch 1..1024/udp-port");
  product_flow_end_owner_t *owner = &product_flow_end_main.owners[worker];
  if (batch && generation != owner->generation)
    return clib_error_return (0, "FlowEnd batch generation mismatch");
  if (owner->control.kind || owner->early_next)
    return clib_error_return (0, "owner already has a controlled close");
  owner->control.generation = generation;
  owner->control.incarnation = incarnation;
  owner->control.slot = slot;
  owner->control.reason = reason;
  owner->control.early = early;
  owner->control.batch = batch;
  owner->control.udp_port = port;
  owner->control.kind = on_packet ? END_CONTROL_NEXT_PACKET : END_CONTROL_NOW;
  if (!on_packet)
    vlib_node_set_state (vlib_get_main_by_index (vlib_get_worker_thread_index (worker)),
                         product_flow_end_control_node.index, VLIB_NODE_STATE_POLLING);
  vlib_cli_output (vm, "flow-end.close=queued owner=%u slot=%u generation=%llu incarnation=%llu on_packet=%u early=%u batch=%u udp_port=%u",
    worker, slot, (unsigned long long) generation,
    (unsigned long long) incarnation, on_packet, early, batch, port);
  return 0;
}
VLIB_CLI_COMMAND (product_flow_end_close_command, static) = {
  .path = "product flow-end close", .function = close_cli,
};

static clib_error_t *
status_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  (void) input; (void) command;
  vlib_cli_output (vm, "flow-end.buffers=%u", product_flow_end_buffer_debt ());
  for (u32 i = 0; i < PRODUCT_FLOW_END_WORKERS; i++)
    {
      const product_flow_end_owner_t *o = &product_flow_end_main.owners[i];
      product_flow_runtime_snapshot_t s = product_flow_runtime_snapshot (o->runtime);
      vlib_cli_output (vm, "flow-end.owner=%u generation=%llu allocated=%llu consumers=%llu terminals=%llu early_frees=%llu released=%llu active_entries=%u linked=%u ending=%u pool_releases=%llu administrative_releases=%llu control=%u alloc_callbacks=%llu ordinary_frees=%llu",
        i, (unsigned long long) o->generation,
        (unsigned long long) o->allocated, (unsigned long long) o->consumers,
        (unsigned long long) o->terminals, (unsigned long long) o->early_frees,
        (unsigned long long) o->released, s.active_entries, s.linked_entries,
        s.ending_entries, (unsigned long long) s.release_count,
        (unsigned long long) s.administrative_release_count, o->control.kind,
        (unsigned long long) o->alloc_callbacks, (unsigned long long) o->ordinary_frees);
    }
  return 0;
}
VLIB_CLI_COMMAND (product_flow_end_status_command, static) = {
  .path = "show product flow-end", .function = status_cli,
};
