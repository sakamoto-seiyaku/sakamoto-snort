/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_expiry.h"
#include "product_observation.h"
#include "product_flow_timeout.h"
#include "product_packet_graph.h"
#include <vlib/file.h>
#include <vlib/threads.h>
#include <sys/timerfd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* S226's qualified owner-local deadline driver. The old A/B path is gated
 * by an explicit startup option and does not define production behavior. */
enum { EXPIRY_WORKERS = 2, EXPIRY_BATCH = 100, EXPIRY_BATCH_GAP_US = 100000 };
enum { EXPIRY_OFF, EXPIRY_POLL, EXPIRY_DEADLINE };
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  product_flow_runtime_t *runtime;
  u64 generation, eligible_us, scheduled_us;
  u64 calls, checks, wakes, batches, closed, released;
  u64 budget_exhausted, oldest_overdue_us, stale_wakes, pending_stale;
  u64 logical_expired;
  u32 due_backlog;
  u32 mode, initialize, timer_file;
  int timer_fd;
  u16 port;
} expiry_owner_t;
static expiry_owner_t owners[EXPIRY_WORKERS];
static u8 experimental_startup, trace_all;
extern vlib_node_registration_t product_flow_expiry_node;

static expiry_owner_t *
current_owner (vlib_main_t *vm)
{
  if (!vm->thread_index || vm->thread_index > EXPIRY_WORKERS ||
      vm->thread_index != vlib_get_thread_index ())
    clib_panic ("flow expiry outside owner");
  return &owners[vlib_get_worker_index (vm->thread_index)];
}

static void
fail (const char *operation)
{
  fprintf (stderr, "%s event=infrastructure_failure operation=%s errno=%d exit_code=70\n",
           experimental_startup ? "s226" : "s227", operation, errno);
  _exit (70);
}

static u64
now_us (vlib_main_t *vm)
{
  return (u64) (vlib_time_now (vm) * 1000000.0);
}

static void
schedule (vlib_main_t *vm, expiry_owner_t *owner)
{
  if (owner->mode != EXPIRY_DEADLINE)
    return;
  u64 next = product_flow_runtime_next_deadline (owner->runtime);
  u64 observation_next = product_observation_deadline (vlib_get_worker_index (vm->thread_index));
  if (observation_next < next) next = observation_next;
  if (next != UINT64_MAX && next < owner->eligible_us)
    next = owner->eligible_us;
  if (owner->scheduled_us == next)
    return;
  struct itimerspec timer = {0};
  if (next != UINT64_MAX)
    {
      /* Relative kernel MONOTONIC wait; the authoritative deadline and the
       * due/release endpoints all remain in the same owner vlib microseconds.
       * Recheck after wake handles early/late notification, without changing
       * any protocol deadline. No wall-clock or cross-worker time offset. */
      u64 now = now_us (vm);
      u64 delay = next > now ? next - now : 1;
      timer.it_value.tv_sec = delay / 1000000;
      timer.it_value.tv_nsec = (delay % 1000000) * 1000;
    }
  if (timerfd_settime (owner->timer_fd, 0, &timer, NULL)) fail ("timerfd_settime");
  owner->scheduled_us = next;
}

static clib_error_t *
ready (clib_file_t *file)
{
  vlib_main_t *vm = vlib_get_main ();
  expiry_owner_t *owner = current_owner (vm);
  if (owner->mode != EXPIRY_DEADLINE || file->private_data != owner->generation)
    {
      owner->stale_wakes++;
      fprintf (stderr, "s227 event=stale_wake owner=%u thread=%u generation=%llu received_generation=%llu accepted=0\n",
        vlib_get_worker_index (vm->thread_index), vm->thread_index,
        (unsigned long long) owner->generation, (unsigned long long) file->private_data);
      return NULL;
    }
  u64 count;
  ssize_t received;
  do received = read (file->file_descriptor, &count, sizeof (count));
  while (received < 0 && errno == EINTR);
  if (received < 0 && errno == EAGAIN) return NULL;
  if (received != sizeof (count)) fail ("timerfd_read");
  owner->wakes++;
  owner->scheduled_us = 0; /* consumed one-shot, a later refresh may re-arm */
  vlib_node_set_interrupt_pending (vm, product_flow_expiry_node.index);
  return NULL;
}

static clib_error_t *
file_error (clib_file_t *file)
{
  (void) file;
  fail ("timerfd_epoll");
  return NULL;
}

static int
attach_timer (expiry_owner_t *owner, u32 index)
{
  owner->timer_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  int fd = owner->timer_fd < 0 ? -1 : fcntl (owner->timer_fd, F_DUPFD_CLOEXEC, 0);
  if (fd < 0) return 0; /* Caller quiesces all partially installed owners. */
  clib_file_t file = {
    .file_descriptor = fd, .polling_thread_index = vlib_get_worker_thread_index (index),
    .private_data = owner->generation, .read_function = ready, .error_function = file_error,
    .description = format (0, "product-flow-expiry-%u%c", index, 0),
  };
  owner->timer_file = clib_file_add (&file_main, &file);
  return 1;
}

static int
matches (const expiry_owner_t *owner, const product_flow_entry_t *entry)
{
  if (!entry || !entry->linked) return 0;
  /* The retained S226 A/B initializer reads UDP state. Its explicit test
   * scope must stay UDP-only; production consumes every supported tracker. */
  if (experimental_startup)
    return entry->key.kind == PRODUCT_OWNER_KEY_L4_PORTS &&
      entry->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP &&
      (entry->key.transport.ports.a == owner->port ||
       entry->key.transport.ports.b == owner->port);
  return (entry->key.kind == PRODUCT_OWNER_KEY_L4_PORTS &&
          (entry->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP ||
           entry->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP)) ||
    (entry->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY &&
     (entry->key.protocol == 1 || entry->key.protocol == 58));
}

static void
refresh (expiry_owner_t *owner, const product_flow_entry_t *entry, u32 slot,
         product_ct_timeout_t timeout, u64 timestamp)
{
  u64 deadline;
  if (!product_flow_deadline (timeout, timestamp, &deadline))
    clib_panic ("flow expiry received an unsupported timeout class");
  if (product_flow_runtime_set_deadline (owner->runtime, slot, owner->generation,
        entry->incarnation, deadline, timeout) != PRODUCT_FLOW_ENTRY_STATUS_OK)
    clib_panic ("flow expiry deadline identity rejected");
}

void
product_flow_expiry_observed (vlib_main_t *vm,
  const product_flow_entry_observation_t *observation, u64 timestamp)
{
  expiry_owner_t *owner = current_owner (vm);
  if (observation && observation->expired_before_observe)
    {
      owner->logical_expired++;
      if (trace_all || owner->logical_expired <= 256)
        fprintf (stderr, "s227 event=logical_expiry owner=%u thread=%u generation=%llu old_slot=%u old_incarnation=%llu old_deadline_us=%llu now_us=%llu new_slot=%u new_incarnation=%llu created=%u\n",
          vlib_get_worker_index (vm->thread_index), vm->thread_index,
          (unsigned long long) owner->generation, observation->previous_slot,
          (unsigned long long) observation->previous_incarnation,
          (unsigned long long) observation->previous_deadline_us, (unsigned long long) timestamp,
          observation->slot, (unsigned long long) (observation->entry ? observation->entry->incarnation : 0),
          observation->created);
    }
  if (!owner->mode || owner->initialize || !observation ||
      !observation->tracker.refresh_deadline || !matches (owner, observation->entry))
    return;
  refresh (owner, observation->entry, observation->slot, observation->tracker.timeout, timestamp);
  schedule (vm, owner);
}

void
product_flow_expiry_changed (vlib_main_t *vm)
{
  schedule (vm, current_owner (vm));
}

void
product_flow_expiry_released (vlib_main_t *vm,
  const product_flow_entry_t *entry, u32 slot)
{
  expiry_owner_t *owner = current_owner (vm);
  if (entry->end_reason != PRODUCT_FLOW_END_EXPIRED || !entry->deadline_us)
    return;
  owner->released++;
  /* Bounded in normal operation; explicit evidence startup can trace every
   * final release. Neither mode retains a packet or changes the END path. */
  if (!experimental_startup && !trace_all && owner->released > 256) return;
  fprintf (stderr, "%s event=release owner=%u thread=%u generation=%llu slot=%u incarnation=%llu deadline_us=%llu release_us=%llu timeout=%u packets=%llu linked=%u heap_position=%u\n",
    experimental_startup ? "s226" : "s227",
    vlib_get_worker_index (vm->thread_index), vm->thread_index,
    (unsigned long long) owner->generation, slot, (unsigned long long) entry->incarnation,
    (unsigned long long) entry->deadline_us, (unsigned long long) now_us (vm),
    entry->timeout_class, (unsigned long long) entry->packets, entry->linked, entry->heap_position);
}

VLIB_NODE_FN (product_flow_expiry_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  (void) frame;
  expiry_owner_t *owner = current_owner (vm);
  if (!owner->mode) return 0;
  owner->calls++;
  if (owner->pending_stale)
    {
      /* A controlled old-notification vector exercises the real callback on
       * its real owner. A wrong acceptance would attempt read(-1) and fail. */
      clib_file_t old_file = {.file_descriptor = -1, .private_data = owner->pending_stale};
      owner->pending_stale = 0;
      ready (&old_file);
      vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_INTERRUPT);
    }
  if (owner->initialize)
    {
      owner->initialize = 0;
      product_flow_runtime_snapshot_t s = product_flow_runtime_snapshot (owner->runtime);
      for (u32 slot = 0; slot < s.capacity; slot++)
        {
          const product_flow_entry_t *entry = product_flow_runtime_entry (owner->runtime, slot);
          if (!matches (owner, entry)) continue;
          product_ct_timeout_t timeout = entry->protocol_state.udp.phase == PRODUCT_UDP_BIDIR
            ? PRODUCT_CT_TIMEOUT_OTHER_BIDIR : entry->protocol_state.udp.phase == PRODUCT_UDP_MULTIPLE
            ? PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE : PRODUCT_CT_TIMEOUT_OTHER_FIRST;
          refresh (owner, entry, slot, timeout, entry->last_seen);
        }
      if (owner->mode == EXPIRY_DEADLINE)
        vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_INTERRUPT);
      fprintf (stderr, "s226 event=initialized owner=%u thread=%u generation=%llu mode=%u timers=%u now_us=%llu batch=%u gap_us=%u\n",
        vlib_get_worker_index (vm->thread_index), vm->thread_index,
        (unsigned long long) owner->generation, owner->mode,
        product_flow_runtime_snapshot (owner->runtime).timer_entries,
        (unsigned long long) now_us (vm), EXPIRY_BATCH, EXPIRY_BATCH_GAP_US);
    }
  u64 now = now_us (vm);
  product_observation_flush_due (vm, now);
  u64 next = product_flow_runtime_next_deadline (owner->runtime);
  if (now >= owner->eligible_us && next <= now)
    {
      u32 closed;
      owner->checks++;
      if (product_flow_runtime_run_due (owner->runtime, now, EXPIRY_BATCH, &closed)
          != PRODUCT_FLOW_ENTRY_STATUS_OK)
        clib_panic ("experiment due batch rejected");
      owner->batches++;
      owner->closed += closed;
      owner->eligible_us = now + EXPIRY_BATCH_GAP_US;
      u64 remaining = product_flow_runtime_next_deadline (owner->runtime);
      owner->due_backlog = remaining != UINT64_MAX && remaining <= now;
      if (closed == EXPIRY_BATCH && owner->due_backlog) owner->budget_exhausted++;
      if (now - next > owner->oldest_overdue_us) owner->oldest_overdue_us = now - next;
      if (experimental_startup || trace_all || owner->batches <= 256)
        fprintf (stderr, "%s event=batch owner=%u thread=%u generation=%llu now_us=%llu oldest_us=%llu closed=%u timers=%u next_us=%llu due_backlog=%u budget_exhausted=%llu\n",
        experimental_startup ? "s226" : "s227",
        vlib_get_worker_index (vm->thread_index), vm->thread_index,
        (unsigned long long) owner->generation, (unsigned long long) now,
        (unsigned long long) next, closed,
        product_flow_runtime_snapshot (owner->runtime).timer_entries,
        (unsigned long long) remaining, owner->due_backlog,
        (unsigned long long) owner->budget_exhausted);
    }
  schedule (vm, owner);
  return 0;
}

VLIB_REGISTER_NODE (product_flow_expiry_node) = {
  .name = "product-flow-expiry", .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

void
product_flow_expiry_quiesce (void)
{
  for (u32 i = 0; i < EXPIRY_WORKERS; i++)
    {
      expiry_owner_t *owner = &owners[i];
      if (owner->mode)
        {
          vlib_main_t *vm = vlib_get_main_by_index (vlib_get_worker_thread_index (i));
          vlib_node_set_state (vm, product_flow_expiry_node.index, VLIB_NODE_STATE_DISABLED);
          if (owner->timer_file != ~0U)
            clib_file_del_by_index (&file_main, owner->timer_file);
          if (owner->timer_fd >= 0) close (owner->timer_fd);
          owner->timer_file = ~0U;
          owner->timer_fd = -1;
          owner->mode = owner->initialize = 0;
          owner->scheduled_us = UINT64_MAX;
          owner->pending_stale = owner->due_backlog = 0;
        }
    }
}

int
product_flow_expiry_bind (u64 generation, product_flow_runtime_t **runtimes)
{
  product_flow_expiry_quiesce ();
  for (u32 i = 0; i < EXPIRY_WORKERS; i++)
    {
      clib_memset (&owners[i], 0, sizeof (owners[i]));
      owners[i].runtime = runtimes ? runtimes[i] : NULL;
      owners[i].generation = generation;
      owners[i].timer_fd = -1;
      owners[i].timer_file = ~0U;
      owners[i].scheduled_us = UINT64_MAX;
      if (runtimes && !experimental_startup)
        {
          /* Fresh empty runtime: attach no entry by scanning. Valid packet
           * observations on its owner will establish each real deadline. */
          if (!generation || product_flow_runtime_snapshot (runtimes[i]).active_entries)
            { product_flow_expiry_quiesce (); return 0; }
          owners[i].mode = EXPIRY_DEADLINE;
          if (!attach_timer (&owners[i], i))
            { product_flow_expiry_quiesce (); return 0; }
          vlib_node_set_state (vlib_get_main_by_index (vlib_get_worker_thread_index (i)),
                              product_flow_expiry_node.index, VLIB_NODE_STATE_INTERRUPT);
        }
    }
  return 1;
}

static clib_error_t *
experiment_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  (void) command;
  if (!experimental_startup)
    return clib_error_return (0, "A/B requires explicit product-flow-expiry experiment startup");
  u32 mode = EXPIRY_OFF, port = 0;
  u64 generation = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "poll")) mode = EXPIRY_POLL;
      else if (unformat (input, "deadline")) mode = EXPIRY_DEADLINE;
      else if (unformat (input, "udp-port %u", &port) ||
               unformat (input, "generation %llu", &generation)) ;
      else return clib_error_return (0, "invalid expiry experiment argument");
    }
  if (!mode || !port || port > 65535 || !generation || !product_packet_graph_accepting ())
    return clib_error_return (0, "requires poll|deadline udp-port <port> generation <active>");
  for (u32 i = 0; i < EXPIRY_WORKERS; i++)
    if (!owners[i].runtime || owners[i].mode || owners[i].generation != generation)
      return clib_error_return (0, "experiment already active or generation mismatch");
  /* The ordinary CLI worker barrier holds. It publishes configuration only;
   * each owner attaches its own table's deadlines in its first invocation. */
  for (u32 i = 0; i < EXPIRY_WORKERS; i++)
    {
      expiry_owner_t *owner = &owners[i];
      owner->port = port;
      owner->mode = mode;
      owner->initialize = 1;
      owner->scheduled_us = UINT64_MAX;
      if (mode == EXPIRY_DEADLINE)
        {
          if (!attach_timer (owner, i))
            {
              product_flow_expiry_quiesce ();
              return clib_error_return (0, "expiry experiment timer allocation failed");
            }
        }
      vlib_node_set_state (vlib_get_main_by_index (vlib_get_worker_thread_index (i)),
                          product_flow_expiry_node.index, VLIB_NODE_STATE_POLLING);
    }
  vlib_cli_output (vm, "expiry.experiment=queued mode=%u generation=%llu udp_port=%u batch=%u gap_us=%u",
    mode, (unsigned long long) generation, port, EXPIRY_BATCH, EXPIRY_BATCH_GAP_US);
  return NULL;
}
VLIB_CLI_COMMAND (product_flow_expiry_experiment_cli, static) = {
  .path = "product expiry experiment", .short_help = "product expiry experiment poll|deadline udp-port N generation G",
  .function = experiment_cli,
};

static clib_error_t *
show_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  (void) input; (void) command;
  for (u32 i = 0; i < EXPIRY_WORKERS; i++)
    {
      expiry_owner_t *o = &owners[i];
      vlib_cli_output (vm, "expiry.owner=%u generation=%llu mode=%u initialize=%u calls=%llu checks=%llu wakes=%llu batches=%llu closed=%llu released=%llu timers=%u next_us=%llu timer_fd=%d timer_file=%u experiment=%u trace_all=%u scheduled_us=%llu due_backlog=%u oldest_overdue_us=%llu budget_exhausted=%llu stale_wakes=%llu logical_expired=%llu",
        i, (unsigned long long) o->generation, o->mode, o->initialize,
        (unsigned long long) o->calls, (unsigned long long) o->checks,
        (unsigned long long) o->wakes, (unsigned long long) o->batches,
        (unsigned long long) o->closed, (unsigned long long) o->released,
        product_flow_runtime_snapshot (o->runtime).timer_entries,
        (unsigned long long) product_flow_runtime_next_deadline (o->runtime),
        o->timer_fd, o->timer_file, experimental_startup, trace_all,
        (unsigned long long) o->scheduled_us, o->due_backlog,
        (unsigned long long) o->oldest_overdue_us, (unsigned long long) o->budget_exhausted,
        (unsigned long long) o->stale_wakes, (unsigned long long) o->logical_expired);
    }
  return NULL;
}
VLIB_CLI_COMMAND (product_flow_expiry_show_cli, static) = {
  .path = "show product expiry", .short_help = "show product expiry", .function = show_cli,
};

static clib_error_t *
stale_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  (void) command;
  u32 owner = ~0U;
  u64 generation = 0;
  if (!unformat (input, "owner %u generation %llu", &owner, &generation) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT || owner >= EXPIRY_WORKERS || !generation ||
      owners[owner].mode != EXPIRY_DEADLINE || owners[owner].generation == generation || owners[owner].pending_stale)
    return clib_error_return (0, "requires active owner and distinct nonzero old generation");
  owners[owner].pending_stale = generation;
  vlib_node_set_state (vlib_get_main_by_index (vlib_get_worker_thread_index (owner)),
                      product_flow_expiry_node.index, VLIB_NODE_STATE_POLLING);
  vlib_cli_output (vm, "expiry.stale=queued owner=%u generation=%llu", owner, (unsigned long long) generation);
  return NULL;
}
VLIB_CLI_COMMAND (product_flow_expiry_stale_cli, static) = {
  .path = "product expiry validate stale-wake",
  .short_help = "product expiry validate stale-wake owner N generation OLD", .function = stale_cli,
};

static clib_error_t *
expiry_config (vlib_main_t *vm, unformat_input_t *input)
{
  (void) vm;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "experiment")) experimental_startup = 1;
      else if (unformat (input, "trace-all")) trace_all = 1;
      else return clib_error_return (0, "unknown flow expiry startup option");
    }
  return NULL;
}
VLIB_CONFIG_FUNCTION (expiry_config, "product-flow-expiry");
