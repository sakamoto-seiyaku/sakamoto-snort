/* SPDX-License-Identifier: Apache-2.0 */

/*
 * OI-1 scheduler/wakeup closure probe.
 *
 * This is test-only code.  The Flow Stack module is deliberately exposed as
 * a small opaque seam: submit, drive, arm_wait, and quiesce.  HEV/lwIP tasks,
 * sockets, pbufs, and TLS remain inside the dynamically loaded adapter.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/file.h>
#include <vlib/threads.h>
#include <vppinfra/file.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define OI1_MAX_TURNS 4096U
#define OI1_SENTINEL_TARGET 64U
#define OI1_WAKE_HISTORY 512U
#define OI1_HARD_QUANTUM 1U
#define OI1_WALL_BUDGET_NS 5000000ULL

typedef enum
{
  OI1_MODE_IDLE = 0,
  OI1_MODE_TIMER,
  OI1_MODE_FD,
  OI1_MODE_PACKET,
  OI1_MODE_MIXED,
  OI1_MODE_FAIRNESS,
} oi1_mode_t;

typedef enum
{
  OI1_STATE_RUNNABLE = 1,
  OI1_STATE_WAITING = 2,
  OI1_STATE_STOPPED = 3,
  OI1_STATE_FAULT = 4,
} oi1_state_t;

typedef struct
{
  int status;
  uint32_t quanta;
  uint32_t work_remaining;
  uint32_t total_task_count;
  uint32_t running_task_count;
  int32_t next_timeout_ms;
  uint64_t generation;
  uint64_t wake_sequence;
  uint64_t input_packets;
  uint64_t output_packets;
  uint64_t timer_callbacks;
  uint64_t callback_count;
  uint64_t foreign_callback_count;
  uint64_t task_residue;
  uint64_t fd_residue;
  uint64_t bound_pthread;
  uint64_t wait_pthread;
  uint64_t wait_publishes;
  uint64_t wait_callback_count;
  uint64_t foreign_thread_attempts;
  uint64_t foreign_thread_rejections;
  int32_t fault_reason;
  uint64_t timer_residue;
  uint64_t credit_residue;
} oi1_driver_result_t;

typedef struct
{
  uint64_t generation;
  uint64_t sequence;
  uint32_t cause;
  uint32_t reserved;
} oi1_wake_token_t;

typedef void *(*oi1_new_fn) (int timer_interval_ms, int always_runnable);
typedef int (*oi1_submit_fn) (void *driver, const void *packet,
                              size_t length);
typedef int (*oi1_drive_fn) (void *driver, uint32_t wake_cause,
                             uint32_t quantum_budget,
                             uint64_t wall_deadline_ns,
                             oi1_driver_result_t *result);
typedef int (*oi1_arm_wait_fn) (void *driver, int wake_sink_fd,
                                uint64_t generation, uint64_t sequence);
typedef int (*oi1_schedule_fd_fn) (void *driver, const void *packet,
                                   size_t length, uint32_t delay_ms);
typedef int (*oi1_foreign_probe_fn) (void *driver);
typedef int (*oi1_request_stop_fn) (void *driver);
typedef int (*oi1_quiesce_fn) (void *driver, uint64_t generation,
                               oi1_driver_result_t *result);

typedef struct
{
  void *handle;
  oi1_new_fn new_driver;
  oi1_submit_fn submit;
  oi1_drive_fn drive;
  oi1_arm_wait_fn arm_wait;
  oi1_schedule_fd_fn schedule_fd;
  oi1_foreign_probe_fn foreign_probe;
  oi1_request_stop_fn request_stop;
  oi1_quiesce_fn quiesce;
} oi1_api_t;

typedef struct
{
  oi1_api_t api;
  void *driver;
  u32 owner_frame_queue;
  u32 sentinel_frame_queue;
  u32 target_thread;
  u32 pending_worker;
  u32 worker_token_pending;
  u32 active;
  u32 finished;
  u32 stop_requested;
  u32 stop_sent;
  u32 fd_fixture_scheduled;
  u32 packet_submitted;
  u32 foreign_probe_done;
  u32 fairness_scheduled;
  u32 sentinel_target;
  u32 mode;
  u32 timer_interval_ms;
  u32 wake_cause;
  oi1_state_t state;
  u64 generation;
  u64 next_wake_sequence;
  u64 worker_invocations;
  u64 drive_calls;
  u64 immediate_rearms;
  u64 accepted_wakes;
  u64 stale_wakes;
  u64 duplicate_wakes;
  u64 wake_publish_errors;
  u64 vpp_buffers_allocated;
  u64 vpp_buffers_freed;
  u64 vpp_buffer_residue;
  u64 sentinel_progress;
  u64 sentinel_first_owner_turn;
  u64 sentinel_last_owner_turn;
  u64 foreign_probe_pass;
  oi1_driver_result_t last;
  int wake_pipe[2];
  u32 wake_file_index;
  u64 accepted_sequences[OI1_WAKE_HISTORY];
  u32 accepted_sequence_count;
  pthread_mutex_t lock;
  char error[256];
} oi1_main_t;

static oi1_main_t oi1_main;

extern vlib_node_registration_t oi1_trigger_node;
extern vlib_node_registration_t oi1_worker_node;
extern vlib_node_registration_t oi1_sentinel_node;

static const uint8_t oi1_probe_packet[33] = {
  0x45, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00,
  0x40, 0x11, 0x66, 0xc9, 0x0a, 0x00, 0x00, 0x02,
  0x0a, 0x00, 0x00, 0x01, 0x9c, 0x40, 0xc0, 0x01,
  0x00, 0x0d, 0x00, 0x00, 'h',  'e',  'l',  'l',
  'o',
};

static uint64_t
oi1_now_ns (void)
{
  struct timespec ts;
  if (clock_gettime (CLOCK_MONOTONIC, &ts) < 0)
    return 0;
  return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static void
oi1_set_error (const char *message)
{
  snprintf (oi1_main.error, sizeof (oi1_main.error), "%s", message);
}

static int
oi1_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol) {
    oi1_set_error (dlerror ());
    return -1;
  }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static int
oi1_load_hev (const char *path)
{
  void *handle;

  if (oi1_main.api.handle)
    return 0;
  if (!path || !path[0]) {
    oi1_set_error ("OI1_HEV_LIB is empty");
    return -1;
  }
  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    oi1_set_error (dlerror ());
    return -1;
  }
#define OI1_LOAD(field, symbol) \
  if (oi1_load_symbol (handle, symbol, &oi1_main.api.field) < 0) \
    goto failed
  OI1_LOAD (new_driver, "hev_sakamoto_owner_inline_new");
  OI1_LOAD (submit, "hev_sakamoto_owner_inline_submit");
  OI1_LOAD (drive, "hev_sakamoto_owner_inline_drive");
  OI1_LOAD (arm_wait, "hev_sakamoto_owner_inline_arm_wait");
  OI1_LOAD (schedule_fd, "hev_sakamoto_owner_inline_schedule_fd");
  OI1_LOAD (foreign_probe, "hev_sakamoto_owner_inline_foreign_probe");
  OI1_LOAD (request_stop, "hev_sakamoto_owner_inline_request_stop");
  OI1_LOAD (quiesce, "hev_sakamoto_owner_inline_quiesce");
#undef OI1_LOAD
  oi1_main.api.handle = handle;
  fprintf (stderr, "oi1 stage=hev-loaded lib=%s\n", path);
  return 0;

failed:
  dlclose (handle);
  memset (&oi1_main.api, 0, sizeof (oi1_main.api));
  return -1;
}

static oi1_mode_t
oi1_mode_from_string (const char *name)
{
  if (!name || !strcmp (name, "idle"))
    return OI1_MODE_IDLE;
  if (!strcmp (name, "timer"))
    return OI1_MODE_TIMER;
  if (!strcmp (name, "fd"))
    return OI1_MODE_FD;
  if (!strcmp (name, "packet"))
    return OI1_MODE_PACKET;
  if (!strcmp (name, "mixed"))
    return OI1_MODE_MIXED;
  if (!strcmp (name, "fairness"))
    return OI1_MODE_FAIRNESS;
  return (oi1_mode_t) -1;
}

static const char *
oi1_mode_name (oi1_mode_t mode)
{
  switch (mode) {
  case OI1_MODE_TIMER: return "timer";
  case OI1_MODE_FD: return "fd";
  case OI1_MODE_PACKET: return "packet";
  case OI1_MODE_MIXED: return "mixed";
  case OI1_MODE_FAIRNESS: return "fairness";
  default: return "idle";
  }
}

static const char *
oi1_state_name (oi1_state_t state)
{
  switch (state) {
  case OI1_STATE_RUNNABLE: return "RUNNABLE";
  case OI1_STATE_WAITING: return "WAITING";
  case OI1_STATE_STOPPED: return "STOPPED";
  case OI1_STATE_FAULT: return "FAULT";
  default: return "UNKNOWN";
  }
}

static void
oi1_record_fault (const char *message)
{
  oi1_main.state = OI1_STATE_FAULT;
  oi1_set_error (message);
}

static int
oi1_sequence_seen (u64 sequence)
{
  for (u32 i = 0; i < oi1_main.accepted_sequence_count; i++)
    if (oi1_main.accepted_sequences[i] == sequence)
      return 1;
  return 0;
}

static void
oi1_accept_wake (vlib_main_t *vm, const oi1_wake_token_t *token)
{
  oi1_main_t *tm = &oi1_main;

  pthread_mutex_lock (&tm->lock);
  if (!tm->active || token->generation != tm->generation) {
    tm->stale_wakes++;
    pthread_mutex_unlock (&tm->lock);
    fprintf (stderr,
             "oi1_wake stage=reject reason=stale generation=%llu "
             "sequence=%llu active-generation=%llu\n",
             (unsigned long long) token->generation,
             (unsigned long long) token->sequence,
             (unsigned long long) tm->generation);
    return;
  }
  if (oi1_sequence_seen (token->sequence) || tm->state != OI1_STATE_WAITING) {
    tm->duplicate_wakes++;
    pthread_mutex_unlock (&tm->lock);
    fprintf (stderr,
             "oi1_wake stage=reject reason=duplicate-or-not-waiting "
             "generation=%llu sequence=%llu state=%s\n",
             (unsigned long long) token->generation,
             (unsigned long long) token->sequence, oi1_state_name (tm->state));
    return;
  }
  if (tm->accepted_sequence_count < OI1_WAKE_HISTORY)
    tm->accepted_sequences[tm->accepted_sequence_count++] = token->sequence;
  tm->accepted_wakes++;
  tm->wake_cause = token->cause;
  tm->state = OI1_STATE_RUNNABLE;
  tm->pending_worker = 1;
  pthread_mutex_unlock (&tm->lock);
  fprintf (stderr,
           "oi1_wake stage=accept generation=%llu sequence=%llu cause=%u\n",
           (unsigned long long) token->generation,
           (unsigned long long) token->sequence, token->cause);
  vlib_node_set_interrupt_pending (vm, oi1_trigger_node.index);
}

static clib_error_t *
oi1_wake_read_ready (clib_file_t *file)
{
  oi1_main_t *tm = (oi1_main_t *) file->private_data;
  vlib_main_t *vm = vlib_get_main ();
  oi1_wake_token_t token;
  ssize_t result;

  for (;;) {
    result = read ((int) file->file_descriptor, &token, sizeof (token));
    if (result == (ssize_t) sizeof (token)) {
      oi1_accept_wake (vm, &token);
      continue;
    }
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return 0;
    if (result < 0 && errno == EINTR)
      continue;
    if (result == 0)
      return clib_error_return (0, "OI1 wake pipe closed");
    tm->wake_publish_errors++;
    return 0;
  }
}

static int
oi1_ensure_wake_file (void)
{
  oi1_main_t *tm = &oi1_main;
  clib_file_t file = { 0 };
  int flags;

  if (tm->wake_file_index != ~0U)
    return 0;
  if (pipe (tm->wake_pipe) < 0)
    return -1;
  flags = fcntl (tm->wake_pipe[0], F_GETFL, 0);
  if (flags >= 0)
    (void) fcntl (tm->wake_pipe[0], F_SETFL, flags | O_NONBLOCK);
  file.read_function = oi1_wake_read_ready;
  file.file_descriptor = tm->wake_pipe[0];
  file.polling_thread_index = 0;
  file.private_data = (uword) tm;
  file.description = format (0, "owner-inline OI1 wake pipe");
  tm->wake_file_index = clib_file_add (&file_main, &file);
  return 0;
}

static int
oi1_enqueue_worker (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  oi1_main_t *tm = &oi1_main;
  u32 buffer;
  u16 target = (u16) tm->target_thread;
  u32 enqueued;

  if (tm->worker_token_pending)
    return 0;
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1)
    return -1;
  tm->vpp_buffers_allocated++;
  enqueued = vlib_buffer_enqueue_to_thread (
    vm, node, tm->owner_frame_queue, &buffer, &target, 1, 1);
  if (enqueued != 1) {
    vlib_buffer_free_one (vm, buffer);
    tm->vpp_buffers_freed++;
    return -1;
  }
  tm->worker_token_pending = 1;
  return 0;
}

static int
oi1_enqueue_worker_from_main (vlib_main_t *vm)
{
  vlib_node_runtime_t *node =
    vlib_node_get_runtime (vm, oi1_trigger_node.index);
  return oi1_enqueue_worker (vm, node);
}

static int
oi1_enqueue_sentinel (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  oi1_main_t *tm = &oi1_main;
  u32 buffers[OI1_SENTINEL_TARGET];
  u16 targets[OI1_SENTINEL_TARGET];
  u32 allocated;
  u32 enqueued;

  allocated = vlib_buffer_alloc (vm, buffers, OI1_SENTINEL_TARGET);
  if (allocated != OI1_SENTINEL_TARGET) {
    tm->vpp_buffers_allocated += allocated;
    if (allocated) {
      vlib_buffer_free (vm, buffers, allocated);
      tm->vpp_buffers_freed += allocated;
    }
    return -1;
  }
  tm->vpp_buffers_allocated += allocated;
  for (u32 i = 0; i < OI1_SENTINEL_TARGET; i++)
    targets[i] = (u16) tm->target_thread;
  enqueued = vlib_buffer_enqueue_to_thread (
    vm, node, tm->sentinel_frame_queue, buffers, targets,
    OI1_SENTINEL_TARGET, OI1_SENTINEL_TARGET);
  if (enqueued != OI1_SENTINEL_TARGET) {
    if (enqueued < OI1_SENTINEL_TARGET)
      vlib_buffer_free (vm, buffers + enqueued,
                        OI1_SENTINEL_TARGET - enqueued);
    if (enqueued < OI1_SENTINEL_TARGET)
      tm->vpp_buffers_freed += OI1_SENTINEL_TARGET - enqueued;
    return -1;
  }
  return 0;
}

static void
oi1_finish_on_worker (vlib_main_t *vm, oi1_driver_result_t *result)
{
  oi1_main_t *tm = &oi1_main;
  int rc;

  rc = tm->api.quiesce (tm->driver, tm->generation, result);
  tm->driver = NULL;
  tm->active = 0;
  tm->finished = 1;
  tm->state = rc == 0 ? OI1_STATE_STOPPED : OI1_STATE_FAULT;
  tm->last = *result;
  fprintf (stderr,
           "oi1_cleanup stage=finished result=%s generation=%llu "
           "task-residue=%llu fd-residue=%llu callbacks=%llu "
           "foreign-callbacks=%llu wait-publishes=%llu "
           "foreign-rejections=%llu timer-residue=%llu "
           "credit-residue=%llu\n",
           rc == 0 ? "PASS" : "FAIL",
           (unsigned long long) tm->generation,
           (unsigned long long) result->task_residue,
           (unsigned long long) result->fd_residue,
           (unsigned long long) result->callback_count,
           (unsigned long long) result->foreign_callback_count,
           (unsigned long long) result->wait_publishes,
           (unsigned long long) result->foreign_thread_rejections,
           (unsigned long long) result->timer_residue,
           (unsigned long long) result->credit_residue);
  (void) vm;
}

static void
oi1_worker_drive (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  oi1_main_t *tm = &oi1_main;
  oi1_driver_result_t result;
  uint64_t deadline;
  int always_runnable;

  if (!tm->driver) {
    always_runnable = tm->mode == OI1_MODE_FAIRNESS;
    tm->driver = tm->api.new_driver ((int) tm->timer_interval_ms,
                                     always_runnable);
    if (!tm->driver) {
      oi1_record_fault ("owner-inline driver creation failed");
      return;
    }
    if (tm->mode == OI1_MODE_FAIRNESS && !tm->fairness_scheduled) {
      if (oi1_enqueue_sentinel (vm, node) < 0) {
        oi1_record_fault ("sentinel enqueue failed");
        return;
      }
      tm->fairness_scheduled = 1;
    }
    if (tm->mode == OI1_MODE_PACKET && !tm->packet_submitted) {
      if (tm->api.submit (tm->driver, oi1_probe_packet,
                          sizeof (oi1_probe_packet)) < 0) {
        oi1_record_fault ("packet submit failed");
        return;
      }
      tm->packet_submitted = 1;
      tm->wake_cause = 2;
    }
    if (!tm->foreign_probe_done) {
      tm->foreign_probe_done = 1;
      if (tm->api.foreign_probe (tm->driver) == 0)
        tm->foreign_probe_pass++;
    }
  }

  if (tm->stop_requested && !tm->stop_sent) {
    if (tm->api.request_stop (tm->driver) < 0) {
      oi1_record_fault ("owner-inline stop request failed");
      return;
    }
    tm->stop_sent = 1;
    tm->wake_cause = 1;
  }

  deadline = oi1_now_ns () + OI1_WALL_BUDGET_NS;
  memset (&result, 0, sizeof (result));
  if (tm->api.drive (tm->driver, tm->wake_cause, OI1_HARD_QUANTUM,
                     deadline, &result) < 0 ||
      result.status == 4) {
    tm->last = result;
    oi1_record_fault ("owner-inline drive fault");
    if (!tm->stop_requested)
      tm->stop_requested = 1;
    if (tm->api.request_stop (tm->driver) < 0)
      return;
    tm->stop_sent = 1;
    if (oi1_enqueue_worker (vm, node) < 0)
      oi1_record_fault ("fault cleanup rearm failed");
    return;
  }
  tm->last = result;
  tm->drive_calls++;
  tm->worker_invocations++;
  tm->state = (oi1_state_t) result.status;
  tm->wake_cause = 1;
  fprintf (stderr,
           "oi1_drive stage=turn generation=%llu turn=%llu status=%s "
           "quanta=%u work=%u tasks=%u running=%u next-timeout-ms=%d "
           "input=%llu output=%llu timer=%llu callback=%llu "
           "pthread=%llu wake-sequence=%llu\n",
           (unsigned long long) tm->generation,
           (unsigned long long) tm->worker_invocations,
           oi1_state_name (tm->state), result.quanta, result.work_remaining,
           result.total_task_count, result.running_task_count,
           result.next_timeout_ms, (unsigned long long) result.input_packets,
           (unsigned long long) result.output_packets,
           (unsigned long long) result.timer_callbacks,
           (unsigned long long) result.callback_count,
           (unsigned long long) result.bound_pthread,
           (unsigned long long) result.wake_sequence);

  if (tm->mode == OI1_MODE_FD || tm->mode == OI1_MODE_MIXED) {
    if (!tm->fd_fixture_scheduled && result.status == 2) {
      if (tm->api.schedule_fd (tm->driver, oi1_probe_packet,
                               sizeof (oi1_probe_packet), 20) < 0) {
        oi1_record_fault ("fd fixture scheduling failed");
        tm->stop_requested = 1;
      } else {
        tm->fd_fixture_scheduled = 1;
      }
    }
  }
  /* The adapter's timer task records its entry callback plus the first loop
   * callback before it sleeps.  A third callback is therefore the first
   * timer-only wake-driven progress, not merely initial task startup. */
  if (tm->mode == OI1_MODE_TIMER && result.timer_callbacks >= 3)
    tm->stop_requested = 1;
  if (tm->mode == OI1_MODE_PACKET && result.output_packets >= 1)
    tm->stop_requested = 1;
  if (tm->mode == OI1_MODE_FD && result.output_packets >= 1)
    tm->stop_requested = 1;
  if (tm->mode == OI1_MODE_MIXED && result.output_packets >= 1 &&
      result.timer_callbacks >= 1)
    tm->stop_requested = 1;
  if (tm->mode == OI1_MODE_FAIRNESS &&
      tm->sentinel_progress >= tm->sentinel_target)
    tm->stop_requested = 1;
  if (tm->worker_invocations >= OI1_MAX_TURNS)
    tm->stop_requested = 1;

  if (result.status == 3) {
    oi1_finish_on_worker (vm, &result);
    return;
  }
  if (tm->state == OI1_STATE_RUNNABLE && !tm->stop_requested) {
    tm->immediate_rearms++;
    if (oi1_enqueue_worker (vm, node) < 0)
      oi1_record_fault ("immediate rearm failed");
    return;
  }
  if (tm->stop_requested) {
    if (!tm->stop_sent) {
      if (tm->api.request_stop (tm->driver) < 0) {
        oi1_record_fault ("stop request failed");
        return;
      }
      tm->stop_sent = 1;
    }
    if (oi1_enqueue_worker (vm, node) < 0)
      oi1_record_fault ("stop rearm failed");
    return;
  }
  if (tm->state == OI1_STATE_WAITING) {
    u64 sequence = ++tm->next_wake_sequence;
    if (tm->api.arm_wait (tm->driver, tm->wake_pipe[1], tm->generation,
                          sequence) < 0) {
      oi1_record_fault ("wait adapter arm failed");
      return;
    }
    fprintf (stderr,
             "oi1_wait stage=armed generation=%llu sequence=%llu "
             "cause=fd-or-timer\n",
             (unsigned long long) tm->generation,
             (unsigned long long) sequence);
  }
}

VLIB_NODE_FN (oi1_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi1_main_t *tm = &oi1_main;
  u32 *from = vlib_frame_vector_args (frame);

  for (u32 i = 0; i < frame->n_vectors; i++) {
    tm->worker_token_pending = 0;
    if (tm->active)
      oi1_worker_drive (vm, node);
    vlib_buffer_free_one (vm, from[i]);
    tm->vpp_buffers_freed++;
    tm->vpp_buffer_residue =
      tm->vpp_buffers_allocated >= tm->vpp_buffers_freed
        ? tm->vpp_buffers_allocated - tm->vpp_buffers_freed : 0;
    if (tm->finished)
      fprintf (stderr,
               "oi1_cleanup stage=vpp-buffer allocated=%llu freed=%llu "
               "residue=%llu\n",
               (unsigned long long) tm->vpp_buffers_allocated,
               (unsigned long long) tm->vpp_buffers_freed,
               (unsigned long long) tm->vpp_buffer_residue);
  }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oi1_worker_node) = {
  .name = "sakamoto-owner-inline-oi1-worker",
  .function = oi1_worker_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (oi1_sentinel_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi1_main_t *tm = &oi1_main;
  u32 *from = vlib_frame_vector_args (frame);
  (void) node;
  for (u32 i = 0; i < frame->n_vectors; i++) {
    if (tm->sentinel_first_owner_turn == 0)
      tm->sentinel_first_owner_turn = tm->worker_invocations;
    tm->sentinel_last_owner_turn = tm->worker_invocations;
    tm->sentinel_progress++;
    vlib_buffer_free_one (vm, from[i]);
    tm->vpp_buffers_freed++;
    tm->vpp_buffer_residue =
      tm->vpp_buffers_allocated >= tm->vpp_buffers_freed
        ? tm->vpp_buffers_allocated - tm->vpp_buffers_freed : 0;
  }
  fprintf (stderr, "oi1_sentinel progress=%llu owner-turn=%llu\n",
           (unsigned long long) tm->sentinel_progress,
           (unsigned long long) tm->worker_invocations);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oi1_sentinel_node) = {
  .name = "sakamoto-owner-inline-oi1-sentinel",
  .function = oi1_sentinel_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (oi1_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi1_main_t *tm = &oi1_main;
  (void) frame;
  if (!tm->pending_worker)
    return 0;
  tm->pending_worker = 0;
  if (oi1_enqueue_worker_from_main (vm) < 0) {
    tm->wake_publish_errors++;
    oi1_record_fault ("main-to-owner enqueue failed");
  }
  (void) node;
  return 0;
}

VLIB_REGISTER_NODE (oi1_trigger_node) = {
  .name = "sakamoto-owner-inline-oi1-trigger",
  .function = oi1_trigger_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

static clib_error_t *
oi1_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
                    vlib_cli_command_t *cmd)
{
  oi1_main_t *tm = &oi1_main;
  u8 *mode_name = NULL;
  u8 *lib_path = NULL;
  const char *env_path;
  oi1_mode_t mode = OI1_MODE_IDLE;
  u32 target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  u32 timer_ms = 0;
  clib_error_t *error;

  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "mode %s", &mode_name))
      ;
    else if (unformat (input, "target-thread %u", &target_thread))
      ;
    else if (unformat (input, "timer-ms %u", &timer_ms))
      ;
    else if (unformat (input, "lib %s", &lib_path))
      ;
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }
  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "at least one VPP worker is required");
  if (target_thread == 0 || target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "target-thread must be a worker");
  if (tm->active || tm->pending_worker || tm->driver)
    return clib_error_return (0, "OI1 driver is already active");
  if (mode_name)
    mode = oi1_mode_from_string ((const char *) mode_name);
  if ((int) mode < 0) {
    vec_free (mode_name);
    return clib_error_return (0, "mode must be idle/timer/fd/packet/mixed/fairness");
  }
  if (timer_ms > 1000) {
    vec_free (mode_name);
    return clib_error_return (0, "timer-ms must be 0..1000");
  }
  env_path = getenv ("OI1_HEV_LIB");
  if (!lib_path && env_path)
    lib_path = format (0, "%s%c", env_path, 0);
  if (oi1_load_hev ((const char *) lib_path) < 0) {
    error = clib_error_return (0, "OI1 HEV load failed: %s", tm->error);
    vec_free (mode_name);
    vec_free (lib_path);
    return error;
  }
  if (oi1_ensure_wake_file () < 0) {
    vec_free (mode_name);
    vec_free (lib_path);
    return clib_error_return_unix (0, "create OI1 wake pipe");
  }
  vec_free (mode_name);
  vec_free (lib_path);
  pthread_mutex_lock (&tm->lock);
  tm->target_thread = target_thread;
  tm->mode = mode;
  tm->timer_interval_ms = timer_ms;
  if (mode == OI1_MODE_TIMER || mode == OI1_MODE_MIXED)
    tm->timer_interval_ms = timer_ms ? timer_ms : 10;
  tm->generation++;
  if (!tm->generation)
    tm->generation = 1;
  tm->next_wake_sequence = 0;
  tm->accepted_sequence_count = 0;
  tm->accepted_wakes = tm->stale_wakes = tm->duplicate_wakes = 0;
  tm->wake_publish_errors = 0;
  tm->vpp_buffers_allocated = tm->vpp_buffers_freed =
    tm->vpp_buffer_residue = 0;
  tm->worker_invocations = tm->drive_calls = tm->immediate_rearms = 0;
  tm->sentinel_progress = tm->sentinel_first_owner_turn =
    tm->sentinel_last_owner_turn = 0;
  tm->sentinel_target = OI1_SENTINEL_TARGET;
  tm->pending_worker = 1;
  tm->worker_token_pending = 0;
  tm->active = 1;
  tm->finished = 0;
  tm->stop_requested = tm->stop_sent = 0;
  tm->fd_fixture_scheduled = tm->packet_submitted = 0;
  tm->foreign_probe_done = tm->fairness_scheduled = 0;
  tm->state = OI1_STATE_RUNNABLE;
  memset (&tm->last, 0, sizeof (tm->last));
  pthread_mutex_unlock (&tm->lock);
  vlib_node_set_interrupt_pending (vm, oi1_trigger_node.index);
  vlib_cli_output (vm, "oi1 queued mode %s target-thread %u generation %llu",
                   oi1_mode_name (mode), target_thread,
                   (unsigned long long) tm->generation);
  return 0;
}

VLIB_CLI_COMMAND (oi1_run_command, static) = {
  .path = "sakamoto-oi1 run",
  .short_help = "sakamoto-oi1 run mode <idle|timer|fd|packet|mixed|fairness> "
                "target-thread <worker> timer-ms <0..1000> lib <HEV>",
  .function = oi1_run_command_fn,
};

static clib_error_t *
oi1_stop_command_fn (vlib_main_t *vm, unformat_input_t *input,
                     vlib_cli_command_t *cmd)
{
  oi1_main_t *tm = &oi1_main;
  (void) input;
  (void) cmd;
  if (!tm->active)
    return clib_error_return (0, "OI1 driver is not active");
  tm->stop_requested = 1;
  if (tm->state == OI1_STATE_WAITING) {
    tm->wake_cause = 1;
    tm->pending_worker = 1;
    vlib_node_set_interrupt_pending (vm, oi1_trigger_node.index);
  }
  vlib_cli_output (vm, "oi1 stop requested generation %llu",
                   (unsigned long long) tm->generation);
  return 0;
}

VLIB_CLI_COMMAND (oi1_stop_command, static) = {
  .path = "sakamoto-oi1 stop",
  .short_help = "stop the OI1 driver",
  .function = oi1_stop_command_fn,
};

static clib_error_t *
oi1_inject_command_fn (vlib_main_t *vm, unformat_input_t *input,
                       vlib_cli_command_t *cmd)
{
  oi1_main_t *tm = &oi1_main;
  u64 generation = 0, sequence = 1;
  u32 cause = 1;
  u8 *kind = NULL;
  oi1_wake_token_t token;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "stale"))
      kind = format (0, "stale%c", 0);
    else if (unformat (input, "duplicate"))
      kind = format (0, "duplicate%c", 0);
    else if (unformat (input, "generation %llu", &generation))
      ;
    else if (unformat (input, "sequence %llu", &sequence))
      ;
    else if (unformat (input, "cause %u", &cause))
      ;
    else
      return clib_error_return (0, "unknown input `%U'",
                                format_unformat_error, input);
  }
  if (tm->wake_pipe[1] < 0) {
    vec_free (kind);
    return clib_error_return (0, "OI1 wake pipe is not ready");
  }
  if (kind && !strcmp ((const char *) kind, "stale"))
    generation = tm->generation ? tm->generation - 1 : 0;
  else if (kind && !strcmp ((const char *) kind, "duplicate") &&
           tm->accepted_sequence_count)
    sequence = tm->accepted_sequences[0];
  if (!generation)
    generation = tm->generation;
  token.generation = generation;
  token.sequence = sequence;
  token.cause = cause;
  token.reserved = 0;
  vec_free (kind);
  if (write (tm->wake_pipe[1], &token, sizeof (token)) !=
      (ssize_t) sizeof (token))
    return clib_error_return_unix (0, "inject OI1 wake");
  vlib_cli_output (vm, "oi1 injected generation %llu sequence %llu",
                   (unsigned long long) generation,
                   (unsigned long long) sequence);
  return 0;
}

VLIB_CLI_COMMAND (oi1_inject_command, static) = {
  .path = "sakamoto-oi1 inject-wake",
  .short_help = "inject-wake stale|duplicate [generation N] [sequence N]",
  .function = oi1_inject_command_fn,
};

static clib_error_t *
oi1_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                     vlib_cli_command_t *cmd)
{
  oi1_main_t *tm = &oi1_main;
  (void) input;
  (void) cmd;
  vlib_cli_output (
    vm,
    "oi1 state=%s mode=%s active=%u finished=%u target-thread=%u "
    "generation=%llu pending=%u token-pending=%u turns=%llu drives=%llu "
    "rearms=%llu wakes=%llu stale=%llu duplicate=%llu pipe-errors=%llu",
    oi1_state_name (tm->state), oi1_mode_name ((oi1_mode_t) tm->mode),
    tm->active, tm->finished, tm->target_thread,
    (unsigned long long) tm->generation, tm->pending_worker,
    tm->worker_token_pending, (unsigned long long) tm->worker_invocations,
    (unsigned long long) tm->drive_calls,
    (unsigned long long) tm->immediate_rearms,
    (unsigned long long) tm->accepted_wakes,
    (unsigned long long) tm->stale_wakes,
    (unsigned long long) tm->duplicate_wakes,
    (unsigned long long) tm->wake_publish_errors);
  vlib_cli_output (
    vm,
    "oi1 result status=%d tasks=%u running=%u next-timeout-ms=%d "
    "input=%llu output=%llu timer=%llu callbacks=%llu foreign-callbacks=%llu "
    "wait-publishes=%llu wait-callbacks=%llu foreign-attempts=%llu "
    "foreign-rejections=%llu task-residue=%llu fd-residue=%llu fault=%d",
    tm->last.status, tm->last.total_task_count,
    tm->last.running_task_count, tm->last.next_timeout_ms,
    (unsigned long long) tm->last.input_packets,
    (unsigned long long) tm->last.output_packets,
    (unsigned long long) tm->last.timer_callbacks,
    (unsigned long long) tm->last.callback_count,
    (unsigned long long) tm->last.foreign_callback_count,
    (unsigned long long) tm->last.wait_publishes,
    (unsigned long long) tm->last.wait_callback_count,
    (unsigned long long) tm->last.foreign_thread_attempts,
    (unsigned long long) tm->last.foreign_thread_rejections,
    (unsigned long long) tm->last.task_residue,
    (unsigned long long) tm->last.fd_residue, tm->last.fault_reason);
  vlib_cli_output (vm,
                   "oi1 vpp-buffers allocated=%llu freed=%llu residue=%llu",
                   (unsigned long long) tm->vpp_buffers_allocated,
                   (unsigned long long) tm->vpp_buffers_freed,
                   (unsigned long long) tm->vpp_buffer_residue);
  vlib_cli_output (vm,
                   "oi1 fairness sentinel=%llu/%u first-owner-turn=%llu "
                   "last-owner-turn=%llu foreign-probe-pass=%llu error=%s",
                   (unsigned long long) tm->sentinel_progress,
                   tm->sentinel_target,
                   (unsigned long long) tm->sentinel_first_owner_turn,
                   (unsigned long long) tm->sentinel_last_owner_turn,
                   (unsigned long long) tm->foreign_probe_pass, tm->error);
  return 0;
}

VLIB_CLI_COMMAND (oi1_show_command, static) = {
  .path = "show sakamoto-oi1",
  .short_help = "show OI1 scheduler/wakeup evidence",
  .function = oi1_show_command_fn,
};

static clib_error_t *
oi1_init (vlib_main_t *vm)
{
  oi1_main_t *tm = &oi1_main;
  clib_memset (tm, 0, sizeof (*tm));
  tm->wake_pipe[0] = tm->wake_pipe[1] = -1;
  tm->wake_file_index = ~0U;
  tm->owner_frame_queue =
    vlib_frame_queue_main_init (oi1_worker_node.index, 0);
  tm->sentinel_frame_queue =
    vlib_frame_queue_main_init (oi1_sentinel_node.index, 0);
  tm->state = OI1_STATE_STOPPED;
  tm->generation = 0;
  if (pthread_mutex_init (&tm->lock, NULL) != 0)
    return clib_error_return (0, "OI1 lock initialization failed");
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (oi1_init);
