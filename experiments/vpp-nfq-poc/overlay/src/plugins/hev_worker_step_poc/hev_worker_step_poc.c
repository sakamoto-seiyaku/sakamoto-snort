/* SPDX-License-Identifier: Apache-2.0 */

/*
 * S119 experimental seam.
 *
 * The VPP main thread only allocates buffers and wakes the trigger node.  The
 * trigger node hands those buffers to a real VPP worker frame queue.  The
 * worker node then invokes the pinned HEV local-I/O proof through dlopen(3),
 * so the HEV task scheduler and its lwIP owner contexts execute on the VPP
 * worker thread itself.  This is intentionally a bounded proof, not a
 * production plugin ABI.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/threads.h>

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S119_MAX_REQUEST 64

typedef struct
{
  const void *data;
  size_t length;
} s119_hev_local_packet_t;

/* Kept ABI-compatible with the pinned hev-socks5-tunnel-owner.h. */
typedef struct
{
  uintptr_t a_io_task;
  uintptr_t a_timer_task;
  uintptr_t b_io_task;
  uintptr_t b_timer_task;
  size_t a_packets_before_stop;
  size_t b_packets_before_a_stop;
  size_t b_packets_after_a_stop;
  size_t a_timer_steps;
  size_t b_timer_steps;
  size_t a_outputs;
  size_t b_outputs;
  unsigned int a_joined;
  unsigned int b_joined;
  unsigned int task_residue;
  unsigned int fd_residue;
} s119_hev_local_io_proof_t;

typedef void *(*s119_owner_new_fn) (const void *config,
                                    const void *connector);
typedef void (*s119_owner_free_fn) (void *owner);
typedef void (*s119_owner_set_lwip_fn) (void *owner, void *lwip);
typedef int (*s119_owner_start_fn) (void *owner);
typedef int (*s119_owner_local_io_pair_fn) (
  void *a, void *b, const s119_hev_local_packet_t *a_packets,
  size_t a_packet_count, const s119_hev_local_packet_t *b_packets,
  size_t b_packet_count, const s119_hev_local_packet_t *b_after_packets,
  size_t b_after_packet_count, s119_hev_local_io_proof_t *proof);
typedef void *(*s119_lwip_create_fn) (void);
typedef void (*s119_lwip_destroy_fn) (void *lwip);

typedef struct
{
  void *handle;
  s119_owner_new_fn owner_new;
  s119_owner_free_fn owner_free;
  s119_owner_set_lwip_fn owner_set_lwip;
  s119_owner_start_fn owner_start;
  s119_owner_local_io_pair_fn owner_local_io_pair;
  s119_lwip_create_fn lwip_create;
  s119_lwip_destroy_fn lwip_destroy;
} s119_hev_api_t;

typedef struct
{
  u32 frame_queue_index;
  u32 target_thread;
  u32 pending_count;
  u32 requested_count;
  u8 probe_started;
  u8 probe_finished;
  u8 loaded;
  u8 reserved;
  u64 enqueued;
  u64 processed;
  u64 probe_calls;
  i32 probe_result;
  u32 last_vpp_thread;
  unsigned long last_vpp_pthread;
  unsigned long hev_entry_pthread;
  uintptr_t owner_a;
  uintptr_t owner_b;
  uintptr_t lwip_a;
  uintptr_t lwip_b;
  u32 last_a_packets;
  u32 last_b_packets;
  u32 last_a_timer_steps;
  u32 last_b_timer_steps;
  u8 *lib_path;
  u32 *pending_buffers;
  u16 *pending_targets;
  s119_hev_api_t api;
  char load_error[256];
} s119_hev_worker_step_poc_main_t;

s119_hev_worker_step_poc_main_t s119_hev_worker_step_poc_main;

extern vlib_node_registration_t s119_hev_worker_step_trigger_node;
extern vlib_node_registration_t s119_hev_worker_step_worker_node;

static void
s119_set_error (const char *message)
{
  snprintf (s119_hev_worker_step_poc_main.load_error,
            sizeof (s119_hev_worker_step_poc_main.load_error), "%s", message);
}

static int
s119_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol)
    {
      snprintf (s119_hev_worker_step_poc_main.load_error,
                sizeof (s119_hev_worker_step_poc_main.load_error),
                "dlsym(%s): %s", name, dlerror ());
      return -1;
    }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static int
s119_load_hev (const char *path)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;
  void *handle;

  if (tm->loaded)
    return 0;
  if (!path || !path[0])
    {
      s119_set_error ("S119_HEV_LIB is empty; pass `lib <path>`");
      return -1;
    }

  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      snprintf (tm->load_error, sizeof (tm->load_error), "dlopen(%s): %s",
                path, dlerror ());
      return -1;
    }

#define S119_LOAD(field, symbol)                                             \
  if (s119_load_symbol (handle, symbol, &tm->api.field) < 0)                 \
    goto load_failed
  S119_LOAD (owner_new, "hev_socks5_tunnel_owner_new");
  S119_LOAD (owner_free, "hev_socks5_tunnel_owner_free");
  S119_LOAD (owner_set_lwip, "hev_socks5_tunnel_owner_set_lwip");
  S119_LOAD (owner_start, "hev_socks5_tunnel_owner_start");
  S119_LOAD (owner_local_io_pair,
             "hev_socks5_tunnel_owner_run_local_io_pair");
  S119_LOAD (lwip_create, "lwip_owner_context_create");
  S119_LOAD (lwip_destroy, "lwip_owner_context_destroy");
#undef S119_LOAD

  tm->api.handle = handle;
  tm->loaded = 1;
  fprintf (stderr, "s119_vpp_worker_probe stage=hev-loaded lib=%s\n", path);
  return 0;

load_failed:
  dlclose (handle);
  memset (&tm->api, 0, sizeof (tm->api));
  return -1;
}

static void
s119_hev_probe_run (vlib_main_t *vm)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;
  static const u8 probe_packet[28] = {
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x01, 0x66, 0xde, 10, 0, 0, 2, 10, 0, 0, 1,
    0x08, 0x00, 0xb5, 0xbc, 0x42, 0x42, 0x00, 0x01,
  };
  const s119_hev_local_packet_t packet = {
    .data = probe_packet,
    .length = sizeof (probe_packet),
  };
  s119_hev_local_io_proof_t proof;
  void *owner_a = NULL;
  void *owner_b = NULL;
  void *lwip_a = NULL;
  void *lwip_b = NULL;
  unsigned long vpp_pthread = (unsigned long) pthread_self ();
  int local_io_result;
  int lifecycle_ok;
  int result = -1;

  tm->probe_started = 1;
  tm->probe_finished = 0;
  tm->probe_calls++;
  tm->last_vpp_thread = vlib_get_thread_index ();
  tm->last_vpp_pthread = vpp_pthread;
  tm->hev_entry_pthread = vpp_pthread;
  fprintf (stderr,
           "s119_vpp_worker_probe stage=enter vpp_thread=%u pthread=%lu\n",
           tm->last_vpp_thread, vpp_pthread);

  if (!tm->loaded)
    {
      s119_set_error ("HEV library is not loaded");
      goto done;
    }

  owner_a = tm->api.owner_new (NULL, NULL);
  owner_b = tm->api.owner_new (NULL, NULL);
  lwip_a = tm->api.lwip_create ();
  lwip_b = tm->api.lwip_create ();
  if (!owner_a || !owner_b || !lwip_a || !lwip_b)
    {
      s119_set_error ("owner/lwIP context allocation failed");
      goto done;
    }
  tm->api.owner_set_lwip (owner_a, lwip_a);
  tm->api.owner_set_lwip (owner_b, lwip_b);
  if (tm->api.owner_start (owner_a) < 0 ||
      tm->api.owner_start (owner_b) < 0)
    {
      s119_set_error ("owner start failed");
      goto done;
    }

  memset (&proof, 0, sizeof (proof));
  local_io_result = tm->api.owner_local_io_pair (
    owner_a, owner_b, &packet, 1, &packet, 1, &packet, 1, &proof);
  lifecycle_ok = proof.a_joined && proof.b_joined && !proof.task_residue &&
                 !proof.fd_residue && proof.a_packets_before_stop &&
                 proof.b_packets_after_a_stop && proof.a_timer_steps &&
                 proof.b_timer_steps;
  /* The local helper's return also requires a wire-output count.  This
   * worker seam intentionally proves task/lwIP lifecycle first; no real VPP
   * packet output is claimed here. */
  result = lifecycle_ok ? 0 : local_io_result;
  tm->owner_a = (uintptr_t) owner_a;
  tm->owner_b = (uintptr_t) owner_b;
  tm->lwip_a = (uintptr_t) lwip_a;
  tm->lwip_b = (uintptr_t) lwip_b;
  tm->last_a_packets = (u32) proof.a_packets_before_stop;
  tm->last_b_packets = (u32) proof.b_packets_after_a_stop;
  tm->last_a_timer_steps = (u32) proof.a_timer_steps;
  tm->last_b_timer_steps = (u32) proof.b_timer_steps;
  tm->probe_result = result;
  fprintf (stderr,
           "s119_vpp_worker_probe stage=hev-return result=%d local_io_result=%d "
           "lifecycle_ok=%d vpp_thread=%u "
           "pthread=%lu owner_a=%p owner_b=%p lwip_a=%p lwip_b=%p "
           "a_packets=%u b_packets=%u a_timer_steps=%u b_timer_steps=%u "
           "a_joined=%u b_joined=%u task_residue=%u fd_residue=%u\n",
           result, local_io_result, lifecycle_ok, tm->last_vpp_thread,
           vpp_pthread, owner_a, owner_b, lwip_a,
           lwip_b, tm->last_a_packets, tm->last_b_packets,
           tm->last_a_timer_steps, tm->last_b_timer_steps, proof.a_joined,
           proof.b_joined, proof.task_residue, proof.fd_residue);

done:
  if (owner_a)
    tm->api.owner_free (owner_a);
  if (owner_b)
    tm->api.owner_free (owner_b);
  if (lwip_a)
    tm->api.lwip_destroy (lwip_a);
  if (lwip_b)
    tm->api.lwip_destroy (lwip_b);
  tm->probe_finished = 1;
  fprintf (stderr,
           "s119_vpp_worker_probe stage=leave vpp_thread=%u pthread=%lu "
           "result=%d\n",
           tm->last_vpp_thread, vpp_pthread, tm->probe_result);
  (void) vm;
}

VLIB_NODE_FN (s119_hev_worker_step_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;
  u32 *from = vlib_frame_vector_args (frame);

  if (!tm->probe_started)
    s119_hev_probe_run (vm);

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      tm->processed++;
      vlib_buffer_free_one (vm, from[i]);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (s119_hev_worker_step_worker_node) = {
  .name = "s119-hev-worker-step-worker",
  .function = s119_hev_worker_step_worker_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (s119_hev_worker_step_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;
  u32 count = tm->pending_count;
  u32 enqueued;

  (void) frame;
  if (!count)
    return 0;
  enqueued = vlib_buffer_enqueue_to_thread (
    vm, node, tm->frame_queue_index, tm->pending_buffers,
    tm->pending_targets, count, 1 /* drop on congestion */);
  tm->enqueued += enqueued;
  tm->pending_count = 0;
  vec_reset_length (tm->pending_buffers);
  vec_reset_length (tm->pending_targets);
  return enqueued;
}

VLIB_REGISTER_NODE (s119_hev_worker_step_trigger_node) = {
  .name = "s119-hev-worker-step-trigger",
  .function = s119_hev_worker_step_trigger_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

static clib_error_t *
s119_hev_worker_step_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;
  u32 count = 1;
  u32 target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  u8 *lib_path = NULL;
  const char *env_path;
  u32 allocated;

  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "count %u", &count))
        ;
      else if (unformat (input, "target-thread %u", &target_thread))
        ;
      else if (unformat (input, "lib %s", &lib_path))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "at least one VPP worker is required");
  if (!count || count > S119_MAX_REQUEST)
    return clib_error_return (0, "count must be 1..%u", S119_MAX_REQUEST);
  if (target_thread == 0 || target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "target-thread must be a worker in 1..%u",
                              vlib_get_n_threads () - 1);
  if (tm->pending_count || tm->probe_started)
    return clib_error_return (0, "previous run is still pending; restart VPP");

  env_path = getenv ("S119_HEV_LIB");
  if (!lib_path)
    lib_path = env_path ? format (0, "%s%c", env_path, 0) : NULL;
  if (!lib_path)
    return clib_error_return (0, "pass lib <path> or set S119_HEV_LIB");
  if (s119_load_hev ((const char *) lib_path) < 0)
    {
      clib_error_t *error = clib_error_return (
        0, "HEV load failed: %s", tm->load_error);
      vec_free (lib_path);
      return error;
    }
  vec_free (lib_path);

  vec_validate (tm->pending_buffers, count - 1);
  vec_validate (tm->pending_targets, count - 1);
  allocated = vlib_buffer_alloc (vm, tm->pending_buffers, count);
  if (allocated != count)
    {
      if (allocated)
        vlib_buffer_free (vm, tm->pending_buffers, allocated);
      vec_reset_length (tm->pending_buffers);
      vec_reset_length (tm->pending_targets);
      return clib_error_return (0, "could only allocate %u of %u buffers",
                                allocated, count);
    }
  for (u32 i = 0; i < count; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, tm->pending_buffers[i]);
      b->current_data = 0;
      b->current_length = 64;
      tm->pending_targets[i] = (u16) target_thread;
    }
  tm->pending_count = count;
  tm->requested_count = count;
  tm->target_thread = target_thread;
  tm->probe_finished = 0;
  tm->probe_result = -1;
  vlib_node_set_interrupt_pending (vm, s119_hev_worker_step_trigger_node.index);
  vlib_cli_output (vm, "s119-hev-worker-step queued count %u target-thread %u",
                   count, target_thread);
  return 0;
}

VLIB_CLI_COMMAND (s119_hev_worker_step_run_command, static) = {
  .path = "s119-hev-worker-step run",
  .short_help = "s119-hev-worker-step run count <1..64> target-thread <worker> "
                "[lib <libhev-socks5-tunnel.so>]",
  .function = s119_hev_worker_step_run_command_fn,
};

static clib_error_t *
s119_hev_worker_step_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                      vlib_cli_command_t *cmd)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;

  (void) vm;
  (void) input;
  (void) cmd;
  vlib_cli_output (
    vm,
    "s119-hev-worker-step loaded %u target-thread %u requested %u pending %u "
    "enqueued %llu processed %llu probe-calls %llu finished %u result %d",
    tm->loaded, tm->target_thread, tm->requested_count, tm->pending_count,
    tm->enqueued, tm->processed, tm->probe_calls, tm->probe_finished,
    tm->probe_result);
  vlib_cli_output (
    vm,
    "s119-hev-worker-step vpp-thread %u vpp-pthread %lu hev-pthread %lu "
    "owner-a %p owner-b %p lwip-a %p lwip-b %p packets %u/%u timers %u/%u",
    tm->last_vpp_thread, tm->last_vpp_pthread, tm->hev_entry_pthread,
    (void *) tm->owner_a, (void *) tm->owner_b, (void *) tm->lwip_a,
    (void *) tm->lwip_b, tm->last_a_packets, tm->last_b_packets,
    tm->last_a_timer_steps, tm->last_b_timer_steps);
  if (tm->load_error[0])
    vlib_cli_output (vm, "s119-hev-worker-step error %s", tm->load_error);
  return 0;
}

VLIB_CLI_COMMAND (s119_hev_worker_step_show_command, static) = {
  .path = "show s119-hev-worker-step",
  .short_help = "show s119-hev-worker-step",
  .function = s119_hev_worker_step_show_command_fn,
};

static clib_error_t *
s119_hev_worker_step_init (vlib_main_t *vm)
{
  s119_hev_worker_step_poc_main_t *tm =
    &s119_hev_worker_step_poc_main;

  clib_memset (tm, 0, sizeof (*tm));
  tm->frame_queue_index =
    vlib_frame_queue_main_init (s119_hev_worker_step_worker_node.index, 0);
  tm->target_thread = ~0;
  tm->probe_result = -1;
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (s119_hev_worker_step_init);
