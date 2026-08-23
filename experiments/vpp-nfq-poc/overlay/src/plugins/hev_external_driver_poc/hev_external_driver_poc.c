/* SPDX-License-Identifier: Apache-2.0 */

/*
 * S120 experimental plugin.
 *
 * The worker node makes exactly one external-driver call per invocation and
 * re-enqueues a token for the next worker turn.  The HEV library owns the
 * task/owner lifecycle; VPP owns the outer scheduling loop.
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

#define S120_MAX_TURNS 4096

typedef struct
{
  const void *data;
  size_t length;
} s120_packet_t;

typedef struct
{
  int status;
  unsigned int quanta;
  unsigned int total_task_count;
  unsigned int running_task_count;
  int next_timeout_ms;
  uintptr_t owner_a;
  uintptr_t owner_b;
  uintptr_t lwip_a;
  uintptr_t lwip_b;
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
  unsigned long bound_pthread;
  unsigned int step_calls;
} s120_driver_result_t;

typedef void *(*s120_owner_new_fn) (const void *config,
                                    const void *connector);
typedef void (*s120_owner_free_fn) (void *owner);
typedef void (*s120_owner_set_lwip_fn) (void *owner, void *lwip);
typedef int (*s120_owner_start_fn) (void *owner);
typedef void *(*s120_lwip_create_fn) (void);
typedef void (*s120_lwip_destroy_fn) (void *lwip);
typedef void *(*s120_driver_new_fn) (
  void *a, void *b, const s120_packet_t *a_packets, size_t a_packet_count,
  const s120_packet_t *b_packets, size_t b_packet_count,
  const s120_packet_t *b_after_packets, size_t b_after_packet_count);
typedef int (*s120_driver_step_fn) (void *driver, unsigned int max_quanta,
                                    s120_driver_result_t *result);
typedef int (*s120_driver_request_stop_fn) (void *driver);
typedef int (*s120_driver_free_fn) (void *driver,
                                    s120_driver_result_t *result);

typedef struct
{
  void *handle;
  s120_owner_new_fn owner_new;
  s120_owner_free_fn owner_free;
  s120_owner_set_lwip_fn owner_set_lwip;
  s120_owner_start_fn owner_start;
  s120_lwip_create_fn lwip_create;
  s120_lwip_destroy_fn lwip_destroy;
  s120_driver_new_fn driver_new;
  s120_driver_step_fn driver_step;
  s120_driver_request_stop_fn driver_request_stop;
  s120_driver_free_fn driver_free;
} s120_hev_api_t;

typedef struct
{
  u32 frame_queue_index;
  u32 target_thread;
  u32 pending;
  u32 run_pending;
  u32 active;
  u32 finished;
  u32 stop_requested;
  u32 queue_error;
  u32 turns;
  u32 max_quanta;
  u64 node_invocations;
  u64 step_calls;
  u32 last_vpp_thread;
  unsigned long worker_pthread;
  void *owner_a;
  void *owner_b;
  void *lwip_a;
  void *lwip_b;
  void *driver;
  s120_driver_result_t last;
  u8 *lib_path;
  u32 pending_buffer;
  u16 pending_target;
  s120_hev_api_t api;
  char load_error[256];
} s120_external_driver_poc_main_t;

s120_external_driver_poc_main_t s120_external_driver_poc_main;

extern vlib_node_registration_t s120_external_driver_trigger_node;
extern vlib_node_registration_t s120_external_driver_worker_node;

static const uint8_t s120_probe_data[28] = {
  0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
  0x40, 0x01, 0x66, 0xde, 10, 0, 0, 2, 10, 0, 0, 1,
  0x08, 0x00, 0xb5, 0xbc, 0x42, 0x42, 0x00, 0x01,
};

static const s120_packet_t s120_a_packets[] = {
  { s120_probe_data, sizeof (s120_probe_data) },
};
static const s120_packet_t s120_b_packets[] = {
  { s120_probe_data, sizeof (s120_probe_data) },
};
static const s120_packet_t s120_b_after_packets[] = {
  { s120_probe_data, sizeof (s120_probe_data) },
};

static void
s120_set_error (const char *message)
{
  snprintf (s120_external_driver_poc_main.load_error,
            sizeof (s120_external_driver_poc_main.load_error), "%s", message);
}

static int
s120_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol)
    {
      snprintf (s120_external_driver_poc_main.load_error,
                sizeof (s120_external_driver_poc_main.load_error),
                "dlsym(%s): %s", name, dlerror ());
      return -1;
    }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static int
s120_load_hev (const char *path)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  void *handle;

  if (tm->api.handle)
    return 0;
  if (!path || !path[0])
    {
      s120_set_error ("S120_HEV_LIB is empty; pass `lib <path>`");
      return -1;
    }
  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      snprintf (tm->load_error, sizeof (tm->load_error), "dlopen(%s): %s",
                path, dlerror ());
      return -1;
    }

#define S120_LOAD(field, symbol)                                             \
  if (s120_load_symbol (handle, symbol, &tm->api.field) < 0)                 \
    goto load_failed
  S120_LOAD (owner_new, "hev_socks5_tunnel_owner_new");
  S120_LOAD (owner_free, "hev_socks5_tunnel_owner_free");
  S120_LOAD (owner_set_lwip, "hev_socks5_tunnel_owner_set_lwip");
  S120_LOAD (owner_start, "hev_socks5_tunnel_owner_start");
  S120_LOAD (lwip_create, "lwip_owner_context_create");
  S120_LOAD (lwip_destroy, "lwip_owner_context_destroy");
  S120_LOAD (driver_new, "hev_s120_external_driver_new");
  S120_LOAD (driver_step, "hev_s120_external_driver_step");
  S120_LOAD (driver_request_stop, "hev_s120_external_driver_request_stop");
  S120_LOAD (driver_free, "hev_s120_external_driver_free");
#undef S120_LOAD

  tm->api.handle = handle;
  fprintf (stderr, "s120_external_driver stage=hev-loaded lib=%s\n", path);
  return 0;

load_failed:
  dlclose (handle);
  memset (&tm->api, 0, sizeof (tm->api));
  return -1;
}

static void
s120_release_owner_state (void)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  if (tm->owner_a)
    tm->api.owner_free (tm->owner_a);
  if (tm->owner_b)
    tm->api.owner_free (tm->owner_b);
  if (tm->lwip_a)
    tm->api.lwip_destroy (tm->lwip_a);
  if (tm->lwip_b)
    tm->api.lwip_destroy (tm->lwip_b);
  tm->owner_a = NULL;
  tm->owner_b = NULL;
  tm->lwip_a = NULL;
  tm->lwip_b = NULL;
}

static int
s120_start_driver (void)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;

  tm->owner_a = tm->api.owner_new (NULL, NULL);
  tm->owner_b = tm->api.owner_new (NULL, NULL);
  tm->lwip_a = tm->api.lwip_create ();
  tm->lwip_b = tm->api.lwip_create ();
  if (!tm->owner_a || !tm->owner_b || !tm->lwip_a || !tm->lwip_b)
    {
      s120_set_error ("owner/lwIP allocation failed");
      s120_release_owner_state ();
      return -1;
    }
  tm->api.owner_set_lwip (tm->owner_a, tm->lwip_a);
  tm->api.owner_set_lwip (tm->owner_b, tm->lwip_b);
  if (tm->api.owner_start (tm->owner_a) < 0 ||
      tm->api.owner_start (tm->owner_b) < 0)
    {
      s120_set_error ("owner start failed");
      s120_release_owner_state ();
      return -1;
    }
  tm->driver = tm->api.driver_new (
    tm->owner_a, tm->owner_b, s120_a_packets, ARRAY_LEN (s120_a_packets),
    s120_b_packets, ARRAY_LEN (s120_b_packets), s120_b_after_packets,
    ARRAY_LEN (s120_b_after_packets));
  if (!tm->driver)
    {
      s120_set_error ("external driver setup failed");
      s120_release_owner_state ();
      return -1;
    }
  tm->active = 1;
  tm->finished = 0;
  tm->turns = 0;
  tm->step_calls = 0;
  tm->worker_pthread = (unsigned long) pthread_self ();
  fprintf (stderr,
           "s120_external_driver stage=setup vpp_thread=%u pthread=%lu "
           "owner_a=%p owner_b=%p lwip_a=%p lwip_b=%p max_quanta=%u\n",
           vlib_get_thread_index (), tm->worker_pthread, tm->owner_a,
           tm->owner_b, tm->lwip_a, tm->lwip_b, tm->max_quanta);
  return 0;
}

static void
s120_finish_driver (void)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  int res;

  if (!tm->driver)
    return;
  res = tm->api.driver_free (tm->driver, &tm->last);
  if (res < 0)
    {
      tm->queue_error = 1;
      s120_set_error ("external driver cleanup reported residue");
    }
  tm->driver = NULL;
  s120_release_owner_state ();
  tm->active = 0;
  tm->finished = 1;
  fprintf (stderr,
           "s120_external_driver stage=finished result=%s turns=%u "
           "step_calls=%llu bound_pthread=%lu a_joined=%u b_joined=%u "
           "task_residue=%u fd_residue=%u\n",
           res == 0 ? "PASS" : "FAIL", tm->turns,
           (unsigned long long) tm->step_calls, tm->last.bound_pthread,
           tm->last.a_joined, tm->last.b_joined, tm->last.task_residue,
           tm->last.fd_residue);
}

static int
s120_enqueue_next_turn (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  u32 buffer;
  u16 target = (u16) vlib_get_thread_index ();
  u32 enqueued;

  if (vlib_buffer_alloc (vm, &buffer, 1) != 1)
    return -1;
  enqueued = vlib_buffer_enqueue_to_thread (
    vm, node, tm->frame_queue_index, &buffer, &target, 1, 1);
  if (enqueued != 1)
    {
      vlib_buffer_free_one (vm, buffer);
      return -1;
    }
  return 0;
}

VLIB_NODE_FN (s120_external_driver_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  u32 *from = vlib_frame_vector_args (frame);

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      int res;
      tm->node_invocations++;
      tm->last_vpp_thread = vlib_get_thread_index ();
      fprintf (stderr,
               "s120_worker_turn stage=enter vpp_thread=%u pthread=%lu "
               "turn=%u invocation=%llu\n",
               tm->last_vpp_thread, (unsigned long) pthread_self (),
               tm->turns + 1, (unsigned long long) tm->node_invocations);

      if (!tm->active && !tm->finished && s120_start_driver () < 0)
        tm->queue_error = 1;
      if (tm->active && tm->stop_requested)
        {
          if (tm->api.driver_request_stop (tm->driver) < 0)
            tm->queue_error = 1;
          tm->stop_requested = 0;
        }
      if (tm->active)
        {
          memset (&tm->last, 0, sizeof (tm->last));
          res = tm->api.driver_step (tm->driver, tm->max_quanta,
                                     &tm->last);
          tm->turns++;
          tm->step_calls = tm->last.step_calls;
          fprintf (stderr,
                   "s120_driver_step status=%d quanta=%u total=%u running=%u "
                   "next_timeout_ms=%d turn=%u step_calls=%llu pthread=%lu\n",
                   tm->last.status, tm->last.quanta,
                   tm->last.total_task_count, tm->last.running_task_count,
                   tm->last.next_timeout_ms, tm->turns,
                   (unsigned long long) tm->step_calls,
                   (unsigned long) pthread_self ());
          if (res < 0 || tm->last.status < 0)
            {
              tm->queue_error = 1;
              s120_set_error ("external driver step failed");
            }
          else if (tm->last.status == 2)
            s120_finish_driver ();
          else if (tm->turns >= S120_MAX_TURNS)
            {
              tm->queue_error = 1;
              s120_set_error ("external driver turn budget exhausted");
              if (tm->api.driver_request_stop (tm->driver) < 0)
                s120_set_error ("external driver stop failed");
            }
        }
      vlib_buffer_free_one (vm, from[i]);
      if (tm->active && !tm->finished && !tm->queue_error &&
          s120_enqueue_next_turn (vm, node) < 0)
        {
          tm->queue_error = 1;
          s120_set_error ("could not enqueue next VPP worker turn");
        }
      fprintf (stderr,
               "s120_worker_turn stage=leave vpp_thread=%u pthread=%lu "
               "active=%u finished=%u queue_error=%u\n",
               tm->last_vpp_thread, (unsigned long) pthread_self (), tm->active,
               tm->finished, tm->queue_error);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (s120_external_driver_worker_node) = {
  .name = "s120-external-driver-worker",
  .function = s120_external_driver_worker_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (s120_external_driver_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  u16 target;
  u32 enqueued;

  (void) frame;
  if (!tm->pending)
    return 0;
  target = tm->pending_target;
  enqueued = vlib_buffer_enqueue_to_thread (
    vm, node, tm->frame_queue_index, &tm->pending_buffer, &target, 1, 1);
  if (enqueued != 1)
    {
      vlib_buffer_free_one (vm, tm->pending_buffer);
      tm->queue_error = 1;
      s120_set_error ("could not enqueue initial VPP worker turn");
    }
  tm->pending = 0;
  return enqueued;
}

VLIB_REGISTER_NODE (s120_external_driver_trigger_node) = {
  .name = "s120-external-driver-trigger",
  .function = s120_external_driver_trigger_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

static clib_error_t *
s120_queue_command (vlib_main_t *vm, u32 target_thread)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  if (target_thread == 0 || target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "target-thread must be a worker in 1..%u",
                              vlib_get_n_threads () - 1);
  if (tm->pending || tm->active)
    return clib_error_return (0, "S120 driver is already queued or active");
  if (!tm->api.handle)
    return clib_error_return (0, "load HEV with `run ... lib <path>` first");
  if (vlib_buffer_alloc (vm, &tm->pending_buffer, 1) != 1)
    return clib_error_return (0, "could not allocate S120 trigger buffer");
  tm->pending_target = (u16) target_thread;
  tm->target_thread = target_thread;
  tm->pending = 1;
  tm->run_pending = 1;
  tm->finished = 0;
  vlib_node_set_interrupt_pending (vm, s120_external_driver_trigger_node.index);
  vlib_cli_output (vm,
                   "s120-external-driver queued target-thread %u budget %u",
                   target_thread, tm->max_quanta);
  return 0;
}

static clib_error_t *
s120_external_driver_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  u32 target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  u32 budget = 1;
  u8 *lib_path = NULL;
  const char *env_path;
  clib_error_t *error;

  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "target-thread %u", &target_thread))
        ;
      else if (unformat (input, "budget %u", &budget))
        ;
      else if (unformat (input, "lib %s", &lib_path))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "at least one VPP worker is required");
  if (!budget || budget > 1024)
    return clib_error_return (0, "budget must be 1..1024");
  env_path = getenv ("S120_HEV_LIB");
  if (!lib_path && env_path)
    lib_path = format (0, "%s%c", env_path, 0);
  if (s120_load_hev ((const char *) lib_path) < 0)
    {
      error = clib_error_return (0, "HEV load failed: %s", tm->load_error);
      vec_free (lib_path);
      return error;
    }
  vec_free (lib_path);
  tm->max_quanta = budget;
  tm->queue_error = 0;
  tm->run_pending = 0;
  tm->stop_requested = 0;
  return s120_queue_command (vm, target_thread);
}

VLIB_CLI_COMMAND (s120_external_driver_run_command, static) = {
  .path = "s120-external-driver run",
  .short_help = "s120-external-driver run target-thread <worker> budget <1..1024> "
                "[lib <libhev-socks5-tunnel.so>]",
  .function = s120_external_driver_run_command_fn,
};

static clib_error_t *
s120_external_driver_stop_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                      vlib_cli_command_t *cmd)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  (void) input;
  (void) cmd;
  if (!tm->active && !tm->pending)
    return clib_error_return (0, "S120 driver is not active");
  tm->stop_requested = 1;
  if (!tm->pending && !tm->active)
    return 0;
  if (!tm->pending && tm->active)
    {
      if (vlib_buffer_alloc (vm, &tm->pending_buffer, 1) != 1)
        return clib_error_return (0, "could not allocate stop trigger buffer");
      tm->pending_target = (u16) tm->target_thread;
      tm->pending = 1;
      vlib_node_set_interrupt_pending (vm,
                                       s120_external_driver_trigger_node.index);
    }
  vlib_cli_output (vm, "s120-external-driver stop requested");
  return 0;
}

VLIB_CLI_COMMAND (s120_external_driver_stop_command, static) = {
  .path = "s120-external-driver stop",
  .short_help = "s120-external-driver stop",
  .function = s120_external_driver_stop_command_fn,
};

static clib_error_t *
s120_external_driver_show_command_fn (vlib_main_t *vm,
                                      unformat_input_t *input,
                                      vlib_cli_command_t *cmd)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  (void) input;
  (void) cmd;
  vlib_cli_output (
    vm,
    "s120-external-driver loaded %u target-thread %u budget %u pending %u "
    "active %u finished %u turns %u invocations %llu step-calls %llu "
    "queue-error %u status %d total %u running %u next-timeout-ms %d",
    tm->api.handle != NULL, tm->target_thread, tm->max_quanta, tm->pending,
    tm->active, tm->finished, tm->turns,
    (unsigned long long) tm->node_invocations,
    (unsigned long long) tm->step_calls, tm->queue_error, tm->last.status,
    tm->last.total_task_count, tm->last.running_task_count,
    tm->last.next_timeout_ms);
  vlib_cli_output (
    vm,
    "s120-external-driver threads worker=%lu bound=%lu owners=%p/%p "
    "lwip=%p/%p packets=%u/%u/%u timers=%u/%u outputs=%u/%u "
    "joined=%u/%u residue=%u/%u",
    tm->worker_pthread, tm->last.bound_pthread,
    (void *) tm->last.owner_a, (void *) tm->last.owner_b,
    (void *) tm->last.lwip_a, (void *) tm->last.lwip_b,
    (u32) tm->last.a_packets_before_stop,
    (u32) tm->last.b_packets_before_a_stop,
    (u32) tm->last.b_packets_after_a_stop, (u32) tm->last.a_timer_steps,
    (u32) tm->last.b_timer_steps, (u32) tm->last.a_outputs,
    (u32) tm->last.b_outputs, tm->last.a_joined, tm->last.b_joined,
    tm->last.task_residue, tm->last.fd_residue);
  if (tm->load_error[0])
    vlib_cli_output (vm, "s120-external-driver error %s", tm->load_error);
  return 0;
}

VLIB_CLI_COMMAND (s120_external_driver_show_command, static) = {
  .path = "show s120-external-driver",
  .short_help = "show s120-external-driver",
  .function = s120_external_driver_show_command_fn,
};

static clib_error_t *
s120_external_driver_init (vlib_main_t *vm)
{
  s120_external_driver_poc_main_t *tm =
    &s120_external_driver_poc_main;
  clib_memset (tm, 0, sizeof (*tm));
  tm->frame_queue_index =
    vlib_frame_queue_main_init (s120_external_driver_worker_node.index, 0);
  tm->max_quanta = 1;
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (s120_external_driver_init);
