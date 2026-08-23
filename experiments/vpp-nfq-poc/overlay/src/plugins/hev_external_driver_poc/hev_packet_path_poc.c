/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-121 experimental packet-path probe.
 *
 * One VPP worker buffer is copied into flow_stack_owner_submit().  The
 * owner-context UDP session synchronously echoes the payload through lwIP's
 * netif output callback; that callback copies the result into a second VPP
 * buffer.  The probe then frees both buffers on the same worker.
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

#define S121_PACKET_LEN 33U

typedef struct s121_packet_path_main s121_packet_path_main_t;

typedef void (*s121_output_fn) (void *data, const void *packet, size_t length);
typedef void (*s121_recv_fn) (void *data, uintptr_t config_identity,
                              uintptr_t session_identity, unsigned int transport,
                              const void *payload, size_t length);

typedef struct
{
  s121_output_fn output;
  void *data;
} s121_callbacks_t;

typedef struct
{
  uintptr_t identity;
  uint16_t tcp_listen_port;
  uint16_t udp_listen_port;
  s121_recv_fn recv;
  void *recv_data;
  const void *tcp_connector;
  const void *udp_connector;
  uint8_t tcp_ip_type;
  uint8_t udp_ip_type;
} s121_session_config_t;

typedef struct
{
  uintptr_t identity;
  size_t max_session_count;
  size_t packet_credit_limit;
  size_t inflight_pbuf_credit_limit;
  size_t protected_socket_credit_limit;
  int task_stack_size;
  int tcp_buffer_size;
  int udp_copy_buffer_nums;
  unsigned int tunnel_mtu;
  uint32_t mapdns_address;
  uint16_t mapdns_port;
  uint32_t mapdns_network;
  uint32_t mapdns_netmask;
  size_t mapdns_cache_size;
  uint32_t server_mark;
  uint16_t server_port;
  uint8_t server_pipeline;
  uint8_t server_fastopen;
  uint8_t server_udp_in_udp;
  char server_addr[256];
  char server_udp_addr[256];
  char server_user[128];
  char server_pass[128];
} s121_owner_config_t;

typedef void *(*s121_create_fn) (const s121_callbacks_t *callbacks);
typedef void *(*s121_create_with_config_fn) (
    const s121_callbacks_t *callbacks, const s121_owner_config_t *config);
typedef void (*s121_owner_config_default_fn) (s121_owner_config_t *config);
typedef int (*s121_configure_fn) (void *context,
                                   const s121_session_config_t *config);
typedef int (*s121_start_fn) (void *context);
typedef int (*s121_submit_fn) (void *context, const void *packet,
                               size_t length);
typedef int (*s121_udp_echo_fn) (void *context, uintptr_t session_identity,
                                 const void *payload, size_t length);
typedef void (*s121_destroy_fn) (void *context);
typedef void *(*s121_lwip_context_fn) (void *context);

typedef struct
{
  void *handle;
  s121_create_fn create;
  s121_create_with_config_fn create_with_config;
  s121_owner_config_default_fn owner_config_default;
  s121_configure_fn configure;
  s121_start_fn start;
  s121_submit_fn submit;
  s121_udp_echo_fn udp_echo;
  s121_destroy_fn destroy;
  s121_lwip_context_fn lwip_context;
} s121_api_t;

struct s121_packet_path_main
{
  s121_api_t api;
  void *context;
  void *lwip_context;
  vlib_main_t *worker_vm;
  u32 frame_queue_index;
  u32 target_thread;
  u32 pending;
  u32 pending_buffer;
  u32 active;
  u32 finished;
  u32 queue_error;
  u32 node_invocations;
  u32 submit_calls;
  u32 recv_calls;
  u32 echo_calls;
  u32 output_calls;
  u32 ingress_buffers_allocated;
  u32 ingress_buffers_freed;
  u32 egress_buffers_allocated;
  u32 egress_buffers_freed;
  u32 ingress_packets;
  u32 egress_packets;
  u32 output_valid;
  u32 output_buffer;
  size_t vpp_to_pbuf_copy_bytes;
  size_t pbuf_to_vpp_copy_bytes;
  size_t recv_payload_bytes;
  size_t output_bytes;
  unsigned long setup_pthread;
  unsigned long submit_pthread;
  unsigned long recv_pthread;
  unsigned long output_pthread;
  int submit_result;
  int echo_result;
  u8 *lib_path;
  char error[256];
};

static s121_packet_path_main_t s121_packet_path_main;

static const u8 s121_udp_packet[S121_PACKET_LEN] = {
  0x45, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00,
  0x40, 0x11, 0x66, 0xc9, 0x0a, 0x00, 0x00, 0x02,
  0x0a, 0x00, 0x00, 0x01, 0x9c, 0x40, 0xc0, 0x01,
  0x00, 0x0d, 0x00, 0x00, 'h',  'e',  'l',  'l',
  'o',
};

static void
s121_set_error (const char *message)
{
  snprintf (s121_packet_path_main.error,
            sizeof (s121_packet_path_main.error), "%s", message);
}

static int
s121_load_symbol (void *handle, const char *name, void *destination)
{
  void *symbol = dlsym (handle, name);
  if (!symbol)
    {
      snprintf (s121_packet_path_main.error,
                sizeof (s121_packet_path_main.error), "dlsym(%s): %s", name,
                dlerror ());
      return -1;
    }
  memcpy (destination, &symbol, sizeof (symbol));
  return 0;
}

static int
s121_load_hev (const char *path)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  void *handle;

  if (tm->api.handle)
    return 0;
  if (!path || !path[0])
    {
      s121_set_error ("S121_HEV_LIB is empty; pass `lib <path>`");
      return -1;
    }
  handle = dlopen (path, RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      snprintf (tm->error, sizeof (tm->error), "dlopen(%s): %s", path,
                dlerror ());
      return -1;
    }

#define S121_LOAD(field, symbol)                                            \
  if (s121_load_symbol (handle, symbol, &tm->api.field) < 0)                 \
    goto load_failed
  S121_LOAD (create, "flow_stack_owner_create");
  S121_LOAD (create_with_config, "flow_stack_owner_create_with_config");
  S121_LOAD (owner_config_default, "hev_socks5_owner_config_default");
  S121_LOAD (configure, "flow_stack_owner_configure_sessions");
  S121_LOAD (start, "flow_stack_owner_start");
  S121_LOAD (submit, "flow_stack_owner_submit");
  S121_LOAD (udp_echo, "flow_stack_owner_udp_echo");
  S121_LOAD (destroy, "flow_stack_owner_destroy");
  S121_LOAD (lwip_context, "flow_stack_owner_lwip_context");
#undef S121_LOAD

  tm->api.handle = handle;
  fprintf (stderr, "s121_packet_path stage=hev-loaded lib=%s\n", path);
  return 0;

load_failed:
  dlclose (handle);
  memset (&tm->api, 0, sizeof (tm->api));
  return -1;
}

static void
s121_output (void *data, const void *packet, size_t length)
{
  s121_packet_path_main_t *tm = data;
  u32 buffer;
  vlib_buffer_t *b;

  tm->output_pthread = (unsigned long) pthread_self ();
  if (!tm->worker_vm || !packet || !length || length > 2048 ||
      tm->output_buffer != ~0U)
    {
      tm->queue_error = 1;
      s121_set_error ("invalid or duplicate lwIP output");
      return;
    }
  if (vlib_buffer_alloc (tm->worker_vm, &buffer, 1) != 1)
    {
      tm->queue_error = 1;
      s121_set_error ("could not allocate VPP egress buffer");
      return;
    }
  b = vlib_get_buffer (tm->worker_vm, buffer);
  {
    const u8 *bytes = packet;
    if (length != S121_PACKET_LEN || bytes[0] != 0x45 || bytes[9] != 0x11 ||
        bytes[20] != 0xc0 || bytes[21] != 0x01 || bytes[22] != 0x9c ||
        bytes[23] != 0x40 || bytes[28] != 'h' || bytes[29] != 'e' ||
        bytes[30] != 'l' || bytes[31] != 'l' || bytes[32] != 'o')
      {
        tm->queue_error = 1;
        s121_set_error ("lwIP output packet did not match UDP echo");
      }
    else
      tm->output_valid = 1;
  }
  b->current_length = length;
  clib_memcpy_fast (vlib_buffer_get_current (b), packet, length);
  tm->output_buffer = buffer;
  tm->output_calls++;
  tm->egress_buffers_allocated++;
  tm->egress_packets++;
  tm->pbuf_to_vpp_copy_bytes += length;
  tm->output_bytes += length;
  fprintf (stderr,
           "s121_packet_path stage=netif-output thread=%lu len=%u "
           "vpp_buffer=%u\n",
           (unsigned long) pthread_self (), (unsigned int) length, buffer);
}

static void
s121_recv (void *data, uintptr_t config_identity, uintptr_t session_identity,
           unsigned int transport, const void *payload, size_t length)
{
  s121_packet_path_main_t *tm = data;
  (void) config_identity;
  tm->recv_pthread = (unsigned long) pthread_self ();
  tm->recv_calls++;
  tm->recv_payload_bytes += length;
  if (transport != 2 || !payload || !length || !tm->context)
    {
      tm->queue_error = 1;
      s121_set_error ("unexpected HEV/lwIP receive callback");
      return;
    }
  tm->echo_result = tm->api.udp_echo (tm->context, session_identity, payload,
                                      length);
  tm->echo_calls++;
  if (tm->echo_result < 0)
    {
      tm->queue_error = 1;
      s121_set_error ("lwIP UDP echo failed");
    }
}

static int
s121_start_owner (vlib_main_t *vm)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  s121_callbacks_t callbacks = {
    .output = s121_output,
    .data = tm,
  };
  s121_session_config_t config;
  s121_owner_config_t owner_config;

  tm->api.owner_config_default (&owner_config);
  /* submit() holds its ingress pbuf while the UDP callback creates the
   * egress pbuf. Keep the bounded POC explicit: two pbuf credits, not an
   * unbounded pool and not a zero-copy claim. */
  owner_config.inflight_pbuf_credit_limit = 2;
  tm->context = tm->api.create_with_config (&callbacks, &owner_config);
  if (!tm->context)
    {
      s121_set_error ("flow stack owner create failed");
      return -1;
    }
  memset (&config, 0, sizeof (config));
  config.identity = 0x121;
  config.udp_listen_port = 49153;
  config.recv = s121_recv;
  config.recv_data = tm;
  config.udp_ip_type = 0;
  if (tm->api.configure (tm->context, &config) < 0 ||
      tm->api.start (tm->context) < 0)
    {
      s121_set_error ("flow stack owner configure/start failed");
      tm->api.destroy (tm->context);
      tm->context = NULL;
      return -1;
    }
  tm->worker_vm = vm;
  tm->lwip_context = tm->api.lwip_context (tm->context);
  tm->setup_pthread = (unsigned long) pthread_self ();
  tm->active = 1;
  tm->finished = 0;
  fprintf (stderr,
           "s121_packet_path stage=setup vpp_thread=%u pthread=%lu "
           "owner=%p lwip=%p udp-port=%u\n",
           vlib_get_thread_index (), tm->setup_pthread, tm->context,
           tm->lwip_context, config.udp_listen_port);
  return 0;
}

static void
s121_finish_owner (void)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  if (tm->context)
    tm->api.destroy (tm->context);
  tm->context = NULL;
  tm->lwip_context = NULL;
  tm->active = 0;
  tm->finished = 1;
  fprintf (stderr,
           "s121_packet_path stage=finished result=%s submits=%u recv=%u "
           "echo=%u outputs=%u ingress=%u/%u egress=%u/%u "
           "copies=%u/%u setup=%lu submit=%lu recv-thread=%lu output=%lu\n",
           tm->queue_error ? "FAIL" : "PASS", tm->submit_calls,
           tm->recv_calls, tm->echo_calls, tm->output_calls,
           tm->ingress_buffers_allocated, tm->ingress_buffers_freed,
           tm->egress_buffers_allocated, tm->egress_buffers_freed,
           (unsigned int) tm->vpp_to_pbuf_copy_bytes,
           (unsigned int) tm->pbuf_to_vpp_copy_bytes, tm->setup_pthread,
           tm->submit_pthread, tm->recv_pthread, tm->output_pthread);
}

static int
s121_enqueue_initial (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  u16 target = (u16) tm->target_thread;
  u32 enqueued;

  enqueued = vlib_buffer_enqueue_to_thread (
      vm, node, tm->frame_queue_index, &tm->pending_buffer, &target, 1, 1);
  if (enqueued != 1)
    {
      vlib_buffer_free_one (vm, tm->pending_buffer);
      tm->queue_error = 1;
      s121_set_error ("could not enqueue S121 ingress buffer");
      return -1;
    }
  return 0;
}

VLIB_NODE_FN (s121_packet_path_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  (void) frame;
  if (!tm->pending)
    return 0;
  (void) s121_enqueue_initial (vm, node);
  tm->pending = 0;
  return 1;
}

VLIB_REGISTER_NODE (s121_packet_path_trigger_node) = {
  .name = "s121-packet-path-trigger",
  .function = s121_packet_path_trigger_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (s121_packet_path_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  u32 *from = vlib_frame_vector_args (frame);

  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      const void *packet;

      tm->node_invocations++;
      tm->worker_vm = vm;
      tm->submit_pthread = (unsigned long) pthread_self ();
      if (!tm->active && !tm->finished && s121_start_owner (vm) < 0)
        tm->queue_error = 1;
      packet = vlib_buffer_get_current (b);
      b->current_length = S121_PACKET_LEN;
      clib_memcpy_fast ((void *) packet, s121_udp_packet,
                        sizeof (s121_udp_packet));
      tm->ingress_packets++;
      tm->ingress_buffers_allocated++;
      if (tm->active && !tm->queue_error)
        {
          tm->submit_result = tm->api.submit (
              tm->context, packet, S121_PACKET_LEN);
          tm->submit_calls++;
          tm->vpp_to_pbuf_copy_bytes += S121_PACKET_LEN;
          if (tm->submit_result < 0)
            {
              tm->queue_error = 1;
              s121_set_error ("flow_stack_owner_submit failed");
            }
        }
      vlib_buffer_free_one (vm, from[i]);
      tm->ingress_buffers_freed++;
      if (tm->output_buffer != ~0U)
        {
          vlib_buffer_free_one (vm, tm->output_buffer);
          tm->output_buffer = ~0U;
          tm->egress_buffers_freed++;
        }
      if (tm->active)
        s121_finish_owner ();
      (void) node;
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (s121_packet_path_worker_node) = {
  .name = "s121-packet-path-worker",
  .function = s121_packet_path_worker_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

static clib_error_t *
s121_packet_path_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  u32 target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  u8 *lib_path = NULL;
  const char *env_path;
  u32 buffer;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "target-thread %u", &target_thread))
        ;
      else if (unformat (input, "lib %s", &lib_path))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }
  if (!target_thread || target_thread >= vlib_get_n_threads ())
    return clib_error_return (0, "target-thread must be a worker in 1..%u",
                              vlib_get_n_threads () - 1);
  if (tm->pending || tm->active)
    return clib_error_return (0, "S121 packet path is already active");
  env_path = getenv ("S121_HEV_LIB");
  if (!lib_path && env_path)
    lib_path = format (0, "%s%c", env_path, 0);
  if (s121_load_hev ((const char *) lib_path) < 0)
    {
      clib_error_t *error = clib_error_return (0, "HEV load failed: %s",
                                               tm->error);
      vec_free (lib_path);
      return error;
    }
  vec_free (lib_path);
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1)
    return clib_error_return (0, "could not allocate S121 ingress buffer");
  tm->pending_buffer = buffer;
  tm->target_thread = target_thread;
  tm->pending = 1;
  tm->finished = 0;
  tm->queue_error = 0;
  tm->output_buffer = ~0U;
  tm->error[0] = 0;
  vlib_node_set_interrupt_pending (vm, s121_packet_path_trigger_node.index);
  vlib_cli_output (vm, "s121-packet-path queued target-thread %u", target_thread);
  return 0;
}

VLIB_CLI_COMMAND (s121_packet_path_run_command, static) = {
  .path = "s121-packet-path run",
  .short_help = "s121-packet-path run target-thread <worker> [lib <path>]",
  .function = s121_packet_path_run_command_fn,
};

static clib_error_t *
s121_packet_path_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *cmd)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  (void) vm;
  (void) input;
  (void) cmd;
  vlib_cli_output (
      vm,
      "s121-packet-path loaded %u target-thread %u pending %u active %u "
           "finished %u invocations %u submit %u recv %u echo %u output %u "
      "output-valid %u queue-error %u submit-result %d echo-result %d",
      tm->api.handle != NULL, tm->target_thread, tm->pending, tm->active,
      tm->finished, tm->node_invocations, tm->submit_calls, tm->recv_calls,
      tm->echo_calls, tm->output_calls, tm->output_valid, tm->queue_error,
      tm->submit_result, tm->echo_result);
  vlib_cli_output (
      vm,
      "s121-packet-path buffers ingress=%u/%u egress=%u/%u copies="
      "%u/%u bytes recv=%u output=%u threads setup=%lu submit=%lu recv=%lu "
      "output=%lu owner=%p lwip=%p",
      tm->ingress_buffers_allocated, tm->ingress_buffers_freed,
      tm->egress_buffers_allocated, tm->egress_buffers_freed,
      (u32) tm->vpp_to_pbuf_copy_bytes,
      (u32) tm->pbuf_to_vpp_copy_bytes, (u32) tm->recv_payload_bytes,
      (u32) tm->output_bytes, tm->setup_pthread, tm->submit_pthread,
      tm->recv_pthread, tm->output_pthread, tm->context, tm->lwip_context);
  if (tm->error[0])
    vlib_cli_output (vm, "s121-packet-path error %s", tm->error);
  return 0;
}

VLIB_CLI_COMMAND (s121_packet_path_show_command, static) = {
  .path = "show s121-packet-path",
  .short_help = "show s121-packet-path",
  .function = s121_packet_path_show_command_fn,
};

static clib_error_t *
s121_packet_path_init (vlib_main_t *vm)
{
  s121_packet_path_main_t *tm = &s121_packet_path_main;
  clib_memset (tm, 0, sizeof (*tm));
  tm->frame_queue_index =
      vlib_frame_queue_main_init (s121_packet_path_worker_node.index, 0);
  tm->output_buffer = ~0U;
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (s121_packet_path_init);
