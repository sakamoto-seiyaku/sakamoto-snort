/* PROTOTYPE — discard after answering the pinned-VPP TUN lane question.
 * Question: can a VPP-only I/O worker read directly into a VPP buffer,
 * hand off only its index to one of N owners, receive that index back,
 * and write/free the same buffer without a payload staging copy? */
#include <vlib/vlib.h>
#include <vlib/buffer_funcs.h>
#include <vlib/threads.h>
#include <vlib/file.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  int io_fd, peer_fd;
  u32 file_index, owner_queue, return_queue;
  u32 owner_count, io_thread;
  u32 last_input_index, last_owner_index, last_return_index;
  u32 last_input_thread, last_owner_thread, last_return_thread;
  u32 last_input_length, last_write_length;
  u64 reads, owner_receives, returns, writes, failures;
} prototype_tun_io_main_t;

static prototype_tun_io_main_t prototype = {
  .io_fd = -1, .peer_fd = -1, .file_index = ~0U,
};

extern vlib_node_registration_t prototype_tun_io_ingress_node;
extern vlib_node_registration_t prototype_tun_io_owner_node;
extern vlib_node_registration_t prototype_tun_io_return_node;

static clib_error_t *
prototype_read_ready (clib_file_t *file)
{
  vlib_main_t *vm = vlib_get_main ();
  if (vm->thread_index != prototype.io_thread ||
      file->file_descriptor != (u32) prototype.io_fd)
    return clib_error_return (0, "prototype I/O thread mismatch");
  for (u32 i = 0; i < 32; i++) {
    u32 bi;
    if (vlib_buffer_alloc (vm, &bi, 1) != 1) {
      __atomic_add_fetch (&prototype.failures, 1, __ATOMIC_RELAXED);
      break;
    }
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    vlib_buffer_reset (b);
    u8 *data = vlib_buffer_get_current (b);
    ssize_t n = read (prototype.io_fd, data,
                      vlib_buffer_get_default_data_size (vm));
    if (n <= 0) {
      vlib_buffer_free (vm, &bi, 1);
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        break;
      __atomic_add_fetch (&prototype.failures, 1, __ATOMIC_RELAXED);
      break;
    }
    b->current_length = (u16) n;
    __atomic_store_n (&prototype.last_input_index, bi, __ATOMIC_RELAXED);
    __atomic_store_n (&prototype.last_input_thread, vm->thread_index, __ATOMIC_RELAXED);
    __atomic_store_n (&prototype.last_input_length, n, __ATOMIC_RELAXED);
    __atomic_add_fetch (&prototype.reads, 1, __ATOMIC_RELAXED);
    vlib_frame_t *frame = vlib_get_frame_to_node (vm, prototype_tun_io_ingress_node.index);
    u32 *to = vlib_frame_vector_args (frame);
    to[0] = bi;
    frame->n_vectors = 1;
    vlib_put_frame_to_node (vm, prototype_tun_io_ingress_node.index, frame);
  }
  return 0;
}

VLIB_NODE_FN (prototype_tun_io_ingress_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++) {
    u32 bi = from[i], failed;
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    /* Synthetic owner key: first byte. Product's canonical selector is not
     * under test here. The actual VPP buffer/index transfer is. */
    u16 target = vlib_get_worker_thread_index (
      ((u8 *) vlib_buffer_get_current (b))[0] % prototype.owner_count);
    if (vm->thread_index != prototype.io_thread ||
        vlib_buffer_enqueue_to_thread_retained (vm, node,
          prototype.owner_queue, &bi, &target, 1, &failed) != 1) {
      __atomic_add_fetch (&prototype.failures, 1, __ATOMIC_RELAXED);
      vlib_buffer_free (vm, &bi, 1);
    }
  }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (prototype_tun_io_ingress_node) = {
  .name = "prototype-tun-io-ingress", .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (prototype_tun_io_owner_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++) {
    u32 bi = from[i], failed;
    u16 target = prototype.io_thread;
    u32 owner = vlib_get_worker_index (vm->thread_index);
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    if (owner >= prototype.owner_count ||
        ((u8 *) vlib_buffer_get_current (b))[0] % prototype.owner_count != owner) {
      __atomic_add_fetch (&prototype.failures, 1, __ATOMIC_RELAXED);
      vlib_buffer_free (vm, &bi, 1);
      continue;
    }
    __atomic_store_n (&prototype.last_owner_index, bi, __ATOMIC_RELAXED);
    __atomic_store_n (&prototype.last_owner_thread, vm->thread_index, __ATOMIC_RELAXED);
    __atomic_add_fetch (&prototype.owner_receives, 1, __ATOMIC_RELAXED);
    if (vlib_buffer_enqueue_to_thread_retained (vm, node,
          prototype.return_queue, &bi, &target, 1, &failed) != 1) {
      __atomic_add_fetch (&prototype.failures, 1, __ATOMIC_RELAXED);
      vlib_buffer_free (vm, &bi, 1);
    }
  }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (prototype_tun_io_owner_node) = {
  .name = "prototype-tun-io-owner", .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (prototype_tun_io_return_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  (void) node;
  for (u32 i = 0; i < frame->n_vectors; i++) {
    u32 bi = from[i];
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    ssize_t n = vm->thread_index == prototype.io_thread
      ? write (prototype.io_fd, vlib_buffer_get_current (b), b->current_length)
      : -1;
    __atomic_store_n (&prototype.last_return_index, bi, __ATOMIC_RELAXED);
    __atomic_store_n (&prototype.last_return_thread, vm->thread_index, __ATOMIC_RELAXED);
    __atomic_store_n (&prototype.last_write_length, n, __ATOMIC_RELAXED);
    __atomic_add_fetch (&prototype.returns, 1, __ATOMIC_RELAXED);
    if (n == b->current_length)
      __atomic_add_fetch (&prototype.writes, 1, __ATOMIC_RELAXED);
    else
      __atomic_add_fetch (&prototype.failures, 1, __ATOMIC_RELAXED);
    vlib_buffer_free (vm, &bi, 1);
  }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (prototype_tun_io_return_node) = {
  .name = "prototype-tun-io-return", .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

static clib_error_t *
prototype_open (vlib_main_t *vm, unformat_input_t *input,
                vlib_cli_command_t *command)
{
  (void) input; (void) command;
  if (prototype.io_fd >= 0)
    return clib_error_return (0, "prototype already open");
  if (vlib_num_workers () < 2)
    return clib_error_return (0, "requires at least one owner plus I/O worker");
  int fd[2];
  if (socketpair (AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fd))
    return clib_error_return (0, "socketpair errno=%d", errno);
  prototype.peer_fd = fd[0];
  prototype.io_fd = fd[1];
  prototype.io_thread = vlib_num_workers ();
  prototype.owner_count = vlib_num_workers () - 1;
  clib_file_t file = {0};
  file.file_descriptor = prototype.io_fd;
  file.polling_thread_index = prototype.io_thread;
  file.read_function = prototype_read_ready;
  file.description = format (0, "prototype-tun-io%c", 0);
  prototype.file_index = clib_file_add (&file_main, &file);
  vlib_cli_output (vm, "prototype.open owners=%u io_thread=%u",
    prototype.owner_count, prototype.io_thread);
  return 0;
}
VLIB_CLI_COMMAND (prototype_open_command, static) = {
  .path = "prototype tun-io open", .function = prototype_open,
};

static clib_error_t *
prototype_send (vlib_main_t *vm, unformat_input_t *input,
                vlib_cli_command_t *command)
{
  (void) command;
  u32 owner;
  if (prototype.io_fd < 0 || !unformat (input, "%u", &owner)
      || owner >= prototype.owner_count)
    return clib_error_return (0, "expected open prototype and owner < %u",
      prototype.owner_count);
  u8 packet[32] = {0};
  packet[0] = (u8) owner;
  packet[1] = (u8) (__atomic_load_n (&prototype.reads, __ATOMIC_RELAXED) + 1);
  for (u32 i = 2; i < sizeof (packet); i++) packet[i] = (u8) i;
  if (send (prototype.peer_fd, packet, sizeof (packet), 0) != sizeof (packet))
    return clib_error_return (0, "prototype peer send failed");
  struct pollfd ready = { .fd = prototype.peer_fd, .events = POLLIN };
  if (poll (&ready, 1, 2000) != 1)
    return clib_error_return (0, "prototype return timed out");
  u8 returned[sizeof (packet)];
  ssize_t n = recv (prototype.peer_fd, returned, sizeof (returned), 0);
  if (n != sizeof (packet) || memcmp (packet, returned, sizeof (packet)))
    return clib_error_return (0, "prototype returned different bytes");
  vlib_cli_output (vm,
    "prototype.echo owner=%u bytes=%u equal=1 input_thread=%u owner_thread=%u return_thread=%u input_buffer=%u owner_buffer=%u return_buffer=%u",
    owner, (u32) n, prototype.last_input_thread,
    prototype.last_owner_thread, prototype.last_return_thread,
    prototype.last_input_index, prototype.last_owner_index,
    prototype.last_return_index);
  return 0;
}
VLIB_CLI_COMMAND (prototype_send_command, static) = {
  .path = "prototype tun-io send", .function = prototype_send,
  .is_mp_safe = 1,
};

static clib_error_t *
prototype_status (vlib_main_t *vm, unformat_input_t *input,
                  vlib_cli_command_t *command)
{
  (void) input; (void) command;
  vlib_cli_output (vm,
    "prototype.status owners=%u io_thread=%u reads=%llu owner_receives=%llu returns=%llu writes=%llu failures=%llu",
    prototype.owner_count, prototype.io_thread,
    (unsigned long long) __atomic_load_n (&prototype.reads, __ATOMIC_RELAXED),
    (unsigned long long) __atomic_load_n (&prototype.owner_receives, __ATOMIC_RELAXED),
    (unsigned long long) __atomic_load_n (&prototype.returns, __ATOMIC_RELAXED),
    (unsigned long long) __atomic_load_n (&prototype.writes, __ATOMIC_RELAXED),
    (unsigned long long) __atomic_load_n (&prototype.failures, __ATOMIC_RELAXED));
  for (u32 thread = 0; thread <= vlib_num_workers (); thread++)
    vlib_cli_output (vm, "prototype.thread index=%u tid=%u cpu=%d role=%s",
      thread, (u32) vlib_worker_threads[thread].lwp,
      vlib_worker_threads[thread].cpu_id,
      thread == 0 ? "main" : thread == prototype.io_thread ? "io" : "owner");
  return 0;
}
VLIB_CLI_COMMAND (prototype_status_command, static) = {
  .path = "prototype tun-io status", .function = prototype_status,
  .is_mp_safe = 1,
};

static clib_error_t *
prototype_init (vlib_main_t *vm)
{
  (void) vm;
  prototype.owner_queue =
    vlib_frame_queue_main_init (prototype_tun_io_owner_node.index, 64);
  prototype.return_queue =
    vlib_frame_queue_main_init (prototype_tun_io_return_node.index, 64);
  return 0;
}
VLIB_INIT_FUNCTION (prototype_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "THROWAWAY TUN I/O worker topology probe",
};
