/* SPDX-License-Identifier: Apache-2.0 */

/*
 * OI-2 test-only async Android socket-broker seam.
 *
 * The owner worker creates nonblocking sockets and submits an opaque request
 * plus one SCM_RIGHTS duplicate.  The broker thread only binds/protects the
 * duplicate and publishes an opaque completion.  The VPP main file callback
 * forwards that completion to the original FlowOwner worker; it never calls
 * transport code.  This is intentionally separate from the product broker
 * and is the VPP integration gate for the contract in prototypes/owner_inline_oi2.
 */

#include <vlib/vlib.h>
#include <vlib/buffer_node.h>
#include <vlib/file.h>
#include <vlib/threads.h>
#include <vppinfra/file.h>

#include "oi2_broker_contract.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define OI2_ABI_VERSION OI2_BROKER_ABI_VERSION
#define OI2_MAX_RECORDS 8U
#define OI2_SENTINEL_TARGET 64U
#define OI2_QUEUE_LIMIT 4U
#define OI2_ACTION_SUCCESS OI2_FLAG_NONE
#define OI2_ACTION_BIND_FAILURE OI2_FLAG_BIND_FAILURE
#define OI2_ACTION_PROTECT_FAILURE OI2_FLAG_PROTECT_FAILURE
#define OI2_ACTION_BROKER_UNAVAILABLE OI2_FLAG_BROKER_UNAVAILABLE

typedef enum
{
  OI2_CELL_FAMILIES = 0,
  OI2_CELL_FAILURES,
  OI2_CELL_DELAYED_STOP,
  OI2_CELL_UNAVAILABLE,
  OI2_CELL_QUEUE_FULL,
  OI2_CELL_TRIPWIRES,
} oi2_cell_t;

typedef enum
{
  OI2_STATE_RUNNABLE = 1,
  OI2_STATE_WAITING = 2,
  OI2_STATE_STOPPED = 3,
  OI2_STATE_FAULT = 4,
} oi2_state_t;

typedef oi2_broker_request_t oi2_request_t;
typedef oi2_broker_completion_t oi2_completion_t;

typedef struct __attribute__ ((packed))
{
  u32 kind;
  oi2_completion_t completion;
} oi2_owner_message_t;

typedef struct
{
  oi2_request_t request;
  int fd;
  u32 submitted;
  u32 completed;
  u32 original_closed;
  u32 connect_count;
  u32 first_send_count;
  u32 outcome;
} oi2_record_t;

typedef struct
{
  int request_pair[2];
  int completion_pair[2];
  pthread_t broker_thread;
  u32 broker_started;
  _Atomic u32 broker_stop_requested;
  u32 broker_running;
  u32 broker_available;
  u32 external_broker;
  u32 broker_delay_ms;
  u32 target_thread;
  u32 owner_frame_queue;
  u32 sentinel_frame_queue;
  u32 completion_file_index;
  u32 worker_token_pending;
  oi2_state_t state;
  u32 active;
  u32 finished;
  u32 stop_requested;
  u32 submitted;
  u32 completed;
  u32 record_count;
  u32 queue_limit;
  u32 inflight;
  u32 cell;
  u64 generation;
  u64 underlay_epoch;
  u64 next_token;
  u64 owner_turns;
  u64 sentinel_progress;
  u64 sentinel_first_owner_turn;
  u64 sentinel_last_owner_turn;
  u64 stale;
  u64 duplicate;
  u64 wrong_owner;
  u64 wrong_epoch;
  u64 bind_calls;
  u64 protect_calls;
  u64 broker_duplicate_closes;
  u64 queue_rejects;
  u64 unavailable_rejects;
  u64 infrastructure_faults;
  u64 transport_failures;
  u64 connect_count;
  u64 first_send_count;
  u64 vpp_buffers_allocated;
  u64 vpp_buffers_freed;
  u64 vpp_buffer_residue;
  oi2_record_t records[OI2_MAX_RECORDS];
  char error[256];
} oi2_main_t;

static oi2_main_t oi2_main;

extern vlib_node_registration_t oi2_trigger_node;
extern vlib_node_registration_t oi2_owner_node;
extern vlib_node_registration_t oi2_sentinel_node;

static const char *
oi2_cell_name (u32 cell)
{
  switch (cell)
    {
    case OI2_CELL_FAMILIES: return "families";
    case OI2_CELL_FAILURES: return "failures";
    case OI2_CELL_DELAYED_STOP: return "delayed-stop";
    case OI2_CELL_UNAVAILABLE: return "unavailable";
    case OI2_CELL_QUEUE_FULL: return "queue-full";
    case OI2_CELL_TRIPWIRES: return "tripwires";
    default: return "unknown";
    }
}

static const char *
oi2_state_name (oi2_state_t state)
{
  switch (state)
    {
    case OI2_STATE_RUNNABLE: return "RUNNABLE";
    case OI2_STATE_WAITING: return "WAITING";
    case OI2_STATE_STOPPED: return "STOPPED";
    case OI2_STATE_FAULT: return "FAULT";
    default: return "UNKNOWN";
    }
}

static int
oi2_set_nonblocking (int fd)
{
  int flags = fcntl (fd, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl (fd, F_SETFL, flags | O_NONBLOCK);
}

static int
oi2_bind_socket (int fd, u32 family)
{
  if (family == 4)
    {
      struct sockaddr_in address = { 0 };
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = htonl (INADDR_ANY);
      return bind (fd, (struct sockaddr *) &address, sizeof (address));
    }
  struct sockaddr_in6 address6 = { 0 };
  address6.sin6_family = AF_INET6;
  address6.sin6_addr = in6addr_any;
  return bind (fd, (struct sockaddr *) &address6, sizeof (address6));
}

static void
oi2_close_record (oi2_record_t *record)
{
  if (record->fd >= 0 && !record->original_closed)
    {
      close (record->fd);
      record->original_closed = 1;
    }
}

static int
oi2_recv_request (int fd, oi2_request_t *request, int *received_fd)
{
  char payload[sizeof (*request)];
  char control[CMSG_SPACE (sizeof (int))];
  struct iovec iov = { .iov_base = payload, .iov_len = sizeof (payload) };
  struct msghdr message = { 0 };
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof (control);
  ssize_t count = recvmsg (fd, &message, MSG_DONTWAIT);
  if (count < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
  if ((size_t) count != sizeof (*request))
    return -1;
  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&message);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN (sizeof (int)))
    return -1;
  memcpy (request, payload, sizeof (*request));
  memcpy (received_fd, CMSG_DATA (cmsg), sizeof (int));
  return 1;
}

static void *
oi2_broker_main (void *data)
{
  oi2_main_t *tm = data;
  tm->broker_running = 1;
  while (!atomic_load_explicit (&tm->broker_stop_requested,
                                memory_order_acquire))
    {
      struct pollfd pollfd = { .fd = tm->request_pair[1], .events = POLLIN };
      int ready = poll (&pollfd, 1, 10);
      if (ready < 0 && errno == EINTR)
        continue;
      if (ready <= 0)
        continue;
      oi2_request_t request = { 0 };
      int duplicate_fd = -1;
      int received = oi2_recv_request (tm->request_pair[1], &request,
                                       &duplicate_fd);
      if (received <= 0)
        {
          if (received < 0)
            break;
          continue;
        }
      if (request.abi_version != OI2_ABI_VERSION || duplicate_fd < 0)
        {
          if (duplicate_fd >= 0)
            close (duplicate_fd);
          tm->broker_duplicate_closes++;
          continue;
        }
      tm->bind_calls++;
      u32 result = OI2_RESULT_SUCCESS;
      if (!tm->broker_available)
        result = OI2_RESULT_BROKER_UNAVAILABLE;
      else if ((request.flags & OI2_ACTION_BIND_FAILURE) ||
               oi2_bind_socket (duplicate_fd, request.family) < 0)
        result = OI2_RESULT_BIND_FAILURE;
      else
        {
          tm->protect_calls++;
          if (request.flags & OI2_ACTION_PROTECT_FAILURE)
            result = OI2_RESULT_PROTECT_FAILURE;
        }
      if (tm->broker_delay_ms)
        usleep ((useconds_t) tm->broker_delay_ms * 1000U);
      close (duplicate_fd);
      tm->broker_duplicate_closes++;
      oi2_completion_t completion = {
        .abi_version = OI2_ABI_VERSION,
        .result = result,
        .fault_reason = result,
        .owner = request.owner,
        .shard = request.shard,
        .token = request.token,
        .generation = request.generation,
        .underlay_epoch = request.underlay_epoch,
      };
      if (send (tm->completion_pair[1], &completion, sizeof (completion),
                MSG_NOSIGNAL) != (ssize_t) sizeof (completion))
        break;
    }
  tm->broker_running = 0;
  return 0;
}

static int
oi2_send_request (oi2_main_t *tm, oi2_record_t *record)
{
  char control[CMSG_SPACE (sizeof (int))];
  char payload[sizeof (record->request)];
  struct iovec iov = { .iov_base = payload, .iov_len = sizeof (payload) };
  struct msghdr message = { 0 };
  memcpy (payload, &record->request, sizeof (record->request));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof (control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&message);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (record->fd));
  memcpy (CMSG_DATA (cmsg), &record->fd, sizeof (record->fd));
  ssize_t count = sendmsg (tm->request_pair[0], &message,
                           MSG_DONTWAIT | MSG_NOSIGNAL);
  if (count == (ssize_t) sizeof (record->request))
    {
      record->submitted = 1;
      tm->submitted++;
      tm->inflight++;
      return 0;
    }
  if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    tm->queue_rejects++;
  else
    tm->unavailable_rejects++;
  oi2_close_record (record);
  return -1;
}

static oi2_record_t *
oi2_find_record (oi2_main_t *tm, u64 token)
{
  for (u32 i = 0; i < tm->record_count; i++)
    if (tm->records[i].request.token == token)
      return &tm->records[i];
  return 0;
}

static void oi2_consume_completion (oi2_main_t *tm,
                                    const oi2_completion_t *completion);

static int
oi2_enqueue_owner_buffer (vlib_main_t *vm, const void *data, size_t size)
{
  oi2_main_t *tm = &oi2_main;
  u32 buffer;
  u16 target = (u16) tm->target_thread;
  if (vlib_buffer_alloc (vm, &buffer, 1) != 1)
    return -1;
  tm->vpp_buffers_allocated++;
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer);
  if (size > vlib_buffer_get_default_data_size (vm))
    {
      vlib_buffer_free_one (vm, buffer);
      tm->vpp_buffers_freed++;
      return -1;
    }
  memcpy (vlib_buffer_get_current (b), data, size);
  vlib_node_runtime_t *node =
    vlib_node_get_runtime (vm, oi2_trigger_node.index);
  if (vlib_buffer_enqueue_to_thread (vm, node, tm->owner_frame_queue,
                                     &buffer, &target, 1, 1) != 1)
    {
      vlib_buffer_free_one (vm, buffer);
      tm->vpp_buffers_freed++;
      return -1;
    }
  if (*(const u32 *) data == 0)
    tm->worker_token_pending = 1;
  return 0;
}

static clib_error_t *
oi2_completion_read_ready (clib_file_t *file)
{
  oi2_main_t *tm = (oi2_main_t *) file->private_data;
  vlib_main_t *vm = vlib_get_main ();
  for (;;)
    {
      oi2_completion_t completion;
      ssize_t count = recv (file->file_descriptor, &completion,
                            sizeof (completion), MSG_DONTWAIT);
      if (count == (ssize_t) sizeof (completion))
        {
          oi2_owner_message_t message = {
            .kind = 1,
            .completion = completion,
          };
          if (oi2_enqueue_owner_buffer (vm, &message, sizeof (message)) < 0)
            tm->queue_rejects++;
          continue;
        }
      if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;
      if (count < 0 && errno == EINTR)
        continue;
      return 0;
    }
}

static int
oi2_schedule_sentinel (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  oi2_main_t *tm = &oi2_main;
  u32 buffers[OI2_SENTINEL_TARGET];
  u16 targets[OI2_SENTINEL_TARGET];
  if (vlib_buffer_alloc (vm, buffers, OI2_SENTINEL_TARGET) !=
      OI2_SENTINEL_TARGET)
    return -1;
  tm->vpp_buffers_allocated += OI2_SENTINEL_TARGET;
  for (u32 i = 0; i < OI2_SENTINEL_TARGET; i++)
    targets[i] = (u16) tm->target_thread;
  u32 enqueued = vlib_buffer_enqueue_to_thread (
    vm, node, tm->sentinel_frame_queue, buffers, targets,
    OI2_SENTINEL_TARGET, OI2_SENTINEL_TARGET);
  if (enqueued != OI2_SENTINEL_TARGET)
    {
      if (enqueued < OI2_SENTINEL_TARGET)
        vlib_buffer_free (vm, buffers + enqueued,
                          OI2_SENTINEL_TARGET - enqueued);
      tm->vpp_buffers_freed += OI2_SENTINEL_TARGET - enqueued;
      return -1;
    }
  (void) node;
  return 0;
}

static int
oi2_create_record (oi2_main_t *tm, u32 family, u32 kind, u32 flags)
{
  if (tm->record_count >= OI2_MAX_RECORDS)
    return -1;
  if (tm->inflight >= tm->queue_limit)
    {
      tm->queue_rejects++;
      return 1;
    }
  int domain = family == 4 ? AF_INET : AF_INET6;
  int type = kind == 1 ? SOCK_STREAM : SOCK_DGRAM;
  int fd = socket (domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      tm->unavailable_rejects++;
      return -1;
    }
  oi2_record_t *record = &tm->records[tm->record_count++];
  memset (record, 0, sizeof (*record));
  record->fd = fd;
  record->request.abi_version = OI2_ABI_VERSION;
  record->request.family = family;
  record->request.kind = kind;
  record->request.owner = tm->target_thread;
  record->request.shard = 3;
  record->request.token = tm->next_token++;
  record->request.generation = tm->generation;
  record->request.underlay_epoch = tm->underlay_epoch;
  /* The contract keeps reserved zero in production; the deterministic
   * delayed-stop cell uses it as a bounded broker-delay test control. */
  record->request.reserved = tm->broker_delay_ms;
  record->request.flags = flags;
  if (tm->cell == OI2_CELL_UNAVAILABLE)
    tm->broker_available = 0;
  if (oi2_send_request (tm, record) < 0)
    return -1;
  return 0;
}

static void
oi2_submit_cell (oi2_main_t *tm)
{
  switch (tm->cell)
    {
    case OI2_CELL_FAMILIES:
      oi2_create_record (tm, 4, 1, OI2_ACTION_SUCCESS);
      oi2_create_record (tm, 4, 2, OI2_ACTION_SUCCESS);
      oi2_create_record (tm, 6, 1, OI2_ACTION_SUCCESS);
      oi2_create_record (tm, 6, 2, OI2_ACTION_SUCCESS);
      break;
    case OI2_CELL_FAILURES:
      oi2_create_record (tm, 4, 1, OI2_ACTION_BIND_FAILURE);
      oi2_create_record (tm, 6, 2, OI2_ACTION_PROTECT_FAILURE);
      break;
    case OI2_CELL_DELAYED_STOP:
      oi2_create_record (tm, 4, 1, OI2_ACTION_SUCCESS);
      break;
    case OI2_CELL_UNAVAILABLE:
      tm->broker_available = 0;
      oi2_create_record (tm, 4, 1, OI2_ACTION_BROKER_UNAVAILABLE);
      break;
    case OI2_CELL_QUEUE_FULL:
      tm->queue_limit = 2;
      for (u32 i = 0; i < 4; i++)
        oi2_create_record (tm, i & 1 ? 6 : 4, i & 1 ? 2 : 1,
                           OI2_ACTION_SUCCESS);
      break;
    case OI2_CELL_TRIPWIRES:
      oi2_create_record (tm, 4, 1, OI2_ACTION_SUCCESS);
      break;
    }
}

static void
oi2_finish (oi2_main_t *tm)
{
  for (u32 i = 0; i < tm->record_count; i++)
    oi2_close_record (&tm->records[i]);
  tm->active = 0;
  tm->finished = 1;
  tm->state = OI2_STATE_STOPPED;
}

static void
oi2_consume_completion (oi2_main_t *tm, const oi2_completion_t *completion)
{
  oi2_record_t *record = oi2_find_record (tm, completion->token);
  if (!tm->active || !record || completion->generation != tm->generation)
    {
      tm->stale++;
      return;
    }
  if (completion->owner != tm->target_thread || completion->shard != 3)
    {
      tm->wrong_owner++;
      oi2_close_record (record);
      return;
    }
  if (completion->underlay_epoch != tm->underlay_epoch)
    {
      tm->wrong_epoch++;
      oi2_close_record (record);
      return;
    }
  if (record->completed)
    {
      tm->duplicate++;
      return;
    }
  record->completed = 1;
  tm->completed++;
  if (tm->inflight)
    tm->inflight--;
  if (completion->result == OI2_RESULT_SUCCESS)
    {
      /* The test seam makes the ordering explicit; no connect/send happens
       * on the request path or before this completion reaches the owner. */
      record->connect_count++;
      record->first_send_count++;
      tm->connect_count++;
      tm->first_send_count++;
    }
  else
    {
      tm->infrastructure_faults++;
      tm->transport_failures++;
    }
  oi2_close_record (record);
  if (tm->cell == OI2_CELL_TRIPWIRES && tm->completed == 1)
    {
      oi2_completion_t duplicate = *completion;
      oi2_consume_completion (tm, &duplicate);
      duplicate.owner++;
      oi2_consume_completion (tm, &duplicate);
      duplicate.owner = tm->target_thread;
      duplicate.underlay_epoch++;
      oi2_consume_completion (tm, &duplicate);
      duplicate.underlay_epoch = tm->underlay_epoch;
      duplicate.generation--;
      oi2_consume_completion (tm, &duplicate);
    }
  if (tm->inflight == 0 &&
      tm->completed + tm->queue_rejects >= tm->record_count &&
      tm->cell != OI2_CELL_DELAYED_STOP)
    oi2_finish (tm);
}

static void
oi2_stop_on_owner (oi2_main_t *tm)
{
  if (!tm->active)
    return;
  tm->generation++;
  for (u32 i = 0; i < tm->record_count; i++)
    oi2_close_record (&tm->records[i]);
  tm->inflight = 0;
  tm->active = 0;
  tm->finished = 1;
  tm->state = OI2_STATE_STOPPED;
}

VLIB_NODE_FN (oi2_owner_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi2_main_t *tm = &oi2_main;
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, from[i]);
      tm->worker_token_pending = 0;
      tm->owner_turns++;
      u8 *data = vlib_buffer_get_current (buffer);
      u32 kind = *(u32 *) data;
      if (kind == 0 && tm->active && !tm->submitted)
        {
          oi2_submit_cell (tm);
          tm->state = tm->inflight ? OI2_STATE_WAITING : OI2_STATE_STOPPED;
        }
      else if (kind == 1)
        oi2_consume_completion (tm,
                                (const oi2_completion_t *)
                                (data + sizeof (u32)));
      if (tm->active && tm->stop_requested)
        oi2_stop_on_owner (tm);
      vlib_buffer_free_one (vm, from[i]);
      tm->vpp_buffers_freed++;
      tm->vpp_buffer_residue = tm->vpp_buffers_allocated >= tm->vpp_buffers_freed
                               ? tm->vpp_buffers_allocated - tm->vpp_buffers_freed : 0;
      (void) node;
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oi2_owner_node) = {
  .name = "sakamoto-owner-inline-oi2-owner",
  .function = oi2_owner_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (oi2_sentinel_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi2_main_t *tm = &oi2_main;
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      if (!tm->sentinel_first_owner_turn)
        tm->sentinel_first_owner_turn = tm->owner_turns;
      tm->sentinel_last_owner_turn = tm->owner_turns;
      tm->sentinel_progress++;
      vlib_buffer_free_one (vm, from[i]);
      tm->vpp_buffers_freed++;
      tm->vpp_buffer_residue = tm->vpp_buffers_allocated >= tm->vpp_buffers_freed
                               ? tm->vpp_buffers_allocated - tm->vpp_buffers_freed : 0;
    }
  (void) node;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oi2_sentinel_node) = {
  .name = "sakamoto-owner-inline-oi2-sentinel",
  .function = oi2_sentinel_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),
};

static int
oi2_enqueue_control (vlib_main_t *vm)
{
  u32 control[2] = { 0, 0 };
  return oi2_enqueue_owner_buffer (vm, control, sizeof (control));
}

VLIB_NODE_FN (oi2_trigger_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi2_main_t *tm = &oi2_main;
  if (!tm->worker_token_pending && oi2_enqueue_control (vm) < 0)
    snprintf (tm->error, sizeof (tm->error), "owner trigger enqueue failed");
  (void) node;
  (void) frame;
  return 0;
}

VLIB_REGISTER_NODE (oi2_trigger_node) = {
  .name = "sakamoto-owner-inline-oi2-trigger",
  .function = oi2_trigger_node_fn,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

static oi2_cell_t
oi2_parse_cell (u8 *name)
{
  if (!name || !strcmp ((char *) name, "families")) return OI2_CELL_FAMILIES;
  if (!strcmp ((char *) name, "failures")) return OI2_CELL_FAILURES;
  if (!strcmp ((char *) name, "delayed-stop")) return OI2_CELL_DELAYED_STOP;
  if (!strcmp ((char *) name, "unavailable")) return OI2_CELL_UNAVAILABLE;
  if (!strcmp ((char *) name, "queue-full")) return OI2_CELL_QUEUE_FULL;
  if (!strcmp ((char *) name, "tripwires")) return OI2_CELL_TRIPWIRES;
  return (oi2_cell_t) ~0U;
}

static clib_error_t *
oi2_run_command_fn (vlib_main_t *vm, unformat_input_t *input,
                    vlib_cli_command_t *cmd)
{
  oi2_main_t *tm = &oi2_main;
  u8 *cell_name = 0;
  u32 target_thread = vlib_get_n_threads () > 1 ? 1 : 0;
  u32 delay_ms = 0;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "cell %s", &cell_name)) ;
      else if (unformat (input, "target-thread %u", &target_thread)) ;
      else if (unformat (input, "delay-ms %u", &delay_ms)) ;
      else return clib_error_return (0, "unknown OI2 input `%U'",
                                     format_unformat_error, input);
    }
  if (target_thread == 0 || target_thread >= vlib_get_n_threads ())
    {
      vec_free (cell_name);
      return clib_error_return (0, "target-thread must be a worker");
    }
  if (delay_ms > 1000 || tm->active)
    {
      vec_free (cell_name);
      return clib_error_return (0, "invalid delay or OI2 already active");
    }
  oi2_cell_t cell = oi2_parse_cell (cell_name);
  vec_free (cell_name);
  if ((int) cell < 0)
    return clib_error_return (0, "cell must be families/failures/delayed-stop/unavailable/queue-full/tripwires");
  tm->target_thread = target_thread;
  tm->cell = cell;
  tm->broker_delay_ms = delay_ms;
  tm->queue_limit = OI2_QUEUE_LIMIT;
  tm->broker_available = 1;
  tm->record_count = tm->submitted = tm->completed = tm->inflight = 0;
  tm->queue_rejects = tm->unavailable_rejects = 0;
  tm->stale = tm->duplicate = tm->wrong_owner = tm->wrong_epoch = 0;
  tm->bind_calls = tm->protect_calls = tm->broker_duplicate_closes = 0;
  tm->infrastructure_faults = tm->transport_failures = 0;
  tm->connect_count = tm->first_send_count = 0;
  tm->sentinel_progress = tm->sentinel_first_owner_turn =
    tm->sentinel_last_owner_turn = tm->owner_turns = 0;
  tm->vpp_buffers_allocated = tm->vpp_buffers_freed = tm->vpp_buffer_residue = 0;
  tm->generation++;
  if (!tm->generation) tm->generation = 1;
  tm->underlay_epoch = 1;
  tm->next_token = 1;
  tm->submitted = 0;
  tm->active = 1;
  tm->finished = 0;
  tm->stop_requested = 0;
  tm->worker_token_pending = 0;
  tm->error[0] = 0;
  if (oi2_schedule_sentinel (vm, vlib_node_get_runtime (vm, oi2_trigger_node.index)) < 0 ||
      oi2_enqueue_control (vm) < 0)
    return clib_error_return (0, "OI2 initial enqueue failed");
  vlib_node_set_interrupt_pending (vm, oi2_trigger_node.index);
  vlib_cli_output (vm, "oi2 queued cell=%s target-thread=%u generation=%llu",
                   oi2_cell_name (cell), target_thread,
                   (unsigned long long) tm->generation);
  return 0;
}

VLIB_CLI_COMMAND (oi2_run_command, static) = {
  .path = "sakamoto-oi2 run",
  .short_help = "sakamoto-oi2 run cell <families|failures|delayed-stop|unavailable|queue-full|tripwires> target-thread <worker> delay-ms <n>",
  .function = oi2_run_command_fn,
};

static clib_error_t *
oi2_stop_command_fn (vlib_main_t *vm, unformat_input_t *input,
                     vlib_cli_command_t *cmd)
{
  oi2_main_t *tm = &oi2_main;
  (void) input;
  (void) cmd;
  if (!tm->active)
    return clib_error_return (0, "OI2 is not active");
  tm->stop_requested = 1;
  vlib_node_set_interrupt_pending (vm, oi2_trigger_node.index);
  vlib_cli_output (vm, "oi2 stop requested generation=%llu",
                   (unsigned long long) tm->generation);
  return 0;
}

VLIB_CLI_COMMAND (oi2_stop_command, static) = {
  .path = "sakamoto-oi2 stop",
  .short_help = "stop the OI2 owner request",
  .function = oi2_stop_command_fn,
};

static clib_error_t *
oi2_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                     vlib_cli_command_t *cmd)
{
  oi2_main_t *tm = &oi2_main;
  (void) input;
  (void) cmd;
  const char *state = tm->active && tm->stop_requested
                        ? "STOPPING" : oi2_state_name (tm->state);
  vlib_cli_output (vm,
                   "oi2 state=%s cell=%s active=%u finished=%u external-broker=%u target-thread=%u generation=%llu owner-turns=%llu sentinel=%llu first-owner-turn=%llu last-owner-turn=%llu",
                   state,
                   oi2_cell_name (tm->cell), tm->active, tm->finished,
                   tm->external_broker, tm->target_thread,
                   (unsigned long long) tm->generation,
                   (unsigned long long) tm->owner_turns,
                   (unsigned long long) tm->sentinel_progress,
                   (unsigned long long) tm->sentinel_first_owner_turn,
                   (unsigned long long) tm->sentinel_last_owner_turn);
  vlib_cli_output (vm,
                   "oi2 requests submitted=%u completed=%u inflight=%u queue-rejects=%llu unavailable=%llu bind=%llu protect=%llu stale=%llu duplicate=%llu wrong-owner=%llu wrong-epoch=%llu",
                   tm->submitted, tm->completed, tm->inflight,
                   (unsigned long long) tm->queue_rejects,
                   (unsigned long long) tm->unavailable_rejects,
                   (unsigned long long) tm->bind_calls,
                   (unsigned long long) tm->protect_calls,
                   (unsigned long long) tm->stale,
                   (unsigned long long) tm->duplicate,
                   (unsigned long long) tm->wrong_owner,
                   (unsigned long long) tm->wrong_epoch);
  vlib_cli_output (vm,
                   "oi2 outcomes connect=%llu first-send=%llu infrastructure-faults=%llu transport-failures=%llu broker-duplicate-closes=%llu buffers=%llu/%llu residue=%llu error=%s",
                   (unsigned long long) tm->connect_count,
                   (unsigned long long) tm->first_send_count,
                   (unsigned long long) tm->infrastructure_faults,
                   (unsigned long long) tm->transport_failures,
                   (unsigned long long) tm->broker_duplicate_closes,
                   (unsigned long long) tm->vpp_buffers_allocated,
                   (unsigned long long) tm->vpp_buffers_freed,
                   (unsigned long long) tm->vpp_buffer_residue, tm->error);
  return 0;
}

VLIB_CLI_COMMAND (oi2_show_command, static) = {
  .path = "show sakamoto-oi2",
  .short_help = "show OI2 async broker evidence",
  .function = oi2_show_command_fn,
};

static clib_error_t *
oi2_init (vlib_main_t *vm)
{
  oi2_main_t *tm = &oi2_main;
  const char *external = getenv ("SAKAMOTO_OI2_EXTERNAL_BROKER");
  const char *request_fd_text = getenv ("SAKAMOTO_OI2_REQUEST_FD");
  const char *completion_fd_text = getenv ("SAKAMOTO_OI2_COMPLETION_FD");
  char *end = 0;
  long request_fd = request_fd_text ? strtol (request_fd_text, &end, 10) : -1;
  bool request_fd_valid = request_fd_text && end && *end == 0 && request_fd >= 0;
  end = 0;
  long completion_fd = completion_fd_text ? strtol (completion_fd_text, &end, 10) : -1;
  bool completion_fd_valid = completion_fd_text && end && *end == 0 && completion_fd >= 0;
  memset (tm, 0, sizeof (*tm));
  tm->request_pair[0] = tm->request_pair[1] = -1;
  tm->completion_pair[0] = tm->completion_pair[1] = -1;
  tm->completion_file_index = ~0U;
  tm->owner_frame_queue = vlib_frame_queue_main_init (oi2_owner_node.index, 0);
  tm->sentinel_frame_queue = vlib_frame_queue_main_init (oi2_sentinel_node.index, 0);
  tm->state = OI2_STATE_STOPPED;
  tm->generation = 0;
  tm->underlay_epoch = 1;
  tm->queue_limit = OI2_QUEUE_LIMIT;
  tm->external_broker = external && external[0] == '1' && request_fd_valid &&
                        completion_fd_valid;
  if (tm->external_broker)
    {
      tm->request_pair[0] = (int) request_fd;
      tm->completion_pair[0] = (int) completion_fd;
    }
  else if (socketpair (AF_UNIX, SOCK_SEQPACKET, 0, tm->request_pair) < 0 ||
           socketpair (AF_UNIX, SOCK_SEQPACKET, 0, tm->completion_pair) < 0)
    return clib_error_return_unix (0, "OI2 socketpair");
  if (oi2_set_nonblocking (tm->request_pair[0]) < 0 ||
      oi2_set_nonblocking (tm->completion_pair[0]) < 0)
    return clib_error_return_unix (0, "OI2 nonblocking");
  clib_file_t file = { 0 };
  file.read_function = oi2_completion_read_ready;
  file.file_descriptor = tm->completion_pair[0];
  file.polling_thread_index = 0;
  file.private_data = (uword) tm;
  file.description = format (0, "owner-inline OI2 completion");
  tm->completion_file_index = clib_file_add (&file_main, &file);
  atomic_store_explicit (&tm->broker_stop_requested, 0, memory_order_release);
  if (!tm->external_broker)
    {
      if (pthread_create (&tm->broker_thread, 0, oi2_broker_main, tm) != 0)
        return clib_error_return_unix (0, "OI2 broker thread");
      tm->broker_started = 1;
    }
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (oi2_init);
