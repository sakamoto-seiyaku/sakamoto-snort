/* SPDX-License-Identifier: Apache-2.0 */
#include "product_vpn_flow_stack_driver.h"
#include "product_vpn_flow_stack_private.h"
#include "product_vpn_socket_broker.h"
#include "product_vpn_tun_adapter.h"
#include "product_packet_graph.h"
#include <vlib/threads.h>
#include <vlib/file.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  product_vpn_flow_stack_t *stack;
  product_vpn_socket_broker_t broker;
  product_vpn_flow_stack_snapshot_t snapshot;
  uint64_t generation;
  uint64_t input_calls, reject_input_at;
  uint64_t hold_until_ms;
  uint32_t index;
  unsigned enabled, stop_requested, stopped, ready, trace;
  int timer_fd;
  u32 reactor_file, timer_file, broker_file;
} product_vpn_stack_owner_t;

/* Fixed shard registry, not shared PCB/task state. The control plane creates
 * it before traffic; each worker subsequently drives only its own element. */
static product_vpn_stack_owner_t owners[PRODUCT_VPN_RETURN_WORKERS];
static product_vpn_flow_stack_config_t limits = {
  .max_sessions = 256, .max_input_packets = 1024, .max_pbufs = 8192,
  .max_pcbs = 258, .max_sockets = 256,
  .max_packet_bytes = 1500, .task_stack_bytes = 32768,
  .broker_timeout_ms = 2500, .idle_timeout_ms = 60000,
};
extern vlib_node_registration_t product_vpn_flow_stack_input_node;

static void schedule(vlib_main_t *vm)
{ vlib_node_set_interrupt_pending(vm, product_vpn_flow_stack_input_node.index); }

static u64 clock_ms(void)
{
  struct timespec time;
  if (clock_gettime(CLOCK_MONOTONIC, &time)) abort();
  return (u64)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static void arm_timer(product_vpn_stack_owner_t *owner, int timeout_ms)
{
  struct itimerspec timer = {0};
  if (timeout_ms >= 0) {
    timer.it_value.tv_sec = timeout_ms / 1000;
    timer.it_value.tv_nsec = (timeout_ms % 1000) * 1000000L;
    if (!timeout_ms) timer.it_value.tv_nsec = 1;
  }
  if (timerfd_settime(owner->timer_fd, 0, &timer, NULL)) abort();
}

static clib_error_t *read_ready(clib_file_t *file)
{
  if (file->private_data) {
    u64 expirations;
    (void)read(file->file_descriptor, &expirations, sizeof(expirations));
  }
  schedule(vlib_get_main());
  return NULL;
}

static u32 subscribe(int original, int timer, u32 owner_index)
{
  /* VPP owns this subscription reference. The HEV/broker/driver retains its
   * own original, so an error-close cannot invalidate VPP's file registry. */
  int fd = fcntl(original, F_DUPFD_CLOEXEC, 0);
  if (fd < 0) return ~0U;
  clib_file_t file = {.file_descriptor = fd,
    .polling_thread_index = vlib_get_worker_thread_index(owner_index),
    .private_data = timer, .read_function = read_ready, .error_function = read_ready,
    .description = format(0, "product-flow-stack-%s%c", timer ? "timer" : "ready", 0)};
  return clib_file_add(&file_main, &file);
}

static void unsubscribe(u32 *file)
{
  if (*file != ~0U) clib_file_del_by_index(&file_main, *file);
  *file = ~0U;
}

static product_vpn_flow_stack_output_result_t output(void *opaque,
  const product_vpn_flow_stack_span_t *spans, unsigned count, size_t total,
  const product_platform_packet_facts_t *platform,
  uint64_t generation, uint64_t serial, uint64_t epoch)
{
  product_vpn_stack_owner_t *owner = opaque;
  if (__atomic_load_n(&owner->stop_requested, __ATOMIC_ACQUIRE))
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED;
  return product_vpn_tun_submit_return(vlib_get_main(), spans, count, total,
                                       platform, generation, serial, epoch);
}

static int request(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  product_vpn_stack_owner_t *owner = opaque;
  return product_vpn_socket_broker_request(&owner->broker, generation, session, fd);
}

static int reply(void *opaque, uint64_t generation, uint64_t session, unsigned error,
                 uint64_t epoch, uint32_t context, int known)
{
  product_vpn_stack_owner_t *owner = opaque;
  if (__atomic_load_n(&owner->stop_requested, __ATOMIC_ACQUIRE)) return -1;
  int result = product_vpn_flow_stack_broker_complete(owner->stack,
      generation, session, error, epoch, context, known);
  if (owner->trace)
    fprintf(stderr, "s237 event=broker_reply thread=%u tls=%u generation=%llu session=%llu success=%d epoch=%llu context=%u known=%d result=%d error=%u\n",
      vlib_get_main()->thread_index, vlib_get_thread_index(),
      (unsigned long long)generation, (unsigned long long)session, error == 0,
      (unsigned long long)epoch, context, known, result, error);
  return result;
}

static int invalidate(void *opaque, uint64_t generation, uint64_t epoch)
{
  product_vpn_stack_owner_t *owner = opaque;
  int result = product_vpn_flow_stack_invalidate_underlay(owner->stack, generation, epoch);
  fprintf(stderr, "s243 event=underlay_invalidation thread=%u tls=%u owner=%u generation=%llu epoch=%llu result=%d\n",
    vlib_get_main()->thread_index, vlib_get_thread_index(), owner->index,
    (unsigned long long)generation, (unsigned long long)epoch, result);
  return result;
}

static void trace(void *opaque, const char *event, uint64_t serial,
                  uint64_t session, uintptr_t object, size_t bytes,
                  int result, unsigned kind)
{
  product_vpn_stack_owner_t *owner = opaque;
  if (!owner->trace && strcmp(event, "uid_conflict")) return;
  fprintf(stderr, "s237 event=%s thread=%u tls=%u owner=%u generation=%llu serial=%llu session=%llu object=%llx bytes=%zu result=%d kind=%u\n",
    event, vlib_get_main()->thread_index, vlib_get_thread_index(),
    owner->index,
    (unsigned long long)owner->generation, (unsigned long long)serial,
    (unsigned long long)session, (unsigned long long)object, bytes, result, kind);
}

static int start_owner(uint64_t generation, u32 index)
{
  product_vpn_stack_owner_t *owner = &owners[index];
  product_vpn_flow_stack_config_t config = limits;
  owner->index = index;
  owner->generation = generation;
  owner->broker.fd = -1;
  owner->timer_fd = -1;
  owner->reactor_file = owner->timer_file = owner->broker_file = ~0U;
  const char *tracing = getenv("SAKAMOTO_PRODUCT_VPN_HEV_TRACE");
  owner->trace = tracing && !strcmp(tracing, "1");
  config.generation = generation;
  config.owner_index = index;
  config.output = output; config.broker = request; config.trace = trace; config.opaque = owner;
  owner->stack = product_vpn_flow_stack_create(&config);
  if (!owner->stack) return 0;
  owner->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (owner->timer_fd >= 0) {
    owner->timer_file = subscribe(owner->timer_fd, 1, index);
    owner->reactor_file = subscribe(product_vpn_flow_stack_poll_fd(owner->stack), 0, index);
  }
  if (owner->timer_fd < 0 || owner->timer_file == ~0U || owner->reactor_file == ~0U) {
    unsubscribe(&owner->timer_file); unsubscribe(&owner->reactor_file);
    if (owner->timer_fd >= 0) close(owner->timer_fd);
    product_vpn_flow_stack_quiesce(owner->stack);
    product_vpn_flow_stack_step(owner->stack, 8, 200);
    if (product_vpn_flow_stack_close(owner->stack)) abort();
    owner->stack = NULL;
    return 0;
  }
  owner->enabled = 1;
  return 1;
}

int product_vpn_flow_stack_driver_start(vlib_main_t *vm, uint64_t generation)
{
  const char *enabled = getenv("SAKAMOTO_PRODUCT_VPN_HEV");
  if (!enabled || strcmp(enabled, "1")) return 1;
  if (!vm || vm->thread_index || !generation ||
      product_packet_graph_worker_count() != PRODUCT_VPN_RETURN_WORKERS) return 0;
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i)
    if (owners[i].enabled) return 0;
  /* Validation may reduce real startup limits, never resize live storage or
   * enlarge the development baseline. Both owners retain independent quotas. */
  const char *configured = getenv("SAKAMOTO_PRODUCT_VPN_HEV_LIMITS");
  if (configured && *configured) {
    u32 values[5], maximum[] = {256, 258, 256, 1024, 8192};
    const char *cursor = configured;
    if (!product_vpn_tun_validation_enabled()) return 0;
    for (unsigned i = 0; i < 5; ++i) {
      char *end;
      if (*cursor < '0' || *cursor > '9') return 0;
      errno = 0;
      unsigned long value = strtoul(cursor, &end, 10);
      if (errno || !value || value > maximum[i] || (i == 1 && value < 3) ||
          (i < 4 ? *end != ',' : *end != '\0')) return 0;
      values[i] = (u32)value;
      cursor = end + (i < 4);
    }
    limits.max_sessions = values[0]; limits.max_pcbs = values[1];
    limits.max_sockets = values[2]; limits.max_input_packets = values[3];
    limits.max_pbufs = values[4];
  }
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i) {
    if (start_owner(generation, i)) continue;
    /* No worker has adopted a shard yet: roll back the whole startup under
     * the barrier, rather than silently running a smaller worker layout. */
    for (u32 j = 0; j < i; ++j) {
      product_vpn_stack_owner_t *owner = &owners[j];
      unsubscribe(&owner->reactor_file); unsubscribe(&owner->timer_file);
      close(owner->timer_fd); owner->timer_fd = -1;
      product_vpn_flow_stack_quiesce(owner->stack);
      product_vpn_flow_stack_step(owner->stack, 8, 200);
      if (product_vpn_flow_stack_close(owner->stack)) abort();
      owner->stack = NULL; owner->enabled = 0;
    }
    return 0;
  }
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i) {
    vlib_main_t *worker = vlib_get_main_by_index(vlib_get_worker_thread_index(i));
    vlib_node_set_state(worker, product_vpn_flow_stack_input_node.index, VLIB_NODE_STATE_INTERRUPT);
    schedule(worker);
  }
  return 1;
}

int product_vpn_flow_stack_driver_attach(int fd, uint32_t index)
{
  if (index >= PRODUCT_VPN_RETURN_WORKERS) { if (fd >= 0) close(fd); return -1; }
  product_vpn_stack_owner_t *owner = &owners[index];
  if (!owner->enabled || owner->broker.fd >= 0 || owner->stop_requested) {
    if (fd >= 0) close(fd);
    return -1;
  }
  int result = product_vpn_socket_broker_open(&owner->broker, fd, owner->generation, index);
  if (!result) {
    owner->broker_file = subscribe(owner->broker.fd, 0, index);
    if (owner->broker_file == ~0U) { product_vpn_socket_broker_close(&owner->broker); return -1; }
    __atomic_store_n(&owner->ready, 1, __ATOMIC_RELEASE);
  }
  return result;
}

void product_vpn_flow_stack_driver_quiesce(void)
{
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i) {
    __atomic_store_n(&owners[i].stop_requested, 1, __ATOMIC_RELEASE);
    if (owners[i].enabled && !__atomic_load_n(&owners[i].stopped, __ATOMIC_ACQUIRE))
      schedule(vlib_get_main_by_index(vlib_get_worker_thread_index(i)));
  }
}
int product_vpn_flow_stack_driver_stopped(void)
{
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i)
    if (owners[i].enabled && !__atomic_load_n(&owners[i].stopped, __ATOMIC_ACQUIRE)) return 0;
  return 1;
}
int product_vpn_flow_stack_driver_enabled(void) { return owners[0].enabled; }
int product_vpn_flow_stack_driver_ready(void)
{
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i)
    if (!__atomic_load_n(&owners[i].ready, __ATOMIC_ACQUIRE)) return 0;
  return 1;
}

int product_vpn_flow_stack_driver_reject_after(uint32_t index, uint32_t packets)
{
  if (index >= PRODUCT_VPN_RETURN_WORKERS || !owners[index].enabled ||
      !packets || packets > 64 || owners[index].reject_input_at)
    return -1;
  owners[index].reject_input_at = owners[index].input_calls + packets;
  return 0;
}

product_vpn_flow_stack_input_result_t product_vpn_flow_stack_driver_input(
  vlib_main_t *vm, const uint8_t *l3, size_t length,
  const product_platform_packet_facts_t *platform, uint64_t generation)
{
  if (!vm || !vm->thread_index ||
      vlib_get_worker_index(vm->thread_index) >= PRODUCT_VPN_RETURN_WORKERS)
    return PRODUCT_VPN_FLOW_STACK_NOT_RUNNING;
  product_vpn_stack_owner_t *owner = &owners[vlib_get_worker_index(vm->thread_index)];
  if (!owner->stack || !__atomic_load_n(&owner->ready, __ATOMIC_ACQUIRE) ||
      __atomic_load_n(&owner->stop_requested, __ATOMIC_ACQUIRE))
    return PRODUCT_VPN_FLOW_STACK_NOT_RUNNING;
  if (++owner->input_calls == owner->reject_input_at) {
    owner->reject_input_at = 0;
    fprintf(stderr, "s237 event=fault_input_capacity thread=%u generation=%llu call=%llu\n",
      vm->thread_index, (unsigned long long)generation, (unsigned long long)owner->input_calls);
    return PRODUCT_VPN_FLOW_STACK_NO_CAPACITY;
  }
  product_vpn_flow_stack_input_result_t result =
    product_vpn_flow_stack_input_copy(owner->stack, l3, length, platform, generation);
  schedule(vm); /* Admission and rejection-with-close can both wake HEV tasks. */
  return result;
}

VLIB_NODE_FN(product_vpn_flow_stack_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  (void)frame;
  if (!vm->thread_index ||
      vlib_get_worker_index(vm->thread_index) >= PRODUCT_VPN_RETURN_WORKERS) return 0;
  product_vpn_stack_owner_t *owner = &owners[vlib_get_worker_index(vm->thread_index)];
  if (!owner->stack) return 0;
  owner->snapshot = product_vpn_flow_stack_snapshot(owner->stack);
  if (owner->hold_until_ms && !__atomic_load_n(&owner->stop_requested, __ATOMIC_ACQUIRE)) {
    u64 now = clock_ms();
    if (now < owner->hold_until_ms) {
      arm_timer(owner, (int)(owner->hold_until_ms - now));
      return 0; /* Diagnostic gate, not an OS sleep or a substitute queue. */
    }
    owner->hold_until_ms = 0;
  }
  unsigned received = product_vpn_socket_broker_receive(&owner->broker, 8, reply, invalidate, owner);
  if (owner->broker.disconnected) {
    __atomic_store_n(&owner->ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->stop_requested, 1, __ATOMIC_RELEASE);
  }
  if (__atomic_load_n(&owner->stop_requested, __ATOMIC_ACQUIRE)) {
    if (owner->snapshot.running)
      fprintf(stderr, "s237 event=quiesce_begin generation=%llu owner=%u thread=%u sessions=%u inputs=%u pbufs=%u sent=%llu outputs=%llu\n",
        (unsigned long long)owner->generation, owner->index, vm->thread_index, owner->snapshot.sessions,
        owner->snapshot.input_packets, owner->snapshot.pbufs,
        (unsigned long long)owner->snapshot.direct_sent,
        (unsigned long long)owner->snapshot.output_accepted);
    product_vpn_flow_stack_quiesce(owner->stack);
  }
  product_vpn_flow_stack_step_result_t result = product_vpn_flow_stack_step(owner->stack, 8, 200);
  owner->snapshot = product_vpn_flow_stack_snapshot(owner->stack);
  if (result.stopped && !product_packet_graph_buffer_debt() &&
      !product_packet_graph_obligation_debt() && !product_packet_graph_completion_frame_debt()) {
    unsubscribe(&owner->reactor_file); unsubscribe(&owner->broker_file);
    unsubscribe(&owner->timer_file);
    close(owner->timer_fd); owner->timer_fd = -1;
    if (product_vpn_flow_stack_close(owner->stack)) abort();
    owner->stack = NULL;
    product_vpn_socket_broker_close(&owner->broker);
    __atomic_store_n(&owner->ready, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&owner->stopped, 1, __ATOMIC_RELEASE);
    fprintf(stderr, "s237 event=owner_stopped generation=%llu owner=%u thread=%u sessions=%u inputs=%u pbufs=%u sockets_created=%llu sockets_closed=%llu timer_fd=%d broker_fd=%d buffers=%llu obligations=%llu frames=%llu\n",
      (unsigned long long)owner->generation, owner->index, vm->thread_index, owner->snapshot.sessions,
      owner->snapshot.input_packets, owner->snapshot.pbufs,
      (unsigned long long)owner->snapshot.sockets_created,
      (unsigned long long)owner->snapshot.sockets_closed, owner->timer_fd, owner->broker.fd,
      (unsigned long long)product_packet_graph_buffer_debt(),
      (unsigned long long)product_packet_graph_obligation_debt(),
      (unsigned long long)product_packet_graph_completion_frame_debt());
    vlib_node_set_state(vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  } else {
    arm_timer(owner, result.timeout_ms);
    if (result.runnable || received == 8 || result.stopped) schedule(vm);
  }
  return received + result.quanta;
}
VLIB_REGISTER_NODE(product_vpn_flow_stack_input_node) = {
  .name = "product-vpn-flow-stack-input", .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

static clib_error_t *status(vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *command)
{
  (void)input; (void)command;
  /* Normal CLI worker barrier makes this owner-published snapshot stable. */
  for (u32 index = 0; index < PRODUCT_VPN_RETURN_WORKERS; ++index) {
  product_vpn_stack_owner_t *owner = &owners[index];
  product_vpn_flow_stack_snapshot_t *s = &owner->snapshot;
  vlib_cli_output(vm, "flow_stack.limits owner=%u sessions=%u pcbs=%u sockets=%u packets=%u pbufs=%u live_resize=0",
    index, limits.max_sessions, limits.max_pcbs, limits.max_sockets,
    limits.max_input_packets, limits.max_pbufs);
  vlib_cli_output(vm, "flow_stack.resources owner=%u pcbs=%u pcb_peak=%u pcb_allocations=%llu pcb_frees=%llu sockets=%u socket_peak=%u input_pbufs=%u pbuf_peak=%u",
    index, s->pcbs, s->pcb_peak, (unsigned long long)s->pcb_allocations,
    (unsigned long long)s->pcb_frees, s->sockets, s->socket_peak, s->input_pbufs, s->pbuf_peak);
  vlib_cli_output(vm, "flow_stack.health owner=%u generation=%llu state=%s reason=%s failures=%llu first_ms=%llu last_ms=%llu last_session=%llu last_error=%d retained_for_generation=1",
    index, (unsigned long long)owner->generation, s->fault_count ? "error" : "ok",
    product_vpn_flow_stack_fault_name(s->last_fault), (unsigned long long)s->fault_count,
    (unsigned long long)s->first_fault_ms, (unsigned long long)s->last_fault_ms,
    (unsigned long long)s->last_fault_session, s->last_fault_error);
  for (unsigned i = 1; i < PRODUCT_VPN_FLOW_STACK_FAULT_COUNT; ++i)
    vlib_cli_output(vm, "flow_stack.failure owner=%u reason=%s count=%llu",
      index, product_vpn_flow_stack_fault_name(i), (unsigned long long)s->faults[i]);
  vlib_cli_output(vm, "flow_stack.copies owner=%u calls=%llu bytes=%llu",
    index, (unsigned long long)s->input_copy_calls, (unsigned long long)s->input_copy_bytes);
  vlib_cli_output(vm, "flow_stack.status generation=%llu enabled=%u owner=%u ready=%u stopped=%u sessions=%u inputs=%u pbufs=%u admissions=%llu rejected=%llu sent=%llu received=%llu outputs=%llu output_rejected=%llu sockets_created=%llu sockets_closed=%llu broker_requests=%llu broker_replies=%llu broker_stale=%llu broker_rejected=%llu",
    (unsigned long long)owner->generation, owner->enabled, index, owner->ready, owner->stopped,
    s->sessions, s->input_packets, s->pbufs, (unsigned long long)s->input_accepted,
    (unsigned long long)s->input_rejected, (unsigned long long)s->direct_sent,
    (unsigned long long)s->direct_received, (unsigned long long)s->output_accepted,
    (unsigned long long)s->output_rejected, (unsigned long long)s->sockets_created,
    (unsigned long long)s->sockets_closed, (unsigned long long)owner->broker.requests,
    (unsigned long long)owner->broker.replies, (unsigned long long)owner->broker.stale,
    (unsigned long long)owner->broker.rejected);
  }
  return NULL;
}
VLIB_CLI_COMMAND(product_vpn_flow_stack_status_command, static) = {
  .path = "show product flow-stack", .function = status,
};

static clib_error_t *hold(vlib_main_t *vm, unformat_input_t *input,
                          vlib_cli_command_t *command)
{
  (void)command;
  u32 ms;
  u32 index = 0;
  (void)unformat(input, "owner %u", &index);
  if (!product_vpn_tun_validation_enabled() || !product_vpn_flow_stack_driver_ready() ||
      index >= PRODUCT_VPN_RETURN_WORKERS ||
      !unformat(input, "%u", &ms) || ms > 5000 ||
      unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return(0, "active HEV validation and hold <0..5000 ms> required");
  owners[index].hold_until_ms = ms ? clock_ms() + ms : 0;
  schedule(vlib_get_main_by_index(vlib_get_worker_thread_index(index)));
  vlib_cli_output(vm, "flow_stack.hold owner=%u ms=%u", index, ms);
  return NULL;
}
VLIB_CLI_COMMAND(product_vpn_flow_stack_hold_command, static) = {
  .path = "product flow-stack hold", .function = hold,
};

static clib_error_t *broker_fault(vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *command)
{
  (void)command;
  u32 index, after, operation;
  if (!product_vpn_tun_validation_enabled() || !product_vpn_flow_stack_driver_ready() ||
      !unformat(input, "owner %u", &index) || index >= PRODUCT_VPN_RETURN_WORKERS)
    return clib_error_return(0, "active HEV validation owner required");
  if (unformat(input, "protect after %u", &after)) operation = PRODUCT_VPN_BROKER_ERROR_PROTECT;
  else if (unformat(input, "bind after %u", &after)) operation = PRODUCT_VPN_BROKER_ERROR_BIND;
  else return clib_error_return(0, "expected protect|bind after <1..64>");
  product_vpn_socket_broker_t *broker = &owners[index].broker;
  if (!after || after > 64 || broker->fault_request_at ||
      unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return(0, "one bounded broker fault at a time");
  broker->fault_request_at = broker->requests + after;
  broker->fault_operation = operation;
  vlib_cli_output(vm, "flow_stack.broker_fault owner=%u operation=%u request=%llu generation=%llu",
    index, operation, (unsigned long long)broker->fault_request_at,
    (unsigned long long)broker->generation);
  return NULL;
}
VLIB_CLI_COMMAND(product_vpn_flow_stack_broker_fault_command, static) = {
  .path = "product flow-stack broker-fault", .function = broker_fault,
};
