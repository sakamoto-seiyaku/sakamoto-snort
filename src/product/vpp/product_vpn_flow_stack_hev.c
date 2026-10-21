/* SPDX-License-Identifier: Apache-2.0 */
#include "product_vpn_flow_stack_private.h"
#include "hev-owner.h"
#include <stdlib.h>

struct product_vpn_flow_stack {
  hev_owner_t *owner;
  product_vpn_flow_stack_config_t config;
};

/* Dependency enums do not escape the implementation. Keep this mapping
 * exhaustive; a newly introduced dependency failure needs explicit handling. */
static const product_vpn_flow_stack_fault_t faults[] = {
#define FAULT(name) [HEV_OWNER_FAULT_##name] = PRODUCT_VPN_FLOW_STACK_FAULT_##name
  FAULT(NONE), FAULT(SESSION_CAPACITY), FAULT(PCB_CAPACITY), FAULT(SOCKET_CAPACITY),
  FAULT(PACKET_CREDIT), FAULT(PBUF_CAPACITY), FAULT(ALLOCATION), FAULT(SOCKET_CREATE),
  FAULT(BROKER_SUBMIT), FAULT(BROKER_TIMEOUT), FAULT(PROTECT), FAULT(BIND),
  FAULT(AUTHORIZATION), FAULT(CONNECT_REFUSED), FAULT(NETWORK_UNREACHABLE),
  FAULT(CONNECT), FAULT(SOCKET_IO), FAULT(OUTPUT_CAPACITY), FAULT(OUTPUT_REJECTED),
#undef FAULT
};
_Static_assert(sizeof(faults) / sizeof(faults[0]) == HEV_OWNER_FAULT_COUNT,
               "map every dependency failure");

const char *product_vpn_flow_stack_fault_name(product_vpn_flow_stack_fault_t fault)
{
  static const char *const names[] = {
    "NONE", "SESSION_CAPACITY", "PCB_CAPACITY", "SOCKET_CAPACITY", "PACKET_CREDIT",
    "PBUF_CAPACITY", "ALLOCATION", "SOCKET_CREATE", "BROKER_SUBMIT", "BROKER_TIMEOUT",
    "PROTECT", "BIND", "AUTHORIZATION", "CONNECT_REFUSED", "NETWORK_UNREACHABLE",
    "CONNECT", "SOCKET_IO", "OUTPUT_CAPACITY", "OUTPUT_REJECTED",
  };
  _Static_assert(sizeof(names) / sizeof(names[0]) == PRODUCT_VPN_FLOW_STACK_FAULT_COUNT,
                 "name every Product failure");
  return (unsigned)fault < PRODUCT_VPN_FLOW_STACK_FAULT_COUNT ? names[fault] : "UNKNOWN";
}

static hev_owner_output_result_t output(void *opaque,
  const hev_owner_span_t *spans, unsigned count, size_t total,
  const hev_owner_facts_t *facts, uint64_t generation, uint64_t serial)
{
  product_vpn_flow_stack_t *stack = opaque;
  product_vpn_flow_stack_span_t borrowed[64];
  if (count > 64) return HEV_OWNER_OUTPUT_REJECTED;
  for (unsigned i = 0; i < count; ++i)
    borrowed[i] = (product_vpn_flow_stack_span_t){spans[i].data, spans[i].length};
  product_platform_packet_facts_t platform = {
    .uid = facts->uid, .network_context_id = facts->network_context,
    .direction = PRODUCT_PACKET_DIRECTION_INPUT,
    .provenance = PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN,
  };
  if (facts->availability & HEV_OWNER_UID_KNOWN)
    platform.availability |= PRODUCT_PLATFORM_UID_KNOWN;
  if (facts->availability & HEV_OWNER_CONTEXT_KNOWN)
    platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
  switch (stack->config.output(stack->config.opaque, borrowed, count, total,
                              &platform, generation, serial, facts->underlay_epoch,
                              facts->flow_incarnation)) {
  case PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED: return HEV_OWNER_OUTPUT_ACCEPTED;
  case PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY: return HEV_OWNER_OUTPUT_NO_MEMORY;
  default: return HEV_OWNER_OUTPUT_REJECTED;
  }
}

static int broker(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  product_vpn_flow_stack_t *stack = opaque;
  return stack->config.broker(stack->config.opaque, generation, session, fd);
}

static void trace(void *opaque, const hev_owner_event_t *event)
{
  product_vpn_flow_stack_t *stack = opaque;
  if (stack->config.trace)
    stack->config.trace(stack->config.opaque, event->event, event->serial,
      event->session, event->object, event->bytes, event->result, event->kind);
}

product_vpn_flow_stack_t *product_vpn_flow_stack_create(
  const product_vpn_flow_stack_config_t *config)
{
  if (!config || !config->output || !config->broker) return NULL;
  product_vpn_flow_stack_t *stack = calloc(1, sizeof(*stack));
  if (!stack) return NULL;
  stack->config = *config;
  hev_owner_config_t dependency = {
    .generation = config->generation, .owner_index = config->owner_index,
    .max_sessions = config->max_sessions, .max_input_packets = config->max_input_packets,
    .max_pcbs = config->max_pcbs, .max_sockets = config->max_sockets,
    .max_pbufs = config->max_pbufs, .max_packet_bytes = config->max_packet_bytes,
    .task_stack_bytes = config->task_stack_bytes,
    .broker_timeout_ms = config->broker_timeout_ms,
    .udp_idle_timeout_ms = config->idle_timeout_ms,
    .output = output, .broker = broker, .trace = trace, .opaque = stack,
  };
  stack->owner = hev_owner_create(&dependency);
  if (!stack->owner) { free(stack); return NULL; }
  return stack;
}

product_vpn_flow_stack_input_result_t product_vpn_flow_stack_input_copy(
  product_vpn_flow_stack_t *stack, const uint8_t *l3, size_t length,
  const product_platform_packet_facts_t *platform, uint64_t generation,
  uint64_t flow_incarnation)
{
  if (!stack || !platform) return PRODUCT_VPN_FLOW_STACK_FAILED;
  if (platform->provenance != PRODUCT_PACKET_PROVENANCE_VPN_TUN ||
      platform->direction != PRODUCT_PACKET_DIRECTION_OUTPUT)
    return PRODUCT_VPN_FLOW_STACK_UNSUPPORTED;
  hev_owner_facts_t facts = {.uid = platform->uid,
    .flow_incarnation = flow_incarnation};
  if (platform->availability & PRODUCT_PLATFORM_UID_KNOWN)
    facts.availability |= HEV_OWNER_UID_KNOWN;
  switch (hev_owner_input_copy(stack->owner, l3, length, &facts, generation)) {
  case HEV_OWNER_INPUT_ACCEPTED: return PRODUCT_VPN_FLOW_STACK_ACCEPTED;
  case HEV_OWNER_INPUT_NO_CAPACITY: return PRODUCT_VPN_FLOW_STACK_NO_CAPACITY;
  case HEV_OWNER_INPUT_UNSUPPORTED: return PRODUCT_VPN_FLOW_STACK_UNSUPPORTED;
  case HEV_OWNER_INPUT_NOT_RUNNING: return PRODUCT_VPN_FLOW_STACK_NOT_RUNNING;
  case HEV_OWNER_INPUT_WRONG_GENERATION: return PRODUCT_VPN_FLOW_STACK_INVALID_GENERATION;
  default: return PRODUCT_VPN_FLOW_STACK_FAILED;
  }
}

product_vpn_flow_stack_step_result_t product_vpn_flow_stack_step(
  product_vpn_flow_stack_t *stack, uint32_t quanta, uint32_t max_us)
{
  if (!stack) return (product_vpn_flow_stack_step_result_t){.timeout_ms = -1};
  hev_owner_step_result_t r = hev_owner_step(stack->owner, quanta, max_us);
  return (product_vpn_flow_stack_step_result_t){r.quanta, r.runnable, r.timeout_ms, r.stopped};
}

void product_vpn_flow_stack_quiesce(product_vpn_flow_stack_t *stack)
{ if (stack) hev_owner_quiesce(stack->owner); }

int product_vpn_flow_stack_close(product_vpn_flow_stack_t *stack)
{
  if (!stack || hev_owner_destroy(stack->owner)) return -1;
  free(stack);
  return 0;
}

int product_vpn_flow_stack_poll_fd(const product_vpn_flow_stack_t *stack)
{ return stack ? hev_owner_poll_fd(stack->owner) : -1; }

int product_vpn_flow_stack_broker_complete(product_vpn_flow_stack_t *stack,
  uint64_t generation, uint64_t session, unsigned error, uint64_t epoch,
  uint32_t context, int context_known)
{
  if (!stack || (context_known != 0 && context_known != 1)) return -1;
  const hev_owner_binding_t binding = {epoch, context, (uint8_t)context_known};
  return hev_owner_broker_result(stack->owner, generation, session, error, &binding);
}

int product_vpn_flow_stack_invalidate_underlay(product_vpn_flow_stack_t *stack,
  uint64_t generation, uint64_t epoch)
{ return stack ? hev_owner_invalidate_underlay(stack->owner, generation, epoch) : -1; }

product_vpn_flow_stack_snapshot_t product_vpn_flow_stack_snapshot(
  const product_vpn_flow_stack_t *stack)
{
  product_vpn_flow_stack_snapshot_t result = {0};
  if (!stack) return result;
  hev_owner_snapshot_t s = hev_owner_snapshot(stack->owner);
#define COPY(field) result.field = s.field
  COPY(input_accepted); COPY(input_rejected); COPY(input_copy_calls); COPY(input_copy_bytes);
  COPY(output_accepted); COPY(output_rejected);
  COPY(sessions_created); COPY(sessions_closed); COPY(sockets_created); COPY(sockets_closed);
  COPY(direct_sent); COPY(direct_received); COPY(broker_requested); COPY(broker_completed);
  COPY(udp_send_calls); COPY(udp_send_requested); COPY(udp_send_datagrams);
  COPY(udp_send_partial); COPY(udp_send_blocked); COPY(udp_send_max);
  COPY(tcp_rx_rounds); COPY(tcp_read_calls); COPY(tcp_read_blocked);
  COPY(tcp_commits); COPY(tcp_commit_bytes); COPY(tcp_write_blocked);
  COPY(tcp_output_calls); COPY(tcp_commit_max);
  COPY(sessions); COPY(input_packets); COPY(pbufs); COPY(pbuf_peak); COPY(running); COPY(stopped);
  COPY(pcbs); COPY(pcb_peak); COPY(sockets); COPY(socket_peak); COPY(input_pbufs);
  COPY(pcb_allocations); COPY(pcb_frees);
  COPY(fault_count); COPY(first_fault_ms); COPY(last_fault_ms); COPY(last_fault_session);
  COPY(last_fault_error);
  for (unsigned i = 0; i < HEV_OWNER_FAULT_COUNT; ++i)
    result.faults[faults[i]] = s.faults[i];
  result.last_fault = s.last_fault < HEV_OWNER_FAULT_COUNT
    ? faults[s.last_fault] : PRODUCT_VPN_FLOW_STACK_FAULT_NONE;
#undef COPY
  return result;
}
