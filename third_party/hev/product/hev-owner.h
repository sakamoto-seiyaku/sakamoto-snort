/* SPDX-License-Identifier: MIT */
#ifndef SAKAMOTO_HEV_OWNER_H
#define SAKAMOTO_HEV_OWNER_H

#include <stddef.h>
#include <stdint.h>

/* Dependency-private interface. Product callers use product_vpn_flow_stack.h;
 * only its HEV implementation sees this header or the socket broker hook. */
typedef struct hev_owner hev_owner_t;

enum { HEV_OWNER_UID_KNOWN = 1, HEV_OWNER_CONTEXT_KNOWN = 2, HEV_OWNER_LOCAL_UDP = 4, HEV_OWNER_LOCAL_TCP = 8 };
typedef struct {
  uint32_t uid;
  uint32_t network_context;
  uint64_t underlay_epoch;
  uint64_t flow_incarnation; /* admitted Product flow, zero if unavailable */
  uint64_t local_reply_token; /* Local TCP DNS frame, zero for ordinary output. */
  uint64_t transport_session; /* Exact owner-local session; never an App ID. */
  uint8_t availability;
} hev_owner_facts_t;

/* A successful bind/protect result identifies its actual binding. Network
 * classification may still be unavailable; success must not imply known. */
typedef struct {
  uint64_t underlay_epoch;
  uint32_t network_context;
  uint8_t context_known;
} hev_owner_binding_t;

typedef struct {
  uint64_t session, underlay_epoch;
  uint32_t network_context;
  uint8_t context_known;
} hev_owner_input_context_t;

typedef struct {
  const uint8_t *data;
  size_t length;
} hev_owner_span_t;

typedef enum {
  HEV_OWNER_INPUT_ACCEPTED = 0,
  HEV_OWNER_INPUT_NO_CAPACITY,
  HEV_OWNER_INPUT_UNSUPPORTED,
  HEV_OWNER_INPUT_NOT_RUNNING,
  HEV_OWNER_INPUT_WRONG_GENERATION,
  HEV_OWNER_INPUT_FAILED,
} hev_owner_input_result_t;

typedef enum {
  HEV_OWNER_OUTPUT_ACCEPTED = 0,
  HEV_OWNER_OUTPUT_NO_MEMORY,
  HEV_OWNER_OUTPUT_REJECTED,
} hev_owner_output_result_t;

/* Execution failures, never policy decisions or delivery acknowledgements.
 * Counters are owner-local and retained for this generation, including after
 * recovery. A packet-resource failure does not close its transport session. */
typedef enum {
  HEV_OWNER_FAULT_NONE,
  HEV_OWNER_FAULT_SESSION_CAPACITY,
  HEV_OWNER_FAULT_PCB_CAPACITY,
  HEV_OWNER_FAULT_SOCKET_CAPACITY,
  HEV_OWNER_FAULT_PACKET_CREDIT,
  HEV_OWNER_FAULT_PBUF_CAPACITY,
  HEV_OWNER_FAULT_ALLOCATION,
  HEV_OWNER_FAULT_SOCKET_CREATE,
  HEV_OWNER_FAULT_BROKER_SUBMIT,
  HEV_OWNER_FAULT_BROKER_TIMEOUT,
  HEV_OWNER_FAULT_PROTECT,
  HEV_OWNER_FAULT_BIND,
  HEV_OWNER_FAULT_AUTHORIZATION,
  HEV_OWNER_FAULT_CONNECT_REFUSED,
  HEV_OWNER_FAULT_NETWORK_UNREACHABLE,
  HEV_OWNER_FAULT_CONNECT,
  HEV_OWNER_FAULT_SOCKET_IO,
  HEV_OWNER_FAULT_OUTPUT_CAPACITY,
  HEV_OWNER_FAULT_OUTPUT_REJECTED,
  HEV_OWNER_FAULT_COUNT,
} hev_owner_fault_t;

/* Output borrows all spans only until the callback returns. Acceptance means
 * the receiver owns an independent copy, never that delivery has completed. */
typedef hev_owner_output_result_t (*hev_owner_output_fn) (
  void *opaque, const hev_owner_span_t *spans, unsigned count, size_t total,
  const hev_owner_facts_t *facts, uint64_t generation, uint64_t output_serial);

/* Nonblocking request only. A zero result means a descriptor duplicate was
 * submitted; the original fd stays in its HEV session until owner teardown.
 * Completion is delivered separately on the same owner via broker_complete. */
typedef int (*hev_owner_broker_fn) (void *opaque, uint64_t generation,
                                   uint64_t session, int fd);

typedef struct {
  const char *event;
  uint64_t serial;
  uint64_t session;
  uintptr_t object;
  size_t bytes;
  int result;
  unsigned kind;
} hev_owner_event_t;
typedef void (*hev_owner_trace_fn) (void *opaque, const hev_owner_event_t *event);

typedef struct {
  uint64_t generation;
  uint32_t owner_index;
  uint32_t max_sessions;
  /* Zero selects max_sessions+2 PCBs (including two listeners), and
   * max_sessions sockets. Fixed before admission, not live resize knobs. */
  uint32_t max_pcbs, max_sockets;
  uint32_t max_input_packets;
  uint32_t max_pbufs;
  uint32_t max_packet_bytes;
  uint32_t task_stack_bytes;
  uint32_t broker_timeout_ms;
  uint32_t udp_idle_timeout_ms;
  hev_owner_output_fn output;
  hev_owner_broker_fn broker;
  /* Synchronous complete datagram borrow; callback must not reenter owner. */
  void (*local_udp)(void *, uint64_t generation, uint64_t session, const uint8_t *, size_t);
  void (*local_tcp_done)(void *, uint64_t generation, uint64_t session, uint64_t token, int success);
  void (*local_close)(void *, uint64_t generation, uint64_t session);
  hev_owner_trace_fn trace;
  void *opaque;
} hev_owner_config_t;

typedef struct {
  uint64_t input_calls, input_accepted, input_rejected;
  uint64_t input_copy_calls, input_copy_bytes;
  uint64_t output_calls, output_accepted, output_rejected;
  uint64_t sessions_created, sessions_closed, sockets_created, sockets_closed;
  uint64_t direct_sent, direct_received, broker_requested, broker_completed;
  uint64_t udp_send_calls, udp_send_requested, udp_send_datagrams;
  uint64_t udp_send_partial, udp_send_blocked, udp_send_max;
  uint64_t tcp_rx_rounds, tcp_read_calls, tcp_read_blocked;
  uint64_t tcp_read_eagain, tcp_read_eintr, tcp_read_eof;
  uint64_t tcp_commits, tcp_commit_bytes, tcp_write_blocked, tcp_output_calls;
  uint64_t tcp_commit_max;
  /* Observations at Direct receive-round entry, not time-weighted occupancy. */
  uint64_t tcp_idle_rounds, tcp_ring_full, tcp_sndbuf_full;
  uint64_t tcp_window_full, tcp_cwnd_full, tcp_pending_rounds;
  uint64_t tcp_ring_peak, tcp_pending_peak, tcp_flight_peak;
  uint32_t tcp_mss_min, tcp_mss_max, tcp_buffer_bytes;
  uint64_t tcp_interest_changes, tcp_read_pauses, tcp_read_resumes;
  /* Opt-in TCP wait diagnostics. Reasons: runnable, upstream, inner_ack,
   * memory, upload, eof, other. Origins: continue, io, ack, recv, poll,
   * timer, other, start. Times sum session wall intervals, never CPU time. */
  uint64_t tcp_yields[7], tcp_wait_ns[7], tcp_ready_ns[7];
  uint64_t tcp_resume_rounds[8], tcp_resume_idle[8];
  uint64_t scheduler_io_polls, scheduler_io_events;
  uint64_t task_quanta, steps, wrong_owner, stale_generation;
  uint32_t sessions, input_packets, input_peak, pbufs, pbuf_peak;
  uint32_t local_udp_sessions, local_udp_peak;
  uint32_t local_tcp_sessions, local_tcp_peak, local_tcp_pending, local_tcp_outputs;
  uint32_t local_tcp_pending_peak, local_tcp_output_peak;
  uint64_t local_tcp_bytes, local_tcp_peak_bytes, local_tcp_frames, local_tcp_delivered, local_tcp_failed;
  uint32_t pcbs, pcb_peak, sockets, socket_peak, input_pbufs;
  uint64_t pcb_allocations, pcb_frees;
  uint64_t faults[HEV_OWNER_FAULT_COUNT];
  uint64_t fault_count, first_fault_ms, last_fault_ms, last_fault_session;
  unsigned last_fault;
  int last_fault_error;
  uint64_t pool_allocations, pool_frees, ram_allocations, ram_frees;
  uint64_t ref_allocations, ref_frees;
  uint32_t pool_live, ram_live, ref_live;
  uint64_t lwip_heap_allocations, lwip_heap_frees;
  size_t lwip_heap_live, lwip_heap_bytes, lwip_heap_peak_bytes;
  uint8_t running, stopped;
} hev_owner_snapshot_t;

typedef struct {
  uint32_t quanta;
  uint32_t runnable;
  int timeout_ms; /* -1 means no HEV timer; not a FlowRuntime CT deadline. */
  uint8_t stopped;
} hev_owner_step_result_t;

/* Allocate/configure before admission. The first operational call binds the
 * thread; callers must serialize this initial handoff. All later calls,
 * including snapshots/close, execute on that thread. No callback may reenter
 * owner operations. Broker callbacks only submit; completion is a later call.
 * Mutable task/PCB state belongs to this owner, never a shared scheduler.
 * Known UID mismatch closes the old transport and rejects the trigger packet;
 * the tuple remains unavailable until task cleanup, then a later packet creates
 * a new session requiring a fresh broker result. Unknown is not a mismatch. */
hev_owner_t *hev_owner_create (const hev_owner_config_t *config);
hev_owner_input_result_t hev_owner_input_copy (
  hev_owner_t *owner, const uint8_t *l3, size_t length,
  const hev_owner_facts_t *facts, uint64_t generation);
/* Synchronous result of this exact admitted UDP input, before any broker wait. */
hev_owner_input_result_t hev_owner_input_copy_context (
  hev_owner_t *owner, const uint8_t *l3, size_t length,
  const hev_owner_facts_t *facts, uint64_t generation, hev_owner_input_context_t *context);
uint64_t hev_owner_local_udp_reservation(const hev_owner_t *);
int hev_owner_local_udp_reply(hev_owner_t *, uint64_t generation, uint64_t session,
  const uint8_t *, size_t);
int hev_owner_local_udp_reply_context(hev_owner_t *, uint64_t generation, uint64_t session,
  const uint8_t *, size_t, const hev_owner_binding_t *);
/* Owner-local byte-stream endpoint. Complete frames are copied out only after
 * input/step has returned, so callbacks never reenter HEV. Every frame gets an
 * independent generation/session/token; DNS IDs carry no transport authority. */
#define HEV_OWNER_LOCAL_TCP_CLIENTS 8U
#define HEV_OWNER_LOCAL_TCP_PENDING 128U
#define HEV_OWNER_LOCAL_TCP_BYTES (2U * 1024U * 1024U)
#define HEV_OWNER_LOCAL_TCP_INLINE_BYTES 512U
int hev_owner_local_tcp_next(hev_owner_t *, uint64_t generation, uint64_t *session,
  uint64_t *token, uint8_t *message, size_t capacity, size_t *length);
/* 0=queued, -1=stale/closed/invalid, -2=output resource shortage; -2 keeps
 * the exact pending token for a small fallback. Inline storage is budgeted. */
int hev_owner_local_tcp_reply(hev_owner_t *, uint64_t generation, uint64_t session,
  uint64_t token, const uint8_t *, size_t, const hev_owner_binding_t *);
int hev_owner_local_tcp_abandon(hev_owner_t *, uint64_t generation, uint64_t session, uint64_t token);
uint64_t hev_owner_local_tcp_reservation(const hev_owner_t *);
hev_owner_step_result_t hev_owner_step (hev_owner_t *owner,
                                       uint32_t quanta, uint32_t max_us);
int hev_owner_broker_complete (hev_owner_t *owner, uint64_t generation,
                               uint64_t session, int success,
                               const hev_owner_binding_t *binding);
/* Same completion with the private broker's operation error preserved:
 * 2=protect, 3=bind, 4=authorization, 5=no underlay. Zero requires a nonzero
 * binding epoch. Epoch invalidations share the ordered broker control channel. */
int hev_owner_broker_result (hev_owner_t *owner, uint64_t generation,
                             uint64_t session, unsigned error,
                             const hev_owner_binding_t *binding);
/* Only the owner mutates sessions. Closes the matching bound epoch before
 * further input/I/O; task cleanup frees PCB/socket/queues. The same tuple can
 * subsequently create a new session. Does not mutate VPP FlowEntry state. */
int hev_owner_invalidate_underlay (hev_owner_t *owner, uint64_t generation,
                                   uint64_t epoch);
void hev_owner_quiesce (hev_owner_t *owner);
/* Close storage only after stopped and all accepted callback work has drained. */
int hev_owner_destroy (hev_owner_t *owner);
hev_owner_snapshot_t hev_owner_snapshot (const hev_owner_t *owner);
int hev_owner_poll_fd (const hev_owner_t *owner);
const char *hev_owner_upstream_revision (void);

#endif
