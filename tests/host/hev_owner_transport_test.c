/* SPDX-License-Identifier: MIT */
#include "hev-owner.h"
#include "lwip/inet_chksum.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Actual HEV owner/session/lwIP and UDP endpoint. Broker is deliberately a
 * request recorder: no Android bind/protect or VPP delivery claim. */
typedef struct {
  uint64_t generation, session;
  int original_fd;
  unsigned requests, outputs, conflicts;
  hev_owner_facts_t returned;
  hev_owner_output_result_t output_result;
} fixture_t;

static int broker(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  fixture_t *f = opaque;
  struct sockaddr_in peer;
  socklen_t size = sizeof(peer);
  assert(getpeername(fd, (struct sockaddr *)&peer, &size) == -1 && errno == ENOTCONN);
  assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
  f->generation = generation; f->session = session; f->original_fd = fd;
  ++f->requests;
  return 0;
}

static hev_owner_output_result_t output(void *opaque, const hev_owner_span_t *spans,
    unsigned count, size_t total, const hev_owner_facts_t *facts,
    uint64_t generation, uint64_t serial)
{
  fixture_t *f = opaque;
  unsigned char packet[64];
  size_t offset = 0;
  assert(generation == 7 && serial && total == 29);
  for (unsigned i = 0; i < count; ++i) {
    assert(spans[i].length <= sizeof(packet) - offset);
    memcpy(packet + offset, spans[i].data, spans[i].length);
    offset += spans[i].length;
  }
  assert(offset == total && packet[28] == 42 && packet[9] == 17);
  f->returned = *facts;
  ++f->outputs;
  return f->output_result;
}

static void trace(void *opaque, const hev_owner_event_t *event)
{
  fixture_t *f = opaque;
  if (!strcmp(event->event, "uid_conflict")) ++f->conflicts;
}

static hev_owner_input_result_t inject_incarnation(hev_owner_t *owner, uint16_t port,
                                      uint32_t uid, int known, uint64_t incarnation)
{
  unsigned char packet[29] = {
    0x45, 0, 0, 29, 0, 1, 0, 0, 64, 17, 0, 0,
    10, 0, 0, 2, 127, 0, 0, 1,
    0x30, 0x39, 0, 0, 0, 9, 0, 0, 42
  };
  packet[22] = port >> 8; packet[23] = port;
  uint16_t checksum = inet_chksum(packet, 20);
  memcpy(packet + 10, &checksum, 2);
  hev_owner_facts_t facts = {.uid = uid,
    .flow_incarnation = incarnation,
    .availability = known ? HEV_OWNER_UID_KNOWN : 0};
  return hev_owner_input_copy(owner, packet, sizeof(packet), &facts, 7);
}

static hev_owner_input_result_t inject(hev_owner_t *owner, uint16_t port,
                                      uint32_t uid, int known)
{ return inject_incarnation(owner, port, uid, known, 0); }

static void step(hev_owner_t *owner)
{
  hev_owner_step_result_t result = hev_owner_step(owner, 4, 10000);
  assert(result.quanta <= 4);
}

static void echo(hev_owner_t *owner, int endpoint, int transport_fd)
{
  step(owner);
  struct pollfd ready = {.fd = endpoint, .events = POLLIN};
  assert(poll(&ready, 1, 1000) == 1);
  struct sockaddr_in peer;
  socklen_t size = sizeof(peer);
  unsigned char data;
  assert(recvfrom(endpoint, &data, 1, 0, (struct sockaddr *)&peer, &size) == 1);
  assert(data == 42);
  assert(sendto(endpoint, &data, 1, 0, (struct sockaddr *)&peer, size) == 1);
  /* Reactor readiness can still be an earlier EPOLLOUT edge. Wait for the
   * actual return datagram, not an unrelated event, before this assertion. */
  ready.fd = transport_fd;
  assert(poll(&ready, 1, 1000) == 1);
  step(owner);
}

int main(void)
{
  alarm(5);
  int endpoint = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(endpoint >= 0);
  struct sockaddr_in address = {.sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  assert(!bind(endpoint, (struct sockaddr *)&address, sizeof(address)));
  socklen_t size = sizeof(address);
  assert(!getsockname(endpoint, (struct sockaddr *)&address, &size));
  uint16_t port = ntohs(address.sin_port);
  fixture_t f = {0};
  const hev_owner_binding_t binding = {.underlay_epoch = 12,
    .network_context = 2, .context_known = 1};
  const hev_owner_binding_t unknown_binding = {.underlay_epoch = 13};
  hev_owner_config_t config = {.generation = 7, .max_sessions = 2,
    .max_input_packets = 2, .max_pbufs = 16, .max_packet_bytes = 1500,
    .task_stack_bytes = 32768, .broker_timeout_ms = 1000,
    .udp_idle_timeout_ms = 1000, .output = output, .broker = broker,
    .trace = trace, .opaque = &f};
  hev_owner_t *owner = hev_owner_create(&config);
  assert(owner);
  assert(inject(owner, port, 10001, 1) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(f.requests == 1 && !hev_owner_snapshot(owner).direct_sent);
  uint64_t first = f.session;
  int first_fd = f.original_fd;
  assert(inject(owner, port, 10001, 1) == HEV_OWNER_INPUT_ACCEPTED);
  assert(hev_owner_snapshot(owner).input_packets == config.max_input_packets);
  /* Pending authorization must not connect/send. Conflicting packet closes
   * that session even with a full input queue; another packet cannot replace
   * it before task cleanup. */
  assert(inject(owner, port, 10002, 1) == HEV_OWNER_INPUT_FAILED);
  assert(f.conflicts == 1);
  assert(inject(owner, port, 10002, 1) == HEV_OWNER_INPUT_FAILED);
  assert(hev_owner_broker_complete(owner, 7, first, 1, &binding) == -1);
  step(owner);
  assert(fcntl(first_fd, F_GETFD) == -1 && errno == EBADF);
  hev_owner_snapshot_t snapshot = hev_owner_snapshot(owner);
  assert(!snapshot.sessions && !snapshot.input_packets && !snapshot.pbufs);
  assert(snapshot.direct_sent == 0 && snapshot.sockets_closed == 1);
  assert(inject(owner, port, 10002, 1) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(f.requests == 2 && f.session != first);
  assert(hev_owner_broker_complete(owner, 7, first, 1, &binding) == -1);
  assert(!hev_owner_broker_complete(owner, 7, f.session, 1, &binding));
  echo(owner, endpoint, f.original_fd);
  assert(f.outputs == 1 && f.returned.uid == 10002);
  assert(f.returned.underlay_epoch == 12 && f.returned.network_context == 2);
  uint64_t second = f.session;
  /* Unknown input does not conflict or erase the reliable session UID. */
  f.output_result = HEV_OWNER_OUTPUT_NO_MEMORY;
  assert(inject(owner, port, 999, 0) == HEV_OWNER_INPUT_ACCEPTED);
  echo(owner, endpoint, f.original_fd);
  f.output_result = HEV_OWNER_OUTPUT_ACCEPTED;
  assert(inject(owner, port, 10002, 1) == HEV_OWNER_INPUT_ACCEPTED);
  echo(owner, endpoint, f.original_fd);
  assert(f.outputs == 3 && f.returned.uid == 10002 && f.session == second);
  /* Connected conflict: no queued input may be sent after the close gate. */
  int second_fd = f.original_fd;
  assert(inject(owner, port, 10002, 1) == HEV_OWNER_INPUT_ACCEPTED);
  assert(inject(owner, port, 10003, 1) == HEV_OWNER_INPUT_FAILED);
  step(owner);
  assert(f.conflicts == 2 && fcntl(second_fd, F_GETFD) == -1 && errno == EBADF);
  unsigned char byte;
  assert(recv(endpoint, &byte, 1, 0) == -1 && errno == EAGAIN);
  assert(inject(owner, port, 10003, 1) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(f.requests == 3 && f.session != second);
  assert(!hev_owner_broker_complete(owner, 7, f.session, 1, &unknown_binding));
  echo(owner, endpoint, f.original_fd);
  assert(f.outputs == 4 && f.returned.uid == 10003);
  assert(f.returned.underlay_epoch == 13 &&
         !(f.returned.availability & HEV_OWNER_CONTEXT_KNOWN));
  assert(inject(owner, port, 10003, 1) == HEV_OWNER_INPUT_ACCEPTED);
  hev_owner_quiesce(owner);
  step(owner);
  snapshot = hev_owner_snapshot(owner);
  assert(snapshot.stopped && !snapshot.sessions && !snapshot.pbufs);
  assert(!snapshot.input_packets && snapshot.direct_sent == 4);
  assert(snapshot.sessions_created == snapshot.sessions_closed);
  assert(snapshot.sockets_created == snapshot.sockets_closed);
  assert(snapshot.lwip_heap_live == 2); /* owner UDP and TCP listeners remain */
  assert(!hev_owner_destroy(owner));
  /* The Product owner retires its UDP socket before the shortest VPP UDP
   * FlowEntry timeout. A same-UID packet with the next full-width flow
   * incarnation must create a fresh session on that triggering packet. */
  fixture_t rollover = {0};
  config.opaque = &rollover;
  config.udp_idle_timeout_ms = 50;
  owner = hev_owner_create(&config);
  assert(owner);
  assert(inject_incarnation(owner, port, 10001, 1,
                            UINT64_C(0x100000001)) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(rollover.requests == 1);
  assert(!hev_owner_broker_complete(owner, 7, rollover.session, 1, &binding));
  echo(owner, endpoint, rollover.original_fd);
  assert(rollover.returned.flow_incarnation == UINT64_C(0x100000001));
  usleep(80000);
  for (unsigned attempt = 0; attempt < 8 && hev_owner_snapshot(owner).sessions; ++attempt)
    step(owner);
  assert(!hev_owner_snapshot(owner).sessions);
  assert(inject_incarnation(owner, port, 10001, 1,
                            UINT64_C(0x100000002)) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(rollover.requests == 2);
  assert(!hev_owner_broker_complete(owner, 7, rollover.session, 1, &binding));
  echo(owner, endpoint, rollover.original_fd);
  assert(rollover.returned.flow_incarnation == UINT64_C(0x100000002));
  hev_owner_quiesce(owner);
  step(owner);
  assert(!hev_owner_snapshot(owner).sessions);
  assert(!hev_owner_destroy(owner));
  /* If an overdue old transport is still live when VPP opens the next
   * FlowEntry, the trigger is rejected once; after bounded cleanup the next
   * datagram creates a new session. Old outputs retain their old lineage. */
  fixture_t delayed = {0};
  config.opaque = &delayed;
  config.udp_idle_timeout_ms = 1000;
  owner = hev_owner_create(&config);
  assert(owner);
  assert(inject_incarnation(owner, port, 10001, 1,
                            UINT64_C(0x100000003)) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(!hev_owner_broker_complete(owner, 7, delayed.session, 1, &binding));
  echo(owner, endpoint, delayed.original_fd);
  assert(delayed.returned.flow_incarnation == UINT64_C(0x100000003));
  assert(inject_incarnation(owner, port, 10001, 1,
                            UINT64_C(0x100000004)) == HEV_OWNER_INPUT_FAILED);
  step(owner);
  assert(!hev_owner_snapshot(owner).sessions);
  assert(inject_incarnation(owner, port, 10001, 1,
                            UINT64_C(0x100000004)) == HEV_OWNER_INPUT_ACCEPTED);
  step(owner);
  assert(delayed.requests == 2);
  assert(!hev_owner_broker_complete(owner, 7, delayed.session, 1, &binding));
  echo(owner, endpoint, delayed.original_fd);
  assert(delayed.returned.flow_incarnation == UINT64_C(0x100000004));
  hev_owner_quiesce(owner);
  step(owner);
  assert(!hev_owner_snapshot(owner).sessions);
  assert(!hev_owner_destroy(owner));
  close(endpoint);
  return 0;
}
