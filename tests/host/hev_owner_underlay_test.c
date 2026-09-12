/* SPDX-License-Identifier: MIT */
#include "hev-owner.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Real HEV/lwIP and kernel UDP sockets. Android authorization is only a
 * completion recorder here; actual Android network changes require Pixel. */
typedef struct {
  hev_owner_t *owner;
  uint64_t generation, sessions[8];
  int descriptors[8], family;
  uint16_t port;
  unsigned requests, outputs, invalidated;
  uint8_t bytes[16];
  uint64_t epochs[16];
} fixture_t;

static uint16_t read16(const uint8_t *p) { return (uint16_t)p[0] << 8 | p[1]; }
static void put16(uint8_t *p, uint16_t n) { p[0] = n >> 8; p[1] = n; }
static uint32_t sum(const uint8_t *p, size_t n)
{
  uint32_t value = 0;
  for (; n > 1; n -= 2, p += 2) value += read16(p);
  return value + (n ? (uint32_t)*p << 8 : 0);
}
static uint16_t checksum(uint32_t value)
{
  while (value >> 16) value = (value & 65535) + (value >> 16);
  return (uint16_t)~value;
}
static int broker(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  fixture_t *f = opaque;
  struct sockaddr_storage address;
  socklen_t size = sizeof(address);
  assert(generation == f->generation && session && f->requests < 8);
  assert(getpeername(fd, (struct sockaddr *)&address, &size) == -1 && errno == ENOTCONN);
  f->sessions[f->requests] = session;
  f->descriptors[f->requests++] = fd;
  return 0;
}
static hev_owner_output_result_t output(void *opaque, const hev_owner_span_t *spans,
  unsigned count, size_t total, const hev_owner_facts_t *facts,
  uint64_t generation, uint64_t serial)
{
  fixture_t *f = opaque;
  uint8_t packet[64];
  size_t offset = 0;
  assert(generation == f->generation && serial && total <= sizeof(packet) && f->outputs < 16);
  for (unsigned i = 0; i < count; ++i) {
    assert(spans[i].length <= total - offset);
    memcpy(packet + offset, spans[i].data, spans[i].length);
    offset += spans[i].length;
  }
  assert(offset == total && total == (f->family == 6 ? 49U : 29U));
  assert(facts->uid == 10001 && facts->availability == 3);
  assert(packet[total - 1] != 98 && packet[total - 1] != 99);
  f->bytes[f->outputs] = packet[total - 1];
  f->epochs[f->outputs++] = facts->underlay_epoch;
  return HEV_OWNER_OUTPUT_ACCEPTED;
}
static void trace(void *opaque, const hev_owner_event_t *event)
{
  fixture_t *f = opaque;
  if (!strcmp(event->event, "underlay_invalidated")) ++f->invalidated;
}
static hev_owner_input_result_t inject(fixture_t *f, uint16_t source, uint8_t byte)
{
  uint8_t packet[49] = {0};
  unsigned ip = f->family == 6 ? 40 : 20, total = ip + 9;
  uint32_t pseudo;
  if (f->family == 6) {
    packet[0] = 0x60; packet[5] = 9; packet[6] = 17; packet[7] = 64;
    assert(inet_pton(AF_INET6, "fd00::2", packet + 8) == 1);
    assert(inet_pton(AF_INET6, "::1", packet + 24) == 1);
    pseudo = sum(packet + 8, 32) + 26;
  } else {
    packet[0] = 0x45; packet[3] = total; packet[8] = 64; packet[9] = 17;
    assert(inet_pton(AF_INET, "10.0.0.2", packet + 12) == 1);
    assert(inet_pton(AF_INET, "127.0.0.1", packet + 16) == 1);
    put16(packet + 10, checksum(sum(packet, 20)));
    pseudo = sum(packet + 12, 8) + 26;
  }
  put16(packet + ip, source); put16(packet + ip + 2, f->port);
  put16(packet + ip + 4, 9); packet[ip + 8] = byte;
  uint16_t check = checksum(pseudo + sum(packet + ip, 9));
  put16(packet + ip + 6, check ? check : 65535);
  hev_owner_facts_t facts = {.uid = 10001, .availability = HEV_OWNER_UID_KNOWN};
  return hev_owner_input_copy(f->owner, packet, total, &facts, f->generation);
}
static void step(fixture_t *f)
{ assert(hev_owner_step(f->owner, 16, 10000).quanta <= 16); }
static void authorize(fixture_t *f, unsigned request, uint64_t epoch)
{
  hev_owner_binding_t binding = {epoch, 2, 1};
  assert(!hev_owner_broker_complete(f->owner, f->generation, f->sessions[request], 1, &binding));
}
static void echo(fixture_t *f, int endpoint, unsigned count)
{
  step(f);
  for (unsigned i = 0; i < count; ++i) {
    struct pollfd fd = {endpoint, POLLIN, 0};
    assert(poll(&fd, 1, 1000) == 1);
    uint8_t byte;
    struct sockaddr_storage peer;
    socklen_t size = sizeof(peer);
    assert(recvfrom(endpoint, &byte, 1, 0, (struct sockaddr *)&peer, &size) == 1);
    assert(byte != 99 && byte != 66);
    assert(sendto(endpoint, &byte, 1, 0, (struct sockaddr *)&peer, size) == 1);
  }
  unsigned target = f->outputs + count;
  for (unsigned i = 0; i < 100 && f->outputs < target; ++i) {
    struct pollfd ready = {hev_owner_poll_fd(f->owner), POLLIN, 0};
    assert(poll(&ready, 1, 10) >= 0);
    step(f);
  }
  assert(f->outputs == target);
}

int main(int argc, char **argv)
{
  alarm(5);
  int family = argc > 1 && !strcmp(argv[1], "ipv6") ? 6 : 4;
  int endpoint = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(endpoint >= 0);
  struct sockaddr_storage address = {0};
  socklen_t size;
  if (family == 6) {
    struct sockaddr_in6 *v6 = (void *)&address;
    v6->sin6_family = AF_INET6; v6->sin6_addr = in6addr_loopback; size = sizeof(*v6);
  } else {
    struct sockaddr_in *v4 = (void *)&address;
    v4->sin_family = AF_INET; v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK); size = sizeof(*v4);
  }
  assert(!bind(endpoint, (struct sockaddr *)&address, size));
  assert(!getsockname(endpoint, (struct sockaddr *)&address, &size));
  uint16_t port = family == 6 ? ntohs(((struct sockaddr_in6 *)&address)->sin6_port)
                            : ntohs(((struct sockaddr_in *)&address)->sin_port);
  fixture_t owners[2] = {0};
  for (unsigned i = 0; i < 2; ++i) {
    fixture_t *f = &owners[i];
    f->family = family; f->port = port; f->generation = 24300 + i;
    hev_owner_config_t config = {.generation = f->generation, .owner_index = i,
      .max_sessions = 4, .max_input_packets = 8, .max_pbufs = 64, .max_packet_bytes = 1500,
      .task_stack_bytes = 32768, .broker_timeout_ms = 1000, .udp_idle_timeout_ms = 3000,
      .output = output, .broker = broker, .trace = trace, .opaque = f};
    f->owner = hev_owner_create(&config); assert(f->owner);
    assert(inject(f, 40000, 1) == HEV_OWNER_INPUT_ACCEPTED); step(f); authorize(f, 0, 11);
    assert(inject(f, 40001, 2) == HEV_OWNER_INPUT_ACCEPTED); step(f); authorize(f, 1, 22);
    echo(f, endpoint, 2);
  }
  for (unsigned i = 0; i < 2; ++i) {
    fixture_t *f = &owners[i];
    int old_fd = f->descriptors[0];
    uint64_t old_session = f->sessions[0];
    assert(inject(f, 40000, 99) == HEV_OWNER_INPUT_ACCEPTED); // Old unsent queue.
    struct sockaddr_storage peer;
    socklen_t peer_size = sizeof(peer);
    assert(!getsockname(old_fd, (struct sockaddr *)&peer, &peer_size));
    uint8_t byte = 98;
    assert(sendto(endpoint, &byte, 1, 0, (struct sockaddr *)&peer, peer_size) == 1);
    assert(hev_owner_invalidate_underlay(f->owner, f->generation + 9, 11) == -1);
    assert(hev_owner_invalidate_underlay(f->owner, f->generation, 0) == -1);
    assert(!hev_owner_invalidate_underlay(f->owner, f->generation, 33));
    assert(!f->invalidated);
    assert(!hev_owner_invalidate_underlay(f->owner, f->generation, 11));
    assert(f->invalidated == 1);
    assert(inject(f, 40000, 99) == HEV_OWNER_INPUT_FAILED); // No overlapping replacement.
    hev_owner_binding_t old_binding = {11, 2, 1};
    assert(hev_owner_broker_complete(f->owner, f->generation, old_session, 1, &old_binding) == -1);
    step(f);
    assert(fcntl(old_fd, F_GETFD) == -1 && errno == EBADF);
    assert(hev_owner_snapshot(f->owner).sessions == 1);
    if (i == 0) assert(hev_owner_snapshot(owners[1].owner).sessions == 2);
    assert(inject(f, 40001, 3) == HEV_OWNER_INPUT_ACCEPTED); echo(f, endpoint, 1);
    assert(f->bytes[2] == 3 && f->epochs[2] == 22); // Unaffected bound network.
    assert(inject(f, 40000, 4) == HEV_OWNER_INPUT_ACCEPTED); step(f);
    assert(f->requests == 3 && f->sessions[2] != old_session);
    assert(hev_owner_broker_complete(f->owner, f->generation, old_session, 1, &old_binding) == -1);
    authorize(f, 2, 33); echo(f, endpoint, 1);
    assert(f->bytes[3] == 4 && f->epochs[3] == 33);
    assert(!hev_owner_invalidate_underlay(f->owner, f->generation, 11));
    assert(f->invalidated == 1 && hev_owner_snapshot(f->owner).sessions == 2);
    // No-underlay admission: typed failure closes without connect/send.
    assert(inject(f, 40002, 66) == HEV_OWNER_INPUT_ACCEPTED); step(f);
    assert(!hev_owner_broker_result(f->owner, f->generation, f->sessions[3], 5, NULL)); step(f);
    assert(fcntl(f->descriptors[3], F_GETFD) == -1 && errno == EBADF);
    // Completed authorization, but invalidation arrives before first I/O.
    assert(inject(f, 40003, 66) == HEV_OWNER_INPUT_ACCEPTED); step(f); authorize(f, 4, 44);
    assert(!hev_owner_invalidate_underlay(f->owner, f->generation, 44)); step(f);
    assert(fcntl(f->descriptors[4], F_GETFD) == -1 && errno == EBADF);
    assert(recv(endpoint, &byte, 1, 0) == -1 && errno == EAGAIN);
    hev_owner_quiesce(f->owner); step(f);
    hev_owner_snapshot_t s = hev_owner_snapshot(f->owner);
    assert(s.stopped && !s.sessions && !s.sockets && !s.input_packets && !s.pbufs);
    assert(s.sessions_created == s.sessions_closed && s.sockets_created == s.sockets_closed);
    assert(s.pool_allocations == s.pool_frees && s.ram_allocations == s.ram_frees && s.ref_allocations == s.ref_frees);
    assert(s.faults[HEV_OWNER_FAULT_NETWORK_UNREACHABLE] == 3);
    assert(!hev_owner_destroy(f->owner));
  }
  close(endpoint);
  printf("UDP%d two-owner epoch invalidation, same-tuple replacement and stale callback PASS\n", family);
  return 0;
}
