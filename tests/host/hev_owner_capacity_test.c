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
#include <time.h>
#include <unistd.h>

/* Real dependency and kernel UDP endpoint; no VPP/Android acceptance claim.
 * Reduced startup limits exercise actual allocation/queue/socket decisions. */
typedef struct {
  hev_owner_t *owner;
  uint64_t generation, pending[16];
  unsigned pending_count, requests, outputs, next_error, released;
  int family, automatic, unreachable, endpoint;
  uint16_t port;
} fixture_t;

static uint64_t millis(void)
{
  struct timespec now;
  assert(!clock_gettime(CLOCK_MONOTONIC, &now));
  return (uint64_t)now.tv_sec * 1000 + (unsigned long)now.tv_nsec / 1000000;
}
static uint16_t read16(const unsigned char *p) { return (uint16_t)p[0] << 8 | p[1]; }
static void write16(unsigned char *p, uint16_t value) { p[0] = value >> 8; p[1] = value; }
static uint32_t sum(const unsigned char *p, size_t length)
{
  uint32_t value = 0;
  while (length > 1) { value += read16(p); p += 2; length -= 2; }
  if (length) value += (uint32_t)*p << 8;
  return value;
}
static uint16_t checksum(uint32_t value)
{
  while (value >> 16) value = (value & 65535) + (value >> 16);
  return (uint16_t)~value;
}

static int broker(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  fixture_t *f = opaque;
  struct sockaddr_storage peer;
  socklen_t length = sizeof(peer);
  assert(generation == f->generation && session && f->pending_count < 16);
  assert(getpeername(fd, (struct sockaddr *)&peer, &length) == -1 && errno == ENOTCONN);
  assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
  f->pending[f->pending_count++] = session;
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
  assert(generation == f->generation && serial && total <= sizeof(packet));
  for (unsigned i = 0; i < count; ++i) {
    assert(spans[i].length <= total - offset);
    memcpy(packet + offset, spans[i].data, spans[i].length);
    offset += spans[i].length;
  }
  assert(offset == total && total == (f->family == 6 ? 49U : 29U));
  assert(packet[total - 1] == 42 && facts->uid == 10001);
  assert(facts->underlay_epoch == 19 && facts->network_context == 2);
  ++f->outputs;
  return HEV_OWNER_OUTPUT_ACCEPTED;
}
static void trace(void *opaque, const hev_owner_event_t *event)
{
  fixture_t *f = opaque;
  if (!strcmp(event->event, "pcbs_reclaimed")) {
    assert(!event->bytes && !event->result);
    ++f->released;
  }
}
static hev_owner_input_result_t inject(fixture_t *f, uint16_t source, uint32_t uid)
{
  unsigned char packet[49] = {0};
  unsigned ip = f->family == 6 ? 40 : 20, total = ip + 9;
  uint32_t pseudo;
  if (f->family == 6) {
    packet[0] = 0x60; packet[5] = 9; packet[6] = 17; packet[7] = 64;
    assert(inet_pton(AF_INET6, "fd00::2", packet + 8) == 1);
    assert(inet_pton(AF_INET6, f->unreachable ? "2001:db8::1" : "::1", packet + 24) == 1);
    pseudo = sum(packet + 8, 32) + 26;
  } else {
    packet[0] = 0x45; packet[3] = total; packet[8] = 64; packet[9] = 17;
    assert(inet_pton(AF_INET, "10.0.0.2", packet + 12) == 1);
    assert(inet_pton(AF_INET, f->unreachable ? "198.18.0.1" : "127.0.0.1", packet + 16) == 1);
    write16(packet + 10, checksum(sum(packet, 20)));
    pseudo = sum(packet + 12, 8) + 26;
  }
  write16(packet + ip, source); write16(packet + ip + 2, f->port);
  write16(packet + ip + 4, 9); packet[ip + 8] = 42;
  uint16_t check = checksum(pseudo + sum(packet + ip, 9));
  write16(packet + ip + 6, check ? check : 65535);
  hev_owner_facts_t facts = {.uid = uid, .availability = HEV_OWNER_UID_KNOWN};
  return hev_owner_input_copy(f->owner, packet, total, &facts, f->generation);
}
static void step(fixture_t *f)
{
  hev_owner_step_result_t result = hev_owner_step(f->owner, 8, 10000);
  assert(result.quanta <= 8);
  if (f->automatic) {
    hev_owner_binding_t binding = {.underlay_epoch = 19, .network_context = 2, .context_known = 1};
    for (unsigned i = 0; i < f->pending_count; ++i) {
      unsigned error = f->next_error;
      f->next_error = 0;
      assert(!hev_owner_broker_result(f->owner, f->generation, f->pending[i], error, &binding));
    }
    f->pending_count = 0;
  }
}
static void echo(fixture_t *f, unsigned count)
{
  unsigned target = f->outputs + count, received = 0;
  uint64_t deadline = millis() + 1000;
  while (f->outputs < target && millis() < deadline) {
    step(f);
    for (;;) {
      unsigned char data[32];
      struct sockaddr_storage peer;
      socklen_t length = sizeof(peer);
      ssize_t n = recvfrom(f->endpoint, data, sizeof(data), MSG_DONTWAIT,
                           (struct sockaddr *)&peer, &length);
      if (n < 0) { assert(errno == EAGAIN || errno == EWOULDBLOCK); break; }
      assert(n == 1 && data[0] == 42);
      ++received;
      assert(sendto(f->endpoint, data, n, 0, (struct sockaddr *)&peer, length) == n);
    }
    struct pollfd fd = {hev_owner_poll_fd(f->owner), POLLIN, 0};
    assert(poll(&fd, 1, 1) >= 0);
  }
  assert(f->outputs == target && received == count);
}
static void stop(fixture_t *f)
{
  f->automatic = 0;
  hev_owner_quiesce(f->owner);
  for (unsigned i = 0; i < 32 && !hev_owner_snapshot(f->owner).stopped; ++i) step(f);
  hev_owner_snapshot_t s = hev_owner_snapshot(f->owner);
  assert(s.stopped && !s.sessions && !s.input_packets && !s.input_pbufs && !s.pbufs && !s.sockets);
  assert(s.pcbs == 2 && s.pcb_allocations - s.pcb_frees == 2);
  assert(s.sessions_created == s.sessions_closed && s.sockets_created == s.sockets_closed);
  assert(!hev_owner_destroy(f->owner) && f->released == 1);
  close(f->endpoint);
}
static void setup(fixture_t *f, int family, unsigned mode)
{
  memset(f, 0, sizeof(*f));
  f->family = family; f->automatic = 1; f->generation = 24100 + mode;
  f->endpoint = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(f->endpoint >= 0);
  struct sockaddr_storage address = {0};
  socklen_t size;
  if (family == 6) {
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
    a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback; size = sizeof(*a);
  } else {
    struct sockaddr_in *a = (struct sockaddr_in *)&address;
    a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); size = sizeof(*a);
  }
  assert(!bind(f->endpoint, (struct sockaddr *)&address, size));
  assert(!getsockname(f->endpoint, (struct sockaddr *)&address, &size));
  f->port = family == 6 ? ntohs(((struct sockaddr_in6 *)&address)->sin6_port)
                       : ntohs(((struct sockaddr_in *)&address)->sin_port);
  hev_owner_config_t config = {.generation = f->generation, .max_sessions = 4,
    .max_pcbs = 8, .max_sockets = 4, .max_input_packets = 8, .max_pbufs = 16,
    .max_packet_bytes = 1500, .task_stack_bytes = 32768, .broker_timeout_ms = 1000,
    .udp_idle_timeout_ms = 1000, .output = output, .broker = broker, .trace = trace, .opaque = f};
  if (mode == 1) config.max_sessions = 1;
  if (mode == 2) config.max_pcbs = 3;
  if (mode == 3) config.max_sockets = 1;
  if (mode == 4) config.max_input_packets = 1;
  if (mode == 5) config.max_pbufs = 4;
  f->owner = hev_owner_create(&config);
  assert(f->owner);
}

int main(int argc, char **argv)
{
  alarm(15);
  int family = argc > 1 && !strcmp(argv[1], "ipv6") ? 6 : 4;
  const hev_owner_fault_t reasons[] = {HEV_OWNER_FAULT_NONE,
    HEV_OWNER_FAULT_SESSION_CAPACITY, HEV_OWNER_FAULT_PCB_CAPACITY,
    HEV_OWNER_FAULT_SOCKET_CAPACITY, HEV_OWNER_FAULT_PACKET_CREDIT, HEV_OWNER_FAULT_PBUF_CAPACITY};
  for (unsigned mode = 1; mode <= 5; ++mode) {
    fixture_t f;
    setup(&f, family, mode);
    assert(inject(&f, 12345, 10001) == HEV_OWNER_INPUT_ACCEPTED);
    echo(&f, 1);
    if (mode <= 3) {
      assert(inject(&f, 12346, 10001) == (mode == 3 ? HEV_OWNER_INPUT_ACCEPTED : HEV_OWNER_INPUT_NO_CAPACITY));
      step(&f);
      assert(hev_owner_snapshot(f.owner).sessions == 1 && f.requests == 1);
      assert(inject(&f, 12345, 10001) == HEV_OWNER_INPUT_ACCEPTED);
      echo(&f, 1);
      /* Free capacity through a separately specified identity-close, then
       * create a new protected transport. No live limit changes or eviction. */
      assert(inject(&f, 12345, 10002) == HEV_OWNER_INPUT_FAILED);
      step(&f);
      assert(!hev_owner_snapshot(f.owner).sessions);
      assert(inject(&f, 12346, 10001) == HEV_OWNER_INPUT_ACCEPTED);
      echo(&f, 1);
    } else {
      unsigned count = mode == 4 ? 1 : 4;
      for (unsigned i = 0; i < count; ++i)
        assert(inject(&f, 12345, 10001) == HEV_OWNER_INPUT_ACCEPTED);
      assert(inject(&f, 12345, 10001) == HEV_OWNER_INPUT_NO_CAPACITY);
      assert(hev_owner_snapshot(f.owner).sessions == 1);
      echo(&f, count);
      assert(inject(&f, 12345, 10001) == HEV_OWNER_INPUT_ACCEPTED);
      echo(&f, 1);
      assert(f.requests == 1 && hev_owner_snapshot(f.owner).sessions_created == 1);
    }
    hev_owner_snapshot_t s = hev_owner_snapshot(f.owner);
    assert(s.faults[reasons[mode]] && s.first_fault_ms && s.last_fault_ms >= s.first_fault_ms);
    stop(&f);
    printf("UDP%d capacity=%u current-packet/new-flow recovery and residue PASS\n", family, mode);
  }
  for (unsigned error = 2; error <= 5; ++error) {
    fixture_t f;
    setup(&f, family, 0);
    if (error == 5) f.unreachable = 1; else f.next_error = error;
    assert(inject(&f, 12345, 10001) == HEV_OWNER_INPUT_ACCEPTED);
    for (unsigned i = 0; i < 4; ++i) step(&f);
    hev_owner_snapshot_t s = hev_owner_snapshot(f.owner);
    unsigned reason = error == 2 ? HEV_OWNER_FAULT_PROTECT : error == 3
      ? HEV_OWNER_FAULT_BIND : error == 4 ? HEV_OWNER_FAULT_AUTHORIZATION
      : HEV_OWNER_FAULT_NETWORK_UNREACHABLE;
    assert(!s.sessions && !s.input_packets && !s.sockets && !s.direct_sent);
    assert(s.sockets_created == 1 && s.sockets_closed == 1 && s.faults[reason] == 1);
    assert(f.requests == 1 && !f.outputs);
    f.unreachable = 0;
    assert(inject(&f, 12346, 10001) == HEV_OWNER_INPUT_ACCEPTED);
    echo(&f, 1);
    assert(f.requests == 2);
    stop(&f);
    printf("UDP%d failure=%u no fallback and fresh-flow recovery PASS\n", family, reason);
  }
  return 0;
}
