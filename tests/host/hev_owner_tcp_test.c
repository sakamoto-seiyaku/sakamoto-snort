/* SPDX-License-Identifier: MIT */
#include "hev-owner.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Real HEV/lwIP, kernel TCP Direct sockets and an independent packet client.
 * The broker is only a nonblocking recorder, not Android protect evidence.
 * Two owners deliberately receive the identical tuple to expose any shared
 * PCB/input/sequence/timer authority, independently of Product hash steering. */
#ifdef SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT
enum { PAYLOAD = 73728, QUEUE = 128, MTU = SAKAMOTO_PRODUCT_VPN_TUN_MTU,
       CLIENT_MSS = SAKAMOTO_PRODUCT_VPN_TUN_MTU - 60 };
#else
enum { PAYLOAD = 73728, QUEUE = 128, MTU = 1500, CLIENT_MSS = 1360 };
#endif
static unsigned blocked_writes;
static int backpressure;

/* Test-only syscall observation: execute the real kernel sendmsg, without
 * changing the Product splice implementation or substituting its result. */
ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
  ssize_t result = syscall(SYS_sendmsg, fd, message, flags);
  if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) ++blocked_writes;
  return result;
}
typedef struct { size_t length; uint8_t bytes[MTU]; } packet_t;
typedef struct {
  hev_owner_t *owner;
  uint64_t generation, broker_session;
  int broker_pending, fd, index, family, refusal, reset, remote_fin;
  int drop_syn, dropped, reject_data, drop_data, rejected_data, dropped_data;
  uint16_t port;
  uint32_t send_seq, receive_seq, acked, sent, received, held_ack_seq;
  unsigned head, tail, outputs, syns, fins, rsts, destroyed, connects, connect_failed;
  unsigned direct_reads, direct_writes, max_data_length;
  int established, fin_sent;
  int pressure, pressure_done;
  int unreachable;
  unsigned other_outputs;
  int hold_ack, ack_released;
  unsigned held_acks;
  unsigned queued_at_ack_release;
  uint64_t ack_release_after, resumed_deadline;
  packet_t packets[QUEUE];
} fixture_t;

static uint64_t millis(void)
{
  struct timespec value;
  assert(!clock_gettime(CLOCK_MONOTONIC, &value));
  return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static uint16_t read16(const uint8_t *p) { return (uint16_t)p[0] << 8 | p[1]; }
static uint32_t read32(const uint8_t *p)
{ return (uint32_t)read16(p) << 16 | read16(p + 2); }
static void write16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void write32(uint8_t *p, uint32_t v) { write16(p, v >> 16); write16(p + 2, v); }
static uint32_t sum(const uint8_t *p, size_t n)
{
  uint32_t value = 0;
  while (n > 1) { value += read16(p); p += 2; n -= 2; }
  if (n) value += (uint32_t)*p << 8;
  return value;
}
static uint16_t checksum(uint32_t value)
{
  while (value >> 16) value = (value & 65535) + (value >> 16);
  return (uint16_t)~value;
}
static uint8_t data_byte(const fixture_t *f, size_t offset)
{ return (uint8_t)(offset * 29 + f->index * 71); }

static int broker(void *opaque, uint64_t generation, uint64_t session, int fd)
{
  fixture_t *f = opaque;
  struct sockaddr_storage address;
  socklen_t size = sizeof(address);
  assert(generation == f->generation && session && !f->broker_pending);
  assert(getpeername(fd, (struct sockaddr *)&address, &size) == -1 && errno == ENOTCONN);
  assert(fcntl(fd, F_GETFL) & O_NONBLOCK);
  if (backpressure) {
    int bytes = 4096;
    assert(!setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)));
  }
  f->broker_session = session;
  f->broker_pending = 1;
  f->fd = fd;
  return 0;
}

static hev_owner_output_result_t output(void *opaque, const hev_owner_span_t *spans,
    unsigned count, size_t total, const hev_owner_facts_t *facts,
    uint64_t generation, uint64_t serial)
{
  fixture_t *f = opaque;
  assert(generation == f->generation && serial && total <= MTU);
  assert(facts->uid == (uint32_t)(10001 + f->index));
  assert(facts->availability & HEV_OWNER_UID_KNOWN);
  if (facts->availability & HEV_OWNER_CONTEXT_KNOWN) {
    assert(facts->underlay_epoch == (uint64_t)(50 + f->index));
    assert(facts->network_context == (uint32_t)(3 + f->index));
  } else assert(!facts->underlay_epoch && !facts->network_context);
  assert(f->tail - f->head < QUEUE);
  packet_t *p = &f->packets[f->tail++ % QUEUE];
  p->length = 0;
  for (unsigned i = 0; i < count; ++i) {
    assert(p->length + spans[i].length <= total);
    memcpy(p->bytes + p->length, spans[i].data, spans[i].length);
    p->length += spans[i].length;
  }
  assert(p->length == total);
  ++f->outputs;
  size_t ip_length = f->family == 6 ? 40 : (p->bytes[0] & 15) * 4;
  size_t tcp_length = (p->bytes[ip_length + 12] >> 4) * 4;
  if (read16(p->bytes + ip_length + 2) != 12345) {
    assert(f->pressure && read16(p->bytes + ip_length + 2) == 12346);
    ++f->other_outputs; --f->tail;
    return HEV_OWNER_OUTPUT_ACCEPTED;
  }
  if (total > ip_length + tcp_length) {
    if (f->reject_data && !f->rejected_data) {
      f->rejected_data = 1; --f->tail;
      return HEV_OWNER_OUTPUT_NO_MEMORY;
    }
    if (f->drop_data && !f->dropped_data) {
      f->dropped_data = 1; --f->tail;
      return HEV_OWNER_OUTPUT_ACCEPTED; /* Independent later packet loss. */
    }
  }
  return HEV_OWNER_OUTPUT_ACCEPTED;
}

static void trace(void *opaque, const hev_owner_event_t *event)
{
  fixture_t *f = opaque;
  if (getenv("HEV_TCP_TRACE"))
    fprintf(stderr, "owner=%d event=%s session=%llu bytes=%zu result=%d kind=%u\n", f->index,
      event->event, (unsigned long long)event->session, event->bytes, event->result, event->kind);
  if (!strcmp(event->event, "tcp_pcb_destroyed")) ++f->destroyed;
  if (!strcmp(event->event, "tcp_connected")) ++f->connects;
  if (!strcmp(event->event, "tcp_connect_failed")) ++f->connect_failed;
  if (!strcmp(event->event, "tcp_direct_receive")) ++f->direct_reads;
  if (!strcmp(event->event, "tcp_direct_send")) ++f->direct_writes;
}

static hev_owner_input_result_t inject_port(fixture_t *f, uint16_t port, uint8_t flags,
                                            uint32_t seq, size_t offset, size_t length)
{
  uint8_t packet[MTU] = {0};
  size_t ip_length = f->family == 6 ? 40 : 20;
  size_t tcp_header = flags & 2 ? 24 : 20;
  size_t tcp_length = tcp_header + length, total = ip_length + tcp_length;
  assert(total <= sizeof(packet));
  uint32_t pseudo;
  if (f->family == 6) {
    packet[0] = 0x60; write16(packet + 4, tcp_length); packet[6] = 6; packet[7] = 64;
    assert(inet_pton(AF_INET6, "fd00::2", packet + 8) == 1);
    assert(inet_pton(AF_INET6, f->unreachable ? "2001:db8::1" : "::1", packet + 24) == 1);
    pseudo = sum(packet + 8, 32) + (uint32_t)tcp_length + 6;
  } else {
    packet[0] = 0x45; write16(packet + 2, total); packet[8] = 64; packet[9] = 6;
    assert(inet_pton(AF_INET, "10.0.0.2", packet + 12) == 1);
    assert(inet_pton(AF_INET, f->unreachable ? "198.18.0.1" : "127.0.0.1", packet + 16) == 1);
    write16(packet + 10, checksum(sum(packet, 20)));
    pseudo = sum(packet + 12, 8) + (uint32_t)tcp_length + 6;
  }
  uint8_t *tcp = packet + ip_length;
  write16(tcp, port); write16(tcp + 2, f->port);
  write32(tcp + 4, seq);
  write32(tcp + 8, f->hold_ack && !f->ack_released ? f->held_ack_seq : f->receive_seq);
  tcp[12] = (uint8_t)((tcp_header / 4) << 4);
  tcp[13] = flags; write16(tcp + 14, 32768);
  if (flags & 2) { tcp[20] = 2; tcp[21] = 4; write16(tcp + 22, CLIENT_MSS); }
  for (size_t i = 0; i < length; ++i) tcp[tcp_header + i] = data_byte(f, offset + i);
  write16(tcp + 16, checksum(pseudo + sum(tcp, tcp_length)));
  hev_owner_facts_t facts = {.uid = (uint32_t)(10001 + f->index),
    .availability = HEV_OWNER_UID_KNOWN};
  return hev_owner_input_copy(f->owner, packet, total, &facts, f->generation);
}

static void inject(fixture_t *f, uint8_t flags, uint32_t seq, size_t offset, size_t length)
{
  assert(inject_port(f, 12345, flags, seq, offset, length) == HEV_OWNER_INPUT_ACCEPTED);
}

static void consume(fixture_t *f)
{
  /* Input may synchronously enqueue output, but never recursively executes
   * this independent client from the borrowed output callback. */
  while (f->head != f->tail) {
    packet_t p = f->packets[f->head++ % QUEUE];
    size_t ip_length = f->family == 6 ? 40 : (p.bytes[0] & 15) * 4;
    assert(ip_length + 20 <= p.length);
    const uint8_t *tcp = p.bytes + ip_length;
    size_t header = (tcp[12] >> 4) * 4, length = p.length - ip_length - header;
    assert(length <= CLIENT_MSS);
    if (length > f->max_data_length) f->max_data_length = (unsigned)length;
    assert(read16(tcp) == f->port && read16(tcp + 2) == 12345);
    uint32_t pseudo = sum(p.bytes + (f->family == 6 ? 8 : 12), f->family == 6 ? 32 : 8)
                      + (uint32_t)(p.length - ip_length) + 6;
    assert(checksum(pseudo + sum(tcp, p.length - ip_length)) == 0);
    uint32_t seq = read32(tcp + 4);
    if (getenv("HEV_TCP_TRACE")) fprintf(stderr,
      "owner=%d packet flags=%u seq=%u ack=%u window=%u data=%zu expected=%u\n",
      f->index, tcp[13], seq, read32(tcp + 8), read16(tcp + 14), length, f->receive_seq);
    if (tcp[13] & 4) { ++f->rsts; continue; }
    if (tcp[13] & 2) {
      assert(header >= 24 && tcp[20] == 2 && tcp[21] == 4);
      assert(read16(tcp + 22) == CLIENT_MSS);
      ++f->syns;
      if (f->drop_syn && !f->dropped) { f->dropped = 1; continue; }
      assert((tcp[13] & 16) && read32(tcp + 8) == 100001);
      f->receive_seq = seq + 1;
      f->held_ack_seq = f->receive_seq;
      f->send_seq = 100001;
      f->established = 1;
      inject(f, 16, f->send_seq, 0, 0);
      continue;
    }
    if (tcp[13] & 16) f->acked = read32(tcp + 8);
    if (length && seq == f->receive_seq) {
      for (size_t i = 0; i < length; ++i)
        assert(tcp[header + i] == data_byte(f, f->received + i));
      f->received += (uint32_t)length;
      f->receive_seq += (uint32_t)length;
    }
    if ((tcp[13] & 1) && seq + length == f->receive_seq) {
      ++f->receive_seq; ++f->fins;
    }
    if (length || (tcp[13] & 1)) {
      if (f->hold_ack && !f->ack_released) {
        if (!f->ack_release_after) f->ack_release_after = millis() + 250;
        ++f->held_acks;
      } else inject(f, 16, f->send_seq, 0, 0);
    }
  }
}

static void tick(fixture_t *f)
{
  hev_owner_step_result_t result = hev_owner_step(f->owner, 4, 10000);
  assert(result.quanta <= 4);
  if (f->broker_pending) {
    f->broker_pending = 0;
    hev_owner_binding_t binding = {.underlay_epoch = (uint64_t)(50 + f->index),
      .network_context = (uint32_t)(3 + f->index), .context_known = 1};
    assert(!hev_owner_broker_complete(f->owner, f->generation, f->broker_session, 1, &binding));
  }
  consume(f);
}

static int endpoint(int family, uint16_t *port)
{
  int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(fd >= 0);
  struct sockaddr_storage storage = {0};
  socklen_t size;
  if (family == 6) {
    struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
    address->sin6_family = AF_INET6; address->sin6_addr = in6addr_loopback;
    size = sizeof(*address);
  } else {
    struct sockaddr_in *address = (struct sockaddr_in *)&storage;
    address->sin_family = AF_INET; address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    size = sizeof(*address);
  }
  assert(!bind(fd, (struct sockaddr *)&storage, size));
  assert(!getsockname(fd, (struct sockaddr *)&storage, &size));
  if (backpressure) {
    int bytes = 4096;
    assert(!setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)));
  }
  *port = family == 6 ? ntohs(((struct sockaddr_in6 *)&storage)->sin6_port)
                      : ntohs(((struct sockaddr_in *)&storage)->sin_port);
  assert(!listen(fd, 4));
  return fd;
}

int main(int argc, char **argv)
{
  setvbuf(stdout, NULL, _IOLBF, 0);
  alarm(25);
  int family = argc > 1 && !strcmp(argv[1], "ipv6") ? 6 : 4;
  int unreachable = argc > 2 && !strcmp(argv[2], "unreachable");
  int refusal = unreachable || (argc > 2 && !strcmp(argv[2], "refusal"));
  int reset = argc > 2 && !strcmp(argv[2], "reset");
  int remote_fin = argc > 2 && !strcmp(argv[2], "remote-fin");
  int underlay = argc > 2 && !strcmp(argv[2], "underlay");
  int hold_ack = argc > 2 && !strcmp(argv[2], "hold-ack");
  int pressure = 0;
  backpressure = argc <= 2;
  static const char *const pressure_names[] = {"session-capacity", "pcb-capacity",
    "socket-capacity", "packet-credit", "pbuf-capacity"};
  for (unsigned i = 0; i < 5; ++i)
    if (argc > 2 && !strcmp(argv[2], pressure_names[i])) pressure = (int)i + 1;
  uint16_t port;
  int server = endpoint(family, &port), peers[2] = {-1, -1};
  uint64_t read_after[2] = {0, 0};
  unsigned server_bytes[2] = {0, 0};
  if (refusal) { close(server); server = -1; }
  fixture_t *fixtures = calloc(2, sizeof(*fixtures));
  assert(fixtures);
  for (int i = 0; i < 2; ++i) {
    fixture_t *f = &fixtures[i];
    f->index = i; f->family = family; f->generation = 24000 + i;
    f->port = port; f->fd = -1;
    f->refusal = refusal; f->reset = reset; f->remote_fin = remote_fin;
    f->hold_ack = hold_ack;
    f->unreachable = unreachable;
    f->pressure = i == 0 ? pressure : 0;
    f->drop_syn = !pressure && !refusal && !reset && !remote_fin && !underlay && !hold_ack && i == 1;
    f->reject_data = !pressure && !refusal && !reset && !remote_fin && !underlay && !hold_ack && i == 0;
    f->drop_data = !pressure && !refusal && !reset && !remote_fin && !underlay && !hold_ack && i == 1;
    hev_owner_config_t config = {.generation = f->generation, .owner_index = (uint32_t)i,
      .max_sessions = 4, .max_input_packets = 64, .max_pbufs = 128,
      .max_packet_bytes = MTU, .task_stack_bytes = 65536, .broker_timeout_ms = 1000,
      .udp_idle_timeout_ms = 1000, .output = output, .broker = broker, .trace = trace, .opaque = f};
    if (f->pressure == 1) config.max_sessions = 1;
    if (f->pressure == 2) config.max_pcbs = 3;
    if (f->pressure == 3) config.max_sockets = 1;
    if (f->pressure == 4) config.max_input_packets = 1;
    if (f->pressure == 5) config.max_pbufs = 8;
    f->owner = hev_owner_create(&config); assert(f->owner);
    inject(f, 2, 100000, 0, 0);
  }
  uint64_t deadline = millis() + 22000;
  int accepted = 0, completed = 0;
  while (millis() < deadline && !completed) {
    for (int i = 0; i < 2; ++i) tick(&fixtures[i]);
    if (server >= 0 && accepted < 2) {
      int fd = accept4(server, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd >= 0) {
        read_after[accepted] = millis() + (backpressure ? 150 : 0);
        peers[accepted++] = fd;
      }
      else assert(errno == EAGAIN || errno == EWOULDBLOCK);
    }
    for (int i = 0; i < accepted; ++i) if (peers[i] >= 0 && millis() >= read_after[i]) {
      uint8_t bytes[4096];
      ssize_t n = recv(peers[i], bytes, sizeof(bytes), 0);
      if (n > 0) {
        assert(send(peers[i], bytes, (size_t)n, MSG_NOSIGNAL) == n);
        server_bytes[i] += (unsigned)n;
        if (remote_fin && server_bytes[i] == PAYLOAD) assert(!shutdown(peers[i], SHUT_WR));
      }
      else if (n == 0) { close(peers[i]); peers[i] = -1; }
      else assert(errno == EAGAIN || errno == EWOULDBLOCK);
    }
    completed = 1;
    for (int i = 0; i < 2; ++i) {
      fixture_t *f = &fixtures[i];
      if (refusal) {
        if (!f->rsts || hev_owner_snapshot(f->owner).sessions) completed = 0;
        continue;
      }
      if (f->pressure && f->connects && !f->pressure_done) {
        assert(hev_owner_snapshot(f->owner).sessions == 1);
        if (f->pressure <= 3) {
          hev_owner_input_result_t r = inject_port(f, 12346, 2, 200000, 0, 0);
          assert(r == (f->pressure == 3 ? HEV_OWNER_INPUT_ACCEPTED : HEV_OWNER_INPUT_NO_CAPACITY));
        } else {
          /* Keep the real HEV input queue occupied, then reject just the next
           * segment. The independent client retransmits it after progress;
           * the original connection completes all bytes and both FINs. */
          unsigned admitted = f->pressure == 4 ? 1 : 8;
          unsigned bytes = f->pressure == 4 ? 1024 : 1;
          for (unsigned n = 0; n < admitted; ++n) {
            inject(f, 24, f->send_seq, f->sent, bytes);
            f->send_seq += bytes; f->sent += bytes;
          }
          assert(inject_port(f, 12345, 24, f->send_seq, f->sent, bytes)
                 == HEV_OWNER_INPUT_NO_CAPACITY);
          assert(hev_owner_snapshot(f->owner).sessions == 1);
        }
        f->pressure_done = 1;
      }
      if (f->established && (!f->pressure || f->pressure_done) &&
          f->sent < PAYLOAD && (hold_ack ? (!f->sent || f->acked == f->send_seq)
                                       : f->received == f->sent)) {
        /* A full receive-window burst exercises actual HEV pbuf-chain writes
         * and the return ring crossing its boundary on later bursts. */
        unsigned limit = f->sent + (f->pressure >= 4 ? 1024 : 32768);
        if (limit > PAYLOAD) limit = PAYLOAD;
        while (f->sent < limit) {
          unsigned chunk = MTU > 1500 && !f->pressure ? CLIENT_MSS : 1024;
          unsigned bytes = limit - f->sent < chunk ? limit - f->sent : chunk;
          inject(f, 24, f->send_seq, f->sent, bytes);
          f->send_seq += bytes; f->sent += bytes;
        }
      }
      if (f->hold_ack && !f->ack_released && f->held_acks && millis() >= f->ack_release_after) {
        /* Release after the remote has queued more bytes than the ring can
         * hold. The owner must consume those already-readable bytes without
         * waiting for another EPOLLET transition or unrelated packet. */
        assert(server_bytes[0] == PAYLOAD && server_bytes[1] == PAYLOAD);
        int queued = 0;
        assert(ioctl(f->fd, FIONREAD, &queued) == 0 && queued > 0);
        f->queued_at_ack_release = (unsigned)queued;
        f->ack_released = 1;
        f->resumed_deadline = millis() + 200;
        inject(f, 16, f->send_seq, 0, 0);
      }
      if (f->hold_ack && f->ack_released && f->received < PAYLOAD)
        assert(millis() < f->resumed_deadline); /* No 1s TCP poll rescue. */
      if (f->received == PAYLOAD && !f->fin_sent && (!remote_fin || f->fins)) {
        if (underlay) assert(!hev_owner_invalidate_underlay(f->owner, f->generation, 50 + i));
        else inject(f, reset ? 20 : 17, f->send_seq, 0, 0);
        ++f->send_seq; f->fin_sent = 1;
      }
      hev_owner_snapshot_t state = hev_owner_snapshot(f->owner);
      if (!f->fin_sent || (underlay ? !f->rsts : (!reset && !f->fins)) ||
          state.sockets_created != state.sockets_closed || (!remote_fin && state.sessions))
        completed = 0;
    }
    struct pollfd descriptors[2] = {{hev_owner_poll_fd(fixtures[0].owner), POLLIN, 0},
                                    {hev_owner_poll_fd(fixtures[1].owner), POLLIN, 0}};
    assert(poll(descriptors, 2, 1) >= 0);
  }
  for (int i = 0; i < 2; ++i) {
    fixture_t *f = &fixtures[i];
    if (!completed) fprintf(stderr, "owner=%d syns=%u received=%u sent=%u fins=%u rst=%u connects=%u sessions=%u\n",
      i, f->syns, f->received, f->sent, f->fins, f->rsts, f->connects, hev_owner_snapshot(f->owner).sessions);
  }
  assert(completed && accepted == (refusal ? 0 : 2));
  if (backpressure) {
    assert(blocked_writes > 0);
    printf("TCP%d real sendmsg EAGAIN=%u existing stream recovered\n", family, blocked_writes);
  }
  if (!pressure && !refusal && !reset && !remote_fin && !underlay && !hold_ack) {
    assert(fixtures[1].syns >= 2 && fixtures[0].syns == 1);
    assert(fixtures[0].rejected_data && fixtures[1].dropped_data);
  }
  for (int i = 0; i < 2; ++i) {
    fixture_t *f = &fixtures[i];
    if (refusal) {
      fprintf(stderr, "refusal owner=%d connects=%u failures=%u rsts=%u\n",
              i, f->connects, f->connect_failed, f->rsts);
      assert(!f->connects && f->connect_failed == 1 && f->rsts == 1);
      hev_owner_snapshot_t state = hev_owner_snapshot(f->owner);
      assert(state.faults[unreachable ? HEV_OWNER_FAULT_NETWORK_UNREACHABLE
                                      : HEV_OWNER_FAULT_CONNECT_REFUSED] == 1);
    }
    else {
      assert(f->received == PAYLOAD && f->sent == PAYLOAD);
      assert(f->connects == 1 && !f->connect_failed && f->rsts == (unsigned)underlay);
      if (underlay) {
        hev_owner_snapshot_t closed = hev_owner_snapshot(f->owner);
        assert(closed.faults[HEV_OWNER_FAULT_NETWORK_UNREACHABLE] == 1);
        assert(closed.sockets_created == 1 && closed.sockets_closed == 1 && !closed.sessions);
        // Continuation of the old byte stream cannot create another socket.
        inject(f, 24, f->send_seq, 0, 1); tick(f);
        assert(hev_owner_snapshot(f->owner).sockets_created == 1);
      }
      assert(f->direct_reads && f->direct_writes);
      if (remote_fin) {
        assert(hev_owner_snapshot(f->owner).sessions == 1 && !f->destroyed);
        /* The detached TIME_WAIT PCB still has correct return facts. */
        inject(f, 17, f->send_seq - 1, 0, 0); consume(f);
      }
    }
    hev_owner_quiesce(f->owner); tick(f);
    hev_owner_snapshot_t s = hev_owner_snapshot(f->owner);
    assert(s.stopped && !s.sessions && !s.pbufs && !s.input_packets);
    if (!refusal) {
      assert(s.tcp_rx_rounds && s.tcp_read_calls && s.tcp_commits);
      assert(s.tcp_read_blocked == s.tcp_read_eagain + s.tcp_read_eintr);
      assert(s.tcp_read_blocked + s.tcp_read_eof <= s.tcp_read_calls);
      assert(s.tcp_commit_bytes == PAYLOAD);
      assert(s.tcp_mss_min == CLIENT_MSS && s.tcp_mss_max == CLIENT_MSS);
      assert(s.tcp_idle_rounds <= s.tcp_rx_rounds);
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
      uint64_t observed_rounds = 0, observed_idle = 0;
      for (unsigned n = 0; n < 8; ++n) {
        observed_rounds += s.tcp_resume_rounds[n];
        observed_idle += s.tcp_resume_idle[n];
      }
      assert(observed_rounds == s.tcp_rx_rounds && observed_idle == s.tcp_idle_rounds);
      assert(s.scheduler_io_polls && s.scheduler_io_events);
#endif
      assert(s.tcp_ring_peak && s.tcp_pending_peak <= s.tcp_ring_peak);
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT
      assert(s.tcp_buffer_bytes == 65528 && s.tcp_ring_peak <= 65528);
      if (hold_ack) assert(s.tcp_ring_peak > 32768);
#else
      assert(s.tcp_buffer_bytes == 32768 && s.tcp_ring_peak <= 32768);
#endif
      if (hold_ack) {
        assert(f->held_acks && f->ack_released && f->queued_at_ack_release);
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
        assert(s.tcp_read_pauses && s.tcp_read_resumes && s.tcp_interest_changes >= 2);
        assert(s.tcp_yields[2] && s.tcp_wait_ns[2] > 10000000);
        assert(s.tcp_resume_rounds[2]); /* The held inner ACK actually wakes it. */
        printf("TCP%d owner=%d inner_ack_wait_ns=%llu ack_wakes=%llu ack_idle=%llu continue_idle=%llu\n",
          family, i, (unsigned long long)s.tcp_wait_ns[2],
          (unsigned long long)s.tcp_resume_rounds[2],
          (unsigned long long)s.tcp_resume_idle[2],
          (unsigned long long)s.tcp_resume_idle[0]);
#endif
      }
#ifdef SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT
      /* Credit fixtures intentionally drip <=1024-byte bursts on owner0. */
      if (f->pressure < 4) assert(f->max_data_length > 2000);
      /* The basic case deliberately caps the outer SO_SNDBUF to 4KiB.
       * Withheld ACKs queue all peer bytes before release, so that case is
       * the deterministic witness of an actual >8KiB inner segment. */
      if (MTU == 10000 && hold_ack) assert(f->max_data_length > 8192);
#endif
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT
      assert(s.tcp_commit_max <= 8);
      if (!pressure && !reset && !remote_fin && !underlay)
        /* The peer echoes <=4KiB per read. At MSS9940 one commit can
         * consume that entire burst; the old >=2 assertion is inapplicable. */
        assert(s.tcp_commit_max >= (4096U + CLIENT_MSS - 1) / CLIENT_MSS);
      if (MTU == 10000 && hold_ack) assert(s.tcp_commit_max >= 2);
#else
      assert(s.tcp_commit_max <= 2); /* A wrapped ring can have two short spans. */
#endif
      printf("TCP%d owner=%d rx_rounds=%llu read_calls=%llu read_blocked=%llu commits=%llu bytes=%llu max_commits=%llu output_calls=%llu\n",
        family, i, (unsigned long long)s.tcp_rx_rounds,
        (unsigned long long)s.tcp_read_calls, (unsigned long long)s.tcp_read_blocked,
        (unsigned long long)s.tcp_commits, (unsigned long long)s.tcp_commit_bytes,
        (unsigned long long)s.tcp_commit_max, (unsigned long long)s.tcp_output_calls);
      printf("TCP%d owner=%d mss=%u max_payload=%u ring_peak=%llu ring_full=%llu sndbuf_full=%llu window_full=%llu cwnd_full=%llu idle_rounds=%llu\n",
        family, i, s.tcp_mss_max, f->max_data_length,
        (unsigned long long)s.tcp_ring_peak, (unsigned long long)s.tcp_ring_full,
        (unsigned long long)s.tcp_sndbuf_full, (unsigned long long)s.tcp_window_full,
        (unsigned long long)s.tcp_cwnd_full, (unsigned long long)s.tcp_idle_rounds);
      printf("TCP%d owner=%d interest_changes=%llu read_pauses=%llu read_resumes=%llu held_acks=%u kernel_queued_at_ack=%u\n",
        family, i, (unsigned long long)s.tcp_interest_changes,
        (unsigned long long)s.tcp_read_pauses, (unsigned long long)s.tcp_read_resumes,
        f->held_acks, f->queued_at_ack_release);
    }
    assert(s.sessions_created == s.sessions_closed && s.sockets_created == s.sockets_closed);
    assert(s.pool_allocations == s.pool_frees && s.ram_allocations == s.ram_frees &&
           s.ref_allocations == s.ref_frees && s.lwip_heap_live == 2);
    assert(f->destroyed == (f->pressure == 3 ? 2U : 1U));
    assert(s.pcbs == 2 && s.pcb_allocations - s.pcb_frees == 2 && !s.sockets);
    if (f->pressure) {
      static const hev_owner_fault_t reasons[] = {HEV_OWNER_FAULT_NONE,
        HEV_OWNER_FAULT_SESSION_CAPACITY, HEV_OWNER_FAULT_PCB_CAPACITY,
        HEV_OWNER_FAULT_SOCKET_CAPACITY, HEV_OWNER_FAULT_PACKET_CREDIT, HEV_OWNER_FAULT_PBUF_CAPACITY};
      assert(f->pressure_done && s.faults[reasons[f->pressure]] > 0);
      assert(s.first_fault_ms && s.last_fault_ms >= s.first_fault_ms);
      assert(s.sessions_created == (f->pressure == 3 ? 2U : 1U));
      assert(s.sockets_created == 1 && s.broker_requested == 1);
      printf("TCP%d pressure=%s failures=%llu original-flow-bytes=%u recovery=1\n", family,
        pressure_names[f->pressure - 1], (unsigned long long)s.faults[reasons[f->pressure]], f->received);
    } else if (pressure) assert(!s.fault_count);
    assert(!hev_owner_destroy(f->owner));
  }
  if (server >= 0) close(server);
  for (int i = 0; i < 2; ++i) if (peers[i] >= 0) close(peers[i]);
  free(fixtures);
  printf("real HEV TCP%d Direct identical-tuple owners: %s PASS\n", family,
         refusal ? "refusal/RST" : reset ? "data/client RST" : remote_fin ? "remote FIN/TIME_WAIT" :
         underlay ? "underlay invalidation/RST, no byte-stream reconnect" :
         hold_ack ? "withheld ACK, already-readable socket data resumed and FIN" :
         "147456 echoed bytes, window bursts, rejected/lost output, SYN retransmit and FIN");
  return 0;
}
