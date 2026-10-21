/* SPDX-License-Identifier: MIT */
#include "hev-owner.h"
#include "hev-lwip-context.h"
#include "hev-socks5-session-udp.h"
#include "hev-socks5-session-tcp.h"
#include "kern/core/hev-task-system-private.h"
#include "lwip/init.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

typedef struct owner_session {
  struct owner_session *next;
  struct hev_owner *owner;
  HevSocks5SessionUDP *transport;
  HevSocks5SessionTCP *tcp;
  struct tcp_pcb *pcb;
  HevTask *task;
  udp_recv_fn receive;
  void *receive_arg;
  hev_owner_facts_t facts;
  uint64_t id, deadline;
  int closing, broker_state, tcp_accepted;
} owner_session_t;

struct hev_owner {
  hev_owner_config_t config;
  hev_owner_snapshot_t stats;
  hev_lwip_context_t lwip;
  HevTaskSystemContext *scheduler;
  HevTaskMutex mutex;
  struct netif interface;
  struct udp_pcb *listener;
  struct tcp_pcb *tcp_listener;
  owner_session_t *sessions, *output_session;
  hev_owner_facts_t input_facts;
  hev_owner_input_result_t input_result;
  uint64_t session_serial, event_serial, output_serial, next_tcp_timer;
  pthread_t thread;
  unsigned char *scratch;
  int bound, entered, input_active;
};

typedef struct {
  HevTaskSystemContext *scheduler;
  hev_lwip_context_t *lwip;
} owner_scope_t;

/* Class metadata is initialized once, not per-owner transport authority. */
static pthread_once_t classes_once = PTHREAD_ONCE_INIT;
static void initialize_classes(void)
{
  (void)hev_socks5_session_udp_class();
  (void)hev_socks5_session_tcp_class();
  (void)hev_socks5_session_iface();
}

/* Only seeds lwIP's synthetic listener-port allocator in this UDP pretend
 * profile. The kernel, not lwIP, chooses every Direct socket's real source
 * port. This is not a cryptographic random-number provider. */
unsigned int lwip_port_rand(void)
{ return *hev_lwip_udp_port(); }

static uint64_t now_ms(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
  return (uint64_t)t.tv_sec * 1000 + (unsigned long)t.tv_nsec / 1000000;
}

static int enter(hev_owner_t *owner, owner_scope_t *scope)
{
  if (!owner || (owner->bound && !pthread_equal(owner->thread, pthread_self())) ||
      owner->entered)
    return -1;
  owner->thread = pthread_self();
  owner->bound = owner->entered = 1;
  scope->scheduler = hev_task_system_get_context();
  scope->lwip = hev_lwip_context_bind(&owner->lwip);
  if (hev_task_system_set_context(owner->scheduler)) abort();
  return 0;
}

static void leave(hev_owner_t *owner, owner_scope_t *scope)
{
  if (hev_task_system_set_context(scope->scheduler)) abort();
  hev_lwip_context_bind(scope->lwip);
  owner->entered = 0;
}

static void trace(hev_owner_t *owner, const char *event, uint64_t session,
                  void *object, size_t bytes, int result, unsigned kind)
{
  hev_owner_event_t value = {event, ++owner->event_serial, session,
                            (uintptr_t)object, bytes, result, kind};
  if (owner->config.trace) owner->config.trace(owner->config.opaque, &value);
}

static void failure(hev_owner_t *owner, hev_owner_fault_t reason,
                    uint64_t session, int error)
{
  uint64_t now = now_ms();
  if (!owner->stats.fault_count) owner->stats.first_fault_ms = now;
  ++owner->stats.fault_count;
  ++owner->stats.faults[reason];
  owner->stats.last_fault_ms = now;
  owner->stats.last_fault_session = session;
  owner->stats.last_fault = reason;
  owner->stats.last_fault_error = error;
  trace(owner, "transport_failure", session, NULL, 0, error, reason);
}

static void resource_failure(void *opaque, unsigned resource)
{
  hev_owner_t *owner = opaque;
  hev_owner_fault_t reason = resource == HEV_LWIP_RESOURCE_PCB
    ? HEV_OWNER_FAULT_PCB_CAPACITY : resource == HEV_LWIP_RESOURCE_PBUF
    ? HEV_OWNER_FAULT_PBUF_CAPACITY : HEV_OWNER_FAULT_ALLOCATION;
  failure(owner, reason, 0, ENOMEM);
  /* A failed PCB allocation cannot invoke a session callback. Do not lose
   * that failed new-flow admission behind ip_input's consumed-pbuf result.
   * Output pbuf failure, in contrast, leaves any accepted input intact. */
  if (owner->input_active && (resource == HEV_LWIP_RESOURCE_PCB ||
                            resource == HEV_LWIP_RESOURCE_PCB_ALLOCATION))
    owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
}

static void connect_failure(owner_session_t *session, int error)
{
  hev_owner_fault_t reason = error == ECONNREFUSED ? HEV_OWNER_FAULT_CONNECT_REFUSED
    : error == ENETUNREACH || error == EHOSTUNREACH || error == ENETDOWN
    ? HEV_OWNER_FAULT_NETWORK_UNREACHABLE : HEV_OWNER_FAULT_CONNECT;
  failure(session->owner, reason, session->id, error);
}

static int create_socket(owner_session_t *session, int family, int type)
{
  hev_owner_t *owner = session->owner;
  if (owner->stats.sockets >= owner->config.max_sockets) {
    failure(owner, HEV_OWNER_FAULT_SOCKET_CAPACITY, session->id, EMFILE);
    return -1;
  }
  int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    int error = errno;
    failure(owner, error == EMFILE || error == ENFILE || error == ENOBUFS || error == ENOMEM
      ? HEV_OWNER_FAULT_SOCKET_CAPACITY : HEV_OWNER_FAULT_SOCKET_CREATE, session->id, error);
    return -1;
  }
  ++owner->stats.sockets_created;
  if (++owner->stats.sockets > owner->stats.socket_peak)
    owner->stats.socket_peak = owner->stats.sockets;
  return fd;
}

static void pbuf_event(void *opaque, void *object, unsigned kind, int allocated)
{
  hev_owner_t *owner = opaque;
  trace(owner, allocated ? "pbuf_alloc" : "pbuf_free", 0, object, 0, 0, kind);
}

static void close_session(owner_session_t *session, const char *reason)
{
  if (session->closing) return;
  session->closing = 1; /* Gate send/receive before waking its task. */
  trace(session->owner, reason, session->id,
        session->tcp ? (void *)session->tcp : (void *)session->transport, 0, 0, 0);
  if (session->task) hev_task_wakeup(session->task);
}

static void release_session(owner_session_t *session)
{
  hev_owner_t *owner = session->owner;
  owner_session_t **link = &owner->sessions;
  while (*link != session) link = &(*link)->next;
  *link = session->next;
  --owner->stats.sessions;
  ++owner->stats.sessions_closed;
  free(session);
}

static err_t output_packet(struct netif *interface, struct pbuf *packet)
{
  hev_owner_t *owner = interface->state;
  owner_session_t *session = owner->output_session;
  hev_owner_facts_t input_facts = owner->input_facts;
  if (owner->lwip.tcp_output_pcb)
    session = tcp_ext_arg_get(owner->lwip.tcp_output_pcb, 0);
  /* Stateless TCP RST has no PCB. Only the current synchronous input can
   * supply identity; it supplies no guessed underlay binding or session. */
  input_facts.availability &= HEV_OWNER_UID_KNOWN;
  input_facts.underlay_epoch = 0;
  input_facts.network_context = 0;
  const hev_owner_facts_t *facts = session ? &session->facts : &input_facts;
  hev_owner_span_t spans[64];
  unsigned count = 0;
  size_t total = 0;
  if (!owner->stats.running || (!session && !owner->input_active) ||
      (session && session->transport && session->closing)) return ERR_IF;
  ++owner->stats.output_calls;
  for (struct pbuf *p = packet; p; p = p->next) {
    if (count == 64 || p->len > owner->config.max_packet_bytes - total)
      goto rejected;
    spans[count++] = (hev_owner_span_t){p->payload, p->len};
    total += p->len;
  }
  if (!count || total != packet->tot_len) goto rejected;
  hev_owner_output_result_t result = owner->config.output(owner->config.opaque,
      spans, count, total, facts, owner->config.generation,
      ++owner->output_serial);
  trace(owner, "output", session ? session->id : 0, packet, total, result, count);
  if (result == HEV_OWNER_OUTPUT_ACCEPTED) {
    ++owner->stats.output_accepted;
    return ERR_OK;
  }
  ++owner->stats.output_rejected;
  failure(owner, result == HEV_OWNER_OUTPUT_NO_MEMORY
    ? HEV_OWNER_FAULT_OUTPUT_CAPACITY : HEV_OWNER_FAULT_OUTPUT_REJECTED,
    session ? session->id : 0, result);
  return result == HEV_OWNER_OUTPUT_NO_MEMORY ? ERR_MEM : ERR_IF;
rejected:
  ++owner->stats.output_rejected;
  failure(owner, HEV_OWNER_FAULT_OUTPUT_REJECTED, session ? session->id : 0, ERR_BUF);
  return ERR_IF;
}

static err_t output4(struct netif *interface, struct pbuf *packet, const ip4_addr_t *destination)
{ (void)destination; return output_packet(interface, packet); }
#if LWIP_IPV6
static err_t output6(struct netif *interface, struct pbuf *packet, const ip6_addr_t *destination)
{ (void)destination; return output_packet(interface, packet); }
#endif

static err_t initialize_interface(struct netif *interface)
{
  hev_owner_t *owner = interface->state;
  interface->name[0] = 'h'; interface->name[1] = 'v';
  interface->mtu = owner->config.max_packet_bytes;
  interface->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_PRETEND;
  interface->output = output4;
#if LWIP_IPV6
  interface->output_ip6 = output6;
#endif
  return ERR_OK;
}

static void session_task(void *opaque)
{
  owner_session_t *session = opaque;
  hev_owner_t *owner = session->owner;
  HevSocks5SessionUDP *transport = session->transport;
  HevTask *task = hev_task_self();
  struct sockaddr_storage destination = {0};
  int family = IP_IS_V6(&transport->pcb->local_ip) ? AF_INET6 : AF_INET;
  socklen_t destination_length;
  if (family == AF_INET6) {
#if LWIP_IPV6
    struct sockaddr_in6 *address = (struct sockaddr_in6 *)&destination;
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(transport->pcb->local_port);
    memcpy(&address->sin6_addr, ip_2_ip6(&transport->pcb->local_ip)->addr, 16);
    destination_length = sizeof(*address);
#else
    goto finished;
#endif
  } else {
    struct sockaddr_in *address = (struct sockaddr_in *)&destination;
    address->sin_family = AF_INET;
    address->sin_port = htons(transport->pcb->local_port);
    address->sin_addr.s_addr = ip_2_ip4(&transport->pcb->local_ip)->addr;
    destination_length = sizeof(*address);
  }
  if (!owner->stats.running || session->closing) goto finished;
  transport->base.fd = create_socket(session, family, SOCK_DGRAM);
  if (transport->base.fd < 0) goto finished;
  session->broker_state = 1;
  session->deadline = now_ms() + owner->config.broker_timeout_ms;
  ++owner->stats.broker_requested;
  trace(owner, "socket_created", session->id, transport, 0, transport->base.fd, 0);
  if (owner->config.broker(owner->config.opaque, owner->config.generation,
                           session->id, transport->base.fd)) {
    failure(owner, HEV_OWNER_FAULT_BROKER_SUBMIT, session->id, 0);
    goto finished;
  }
  while (owner->stats.running && !session->closing && session->broker_state == 1) {
    uint64_t now = now_ms();
    if (now >= session->deadline) {
      failure(owner, HEV_OWNER_FAULT_BROKER_TIMEOUT, session->id, ETIMEDOUT);
      goto finished;
    }
    hev_task_sleep((unsigned int)(session->deadline - now));
  }
  if (!owner->stats.running || session->closing || session->broker_state != 2)
    goto finished;
  if (connect(transport->base.fd, (struct sockaddr *)&destination,
              destination_length)) {
    connect_failure(session, errno);
    goto finished;
  }
  trace(owner, "udp_connected", session->id, transport, 0, transport->base.fd, 17);
  if (hev_task_add_fd(task, transport->base.fd, POLLIN | POLLOUT)) {
    failure(owner, HEV_OWNER_FAULT_SOCKET_IO, session->id, errno);
    goto finished;
  }
  session->deadline = now_ms() + owner->config.udp_idle_timeout_ms;
  while (owner->stats.running && !session->closing) {
    int sent, received, result = ERR_OK;
    uint64_t now = now_ms();
    if (now >= session->deadline) break;
    sent = hev_socks5_session_udp_direct_send(transport);
    unsigned requested = transport->direct_send_requested;
    if (requested) {
      ++owner->stats.udp_send_calls;
      owner->stats.udp_send_requested += requested;
      if (requested > owner->stats.udp_send_max) owner->stats.udp_send_max = requested;
      if (!sent) ++owner->stats.udp_send_blocked;
      if (sent > 0 && (unsigned)sent < requested) ++owner->stats.udp_send_partial;
    }
    if (sent < 0) {
      failure(owner, HEV_OWNER_FAULT_SOCKET_IO, session->id, errno);
      break;
    }
    if (sent) {
      owner->stats.input_packets -= (unsigned)sent;
      owner->stats.direct_sent += (unsigned)sent;
      owner->stats.udp_send_datagrams += (unsigned)sent;
      session->deadline = now + owner->config.udp_idle_timeout_ms;
    }
    owner->output_session = session;
    received = hev_socks5_session_udp_direct_receive(transport, owner->scratch,
        owner->config.max_packet_bytes - (family == AF_INET6 ? 48 : 28), &result);
    owner->output_session = NULL;
    if (received < 0) {
      failure(owner, HEV_OWNER_FAULT_SOCKET_IO, session->id, errno);
      break;
    }
    if (received) {
      ++owner->stats.direct_received;
      session->deadline = now_ms() + owner->config.udp_idle_timeout_ms;
      trace(owner, "direct_receive", session->id, transport, 0, result, 0);
    }
    if (sent || received) hev_task_yield(HEV_TASK_YIELD);
    else {
      now = now_ms();
      if (now < session->deadline)
        hev_task_sleep((unsigned int)(session->deadline - now));
    }
  }
finished:
  owner->stats.input_packets -= (unsigned)transport->frames;
  int fd = transport->base.fd;
  trace(owner, "session_closing", session->id, transport, 0, fd, 0);
  hev_object_unref(HEV_OBJECT(transport)); /* inherited close, PCB and queue free */
  if (fd >= 0) { ++owner->stats.sockets_closed; --owner->stats.sockets; }
  release_session(session);
}

static void receive_input(void *opaque, struct udp_pcb *pcb, struct pbuf *packet,
                          const ip_addr_t *address, u16_t port)
{
  owner_session_t *session = opaque;
  hev_owner_t *owner = session->owner;
  const hev_owner_facts_t *facts = &owner->input_facts;
  if (!packet) { close_session(session, "pcb_closed"); return; }
  if (session->closing || !owner->stats.running) goto rejected;
  if ((session->facts.availability & facts->availability & HEV_OWNER_UID_KNOWN) &&
      session->facts.uid != facts->uid) {
    close_session(session, "uid_conflict");
    goto rejected;
  }
  if (session->facts.flow_incarnation && facts->flow_incarnation &&
      session->facts.flow_incarnation != facts->flow_incarnation) {
    close_session(session, "flow_incarnation_conflict");
    goto rejected;
  }
  if (!session->facts.flow_incarnation)
    session->facts.flow_incarnation = facts->flow_incarnation;
  if (!(session->facts.availability & HEV_OWNER_UID_KNOWN) &&
      (facts->availability & HEV_OWNER_UID_KNOWN)) {
    session->facts.uid = facts->uid;
    session->facts.availability |= HEV_OWNER_UID_KNOWN;
  }
  if (owner->lwip.pbuf_live[HEV_LWIP_PBUF_POOL] > owner->config.max_input_packets) {
    pbuf_free(packet);
    owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
    failure(owner, HEV_OWNER_FAULT_PACKET_CREDIT, session->id, ENOBUFS);
    return;
  }
  int before = session->transport->frames;
  session->receive(session->receive_arg, pcb, packet, address, port);
  if (session->transport->frames == before) {
    owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
    failure(owner, HEV_OWNER_FAULT_ALLOCATION, session->id, ENOMEM);
    return;
  }
  ++owner->stats.input_packets;
  if (owner->stats.input_packets > owner->stats.input_peak)
    owner->stats.input_peak = owner->stats.input_packets;
  owner->input_result = HEV_OWNER_INPUT_ACCEPTED;
  return;
rejected:
  pbuf_free(packet);
  owner->input_result = HEV_OWNER_INPUT_FAILED;
}

static void create_session(void *opaque, struct udp_pcb *pcb, struct pbuf *packet,
                           const ip_addr_t *address, u16_t port)
{
  hev_owner_t *owner = opaque;
  owner_session_t *session;
  HevTask *task;
  (void)packet; (void)address; (void)port;
  owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
  if (owner->stats.sessions >= owner->config.max_sessions ||
      owner->session_serial == UINT64_MAX) {
    failure(owner, HEV_OWNER_FAULT_SESSION_CAPACITY, 0, ENOBUFS);
    goto rejected;
  }
  if (owner->lwip.pbuf_live[HEV_LWIP_PBUF_POOL] > owner->config.max_input_packets) {
    failure(owner, HEV_OWNER_FAULT_PACKET_CREDIT, 0, ENOBUFS);
    goto rejected;
  }
  session = calloc(1, sizeof(*session));
  if (!session) goto allocation_failed;
  task = hev_task_new(owner->config.task_stack_bytes);
  if (!task) { free(session); goto allocation_failed; }
  session->transport = hev_socks5_session_udp_direct_new(pcb, &owner->mutex,
      owner->config.max_input_packets);
  if (!session->transport) {
    hev_task_unref(task); free(session); goto allocation_failed;
  }
  session->owner = owner;
  session->task = task;
  session->facts = owner->input_facts;
  /* Input's network observation is not proof of socket binding. */
  session->facts.availability &= HEV_OWNER_UID_KNOWN;
  session->facts.network_context = 0;
  session->facts.underlay_epoch = 0;
  session->id = ++owner->session_serial;
  session->receive = pcb->recv;
  session->receive_arg = pcb->recv_arg;
  udp_recv(pcb, receive_input, session);
  hev_socks5_session_set_task(HEV_SOCKS5_SESSION(session->transport), task);
  session->next = owner->sessions;
  owner->sessions = session;
  ++owner->stats.sessions;
  ++owner->stats.sessions_created;
  trace(owner, "session_created", session->id, session->transport, 0, 0, 0);
  hev_task_run(task, session_task, session);
  return;
allocation_failed:
  failure(owner, HEV_OWNER_FAULT_ALLOCATION, 0, ENOMEM);
rejected:
  udp_remove(pcb);
}

static void tcp_pcb_destroyed(u8_t id, void *opaque)
{
  owner_session_t *session = opaque;
  (void)id;
  if (!session) return;
  trace(session->owner, "tcp_pcb_destroyed", session->id, session->pcb, 0, 0, 6);
  session->pcb = NULL;
  if (session->tcp) session->tcp->pcb = NULL;
  close_session(session, "tcp_pcb_closed");
  if (!session->task) release_session(session);
}

static void tcp_session_task(void *opaque)
{
  owner_session_t *session = opaque;
  hev_owner_t *owner = session->owner;
  HevSocks5SessionTCP *transport = session->tcp;
  HevSocks5 *socket_owner = HEV_SOCKS5(transport);
  struct sockaddr_storage destination = {0};
  socklen_t destination_length;
  int family, graceful = 0;
  if (!owner->stats.running || session->closing || !session->pcb) goto finished;
  family = IP_IS_V6(&session->pcb->local_ip) ? AF_INET6 : AF_INET;
  if (family == AF_INET6) {
    struct sockaddr_in6 *address = (struct sockaddr_in6 *)&destination;
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(session->pcb->local_port);
    memcpy(&address->sin6_addr, ip_2_ip6(&session->pcb->local_ip)->addr, 16);
    destination_length = sizeof(*address);
  } else {
    struct sockaddr_in *address = (struct sockaddr_in *)&destination;
    address->sin_family = AF_INET;
    address->sin_port = htons(session->pcb->local_port);
    address->sin_addr.s_addr = ip_2_ip4(&session->pcb->local_ip)->addr;
    destination_length = sizeof(*address);
  }
  socket_owner->fd = create_socket(session, family, SOCK_STREAM);
  if (socket_owner->fd < 0) goto finished;
  session->broker_state = 1;
  session->deadline = now_ms() + owner->config.broker_timeout_ms;
  ++owner->stats.broker_requested;
  trace(owner, "socket_created", session->id, transport, 0, socket_owner->fd, 6);
  if (owner->config.broker(owner->config.opaque, owner->config.generation,
                          session->id, socket_owner->fd)) {
    failure(owner, HEV_OWNER_FAULT_BROKER_SUBMIT, session->id, 0);
    goto finished;
  }
  while (owner->stats.running && !session->closing && session->broker_state == 1) {
    uint64_t now = now_ms();
    if (now >= session->deadline) {
      failure(owner, HEV_OWNER_FAULT_BROKER_TIMEOUT, session->id, ETIMEDOUT);
      goto finished;
    }
    hev_task_sleep((unsigned)(session->deadline - now));
  }
  if (!owner->stats.running || session->closing || session->broker_state != 2)
    goto finished;
  /* The SYN-created session owns initial SYN-ACK/retransmission facts, but
   * kernel connect waits for the real inner handshake and successful protect. */
  while (owner->stats.running && !session->closing && !session->tcp_accepted)
    hev_task_yield(HEV_TASK_WAITIO);
  if (!owner->stats.running || session->closing) goto finished;
  if (hev_task_add_fd(session->task, socket_owner->fd, POLLIN | POLLOUT)) {
    failure(owner, HEV_OWNER_FAULT_SOCKET_IO, session->id, errno);
    goto finished;
  }
  int connected = connect(socket_owner->fd, (struct sockaddr *)&destination,
                          destination_length);
  int connect_error = connected ? errno : 0;
  trace(owner, "tcp_connect_attempt", session->id, transport, destination_length,
        connected, (unsigned)connect_error);
  if (connected && connect_error != EINPROGRESS) {
    trace(owner, "tcp_connect_failed", session->id, transport, 0, connect_error, 6);
    connect_failure(session, connect_error);
    goto finished;
  }
  session->deadline = now_ms() + 10000; /* Pinned HEV connect-timeout default. */
  while (connected && owner->stats.running && !session->closing) {
    struct pollfd descriptor = {socket_owner->fd, POLLOUT, 0};
    int ready = poll(&descriptor, 1, 0);
    if (ready < 0 && errno != EINTR) {
      connect_failure(session, errno);
      goto finished;
    }
    if (ready > 0 && descriptor.revents) {
      int error = 0;
      socklen_t size = sizeof(error);
      int queried = getsockopt(socket_owner->fd, SOL_SOCKET, SO_ERROR, &error, &size);
      trace(owner, "tcp_connect_ready", session->id, transport,
            (size_t)descriptor.revents, error, (unsigned)queried);
      if (queried || error) {
        trace(owner, "tcp_connect_failed", session->id, transport, 0, error, 6);
        connect_failure(session, queried ? errno : error);
        goto finished;
      }
      connected = 0;
      break;
    }
    uint64_t now = now_ms();
    if (now >= session->deadline) {
      connect_failure(session, ETIMEDOUT);
      goto finished;
    }
    hev_task_sleep((unsigned)(session->deadline - now));
  }
  if (!owner->stats.running || session->closing) goto finished;
  trace(owner, "tcp_connected", session->id, transport, 0, socket_owner->fd, 6);
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
  unsigned registered_events = POLLIN | POLLOUT;
#endif
  while (owner->stats.running && !session->closing && transport->pcb) {
    uint64_t sent_before = transport->direct_sent_bytes;
    uint64_t received_before = transport->direct_received_bytes;
    struct tcp_pcb *pcb = transport->pcb;
    size_t used = transport->buffer->use_size;
    size_t pending = transport->buffer->rda_size;
    u32_t flight = pcb->snd_nxt - pcb->lastack;
    u16_t mss = tcp_mss(pcb);
    if (used == transport->buffer->max_size) ++owner->stats.tcp_ring_full;
    if (!tcp_sndbuf(pcb)) ++owner->stats.tcp_sndbuf_full;
    if (flight >= pcb->snd_wnd) ++owner->stats.tcp_window_full;
    if (flight >= pcb->cwnd) ++owner->stats.tcp_cwnd_full;
    if (pending) ++owner->stats.tcp_pending_rounds;
    if (used > owner->stats.tcp_ring_peak) owner->stats.tcp_ring_peak = used;
    if (pending > owner->stats.tcp_pending_peak) owner->stats.tcp_pending_peak = pending;
    if (flight > owner->stats.tcp_flight_peak) owner->stats.tcp_flight_peak = flight;
    if (!owner->stats.tcp_mss_min || mss < owner->stats.tcp_mss_min)
      owner->stats.tcp_mss_min = mss;
    if (mss > owner->stats.tcp_mss_max) owner->stats.tcp_mss_max = mss;
    int sent = hev_socks5_session_tcp_direct_send(transport);
    int send_error = sent == -2 ? errno : 0;
    int received = sent == -2 ? -2 : hev_socks5_session_tcp_direct_receive(transport);
    int receive_error = received == -2 ? errno : 0;
    if (sent != -2) {
      ++owner->stats.tcp_rx_rounds;
      owner->stats.tcp_read_calls += transport->direct_read_calls;
      owner->stats.tcp_read_blocked += transport->direct_read_blocked;
      owner->stats.tcp_commits += transport->direct_commits;
      owner->stats.tcp_commit_bytes += transport->direct_commit_bytes;
      owner->stats.tcp_write_blocked += transport->direct_write_blocked;
      owner->stats.tcp_output_calls += transport->direct_output_calls;
      if (transport->direct_commits > owner->stats.tcp_commit_max)
        owner->stats.tcp_commit_max = transport->direct_commits;
      if (transport->direct_sent_bytes == sent_before &&
          transport->direct_received_bytes == received_before &&
          !transport->direct_commit_bytes) ++owner->stats.tcp_idle_rounds;
    }
    if (transport->direct_write_error) {
      trace(owner, "tcp_write_deferred", session->id, transport,
            transport->direct_deferred_bytes, transport->direct_write_error,
            owner->lwip.pbufs);
      transport->direct_write_error = 0;
    }
    if (transport->direct_sent_bytes != sent_before) {
      ++owner->stats.direct_sent;
      trace(owner, "tcp_direct_send", session->id, transport,
            transport->direct_sent_bytes - sent_before, sent, 6);
    }
    if (transport->direct_received_bytes != received_before) {
      ++owner->stats.direct_received;
      trace(owner, "tcp_direct_receive", session->id, transport,
            transport->direct_received_bytes - received_before, received, 6);
    }
    if (sent == -2 || received == -2) {
      failure(owner, HEV_OWNER_FAULT_SOCKET_IO, session->id,
              sent == -2 ? send_error : receive_error);
      break;
    }
    if (transport->direct_tx_eof && transport->direct_fin_sent && !transport->queue &&
        !hev_ring_buffer_get_use_size(transport->buffer)) {
      graceful = 1;
      break;
    }
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
    /* A full ring cannot consume socket data. Keep the original owner and
     * transport state, but suppress new-data edges until space exists. ACK
     * callbacks still wake this task; every resumed round tries nonblocking
     * receive before considering its subscription, even with POLLIN disabled.
     * Thus queued data never depends on a new socket edge after ACK release. */
    unsigned wanted = POLLERR;
    if (!transport->direct_rx_eof &&
        transport->buffer->use_size < transport->buffer->max_size) wanted |= POLLIN;
    if (!transport->direct_tx_eof && transport->queue) wanted |= POLLOUT;
    if (wanted != registered_events) {
      if (hev_task_mod_fd(session->task, socket_owner->fd, wanted)) {
        failure(owner, HEV_OWNER_FAULT_SOCKET_IO, session->id, errno);
        break;
      }
      ++owner->stats.tcp_interest_changes;
      if ((registered_events & POLLIN) && !(wanted & POLLIN)) ++owner->stats.tcp_read_pauses;
      if (!(registered_events & POLLIN) && (wanted & POLLIN)) ++owner->stats.tcp_read_resumes;
      registered_events = wanted;
    }
#endif
    hev_task_yield(sent > 0 || received > 0 ? HEV_TASK_YIELD : HEV_TASK_WAITIO);
  }
finished:
  if (graceful && session->pcb) {
    trace(owner, "tcp_graceful_detach", session->id, session->pcb, 0,
          session->pcb->state, 6);
    hev_socks5_session_tcp_direct_detach(transport);
  }
  int fd = socket_owner->fd;
  trace(owner, "session_closing", session->id, transport, 0, fd, 6);
  hev_object_unref(HEV_OBJECT(transport));
  if (fd >= 0) { ++owner->stats.sockets_closed; --owner->stats.sockets; }
  session->tcp = NULL;
  session->task = NULL;
  /* Graceful FIN/TIME_WAIT PCB keeps only this transport's minimal facts.
   * It is reclaimed by lwIP's timer, or synchronously by owner quiesce. */
  if (!session->pcb) release_session(session);
}

static err_t create_tcp_session(u8_t id, struct tcp_pcb_listen *listener,
                                struct tcp_pcb *pcb)
{
  hev_owner_t *owner = listener->callback_arg;
  owner_session_t *session;
  HevTask *task;
  static const struct tcp_ext_arg_callbacks callbacks = {tcp_pcb_destroyed, NULL};
  if (!owner->stats.running) goto rejected;
  if (owner->stats.sessions >= owner->config.max_sessions ||
      owner->session_serial == UINT64_MAX) {
    failure(owner, HEV_OWNER_FAULT_SESSION_CAPACITY, 0, ENOBUFS);
    goto rejected;
  }
  session = calloc(1, sizeof(*session));
  if (!session) goto allocation_failed;
  task = hev_task_new(owner->config.task_stack_bytes);
  if (!task) { free(session); goto allocation_failed; }
  session->tcp = hev_socks5_session_tcp_direct_new(pcb, &owner->mutex, TCP_SND_BUF);
  if (!session->tcp) { hev_task_unref(task); free(session); goto allocation_failed; }
  session->owner = owner;
  session->task = task;
  session->pcb = pcb;
  session->facts = owner->input_facts;
  session->facts.availability &= HEV_OWNER_UID_KNOWN;
  session->facts.network_context = 0;
  session->facts.underlay_epoch = 0;
  session->id = ++owner->session_serial;
  hev_socks5_session_set_task(HEV_SOCKS5_SESSION(session->tcp), task);
  tcp_ext_arg_set(pcb, id, session);
  tcp_ext_arg_set_callbacks(pcb, id, &callbacks);
  session->next = owner->sessions;
  owner->sessions = session;
  ++owner->stats.sessions;
  ++owner->stats.sessions_created;
  trace(owner, "session_created", session->id, session->tcp, 0, 0, 6);
  trace(owner, "tcp_pcb_created", session->id, pcb, 0, pcb->state, 6);
  hev_task_run(task, tcp_session_task, session);
  owner->input_result = HEV_OWNER_INPUT_ACCEPTED;
  return ERR_OK;
allocation_failed:
  failure(owner, HEV_OWNER_FAULT_ALLOCATION, 0, ENOMEM);
rejected:
  owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
  return ERR_MEM; /* lwIP owns the rejected candidate PCB. */
}

static err_t accept_tcp_session(void *opaque, struct tcp_pcb *pcb, err_t error)
{
  (void)opaque;
  if (!pcb || error != ERR_OK) return ERR_MEM;
  owner_session_t *session = tcp_ext_arg_get(pcb, 0);
  if (!session || session->closing) return ERR_VAL;
  session->tcp_accepted = 1;
  trace(session->owner, "tcp_handshake", session->id, pcb, 0, pcb->state, 6);
  hev_task_wakeup(session->task);
  return ERR_OK;
}

static err_t guard_tcp_input(void *opaque, struct tcp_pcb *pcb)
{
  hev_owner_t *owner = opaque;
  if (pcb->state == LISTEN) {
    if (owner->stats.sessions >= owner->config.max_sessions) {
      owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
      failure(owner, HEV_OWNER_FAULT_SESSION_CAPACITY, 0, ENOBUFS);
      return ERR_MEM;
    }
    if (owner->lwip.pbuf_live[HEV_LWIP_PBUF_POOL] > owner->config.max_input_packets) {
      owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
      failure(owner, HEV_OWNER_FAULT_PACKET_CREDIT, 0, ENOBUFS);
      return ERR_MEM;
    }
    return ERR_OK;
  }
  owner_session_t *session = tcp_ext_arg_get(pcb, 0);
  if (!session) return ERR_OK;
  if ((session->facts.availability & owner->input_facts.availability & HEV_OWNER_UID_KNOWN) &&
      session->facts.uid != owner->input_facts.uid)
    close_session(session, "uid_conflict");
  if (session->facts.flow_incarnation && owner->input_facts.flow_incarnation &&
      session->facts.flow_incarnation != owner->input_facts.flow_incarnation)
    close_session(session, "flow_incarnation_conflict");
  if (!session->facts.flow_incarnation)
    session->facts.flow_incarnation = owner->input_facts.flow_incarnation;
  if (!(session->facts.availability & HEV_OWNER_UID_KNOWN) &&
      (owner->input_facts.availability & HEV_OWNER_UID_KNOWN)) {
    session->facts.uid = owner->input_facts.uid;
    session->facts.availability |= HEV_OWNER_UID_KNOWN;
  }
  if (session->closing) {
    /* This hook must not mutate PCB lists. The task/next owner step aborts
     * after tcp_input returns, even for a detached TIME_WAIT record. */
    owner->input_result = HEV_OWNER_INPUT_FAILED;
    return ERR_VAL;
  }
  if (owner->lwip.pbuf_live[HEV_LWIP_PBUF_POOL] > owner->config.max_input_packets) {
    owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
    failure(owner, HEV_OWNER_FAULT_PACKET_CREDIT, session->id, ENOBUFS);
    return ERR_MEM;
  }
  return ERR_OK;
}

hev_owner_t *hev_owner_create(const hev_owner_config_t *config)
{
  if (!config || !config->generation || !config->max_sessions ||
      config->max_sessions > UINT32_MAX - 2 || (config->max_pcbs && config->max_pcbs < 3) ||
      !config->max_input_packets || config->max_input_packets > INT_MAX ||
      !config->max_pbufs || config->max_packet_bytes < 29 ||
      config->max_packet_bytes > 65535 || config->task_stack_bytes < 32768 ||
      config->task_stack_bytes > INT_MAX || !config->broker_timeout_ms ||
      !config->udp_idle_timeout_ms || !config->output || !config->broker)
    return NULL;
  hev_owner_t *owner = calloc(1, sizeof(*owner));
  if (!owner) return NULL;
  owner->config = *config;
  owner->stats.tcp_buffer_bytes = TCP_SND_BUF;
  if (!owner->config.max_pcbs) owner->config.max_pcbs = config->max_sessions + 2;
  if (!owner->config.max_sockets) owner->config.max_sockets = config->max_sessions;
  owner->scratch = malloc(config->max_packet_bytes - 28);
  if (!owner->scratch) { free(owner); return NULL; }
  pthread_once(&classes_once, initialize_classes);
  HevTaskSystemContext *previous = hev_task_system_get_context();
  if (hev_task_system_set_context(NULL)) abort();
  if (hev_task_system_init()) {
    if (hev_task_system_set_context(previous)) abort();
    free(owner->scratch); free(owner); return NULL;
  }
  owner->scheduler = hev_task_system_get_context();
  hev_lwip_context_init(&owner->lwip);
  owner->lwip.max_pbufs = config->max_pbufs;
  owner->lwip.max_pcbs = owner->config.max_pcbs;
  owner->lwip.resource_failure = resource_failure;
  owner->lwip.resource_opaque = owner;
  owner->lwip.pbuf_event = pbuf_event;
  owner->lwip.pbuf_opaque = owner;
  owner->lwip.tcp_input_guard = guard_tcp_input;
  owner->lwip.tcp_opaque = owner;
  hev_lwip_context_t *previous_lwip = hev_lwip_context_bind(&owner->lwip);
  lwip_init();
  hev_task_mutex_init(&owner->mutex);
  ip4_addr_t address, mask, gateway;
  IP4_ADDR(&address, 10, 0, 0, 1);
  IP4_ADDR(&mask, 255, 255, 255, 0);
  ip4_addr_set_zero(&gateway);
  int added = netif_add(&owner->interface, &address, &mask, &gateway, owner,
                         initialize_interface, ip_input) != NULL;
  if (added) {
    netif_set_default(&owner->interface);
    owner->listener = udp_new_ip_type(IPADDR_TYPE_ANY);
  }
  if (owner->listener) {
    owner->listener->pretend_netif_idx = netif_get_index(&owner->interface);
    if (udp_bind(owner->listener, IP_ANY_TYPE, 0) == ERR_OK) {
      udp_recv(owner->listener, create_session, owner);
      struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
      if (pcb) {
        tcp_bind_netif(pcb, &owner->interface);
        if (tcp_bind(pcb, NULL, 0) == ERR_OK)
          owner->tcp_listener = tcp_listen(pcb);
        if (!owner->tcp_listener) tcp_abort(pcb);
      }
      if (owner->tcp_listener) {
        static const struct tcp_ext_arg_callbacks callbacks = {NULL, create_tcp_session};
        u8_t id = tcp_ext_arg_alloc_id();
        if (id != 0) abort();
        tcp_arg(owner->tcp_listener, owner);
        tcp_ext_arg_set_callbacks(owner->tcp_listener, id, &callbacks);
        tcp_accept(owner->tcp_listener, accept_tcp_session);
        owner->stats.running = 1;
      }
    }
  }
  if (!owner->stats.running) {
    if (owner->tcp_listener) tcp_close(owner->tcp_listener);
    if (owner->listener) udp_remove(owner->listener);
    if (added) netif_remove(&owner->interface);
    hev_task_system_fini();
  }
  hev_lwip_context_bind(previous_lwip);
  if (hev_task_system_set_context(previous)) abort();
  if (!owner->stats.running) {
    free(owner->scratch); free(owner); return NULL;
  }
  return owner;
}

hev_owner_input_result_t hev_owner_input_copy(hev_owner_t *owner,
    const uint8_t *l3, size_t length, const hev_owner_facts_t *facts,
    uint64_t generation)
{
  owner_scope_t scope;
  if (enter(owner, &scope)) return HEV_OWNER_INPUT_FAILED;
  ++owner->stats.input_calls;
  owner->input_result = HEV_OWNER_INPUT_FAILED;
  if (!owner->stats.running) owner->input_result = HEV_OWNER_INPUT_NOT_RUNNING;
  else if (generation != owner->config.generation) {
    ++owner->stats.stale_generation;
    owner->input_result = HEV_OWNER_INPUT_WRONG_GENERATION;
  } else if (!l3 || !facts || length < 28 || length > owner->config.max_packet_bytes) {
    owner->input_result = HEV_OWNER_INPUT_FAILED;
  } else if (!((l3[0] >> 4 == 4 && (l3[9] == 17 || l3[9] == 6))
#if LWIP_IPV6
               || (length >= 48 && l3[0] >> 4 == 6 &&
                   (l3[6] == 17 || l3[6] == 6 || l3[6] == 0 || l3[6] == 43 || l3[6] == 60))
#endif
              )) {
    owner->input_result = HEV_OWNER_INPUT_UNSUPPORTED;
  } else {
    owner->input_facts = *facts;
    struct pbuf *packet = pbuf_alloc(PBUF_RAW, length, PBUF_POOL);
    if (!packet) owner->input_result = HEV_OWNER_INPUT_NO_CAPACITY;
    else {
      ++owner->stats.input_copy_calls;
      owner->stats.input_copy_bytes += length;
      if (pbuf_take(packet, l3, length) != ERR_OK) pbuf_free(packet);
      else {
        /* Boundary acceptance is not an assertion that lwIP delivered data.
         * TCP pure ACK/FIN/retransmit need not invoke an application callback. */
        owner->input_result = HEV_OWNER_INPUT_ACCEPTED;
        owner->input_active = 1;
        if (ip_input(packet, &owner->interface) != ERR_OK)
          owner->input_result = HEV_OWNER_INPUT_FAILED;
        owner->input_active = 0;
      }
    }
  }
  hev_owner_input_result_t result = owner->input_result;
  if (result == HEV_OWNER_INPUT_ACCEPTED) ++owner->stats.input_accepted;
  else ++owner->stats.input_rejected;
  leave(owner, &scope);
  return result;
}

int hev_owner_broker_complete(hev_owner_t *owner, uint64_t generation,
    uint64_t id, int success, const hev_owner_binding_t *binding)
{
  return hev_owner_broker_result(owner, generation, id, success ? 0 : 4, binding);
}

int hev_owner_broker_result(hev_owner_t *owner, uint64_t generation,
    uint64_t id, unsigned error, const hev_owner_binding_t *binding)
{
  owner_scope_t scope;
  int success = error == 0;
  if (error != 0 && error != 2 && error != 3 && error != 4 && error != 5) return -1;
  if (success && (!binding || !binding->underlay_epoch || binding->context_known > 1)) return -1;
  if (enter(owner, &scope)) return -1;
  int result = -1;
  if (generation == owner->config.generation && owner->stats.running) {
    for (owner_session_t *s = owner->sessions; s; s = s->next) {
      if (s->id != id || s->closing || s->broker_state != 1) continue;
      if (now_ms() >= s->deadline) {
        failure(owner, HEV_OWNER_FAULT_BROKER_TIMEOUT, s->id, ETIMEDOUT);
        close_session(s, "broker_timeout");
        break;
      }
      s->broker_state = success ? 2 : -1;
      if (!success)
        failure(owner, error == 2 ? HEV_OWNER_FAULT_PROTECT : error == 3
          ? HEV_OWNER_FAULT_BIND : error == 5 ? HEV_OWNER_FAULT_NETWORK_UNREACHABLE
          : HEV_OWNER_FAULT_AUTHORIZATION, s->id, (int)error);
      if (success) {
        s->facts.underlay_epoch = binding->underlay_epoch;
        s->facts.network_context = binding->context_known ? binding->network_context : 0;
        if (binding->context_known) s->facts.availability |= HEV_OWNER_CONTEXT_KNOWN;
      }
      ++owner->stats.broker_completed;
      if (s->task) hev_task_wakeup(s->task);
      result = 0;
      break;
    }
  } else if (generation != owner->config.generation) ++owner->stats.stale_generation;
  leave(owner, &scope);
  return result;
}

int hev_owner_invalidate_underlay(hev_owner_t *owner, uint64_t generation,
                                  uint64_t epoch)
{
  owner_scope_t scope;
  if (!epoch || enter(owner, &scope)) return -1;
  int result = -1;
  if (generation == owner->config.generation && owner->stats.running) {
    result = 0;
    /* The fixed owner session cap bounds this control-event scan. Pending
     * authorizations have no binding yet: the ordered broker sends every old
     * epoch reply before its invalidation and never authorizes it afterwards. */
    for (owner_session_t *s = owner->sessions; s; s = s->next) {
      if (s->closing || s->broker_state != 2 || s->facts.underlay_epoch != epoch) continue;
      failure(owner, HEV_OWNER_FAULT_NETWORK_UNREACHABLE, s->id, ENETDOWN);
      close_session(s, "underlay_invalidated");
    }
  } else if (generation != owner->config.generation) ++owner->stats.stale_generation;
  leave(owner, &scope);
  return result;
}

void hev_owner_quiesce(hev_owner_t *owner)
{
  owner_scope_t scope;
  if (enter(owner, &scope)) return;
  owner->stats.running = 0;
  for (owner_session_t *s = owner->sessions; s; s = s->next)
    close_session(s, "quiesce");
  leave(owner, &scope);
}

hev_owner_step_result_t hev_owner_step(hev_owner_t *owner, uint32_t quanta,
                                      uint32_t max_us)
{
  owner_scope_t scope;
  hev_owner_step_result_t result = {.timeout_ms = -1};
  if (enter(owner, &scope)) return result;
  ++owner->stats.steps;
  /* One bounded protocol-timer turn at a time. No busy sleep or catch-up loop;
   * the external driver receives the next deadline through this same seam. */
  if (owner->stats.running && (tcp_active_pcbs || tcp_tw_pcbs)) {
    uint64_t now = now_ms();
    if (!owner->next_tcp_timer) owner->next_tcp_timer = now + TCP_TMR_INTERVAL;
    if (now >= owner->next_tcp_timer) {
      tcp_tmr();
      owner->next_tcp_timer += TCP_TMR_INTERVAL;
    }
  } else owner->next_tcp_timer = 0;
  for (owner_session_t *s = owner->sessions, *next; s; s = next) {
    next = s->next;
    if (s->closing && !s->task && s->pcb) tcp_abort(s->pcb);
  }
  result.quanta = hev_task_system_step(quanta, max_us);
  owner->stats.task_quanta += result.quanta;
  result.runnable = owner->scheduler->running_task_count;
  result.timeout_ms = hev_task_timer_get_timeout(owner->scheduler->timer);
  if (owner->stats.running && (tcp_active_pcbs || tcp_tw_pcbs)) {
    uint64_t now = now_ms();
    if (!owner->next_tcp_timer) owner->next_tcp_timer = now + TCP_TMR_INTERVAL;
    int timeout = owner->next_tcp_timer > now ? (int)(owner->next_tcp_timer - now) : 0;
    if (result.timeout_ms < 0 || timeout < result.timeout_ms) result.timeout_ms = timeout;
  }
  if (!owner->stats.running && !owner->scheduler->total_task_count &&
      !hev_list_first(&owner->scheduler->all_tasks) &&
      !owner->stats.sessions && !owner->stats.input_packets && !owner->lwip.pbufs)
    owner->stats.stopped = 1;
  result.stopped = owner->stats.stopped;
  leave(owner, &scope);
  return result;
}

int hev_owner_destroy(hev_owner_t *owner)
{
  owner_scope_t scope;
  if (!owner || !owner->stats.stopped || enter(owner, &scope)) return -1;
  udp_remove(owner->listener);
  tcp_close(owner->tcp_listener);
  netif_remove(&owner->interface);
  if (owner->lwip.heap_live || owner->lwip.pbufs || owner->lwip.pcbs || owner->lwip.udp ||
      tcp_bound_pcbs || tcp_listen_pcbs.pcbs || tcp_active_pcbs || tcp_tw_pcbs) abort();
  trace(owner, "pcbs_reclaimed", 0, owner, owner->lwip.pcbs,
        owner->lwip.pcb_allocations == owner->lwip.pcb_frees ? 0 : -1, 0);
  hev_task_system_fini();
  trace(owner, "owner_destroyed", 0, owner, owner->lwip.heap_live, 0, owner->lwip.pbufs);
  leave(owner, &scope);
  free(owner->scratch); free(owner);
  return 0;
}

hev_owner_snapshot_t hev_owner_snapshot(const hev_owner_t *owner)
{
  hev_owner_snapshot_t result = {0};
  if (!owner || (owner->bound && !pthread_equal(owner->thread, pthread_self())))
    return result;
  result = owner->stats;
  const hev_lwip_context_t *c = &owner->lwip;
  result.pbufs = c->pbufs; result.pbuf_peak = c->pbuf_peak;
  result.pcbs = c->pcbs; result.pcb_peak = c->pcb_peak;
  result.pcb_allocations = c->pcb_allocations; result.pcb_frees = c->pcb_frees;
  result.input_pbufs = c->pbuf_live[HEV_LWIP_PBUF_POOL];
  result.pool_live = c->pbuf_live[HEV_LWIP_PBUF_POOL];
  result.ram_live = c->pbuf_live[HEV_LWIP_PBUF_RAM];
  result.ref_live = c->pbuf_live[HEV_LWIP_PBUF_REF];
  result.pool_allocations = c->pbuf_allocations[HEV_LWIP_PBUF_POOL];
  result.pool_frees = c->pbuf_frees[HEV_LWIP_PBUF_POOL];
  result.ram_allocations = c->pbuf_allocations[HEV_LWIP_PBUF_RAM];
  result.ram_frees = c->pbuf_frees[HEV_LWIP_PBUF_RAM];
  result.ref_allocations = c->pbuf_allocations[HEV_LWIP_PBUF_REF];
  result.ref_frees = c->pbuf_frees[HEV_LWIP_PBUF_REF];
  result.lwip_heap_allocations = c->heap_allocations;
  result.lwip_heap_frees = c->heap_frees;
  result.lwip_heap_live = c->heap_live;
  result.lwip_heap_bytes = c->heap_bytes;
  result.lwip_heap_peak_bytes = c->heap_peak_bytes;
  return result;
}

int hev_owner_poll_fd(const hev_owner_t *owner)
{
  if (!owner || (owner->bound && !pthread_equal(owner->thread, pthread_self())))
    return -1;
  return owner->scheduler->reactor->fd;
}

const char *hev_owner_upstream_revision(void)
{ return "3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70"; }
