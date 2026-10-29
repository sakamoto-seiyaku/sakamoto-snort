/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_root_dns_io.h"
#include "product_dns_route.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
  product_dns_proxy_key_t key;
  uint16_t id;
  uint8_t active, channel;
  uint8_t *pending; size_t length; uint64_t deadline;
} udp_request_t;
typedef struct {
  product_dns_proxy_key_t key;
  uint64_t cookie, deadline;
  int fd;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  uint8_t connecting, authorized, header[2];
  uint8_t *output, *input;
  size_t output_length, output_at, input_length, input_at, header_at;
} tcp_socket_t;
#define ROOT_DNS_UPSTREAM_SOCKETS (PRODUCT_DNS_PROXY_SOCKETS - 2U)
typedef struct {
  uint64_t cookie, last_activity;
  int fd;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  uint8_t authorized;
} udp_socket_t;
struct product_root_dns_io {
  uint64_t generation;
  uint64_t *sequence;
  uint32_t mark;
  size_t pending_bytes;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  product_root_dns_io_callbacks_t callbacks;
  void *context;
  product_root_dns_io_status_t status;
  udp_socket_t channels[ROOT_DNS_UPSTREAM_SOCKETS];
  udp_request_t udp[PRODUCT_DNS_PROXY_TRANSACTIONS];
  tcp_socket_t tcp[PRODUCT_ROOT_DNS_TCP_SOCKETS];
  uint8_t received[PRODUCT_DNS_MESSAGE_MAX];
};

uint64_t product_root_dns_io_reservation (void)
{
  return sizeof (product_root_dns_io_t) + PRODUCT_ROOT_DNS_TCP_SOCKETS *
    (2U * PRODUCT_DNS_MESSAGE_MAX + 2U) +
    PRODUCT_DNS_MESSAGE_MAX;
}

static int same_key (const product_dns_proxy_key_t *a, const product_dns_proxy_key_t *b)
{ return !memcmp (a, b, sizeof (*a)); }

static void allocation (product_root_dns_io_t *io, size_t bytes)
{
  io->status.allocated_bytes += bytes;
  if (io->status.allocated_bytes > io->status.high_water_bytes)
    io->status.high_water_bytes = io->status.allocated_bytes;
}

static int new_socket (product_root_dns_io_t *io, unsigned family, unsigned type, uint64_t *cookie)
{
  if (io->status.sockets >= ROOT_DNS_UPSTREAM_SOCKETS) { ++io->status.capacity; return -2; }
  if (*io->sequence == (UINT64_C(1) << 42) - 1) return -1;
  int fd = socket (family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  if (io->mark && setsockopt (fd, SOL_SOCKET, SO_MARK, &io->mark, sizeof (io->mark)))
    { close (fd); return -1; }
  *cookie = ++*io->sequence;
  ++io->status.sockets; ++io->status.opened;
  if (io->status.sockets > io->status.high_water_sockets)
    io->status.high_water_sockets = io->status.sockets;
  return fd;
}

static void close_socket (product_root_dns_io_t *io, int *fd, uint64_t cookie)
{
  if (*fd < 0) return;
  int owned = *fd; *fd = -1;
  (void) io->callbacks.watch (io->context, owned, 0, cookie);
  close (owned); --io->status.sockets; ++io->status.closed;
}

static void close_tcp (product_root_dns_io_t *io, tcp_socket_t *tcp)
{
  close_socket (io, &tcp->fd, tcp->cookie);
  io->status.allocated_bytes -= tcp->output_length + tcp->input_length;
  free (tcp->output); free (tcp->input);
  memset (tcp, 0, sizeof (*tcp)); tcp->fd = -1;
}

static int same_address (const struct sockaddr_storage *a, socklen_t alen,
  const struct sockaddr_storage *b, socklen_t blen)
{ return alen == blen && !memcmp (a, b, alen); }

static int selected_address (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  struct sockaddr_storage *resolver, socklen_t *length)
{
  memset (resolver, 0, sizeof (*resolver));
  if (!key || !key->resolver_family) { *resolver = io->resolver; *length = io->resolver_length; return 1; }
  if (!key->resolver_port || key->resolver_port > UINT16_MAX) return 0;
  if (key->resolver_family == 4)
    {
      struct sockaddr_in *a = (struct sockaddr_in *) resolver;
      a->sin_family = AF_INET; a->sin_port = htons (key->resolver_port);
      memcpy (&a->sin_addr, key->resolver_address, 4); *length = sizeof (*a); return 1;
    }
  if (key->resolver_family == 6)
    {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *) resolver;
      a->sin6_family = AF_INET6; a->sin6_port = htons (key->resolver_port);
      memcpy (&a->sin6_addr, key->resolver_address, 16); *length = sizeof (*a); return 1;
    }
  return 0;
}

static int udp_default (const product_root_dns_io_t *io, const udp_socket_t *channel)
{ return same_address (&io->resolver, io->resolver_length, &channel->resolver, channel->resolver_length); }
static int udp_busy (const product_root_dns_io_t *io, unsigned channel)
{
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active && io->udp[i].channel == channel) return 1;
  return 0;
}
static void close_udp (product_root_dns_io_t *io, udp_socket_t *channel, int failed)
{
  int is_default = udp_default (io, channel), authorized = channel->authorized;
  close_socket (io, &channel->fd, channel->cookie);
  channel->authorized = 0;
  if (is_default) io->status.udp_state = !failed && authorized
    ? PRODUCT_ROOT_DNS_UDP_IDLE : PRODUCT_ROOT_DNS_UDP_FAILED;
}

static udp_socket_t *open_udp (product_root_dns_io_t *io, const struct sockaddr_storage *resolver,
  socklen_t length, uint64_t now, int *result)
{
  *result = -1;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd >= 0 && same_address (&io->channels[i].resolver,
          io->channels[i].resolver_length, resolver, length)) { *result = 1; return &io->channels[i]; }
  if (io->status.sockets >= ROOT_DNS_UPSTREAM_SOCKETS)
    {
      udp_socket_t *oldest = NULL;
      for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
        if (io->channels[i].fd >= 0 && !udp_busy (io, i) &&
            (!oldest || io->channels[i].last_activity < oldest->last_activity)) oldest = &io->channels[i];
      if (!oldest) { ++io->status.capacity; *result = 0; return NULL; }
      close_udp (io, oldest, 0);
    }
  udp_socket_t *channel = NULL;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd < 0) { channel = &io->channels[i]; break; }
  if (!channel) { ++io->status.capacity; *result = 0; return NULL; }
  *channel = (udp_socket_t) {.fd = -1, .resolver = *resolver, .resolver_length = length, .last_activity = now};
  if (udp_default (io, channel)) io->status.udp_state = PRODUCT_ROOT_DNS_UDP_AUTHORIZING;
  channel->fd = new_socket (io, resolver->ss_family, SOCK_DGRAM, &channel->cookie);
  if (channel->fd < 0) { *result = channel->fd == -2 ? 0 : -1; channel->fd = -1; close_udp (io, channel, 1); return NULL; }
  channel->authorized = !io->callbacks.authorize;
  if (io->callbacks.authorize)
    {
      if (io->callbacks.authorize (io->context, channel->fd, channel->cookie))
        { close_udp (io, channel, 1); return NULL; }
      *result = 1; return channel;
    }
  if (connect (channel->fd, (const struct sockaddr *) resolver, length) ||
      !io->callbacks.watch (io->context, channel->fd, PRODUCT_ROOT_DNS_READ, channel->cookie))
    { close_udp (io, channel, 1); return NULL; }
  if (udp_default (io, channel)) io->status.udp_state = PRODUCT_ROOT_DNS_UDP_AUTHORIZED;
  *result = 1; return channel;
}

product_root_dns_io_t *product_root_dns_io_open (uint64_t generation,
  const product_dns_proxy_route_t *route, uint32_t mark, uint64_t *sequence,
  const product_root_dns_io_callbacks_t *callbacks, void *context, uint64_t now)
{
  if (!generation || !product_dns_route_valid (route) || !route->enabled || !sequence ||
      !callbacks || !callbacks->watch || !callbacks->answer || !callbacks->failed) return NULL;
  product_root_dns_io_t *io = calloc (1, sizeof (*io));
  if (!io) return NULL;
  io->generation = generation; io->mark = mark; io->sequence = sequence;
  io->callbacks = *callbacks; io->context = context;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i) io->channels[i].fd = -1;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i) io->tcp[i].fd = -1;
  product_dns_proxy_key_t key = {.resolver_family = route->family, .resolver_port = route->port};
  memcpy (key.resolver_address, route->address, 16);
  if (!selected_address (io, &key, &io->resolver, &io->resolver_length)) { free (io); return NULL; }
  allocation (io, sizeof (*io));
  int result;
  if (!open_udp (io, &io->resolver, io->resolver_length, now, &result) && !route->endpoint_count)
    { product_root_dns_io_close (io); return NULL; }
  return io;
}

void product_root_dns_io_cancel (product_root_dns_io_t *io, const product_dns_proxy_key_t *key)
{
  if (!io || !key) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active && same_key (&io->udp[i].key, key))
      { io->status.allocated_bytes -= io->udp[i].length; io->pending_bytes -= io->udp[i].length; free (io->udp[i].pending);
        memset (&io->udp[i], 0, sizeof (io->udp[i])); --io->status.requests; }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && same_key (&io->tcp[i].key, key)) close_tcp (io, &io->tcp[i]);
}

void product_root_dns_io_close (product_root_dns_io_t *io)
{
  if (!io) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i) free (io->udp[i].pending);
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i) close_tcp (io, &io->tcp[i]);
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    close_socket (io, &io->channels[i].fd, io->channels[i].cookie);
  free (io);
}

static int send_udp (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  const uint8_t *wire, size_t length, uint64_t deadline, uint64_t now)
{
  struct sockaddr_storage resolver; socklen_t resolver_length;
  if (!selected_address (io, key, &resolver, &resolver_length)) return -1;
  int opened;
  udp_socket_t *channel = open_udp (io, &resolver, resolver_length, now, &opened);
  if (!channel) return opened;
  unsigned index = channel - io->channels;
  uint16_t id = ((uint16_t) wire[0] << 8) | wire[1];
  udp_request_t *request = NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active)
      {
        if (same_key (&io->udp[i].key, key)) request = &io->udp[i];
        else if (io->udp[i].channel == index && io->udp[i].id == id) return -1;
      }
  if (!request)
    for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
      if (!io->udp[i].active) { request = &io->udp[i]; break; }
  if (!request) { ++io->status.capacity; return 0; }
  if (!channel->authorized)
    {
      if (request->pending) return 1;
      if (length > PRODUCT_DNS_MESSAGE_MAX - io->pending_bytes) { ++io->status.capacity; return 0; }
      uint8_t *copy = malloc (length); if (!copy) return -1;
      memcpy (copy, wire, length); allocation (io, length); io->pending_bytes += length;
      if (!request->active) ++io->status.requests;
      *request = (udp_request_t) {.key = *key, .id = id, .active = 1, .channel = index,
        .pending = copy, .length = length, .deadline = deadline};
      return 1;
    }
  ssize_t sent = send (channel->fd, wire, length, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (sent != (ssize_t) length) { ++io->status.errors; return -1; }
  if (!request->active) ++io->status.requests;
  *request = (udp_request_t) {.key = *key, .id = id, .active = 1, .channel = index};
  ++io->status.udp_sent; channel->last_activity = now;
  return 1;
}

int product_root_dns_io_send (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t deadline, uint64_t now)
{
  if (!io || !key || key->generation != io->generation || !wire || length < 2 ||
      length > PRODUCT_DNS_MESSAGE_MAX || deadline <= now) return -1;
  if (transport == PRODUCT_DNS_PROXY_UDP) return send_udp (io, key, wire, length, deadline, now);
  if (transport != PRODUCT_DNS_PROXY_TCP) return -1;
  tcp_socket_t *tcp = NULL;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && same_key (&io->tcp[i].key, key)) return 1;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd < 0) { tcp = &io->tcp[i]; break; }
  if (!tcp) { ++io->status.capacity; return 0; }
  tcp->output = malloc (length + 2);
  if (!tcp->output) return -1;
  tcp->output_length = length + 2; allocation (io, length + 2);
  tcp->output[0] = length >> 8; tcp->output[1] = length;
  memcpy (tcp->output + 2, wire, length); tcp->key = *key; tcp->deadline = deadline;
  if (!selected_address (io, key, &tcp->resolver, &tcp->resolver_length)) { close_tcp (io, tcp); return -1; }
  tcp->fd = new_socket (io, tcp->resolver.ss_family, SOCK_STREAM, &tcp->cookie);
  if (tcp->fd < 0) { int result = tcp->fd == -2 ? 0 : -1; tcp->fd = -1; close_tcp (io, tcp); return result; }
  if (io->callbacks.authorize) {
    if (io->callbacks.authorize (io->context, tcp->fd, tcp->cookie))
      { close_tcp (io, tcp); return -1; }
    return 1;
  }
  tcp->authorized = 1;
  int result = connect (tcp->fd, (struct sockaddr *) &tcp->resolver, tcp->resolver_length);
  if (result && errno != EINPROGRESS) { close_tcp (io, tcp); return -1; }
  tcp->connecting = result != 0;
  if (!io->callbacks.watch (io->context, tcp->fd, PRODUCT_ROOT_DNS_READ | PRODUCT_ROOT_DNS_WRITE, tcp->cookie))
    { close_tcp (io, tcp); return -1; }
  return 1;
}

int product_root_dns_io_authorized (product_root_dns_io_t *io, uint64_t generation,
  uint64_t cookie, int success, uint64_t now)
{
  if (!io || generation != io->generation) return -1;
  for (unsigned index = 0; index < ROOT_DNS_UPSTREAM_SOCKETS; ++index)
    {
      udp_socket_t *channel = &io->channels[index];
      if (channel->fd < 0 || channel->cookie != cookie || channel->authorized) continue;
      if (success && !connect (channel->fd, (struct sockaddr *) &channel->resolver, channel->resolver_length) &&
          io->callbacks.watch (io->context, channel->fd, PRODUCT_ROOT_DNS_READ, cookie))
        {
          channel->authorized = 1;
          if (udp_default (io, channel)) io->status.udp_state = PRODUCT_ROOT_DNS_UDP_AUTHORIZED;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].pending && io->udp[i].channel == index)
              {
                udp_request_t *r = &io->udp[i]; product_dns_proxy_key_t key = r->key;
                int sent = r->deadline > now && send (channel->fd, r->pending, r->length,
                  MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t) r->length;
                io->status.allocated_bytes -= r->length; io->pending_bytes -= r->length;
                free (r->pending); r->pending = NULL; r->length = 0;
                if (sent) { ++io->status.udp_sent; channel->last_activity = now; }
                else { ++io->status.errors; io->callbacks.failed (io->context, &key, now); }
              }
          return 0;
        }
      product_dns_proxy_key_t keys[PRODUCT_DNS_PROXY_TRANSACTIONS]; unsigned count = 0;
      for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
        if (io->udp[i].active && io->udp[i].channel == index) keys[count++] = io->udp[i].key;
      close_udp (io, channel, 1); ++io->status.errors;
      for (unsigned i = 0; i < count; ++i) io->callbacks.failed (io->context, &keys[i], now);
      return 0;
    }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    {
      tcp_socket_t *tcp = &io->tcp[i];
      if (tcp->fd < 0 || tcp->cookie != cookie || tcp->authorized) continue;
      success = success && tcp->deadline > now;
      int result = success ? connect (tcp->fd, (struct sockaddr *) &tcp->resolver, tcp->resolver_length) : -1;
      if (success && (!result || errno == EINPROGRESS))
        {
          tcp->authorized = 1; tcp->connecting = result != 0;
          if (io->callbacks.watch (io->context, tcp->fd, PRODUCT_ROOT_DNS_READ | PRODUCT_ROOT_DNS_WRITE, cookie)) return 0;
        }
      product_dns_proxy_key_t key = tcp->key;
      close_tcp (io, tcp); ++io->status.errors; io->callbacks.failed (io->context, &key, now); return 0;
    }
  ++io->status.stale; return -1;
}

static void tcp_failed (product_root_dns_io_t *io, tcp_socket_t *tcp, uint64_t now)
{
  product_dns_proxy_key_t key = tcp->key;
  ++io->status.errors; close_tcp (io, tcp);
  io->callbacks.failed (io->context, &key, now);
}

static void tcp_ready (product_root_dns_io_t *io, tcp_socket_t *tcp, unsigned events, uint64_t now)
{
  if (tcp->deadline <= now || (events & PRODUCT_ROOT_DNS_ERROR))
    { tcp_failed (io, tcp, now); return; }
  if (tcp->connecting)
    {
      int error = 0; socklen_t length = sizeof (error);
      if (getsockopt (tcp->fd, SOL_SOCKET, SO_ERROR, &error, &length) || error)
        { tcp_failed (io, tcp, now); return; }
      tcp->connecting = 0;
    }
  if (events & PRODUCT_ROOT_DNS_WRITE)
    {
      ssize_t sent = send (tcp->fd, tcp->output + tcp->output_at,
        tcp->output_length - tcp->output_at, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
      if (sent <= 0) { tcp_failed (io, tcp, now); return; }
      io->status.tcp_write_bytes += sent;
      tcp->output_at += sent;
      if (tcp->output_at == tcp->output_length)
        {
          ++io->status.tcp_sent;
          if (!io->callbacks.watch (io->context, tcp->fd, PRODUCT_ROOT_DNS_READ, tcp->cookie))
            { tcp_failed (io, tcp, now); return; }
        }
    }
  if (!(events & PRODUCT_ROOT_DNS_READ)) return;
  for (unsigned budget = 0; budget < 16; ++budget)
    {
      uint8_t *destination = tcp->header_at < 2 ? tcp->header + tcp->header_at : tcp->input + tcp->input_at;
      size_t remaining = tcp->header_at < 2 ? 2 - tcp->header_at : tcp->input_length - tcp->input_at;
      ssize_t received = recv (tcp->fd, destination, remaining, MSG_DONTWAIT);
      if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
      if (received <= 0) { tcp_failed (io, tcp, now); return; }
      io->status.tcp_read_bytes += received;
      if (tcp->header_at < 2)
        {
          tcp->header_at += received;
          if (tcp->header_at < 2) continue;
          tcp->input_length = ((size_t) tcp->header[0] << 8) | tcp->header[1];
          if (tcp->input_length < 12) { tcp_failed (io, tcp, now); return; }
          tcp->input = malloc (tcp->input_length);
          if (!tcp->input) { tcp->input_length = 0; tcp_failed (io, tcp, now); return; }
          allocation (io, tcp->input_length);
        }
      else
        {
          tcp->input_at += received;
          if (tcp->input_at == tcp->input_length)
            {
              ++io->status.tcp_received;
              io->callbacks.answer (io->context, &tcp->key, PRODUCT_DNS_PROXY_TCP,
                tcp->input, tcp->input_length, now);
              return; /* The callback may cancel and free this exact socket. */
            }
        }
    }
}

void product_root_dns_io_ready (product_root_dns_io_t *io, uint64_t generation,
  uint64_t cookie, int fd, unsigned events, uint64_t now)
{
  if (!io) return;
  if (generation != io->generation) { ++io->status.stale; return; }
  for (unsigned index = 0; index < ROOT_DNS_UPSTREAM_SOCKETS; ++index)
    {
      udp_socket_t *channel = &io->channels[index];
      if (channel->fd < 0 || channel->cookie != cookie || channel->fd != fd) continue;
      if (events & PRODUCT_ROOT_DNS_ERROR)
        {
          product_dns_proxy_key_t keys[PRODUCT_DNS_PROXY_TRANSACTIONS]; unsigned count = 0;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].active && io->udp[i].channel == index) keys[count++] = io->udp[i].key;
          close_udp (io, channel, 1); ++io->status.errors;
          for (unsigned i = 0; i < count; ++i) io->callbacks.failed (io->context, &keys[i], now);
          return;
        }
      for (unsigned budget = 0; budget < 16; ++budget)
        {
          if (channel->fd != fd || channel->cookie != cookie) return;
          ssize_t received = recv (fd, io->received, sizeof (io->received), MSG_DONTWAIT | MSG_TRUNC);
          if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
          if (received < 0)
            { product_root_dns_io_ready (io, generation, cookie, fd, PRODUCT_ROOT_DNS_ERROR, now); return; }
          if (received < 2 || received > (ssize_t) sizeof (io->received)) continue;
          uint16_t id = ((uint16_t) io->received[0] << 8) | io->received[1];
          ++io->status.udp_received; channel->last_activity = now;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].active && io->udp[i].channel == index && io->udp[i].id == id)
              {
                product_dns_proxy_key_t key = io->udp[i].key;
                io->callbacks.answer (io->context, &key, PRODUCT_DNS_PROXY_UDP, io->received, received, now);
                break;
              }
        }
      return;
    }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && io->tcp[i].cookie == cookie && io->tcp[i].fd == fd)
      { tcp_ready (io, &io->tcp[i], events, now); return; }
  ++io->status.stale;
}

uint64_t product_root_dns_io_deadline (const product_root_dns_io_t *io)
{
  uint64_t due = UINT64_MAX;
  if (io) for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd >= 0 && !udp_busy (io, i) &&
        io->channels[i].last_activity + PRODUCT_ROOT_DNS_IDLE_US < due)
      due = io->channels[i].last_activity + PRODUCT_ROOT_DNS_IDLE_US;
  return due;
}
void product_root_dns_io_expire (product_root_dns_io_t *io, uint64_t now)
{
  if (!io) return;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd >= 0 && !udp_busy (io, i) &&
        io->channels[i].last_activity + PRODUCT_ROOT_DNS_IDLE_US <= now)
      close_udp (io, &io->channels[i], !io->channels[i].authorized);
}
product_root_dns_io_status_t product_root_dns_io_status (const product_root_dns_io_t *io)
{
  if (!io) return (product_root_dns_io_status_t) {0};
  product_root_dns_io_status_t status = io->status;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    {
      status.authorizing += io->channels[i].fd >= 0 && !io->channels[i].authorized;
      if (udp_default (io, &io->channels[i]))
        status.udp_ready |= io->channels[i].fd >= 0 && io->channels[i].authorized;
    }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    status.authorizing += io->tcp[i].fd >= 0 && !io->tcp[i].authorized;
  return status;
}
