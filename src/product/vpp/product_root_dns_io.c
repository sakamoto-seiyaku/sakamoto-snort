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
  uint8_t active;
} udp_request_t;
typedef struct {
  product_dns_proxy_key_t key;
  uint64_t cookie;
  int fd;
  uint8_t connecting, header[2];
  uint8_t *output, *input;
  size_t output_length, output_at, input_length, input_at, header_at;
} tcp_socket_t;
struct product_root_dns_io {
  uint64_t generation, udp_cookie, last_activity;
  uint64_t *sequence;
  uint32_t mark;
  int udp_fd;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  product_root_dns_io_callbacks_t callbacks;
  void *context;
  product_root_dns_io_status_t status;
  udp_request_t udp[PRODUCT_DNS_PROXY_TRANSACTIONS];
  tcp_socket_t tcp[PRODUCT_ROOT_DNS_TCP_SOCKETS];
  uint8_t received[PRODUCT_DNS_MESSAGE_MAX];
};

uint64_t product_root_dns_io_reservation (void)
{
  return sizeof (product_root_dns_io_t) + PRODUCT_ROOT_DNS_TCP_SOCKETS *
    (2U * PRODUCT_DNS_MESSAGE_MAX + 2U);
}

static int same_key (const product_dns_proxy_key_t *a, const product_dns_proxy_key_t *b)
{ return !memcmp (a, b, sizeof (*a)); }

static void allocation (product_root_dns_io_t *io, size_t bytes)
{
  io->status.allocated_bytes += bytes;
  if (io->status.allocated_bytes > io->status.high_water_bytes)
    io->status.high_water_bytes = io->status.allocated_bytes;
}

static int new_socket (product_root_dns_io_t *io, unsigned type, uint64_t *cookie)
{
  if (*io->sequence == (UINT64_C(1) << 42) - 1) return -1;
  int fd = socket (io->resolver.ss_family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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

static int open_udp (product_root_dns_io_t *io, uint64_t now)
{
  if (io->udp_fd >= 0) return 1;
  io->udp_fd = new_socket (io, SOCK_DGRAM, &io->udp_cookie);
  if (io->udp_fd < 0) return 0;
  if (connect (io->udp_fd, (struct sockaddr *) &io->resolver, io->resolver_length) ||
      !io->callbacks.watch (io->context, io->udp_fd, PRODUCT_ROOT_DNS_READ, io->udp_cookie))
    { close_socket (io, &io->udp_fd, io->udp_cookie); return 0; }
  io->last_activity = now;
  return 1;
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
  io->callbacks = *callbacks; io->context = context; io->udp_fd = -1;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i) io->tcp[i].fd = -1;
  if (route->family == 4)
    {
      struct sockaddr_in *address = (struct sockaddr_in *) &io->resolver;
      address->sin_family = AF_INET; address->sin_port = htons (route->port);
      memcpy (&address->sin_addr, route->address, 4); io->resolver_length = sizeof (*address);
    }
  else
    {
      struct sockaddr_in6 *address = (struct sockaddr_in6 *) &io->resolver;
      address->sin6_family = AF_INET6; address->sin6_port = htons (route->port);
      memcpy (&address->sin6_addr, route->address, 16); io->resolver_length = sizeof (*address);
    }
  allocation (io, sizeof (*io));
  if (!open_udp (io, now)) { product_root_dns_io_close (io); return NULL; }
  return io;
}

void product_root_dns_io_cancel (product_root_dns_io_t *io, const product_dns_proxy_key_t *key)
{
  if (!io || !key) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active && same_key (&io->udp[i].key, key))
      { memset (&io->udp[i], 0, sizeof (io->udp[i])); --io->status.requests; }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && same_key (&io->tcp[i].key, key)) close_tcp (io, &io->tcp[i]);
}

void product_root_dns_io_close (product_root_dns_io_t *io)
{
  if (!io) return;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i) close_tcp (io, &io->tcp[i]);
  close_socket (io, &io->udp_fd, io->udp_cookie);
  free (io);
}

static int send_udp (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  const uint8_t *wire, size_t length, uint64_t now)
{
  if (!open_udp (io, now)) return -1;
  uint16_t id = ((uint16_t) wire[0] << 8) | wire[1];
  udp_request_t *request = NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active)
      {
        if (same_key (&io->udp[i].key, key)) request = &io->udp[i];
        else if (io->udp[i].id == id) return -1;
      }
  if (!request)
    for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
      if (!io->udp[i].active) { request = &io->udp[i]; break; }
  if (!request) { ++io->status.capacity; return 0; }
  ssize_t sent = send (io->udp_fd, wire, length, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (sent != (ssize_t) length) { ++io->status.errors; return -1; }
  if (!request->active) ++io->status.requests;
  *request = (udp_request_t) {.key = *key, .id = id, .active = 1};
  ++io->status.udp_sent; io->last_activity = now;
  return 1;
}

int product_root_dns_io_send (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t deadline, uint64_t now)
{
  if (!io || !key || key->generation != io->generation || !wire || length < 2 ||
      length > PRODUCT_DNS_MESSAGE_MAX || deadline <= now) return -1;
  if (transport == PRODUCT_DNS_PROXY_UDP) return send_udp (io, key, wire, length, now);
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
  memcpy (tcp->output + 2, wire, length); tcp->key = *key;
  tcp->fd = new_socket (io, SOCK_STREAM, &tcp->cookie);
  if (tcp->fd < 0) { close_tcp (io, tcp); return -1; }
  int result = connect (tcp->fd, (struct sockaddr *) &io->resolver, io->resolver_length);
  if (result && errno != EINPROGRESS) { close_tcp (io, tcp); return -1; }
  tcp->connecting = result != 0;
  if (!io->callbacks.watch (io->context, tcp->fd, PRODUCT_ROOT_DNS_READ | PRODUCT_ROOT_DNS_WRITE, tcp->cookie))
    { close_tcp (io, tcp); return -1; }
  return 1;
}

static void tcp_failed (product_root_dns_io_t *io, tcp_socket_t *tcp, uint64_t now)
{
  product_dns_proxy_key_t key = tcp->key;
  ++io->status.errors; close_tcp (io, tcp);
  io->callbacks.failed (io->context, &key, now);
}

static void tcp_ready (product_root_dns_io_t *io, tcp_socket_t *tcp, unsigned events, uint64_t now)
{
  if (events & PRODUCT_ROOT_DNS_ERROR)
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
  if (io->udp_fd >= 0 && io->udp_cookie == cookie && io->udp_fd == fd)
    {
      if (events & PRODUCT_ROOT_DNS_ERROR)
        {
          product_dns_proxy_key_t keys[PRODUCT_DNS_PROXY_TRANSACTIONS]; unsigned count = 0;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].active) keys[count++] = io->udp[i].key;
          close_socket (io, &io->udp_fd, io->udp_cookie); ++io->status.errors;
          for (unsigned i = 0; i < count; ++i) io->callbacks.failed (io->context, &keys[i], now);
          return;
        }
      for (unsigned budget = 0; budget < 16; ++budget)
        {
          ssize_t received = recv (fd, io->received, sizeof (io->received), MSG_DONTWAIT | MSG_TRUNC);
          if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
          if (received < 0)
            { product_root_dns_io_ready (io, generation, cookie, fd, PRODUCT_ROOT_DNS_ERROR, now); return; }
          if (received < 2 || received > (ssize_t) sizeof (io->received)) continue;
          uint16_t id = ((uint16_t) io->received[0] << 8) | io->received[1];
          ++io->status.udp_received; io->last_activity = now;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].active && io->udp[i].id == id)
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
{ return io && io->udp_fd >= 0 && !io->status.requests ? io->last_activity + PRODUCT_ROOT_DNS_IDLE_US : UINT64_MAX; }
void product_root_dns_io_expire (product_root_dns_io_t *io, uint64_t now)
{
  if (io && product_root_dns_io_deadline (io) <= now)
    close_socket (io, &io->udp_fd, io->udp_cookie);
}
product_root_dns_io_status_t product_root_dns_io_status (const product_root_dns_io_t *io)
{ return io ? io->status : (product_root_dns_io_status_t) {0}; }
