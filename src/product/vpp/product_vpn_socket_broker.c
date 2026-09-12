/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "product_vpn_socket_broker.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void put32(unsigned char *p, uint32_t value)
{ for (unsigned i = 0; i < 4; ++i) p[i] = value >> (24 - i * 8); }
static void put64(unsigned char *p, uint64_t value)
{ for (unsigned i = 0; i < 8; ++i) p[i] = value >> (56 - i * 8); }
static uint32_t get32(const unsigned char *p)
{
  uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i) value = (value << 8) | p[i];
  return value;
}
static uint64_t get64(const unsigned char *p)
{
  uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) value = (value << 8) | p[i];
  return value;
}

int product_vpn_socket_broker_open(product_vpn_socket_broker_t *broker,
  int fd, uint64_t generation, uint32_t owner)
{
  int type = 0;
  struct ucred peer;
  struct sockaddr_storage address;
  socklen_t type_size = sizeof(type), peer_size = sizeof(peer), size = sizeof(address);
  if (broker) { memset(broker, 0, sizeof(*broker)); broker->fd = -1; }
  if (!broker || fd < 0 || !generation) goto rejected;
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_size) ||
      type != SOCK_SEQPACKET || getpeername(fd, (struct sockaddr *)&address, &size) ||
      address.ss_family != AF_UNIX ||
      getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) || peer.uid != geteuid())
    goto rejected;
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) || fcntl(fd, F_SETFD, FD_CLOEXEC))
    goto rejected;
  broker->fd = fd; broker->generation = generation; broker->owner = owner;
  return 0;
rejected:
  if (fd >= 0) close(fd);
  return -1;
}

void product_vpn_socket_broker_close(product_vpn_socket_broker_t *broker)
{
  if (!broker) return;
  if (broker->fd >= 0) close(broker->fd);
  broker->fd = -1;
}

int product_vpn_socket_broker_request(product_vpn_socket_broker_t *broker,
  uint64_t generation, uint64_t session, int original_fd)
{
  if (!broker || broker->fd < 0 || generation != broker->generation ||
      !session || original_fd < 0) return -1;
  unsigned char data[PRODUCT_VPN_BROKER_REQUEST_BYTES] = {0};
  put32(data, PRODUCT_VPN_BROKER_MAGIC); put32(data + 4, PRODUCT_VPN_BROKER_REQUEST);
  put64(data + 8, generation); put64(data + 16, session); put32(data + 24, broker->owner);
  int inject = broker->fault_request_at == broker->requests + 1;
  if (inject) put32(data + 28, broker->fault_operation);
  union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } control = {0};
  struct iovec span = {.iov_base = data, .iov_len = sizeof(data)};
  struct msghdr message = {.msg_iov = &span, .msg_iovlen = 1,
    .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &original_fd, sizeof(original_fd));
  if (sendmsg(broker->fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof(data)) {
    ++broker->rejected;
    return -1;
  }
  ++broker->requests;
  if (inject) { broker->fault_request_at = 0; broker->fault_operation = 0; }
  return 0;
}

unsigned product_vpn_socket_broker_receive(product_vpn_socket_broker_t *broker,
  unsigned budget, product_vpn_socket_broker_reply_fn reply,
  product_vpn_socket_broker_invalidate_fn invalidate, void *opaque)
{
  if (!broker || broker->fd < 0 || !reply) return 0;
  if (budget > 32) budget = 32;
  unsigned consumed = 0;
  while (consumed < budget) {
    unsigned char data[PRODUCT_VPN_BROKER_REPLY_BYTES];
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(16 * sizeof(int))]; } control = {0};
    struct iovec span = {.iov_base = data, .iov_len = sizeof(data)};
    struct msghdr message = {.msg_iov = &span, .msg_iovlen = 1,
      .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    ssize_t length = recvmsg(broker->fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
    if (length < 0) {
      ++broker->disconnected;
      product_vpn_socket_broker_close(broker);
      break;
    }
    int unexpected_control = 0;
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h)) {
      unexpected_control = 1;
      if (h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS ||
          h->cmsg_len < CMSG_LEN(0)) continue;
      size_t count = (h->cmsg_len - CMSG_LEN(0)) / sizeof(int);
      for (size_t i = 0; i < count; ++i) {
        int fd;
        memcpy(&fd, (unsigned char *)CMSG_DATA(h) + i * sizeof(fd), sizeof(fd));
        close(fd);
      }
    }
    if (!length) {
      ++broker->disconnected;
      product_vpn_socket_broker_close(broker);
      break;
    }
    ++consumed;
    if (length != sizeof(data) || unexpected_control ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        get32(data) != PRODUCT_VPN_BROKER_MAGIC || (get32(data + 44) & ~7U)) {
      ++broker->rejected;
      continue;
    }
    uint64_t generation = get64(data + 8), session = get64(data + 16);
    if (generation != broker->generation || get32(data + 24) != broker->owner) {
      ++broker->stale;
      continue;
    }
    uint32_t flags = get32(data + 44), error = get32(data + 28);
    if (get32(data + 4) == PRODUCT_VPN_BROKER_INVALIDATE) {
      if (session || error || flags || get32(data + 40) || !get64(data + 32) || !invalidate)
        ++broker->rejected;
      else if (invalidate(opaque, generation, get64(data + 32))) ++broker->stale;
      else ++broker->invalidations;
      continue;
    }
    if (get32(data + 4) != PRODUCT_VPN_BROKER_REPLY || !session) {
      ++broker->rejected;
      continue;
    }
    int success = (flags & (PRODUCT_VPN_BROKER_BOUND | PRODUCT_VPN_BROKER_PROTECTED)) ==
      (PRODUCT_VPN_BROKER_BOUND | PRODUCT_VPN_BROKER_PROTECTED);
    if ((success && (error || !get64(data + 32))) || (!success && error != PRODUCT_VPN_BROKER_ERROR_PROTECT
          && error != PRODUCT_VPN_BROKER_ERROR_BIND
          && error != PRODUCT_VPN_BROKER_ERROR_AUTHORIZATION
          && error != PRODUCT_VPN_BROKER_ERROR_NO_UNDERLAY)) {
      ++broker->rejected;
      continue;
    }
    if (reply(opaque, generation, session, error, get64(data + 32),
              get32(data + 40), !!(flags & PRODUCT_VPN_BROKER_CONTEXT_KNOWN)))
      ++broker->stale;
    else ++broker->replies;
  }
  return consumed;
}
