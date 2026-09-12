/* SPDX-License-Identifier: Apache-2.0 */
#include "product_vpn_socket_broker.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void put32(unsigned char *p, uint32_t value)
{ for (unsigned i = 0; i < 4; ++i) p[i] = value >> (24 - i * 8); }
static void put64(unsigned char *p, uint64_t value)
{ for (unsigned i = 0; i < 8; ++i) p[i] = value >> (56 - i * 8); }
static unsigned fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  assert(directory);
  unsigned count = 0;
  while (readdir(directory)) ++count;
  closedir(directory);
  return count;
}
typedef struct { unsigned calls, error, invalidations, ordered; int success, known; } fixture_t;
static int invalidate(void *opaque, uint64_t generation, uint64_t epoch)
{
  fixture_t *f = opaque;
  assert(generation == 7 && epoch == 11);
  ++f->invalidations;
  if (f->ordered) assert(f->calls == 4);
  return 0;
}
static int reply(void *opaque, uint64_t generation, uint64_t session,
                 unsigned error, uint64_t epoch, uint32_t context, int known)
{
  fixture_t *f = opaque;
  assert(generation == 7 && epoch == 11 && context == 0);
  if (session != 5) return -1;
  ++f->calls; f->success = error == 0; f->known = known; f->error = error;
  return 0;
}
static void make_reply(unsigned char *data, uint64_t generation,
                       uint64_t session, unsigned flags, unsigned error)
{
  memset(data, 0, 48);
  put32(data, PRODUCT_VPN_BROKER_MAGIC); put32(data + 4, PRODUCT_VPN_BROKER_REPLY);
  put64(data + 8, generation); put64(data + 16, session); put32(data + 24, 1);
  put32(data + 28, error); put64(data + 32, 11); put32(data + 44, flags);
}
int main(void)
{
  unsigned baseline = fd_count();
  int pair[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair));
  product_vpn_socket_broker_t broker;
  assert(!product_vpn_socket_broker_open(&broker, pair[0], 7, 1));
  assert(fcntl(pair[0], F_GETFL) & O_NONBLOCK);
  int original = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  assert(original >= 0);
  assert(product_vpn_socket_broker_request(&broker, 6, 5, original) == -1);
  assert(!product_vpn_socket_broker_request(&broker, 7, 5, original));
  unsigned char request[32];
  union { struct cmsghdr align; unsigned char data[CMSG_SPACE(sizeof(int))]; } control = {0};
  struct iovec span = {.iov_base = request, .iov_len = sizeof(request)};
  struct msghdr message = {.msg_iov = &span, .msg_iovlen = 1,
    .msg_control = control.data, .msg_controllen = sizeof(control.data)};
  assert(recvmsg(pair[1], &message, MSG_CMSG_CLOEXEC) == sizeof(request));
  assert(request[0] == 0x53 && request[3] == 0x37 && request[7] == 1 &&
         request[15] == 7 && request[23] == 5 && request[27] == 1 && request[31] == 0);
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  assert(header && header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)));
  int duplicate;
  memcpy(&duplicate, CMSG_DATA(header), sizeof(duplicate));
  assert(duplicate != original && (fcntl(duplicate, F_GETFD) & FD_CLOEXEC));
  /* Binding the transferred reference acts on the original socket. Closing
   * that broker reference does not close the HEV-owned original reference. */
  struct sockaddr_in address = {.sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  assert(!bind(duplicate, (struct sockaddr *)&address, sizeof(address)));
  close(duplicate);
  socklen_t size = sizeof(address);
  assert(!getsockname(original, (struct sockaddr *)&address, &size) && address.sin_port);
  fixture_t fixture = {0};
  unsigned char response[49];
  make_reply(response, 7, 5, 7, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  assert(product_vpn_socket_broker_receive(&broker, 1, reply, invalidate, &fixture) == 1);
  assert(fixture.calls == 1 && fixture.success && fixture.known);
  make_reply(response, 7, 5, 3, 0); /* Success, context explicitly unknown. */
  assert(send(pair[1], response, 48, 0) == 48);
  product_vpn_socket_broker_receive(&broker, 1, reply, invalidate, &fixture);
  assert(fixture.calls == 2 && fixture.success && !fixture.known);
  make_reply(response, 7, 5, 1, 3); /* Protect succeeded, bind failed. */
  assert(send(pair[1], response, 48, 0) == 48);
  product_vpn_socket_broker_receive(&broker, 1, reply, invalidate, &fixture);
  assert(fixture.calls == 3 && !fixture.success);
  make_reply(response, 6, 5, 3, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 4, 3, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 5, 3, 0); put32(response + 24, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  assert(product_vpn_socket_broker_receive(&broker, 2, reply, invalidate, &fixture) == 2);
  assert(broker.stale == 2 && fixture.calls == 3);
  assert(product_vpn_socket_broker_receive(&broker, 2, reply, invalidate, &fixture) == 1);
  assert(broker.stale == 3);
  make_reply(response, 7, 5, 3, 0);
  assert(send(pair[1], response, 47, 0) == 47);
  response[48] = 0;
  assert(send(pair[1], response, 49, 0) == 49);
  assert(product_vpn_socket_broker_receive(&broker, 32, reply, invalidate, &fixture) == 2);
  assert(broker.rejected == 2);
  unsigned before = fd_count();
  span.iov_base = response; span.iov_len = 48;
  message.msg_flags = 0; message.msg_controllen = sizeof(control.data);
  header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &original, sizeof(original));
  assert(sendmsg(pair[1], &message, 0) == 48);
  assert(product_vpn_socket_broker_receive(&broker, 32, reply, invalidate, &fixture) == 1);
  assert(broker.rejected == 3 && fd_count() == before);
  /* One ordered channel: old binding completion precedes retirement; the
   * next reply can explicitly report no available underlay. */
  fixture.ordered = 1;
  make_reply(response, 7, 5, 3, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 0, 0, 0);
  put32(response + 4, PRODUCT_VPN_BROKER_INVALIDATE);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 5, 0, PRODUCT_VPN_BROKER_ERROR_NO_UNDERLAY);
  assert(send(pair[1], response, 48, 0) == 48);
  assert(product_vpn_socket_broker_receive(&broker, 32, reply, invalidate, &fixture) == 3);
  assert(fixture.calls == 5 && fixture.error == PRODUCT_VPN_BROKER_ERROR_NO_UNDERLAY);
  assert(fixture.invalidations == 1 && broker.invalidations == 1);
  /* Invalidation has no session, flags, context or descriptors; wrong
   * generation/owner must not mutate the owner. Zero-epoch success is invalid. */
  fixture.ordered = 0;
  make_reply(response, 7, 1, 0, 0); put32(response + 4, PRODUCT_VPN_BROKER_INVALIDATE);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 0, 1, 0); put32(response + 4, PRODUCT_VPN_BROKER_INVALIDATE);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 0, 0, 0); put32(response + 4, PRODUCT_VPN_BROKER_INVALIDATE);
  put32(response + 40, 1);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 0, 0, 0); put32(response + 4, PRODUCT_VPN_BROKER_INVALIDATE);
  put64(response + 32, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 6, 0, 0, 0); put32(response + 4, PRODUCT_VPN_BROKER_INVALIDATE);
  assert(send(pair[1], response, 48, 0) == 48);
  make_reply(response, 7, 5, 3, 0); put64(response + 32, 0);
  assert(send(pair[1], response, 48, 0) == 48);
  assert(product_vpn_socket_broker_receive(&broker, 32, reply, invalidate, &fixture) == 6);
  assert(broker.rejected == 8 && broker.stale == 4 && fixture.invalidations == 1);
  close(original); close(pair[1]);
  product_vpn_socket_broker_receive(&broker, 1, reply, invalidate, &fixture);
  assert(broker.disconnected == 1 && broker.fd == -1);
  product_vpn_socket_broker_close(&broker);
  assert(fd_count() == baseline);
  assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
  assert(product_vpn_socket_broker_open(&broker, pair[0], 7, 1) == -1);
  assert(broker.fd == -1 && fcntl(pair[0], F_GETFD) == -1 && errno == EBADF);
  close(pair[1]);
  assert(fd_count() == baseline);
  return 0;
}
