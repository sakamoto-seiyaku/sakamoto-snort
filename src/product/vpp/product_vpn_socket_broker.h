/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_SOCKET_BROKER_H
#define SAKAMOTO_PRODUCT_VPN_SOCKET_BROKER_H
#include <stdint.h>

/* Private fixed wire protocol over one owner-local AF_UNIX/SOCK_SEQPACKET
 * channel. All integers are big endian, not native C structure layouts.
 * Request (32 bytes): magic, operation, generation, session, owner, diagnostic.
 * diagnostic=0 normally; validation-only 2/3 forces a real protect/bind failure
 * for this one request. It never authorizes an unprotected socket.
 * Reply (48 bytes): magic, operation, generation, session, owner, error,
 *                   underlay_epoch, network_context, flags.
 * Invalidation uses the reply layout with operation=3, session/error/context/
 * flags=0 and the nonzero retired binding epoch. Android serializes these
 * messages with authorization replies; no old-epoch reply follows retirement.
 * Request carries exactly one SCM_RIGHTS duplicate; reply/event carries no fd. */
enum {
  PRODUCT_VPN_BROKER_MAGIC = 0x53323337,
  PRODUCT_VPN_BROKER_REQUEST = 1,
  PRODUCT_VPN_BROKER_REPLY = 2,
  PRODUCT_VPN_BROKER_INVALIDATE = 3,
  PRODUCT_VPN_BROKER_REQUEST_BYTES = 32,
  PRODUCT_VPN_BROKER_REPLY_BYTES = 48,
  PRODUCT_VPN_BROKER_PROTECTED = 1,
  PRODUCT_VPN_BROKER_BOUND = 2,
  PRODUCT_VPN_BROKER_CONTEXT_KNOWN = 4,
  PRODUCT_VPN_BROKER_ERROR_PROTECT = 2,
  PRODUCT_VPN_BROKER_ERROR_BIND = 3,
  PRODUCT_VPN_BROKER_ERROR_AUTHORIZATION = 4,
  PRODUCT_VPN_BROKER_ERROR_NO_UNDERLAY = 5,
};

typedef struct {
  int fd;
  uint32_t owner;
  uint64_t generation;
  uint64_t requests, replies, rejected, stale, disconnected, invalidations;
  uint64_t fault_request_at;
  uint32_t fault_operation;
} product_vpn_socket_broker_t;

typedef int (*product_vpn_socket_broker_reply_fn)(void *opaque,
  uint64_t generation, uint64_t session, unsigned error, uint64_t epoch,
  uint32_t context, int context_known);
typedef int (*product_vpn_socket_broker_invalidate_fn)(void *opaque,
  uint64_t generation, uint64_t epoch);

/* Consumes fd on every path. Caller initializes storage once before use;
 * calls, counters and descriptor operations subsequently belong to its owner. */
int product_vpn_socket_broker_open(product_vpn_socket_broker_t *broker,
  int fd, uint64_t generation, uint32_t owner);
void product_vpn_socket_broker_close(product_vpn_socket_broker_t *broker);
/* Borrows original_fd. Successful send creates a receiver-owned descriptor
 * reference, never transfers the HEV session's original reference. */
int product_vpn_socket_broker_request(product_vpn_socket_broker_t *broker,
  uint64_t generation, uint64_t session, int original_fd);
/* Nonblocking, at most min(budget, 32) datagrams. Callback receives values,
 * never packet storage or descriptors. Callback rejects obsolete sessions. */
unsigned product_vpn_socket_broker_receive(product_vpn_socket_broker_t *broker,
  unsigned budget, product_vpn_socket_broker_reply_fn reply,
  product_vpn_socket_broker_invalidate_fn invalidate, void *opaque);
#endif
