/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_DNS_IO_H
#define SAKAMOTO_PRODUCT_ROOT_DNS_IO_H
#include "product_dns_proxy.h"

#define PRODUCT_ROOT_DNS_TCP_SOCKETS (PRODUCT_DNS_PROXY_SOCKETS - 3U)
/* A capture bit above Android's routing/netId fields. The OUTPUT rule masks
 * only this bit, so platform route selection may retain its own lower bits. */
#define PRODUCT_ROOT_DNS_SOCKET_MARK UINT32_C(0x40000000)
#define PRODUCT_ROOT_DNS_IDLE_US UINT64_C(30000000)
enum { PRODUCT_ROOT_DNS_READ=1, PRODUCT_ROOT_DNS_WRITE=2, PRODUCT_ROOT_DNS_ERROR=4 };
typedef enum {
  PRODUCT_ROOT_DNS_UDP_NONE = 0,
  PRODUCT_ROOT_DNS_UDP_AUTHORIZING,
  PRODUCT_ROOT_DNS_UDP_AUTHORIZED,
  PRODUCT_ROOT_DNS_UDP_IDLE,
  PRODUCT_ROOT_DNS_UDP_FAILED,
} product_root_dns_udp_state_t;

typedef struct product_root_dns_io product_root_dns_io_t;
typedef struct {
  /* Optional async platform authorization; completion must precede connect. */
  int (*authorize) (void *, int fd, uint64_t cookie);
  int (*watch) (void *, int fd, unsigned events, uint64_t cookie);
  void (*answer) (void *, const product_dns_proxy_key_t *, unsigned,
    const uint8_t *, size_t, uint64_t now_us);
  void (*failed) (void *, const product_dns_proxy_key_t *, uint64_t now_us);
} product_root_dns_io_callbacks_t;
typedef struct {
  uint64_t allocated_bytes, high_water_bytes, opened, closed, stale, errors;
  uint64_t udp_sent, udp_received, tcp_sent, tcp_received, capacity;
  uint64_t tcp_read_bytes, tcp_write_bytes;
  uint32_t sockets, high_water_sockets, requests, authorizing;
  uint8_t udp_ready;
  product_root_dns_udp_state_t udp_state;
} product_root_dns_io_status_t;

/* Actual nonblocking Root socket operations. The existing owner provides all
 * readiness and monotonic time; this module owns no thread, poller or timer.
 * A zero mark is reserved for a controlled Host socket fixture. Product Root
 * supplies its exact scoped upstream mark and never retries without it. */
product_root_dns_io_t *product_root_dns_io_open (uint64_t generation,
  const product_dns_proxy_route_t *, uint32_t mark, uint64_t *owner_socket_sequence,
  const product_root_dns_io_callbacks_t *, void *, uint64_t now_us);
int product_root_dns_io_authorized (product_root_dns_io_t *, uint64_t generation,
  uint64_t cookie, int success, uint64_t now_us);
void product_root_dns_io_close (product_root_dns_io_t *);
int product_root_dns_io_send (product_root_dns_io_t *, const product_dns_proxy_key_t *,
  unsigned transport, const uint8_t *, size_t, uint64_t deadline, uint64_t now_us);
void product_root_dns_io_cancel (product_root_dns_io_t *, const product_dns_proxy_key_t *);
void product_root_dns_io_ready (product_root_dns_io_t *, uint64_t generation,
  uint64_t cookie, int fd, unsigned events, uint64_t now_us);
uint64_t product_root_dns_io_deadline (const product_root_dns_io_t *);
void product_root_dns_io_expire (product_root_dns_io_t *, uint64_t now_us);
product_root_dns_io_status_t product_root_dns_io_status (const product_root_dns_io_t *);
uint64_t product_root_dns_io_reservation (void);
#endif
