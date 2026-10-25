/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_DNS_TCP_IO_H
#define SAKAMOTO_PRODUCT_ROOT_DNS_TCP_IO_H
#include "product_root_dns_io.h"

#define PRODUCT_ROOT_DNS_TCP_CLIENTS 8U
#define PRODUCT_ROOT_DNS_TCP_OUTPUTS 128U
#define PRODUCT_ROOT_DNS_TCP_WORK_BYTES (2U * 1024U * 1024U)
#define PRODUCT_ROOT_DNS_TCP_LISTEN_BASE 15353U
#define PRODUCT_ROOT_DNS_TCP_MARK_MASK UINT32_C(0x07e00000)
#define PRODUCT_ROOT_DNS_TCP_MARK_SHIFT 21U
#define PRODUCT_ROOT_DNS_TCP_EDGE 8U

typedef struct {
  uint8_t family, saved_syn;
  uint8_t source_address[16], resolver_address[16];
  uint16_t source_port, resolver_port;
  uint32_t syn_sequence;
} product_root_dns_tcp_endpoint_t;
typedef struct product_root_dns_tcp_io product_root_dns_tcp_io_t;
typedef struct {
  int (*watch)(void *, int fd, unsigned events, uint64_t cookie);
  int (*accepted)(void *, uint64_t session, const product_root_dns_tcp_endpoint_t *);
  void (*query)(void *, uint64_t session, uint64_t token,
                const uint8_t *, size_t, uint64_t now_us);
  void (*delivered)(void *, uint64_t token, int success);
  void (*ended)(void *, uint64_t session, uint64_t now_us);
} product_root_dns_tcp_callbacks_t;
typedef struct {
  uint64_t allocated_bytes, high_water_bytes, accepted, closed, rejected, stale;
  uint64_t frames, delivered, write_failed, capacity, partial_expired;
  uint32_t sockets, clients, high_water_clients, pending, outputs, high_water_outputs;
  uint16_t port;
  uint8_t accepting;
  int last_error;
} product_root_dns_tcp_status_t;

/* Root's nonblocking local socket boundary. The existing owner supplies file
 * readiness and time. No thread, poller, policy permission or VPP buffer is
 * owned here. Each complete frame receives an independent opaque token. */
product_root_dns_tcp_io_t *product_root_dns_tcp_io_open(uint64_t generation,
  uint16_t port, uint64_t *socket_sequence,
  const product_root_dns_tcp_callbacks_t *, void *, uint64_t now_us);
void product_root_dns_tcp_io_close(product_root_dns_tcp_io_t *, uint64_t now_us);
/* Stop accepting/framing new requests, retaining bounded legal failure output. */
void product_root_dns_tcp_io_quiesce(product_root_dns_tcp_io_t *, uint64_t now_us);
/* Reopen the same owner listeners without discarding older bounded output. */
int product_root_dns_tcp_io_resume(product_root_dns_tcp_io_t *, uint64_t now_us);
int product_root_dns_tcp_io_ready(product_root_dns_tcp_io_t *, uint64_t generation,
  uint64_t cookie, int fd, unsigned events, uint64_t now_us);
int product_root_dns_tcp_io_reply(product_root_dns_tcp_io_t *, uint64_t session,
  uint64_t token, const uint8_t *, size_t, uint64_t now_us);
void product_root_dns_tcp_io_expire(product_root_dns_tcp_io_t *, uint64_t now_us);
uint64_t product_root_dns_tcp_io_deadline(const product_root_dns_tcp_io_t *);
product_root_dns_tcp_status_t product_root_dns_tcp_io_status(const product_root_dns_tcp_io_t *);
#endif
