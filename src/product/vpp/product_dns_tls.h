/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DNS_TLS_H
#define PRODUCT_DNS_TLS_H
#include "product_dns_alpn.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Private transport implementation. No TLS object crosses the DNS Core's
 * message/context/event boundary or survives its owning Adapter. */
#define PRODUCT_DNS_TLS_TRUST_BYTES (1024U*1024U)
#define PRODUCT_DNS_TLS_OWNER_BYTES (1024U*1024U)
#define PRODUCT_DNS_TLS_CONNECTION_BYTES (256U*1024U)
#define PRODUCT_DNS_TLS_CERTIFICATE_BYTES 16384U
#define PRODUCT_DNS_TLS_TRUST_INPUT_BYTES (512U*1024U)
#define PRODUCT_DNS_TLS_TRUST_CERTIFICATES 256U
typedef struct product_dns_tls_owner product_dns_tls_owner_t;
typedef struct product_dns_tls product_dns_tls_t;
typedef struct {
  uint64_t bytes, high_water_bytes, rejected;
  uint32_t trust_certificates, authenticated;
} product_dns_tls_resources_t;
product_dns_tls_owner_t *product_dns_tls_owner_open(const char *trust_directory);
void product_dns_tls_owner_close(product_dns_tls_owner_t *);
product_dns_tls_resources_t product_dns_tls_resources(const product_dns_tls_owner_t *);
size_t product_dns_tls_reservation(unsigned connections);
product_dns_tls_t *product_dns_tls_open(product_dns_tls_owner_t *, int fd, const char *identity);
/* DoH uses a separate client profile that offers ALPN "http/1.1" only. */
product_dns_tls_t *product_dns_tls_open_doh(product_dns_tls_owner_t *, int fd, const char *identity);
int product_dns_tls_alpn_state(const product_dns_tls_t *);
/* Orderly TLS close_notify from the peer (not a bare TCP end). */
int product_dns_tls_peer_closed(const product_dns_tls_t *);
void product_dns_tls_close(product_dns_tls_t *);
/* One nonblocking progress attempt; 1 authenticated, 0 dependency-blocked,
 * -1 failed. wanted uses the existing Adapter READ/WRITE event bits. */
int product_dns_tls_handshake(product_dns_tls_t *, unsigned *wanted);
int product_dns_tls_pending(const product_dns_tls_t *);
int product_dns_tls_error(const product_dns_tls_t *);
ssize_t product_dns_tls_write(product_dns_tls_t *, const uint8_t *, size_t, unsigned *wanted);
ssize_t product_dns_tls_read(product_dns_tls_t *, uint8_t *, size_t, unsigned *wanted);
#endif
