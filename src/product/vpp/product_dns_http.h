/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DNS_HTTP_H
#define PRODUCT_DNS_HTTP_H
#include <stddef.h>
#include <stdint.h>

/* Private DoH HTTP/1.1 framing. It has no socket, TLS or clock dependency: the
 * Adapter feeds the exact decrypted bytes it read and receives one bounded DNS
 * message. One exchange uses one connection. No redirect, compression or HTTP
 * proxy behavior exists here; each is reported as a distinct failure. */
#define PRODUCT_DNS_HTTP_HEADER_BYTES 8192U
#define PRODUCT_DNS_HTTP_HEADER_FIELDS 64U
#define PRODUCT_DNS_HTTP_PATH_BYTES 512U
#define PRODUCT_DNS_HTTP_HOST_BYTES 255U
#define PRODUCT_DNS_HTTP_REQUEST_MAX (PRODUCT_DNS_HTTP_HEADER_BYTES+65535U)

typedef enum {
  PRODUCT_DNS_HTTP_MORE = 0,
  PRODUCT_DNS_HTTP_DONE = 1,
  PRODUCT_DNS_HTTP_FRAMING = -1,       /* malformed line, header, length or chunk */
  PRODUCT_DNS_HTTP_STATUS = -2,        /* final status is not 200 */
  PRODUCT_DNS_HTTP_REDIRECT = -3,      /* 3xx; never followed */
  PRODUCT_DNS_HTTP_CONTENT_TYPE = -4,  /* missing or not application/dns-message */
  PRODUCT_DNS_HTTP_ENCODING = -5,      /* Content-Encoding or Transfer-Encoding not supported */
  PRODUCT_DNS_HTTP_HEADER_LIMIT = -6,  /* header bytes or field count above bound */
  PRODUCT_DNS_HTTP_BODY_LIMIT = -7,    /* body above caller capacity */
  PRODUCT_DNS_HTTP_EMPTY = -8,         /* final body below a DNS header */
  PRODUCT_DNS_HTTP_TRAILING = -9,      /* bytes after the one allowed response */
  PRODUCT_DNS_HTTP_CLOSED = -10,       /* connection ended before a complete response */
  PRODUCT_DNS_HTTP_AGE = -11           /* malformed or repeated Age */
} product_dns_http_result_t;

typedef struct {
  uint8_t state, chunked, has_length, content_type_ok, age_seen, close_delimited;
  uint8_t connection_close, line_overflow;
  uint16_t status, fields;
  uint32_t age;
  uint32_t header_bytes;
  uint64_t length, chunk_remaining;
  size_t line_at;
  uint8_t *body;
  size_t body_cap, body_at;
  char line[PRODUCT_DNS_HTTP_HEADER_BYTES];
} product_dns_http_response_t;

/* POST with Content-Type and Accept application/dns-message. host may be a
 * name, an IPv4 address or an unbracketed IPv6 address; the Host field brackets
 * IPv6 and omits the default port 443. Returns the byte count or 0. */
size_t product_dns_http_build_request(uint8_t *out, size_t capacity, const char *host,
  uint16_t port, const char *path, const uint8_t *dns, size_t dns_length);
int product_dns_http_path_valid(const char *path);
void product_dns_http_init(product_dns_http_response_t *response, uint8_t *body, size_t capacity);
/* Consumes input until the response completes or fails. consumed is always set. */
int product_dns_http_feed(product_dns_http_response_t *response, const uint8_t *bytes,
  size_t length, size_t *consumed);
/* Orderly close: legal only for an identity body delimited by the connection. */
int product_dns_http_eof(product_dns_http_response_t *response);
#endif
