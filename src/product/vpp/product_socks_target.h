/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_SOCKS_TARGET_H
#define SAKAMOTO_PRODUCT_SOCKS_TARGET_H

#include "product_http_target.h"

/* SOCKS4, SOCKS4a and SOCKS5 request targets of one TCP connection
 * (APPLICATION_DNS_SPEC section 11). The client stream supplies the request,
 * the server stream the SOCKS5 method selection that proves a real negotiation
 * and, for SOCKS4/4a, the reply that confirms it. The outer proxy endpoint is
 * the connection's own address; the target is only what the request names.
 *
 * Only CONNECT names a remote target. BIND and UDP ASSOCIATE are reported with
 * reason COMMAND and no target. After the request the connection is a tunnel
 * and parsing ends. The same bounded result type as HTTP is used. */
#define PRODUCT_SOCKS_BUFFER_BYTES 600U   /* SOCKS4a: 8 + 255 user + 1 + 255 host + 1, SOCKS5 auth 513 */
#define PRODUCT_SOCKS_FIELD_BYTES 255U

typedef enum {
  PRODUCT_SOCKS_VERSION_NONE = 0, PRODUCT_SOCKS_VERSION_4 = 4, PRODUCT_SOCKS_VERSION_5 = 5,
} product_socks_version_t;

/* Values shared with product_http_target_stop_t where the meaning is the same. */
typedef enum {
  PRODUCT_SOCKS_RUNNING = 0,
  PRODUCT_SOCKS_STOP_NOT_SOCKS = 1, /* first bytes are not a SOCKS greeting or request */
  PRODUCT_SOCKS_STOP_MALFORMED = 2,
  PRODUCT_SOCKS_STOP_LIMIT = 3,     /* a field or message above its bound */
  PRODUCT_SOCKS_STOP_METHOD = 4,    /* server chose no acceptable or an unsupported method */
  PRODUCT_SOCKS_STOP_TUNNEL = 6,    /* the request was seen; tunnel bytes follow */
  PRODUCT_SOCKS_STOP_SEQUENCE = 7,  /* the caller lost bytes */
} product_socks_stop_t;

typedef struct {
  uint8_t buffer[PRODUCT_SOCKS_BUFFER_BYTES];
  uint16_t length;
  uint8_t version, state, stop, method, server_bytes, server_version;
  uint8_t offered_no_auth, offered_password, only_no_auth;
  uint8_t confirmed;   /* SOCKS5: valid method selection; SOCKS4: reply 0x00 0x5a */
  uint8_t socks4a, command, reply;
  uint64_t requests;
} product_socks_target_t;

void product_socks_target_init (product_socks_target_t *, unsigned version);

/* Client-direction bytes. PRODUCT_HTTP_FEED_REQUEST fills *request. */
int product_socks_target_client (product_socks_target_t *, const uint8_t *, size_t, size_t *consumed,
  product_http_request_t *request);
/* Server-direction bytes. May complete a request the client already sent while
 * waiting for the SOCKS5 method selection. */
int product_socks_target_server (product_socks_target_t *, const uint8_t *, size_t,
  product_http_request_t *request);
void product_socks_target_lost (product_socks_target_t *);

#endif
