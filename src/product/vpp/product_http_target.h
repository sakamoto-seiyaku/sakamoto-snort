/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_HTTP_TARGET_H
#define SAKAMOTO_PRODUCT_HTTP_TARGET_H

#include <stddef.h>
#include <stdint.h>

/* Visible cleartext HTTP/1.x request targets (APPLICATION_DNS_SPEC section 11).
 *
 * An incremental parser for one direction of one TCP connection. It follows
 * message framing (Content-Length, chunked) only to find the next request head;
 * it never stores a body. For every request head it reports the effective
 * target: the absolute-form authority, a CONNECT authority, or the single Host
 * of an origin-form request. A request whose target cannot be established is
 * reported as unavailable with the reason and parsing continues; framing it
 * cannot trust ends parsing for the connection, which is then not a source of
 * further targets.
 *
 * The caller owns ordering: bytes must arrive contiguous and in order, and the
 * head buffer must stay stable and untouched between calls for one connection. */
#define PRODUCT_HTTP_HEAD_BYTES 4096U
#define PRODUCT_HTTP_FIELDS 64U
#define PRODUCT_HTTP_NAME_BYTES 254U /* host name plus NUL, same bound as SNI */
#define PRODUCT_HTTP_STRAY_LINE_BYTES 8U
#define PRODUCT_HTTP_TRAILER_BYTES 1024U

typedef enum {
  PRODUCT_HTTP_TARGET_NONE = 0,
  PRODUCT_HTTP_TARGET_NAME,
  PRODUCT_HTTP_TARGET_IPV4,
  PRODUCT_HTTP_TARGET_IPV6,
} product_http_target_kind_t;

/* Why one request has no usable target; the connection keeps being parsed. */
typedef enum {
  PRODUCT_HTTP_TARGET_OK = 0,
  PRODUCT_HTTP_TARGET_NO_HOST,        /* origin-form without a Host field */
  PRODUCT_HTTP_TARGET_DUPLICATE_HOST, /* more than one Host field */
  PRODUCT_HTTP_TARGET_BAD_AUTHORITY,  /* not a valid host name, IP literal or port */
  PRODUCT_HTTP_TARGET_USERINFO,       /* absolute-form with userinfo */
  PRODUCT_HTTP_TARGET_SCHEME,         /* absolute-form with a scheme other than http */
  PRODUCT_HTTP_TARGET_FORM,           /* request-target form not usable for this method */
  PRODUCT_HTTP_TARGET_COMMAND,        /* SOCKS BIND or UDP ASSOCIATE: no remote connect target */
} product_http_target_reason_t;

/* Why parsing of the whole connection ended. Zero means still running. */
typedef enum {
  PRODUCT_HTTP_RUNNING = 0,
  PRODUCT_HTTP_STOP_NOT_HTTP,   /* first bytes are not an HTTP/1.x request */
  PRODUCT_HTTP_STOP_MALFORMED,  /* request line or field syntax */
  PRODUCT_HTTP_STOP_HEAD_LIMIT, /* head above the byte or field bound */
  PRODUCT_HTTP_STOP_VERSION,    /* not HTTP/1.0 or HTTP/1.1 */
  PRODUCT_HTTP_STOP_FRAMING,    /* body framing that cannot be trusted */
  PRODUCT_HTTP_STOP_TUNNEL,     /* CONNECT or protocol upgrade: no longer HTTP/1.x requests */
  PRODUCT_HTTP_STOP_SEQUENCE,   /* the caller lost bytes */
} product_http_target_stop_t;

typedef struct {
  uint64_t index;           /* ordinal of this request on the connection, from 0 */
  uint8_t kind, reason;     /* kind NONE with a reason, or a usable target */
  uint8_t via_host_field;   /* target came from Host rather than the request-target */
  uint8_t connect;          /* CONNECT method */
  uint16_t port;            /* 0 when absent */
  uint16_t name_length;
  uint8_t address[16];      /* IPv4 in the first four bytes */
  char name[PRODUCT_HTTP_NAME_BYTES];
} product_http_request_t;

typedef struct {
  uint64_t requests;        /* heads completed so far */
  uint64_t body_remaining;  /* Content-Length or current chunk bytes still to skip */
  uint32_t trailer_bytes;
  uint16_t head_length, line_length;
  uint8_t state, stop, stray, chunk_digits, in_extension, prev_cr;
} product_http_target_t;

enum { PRODUCT_HTTP_FEED_MORE = 0, PRODUCT_HTTP_FEED_REQUEST = 1, PRODUCT_HTTP_FEED_STOPPED = 2 };

void product_http_target_init (product_http_target_t *);

/* Feed in-order bytes. PRODUCT_HTTP_FEED_REQUEST fills *request and may leave
 * bytes unconsumed (*consumed < length): call again with the remainder.
 * PRODUCT_HTTP_FEED_STOPPED means t->stop is set; further bytes are ignored. */
int product_http_target_feed (product_http_target_t *, uint8_t head[PRODUCT_HTTP_HEAD_BYTES],
  const uint8_t *bytes, size_t length, size_t *consumed, product_http_request_t *request);

/* host [":" port] or "[" IPv6 "]" [":" port], as used by HTTP and the SOCKS domain form.
 * Fills kind, name or address and port; returns a product_http_target_reason_t. */
unsigned product_http_target_authority (const uint8_t *, size_t, product_http_request_t *);

/* The caller saw a gap or inconsistent overlap. */
void product_http_target_lost (product_http_target_t *);

#endif
