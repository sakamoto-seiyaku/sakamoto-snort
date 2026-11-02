/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_TARGET_H
#define SAKAMOTO_PRODUCT_TARGET_H
#include <stdint.h>
#define PRODUCT_HTTP_NAME_BYTES 254U
enum { PRODUCT_TARGET_SOURCE_NONE, PRODUCT_TARGET_TLS_SNI, PRODUCT_TARGET_QUIC_SNI,
  PRODUCT_TARGET_DTLS_SNI, PRODUCT_TARGET_HTTP_HOST, PRODUCT_TARGET_HTTP_ABSOLUTE,
  PRODUCT_TARGET_HTTP_CONNECT, PRODUCT_TARGET_SOCKS4, PRODUCT_TARGET_SOCKS5 };
typedef struct {
  uint64_t index;           /* ordinal of this request on the connection, from 0 */
  uint8_t kind, reason;     /* kind NONE with a reason, or a usable target */
  uint8_t via_host_field;   /* target came from Host rather than the request-target */
  uint8_t connect;          /* CONNECT method */
  uint16_t port;            /* 0 when absent */
  uint16_t name_length;
  uint8_t address[16];      /* IPv4 in the first four bytes */
  char name[PRODUCT_HTTP_NAME_BYTES];
  uint8_t source, reserved; /* real producer; no DNS or endpoint inference */
} product_target_value_t;
_Static_assert (sizeof (product_target_value_t) == 288, "target value ABI");
#endif
