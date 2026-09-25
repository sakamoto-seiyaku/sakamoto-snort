/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_HELLO_H
#define SAKAMOTO_PRODUCT_HELLO_H
#include "product_flow_entry.h"
/* Internal synchronous borrowed spans, in handshake-byte order. Producers
 * validate bounds/count (<=32) and contiguous logical coverage before calling. */
typedef struct { unsigned at, size; } product_hello_span_t;
/* Main-thread startup, before packet workers may call the producer. */
int product_quic_init(void);
unsigned product_sni_parse_hello(const uint8_t *bytes,
  const product_hello_span_t *spans,unsigned count,unsigned size,
  product_sni_state_t *state);
void product_flow_quic_observe(product_flow_entry_t *entry,
  const uint8_t *payload,uint32_t length);
#endif
