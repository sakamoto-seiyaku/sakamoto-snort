/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FLOW_TRACKER_H
#define SAKAMOTO_PRODUCT_FLOW_TRACKER_H

#include "product_packet.h"

typedef enum {
  PRODUCT_FLOW_DIRECTION_UNKNOWN = 0,
  PRODUCT_FLOW_DIRECTION_ORIG = 1,
  PRODUCT_FLOW_DIRECTION_REPLY = 2,
} product_flow_direction_t;

typedef enum {
  PRODUCT_CT_UNKNOWN = 0,
  PRODUCT_CT_NEW,
  PRODUCT_CT_ESTABLISHED,
  PRODUCT_CT_INVALID,
} product_ct_state_t;

typedef enum {
  PRODUCT_CT_UPDATE_NONE = 0,
  PRODUCT_CT_UPDATE_VALID_NEW,
  PRODUCT_CT_UPDATE_VALID,
  PRODUCT_CT_UPDATE_INVALID,
} product_ct_update_t;

/* Internal OVS class names, not policy aliases (UDP_SINGLE/UDP_MULTIPLE). */
typedef enum {
  PRODUCT_CT_TIMEOUT_NONE = 0,
  PRODUCT_CT_TIMEOUT_OTHER_FIRST,
  PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE,
  PRODUCT_CT_TIMEOUT_OTHER_BIDIR,
} product_ct_timeout_t;

typedef struct {
  product_ct_state_t state;
  product_flow_direction_t direction;
} product_ct_facts_t;

typedef struct {
  product_ct_facts_t facts;
  product_ct_update_t update;
  product_ct_timeout_t timeout;
  uint8_t refresh_deadline;
  uint8_t close_old_instance;
  uint8_t create_replacement;
} product_tracker_result_t;

enum {
  PRODUCT_UDP_EMPTY = 0,
  PRODUCT_UDP_FIRST,
  PRODUCT_UDP_MULTIPLE,
  PRODUCT_UDP_BIDIR,
};
typedef struct { uint8_t phase; } product_udp_state_t;

/* Synchronous owner-local protocol seam. Consumes the shared parser's facts;
 * no bytes, table, clock, policy or allocation. EMPTY requires the first
 * observer's ORIG direction. Invalid input never changes accepted state. */
product_tracker_result_t product_udp_update (
  product_udp_state_t *state, const product_packet_facts_t *packet,
  product_flow_direction_t direction);

#endif
