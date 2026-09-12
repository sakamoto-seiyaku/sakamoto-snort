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
  PRODUCT_CT_UPDATE_NEW,
} product_ct_update_t;

/* Internal OVS class names, not policy aliases (UDP_SINGLE/UDP_MULTIPLE). */
typedef enum {
  PRODUCT_CT_TIMEOUT_NONE = 0,
  PRODUCT_CT_TIMEOUT_OTHER_FIRST,
  PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE,
  PRODUCT_CT_TIMEOUT_OTHER_BIDIR,
  PRODUCT_CT_TIMEOUT_TCP_FIRST_PACKET,
  PRODUCT_CT_TIMEOUT_TCP_OPENING,
  PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED,
  PRODUCT_CT_TIMEOUT_TCP_CLOSING,
  PRODUCT_CT_TIMEOUT_TCP_FIN_WAIT,
  PRODUCT_CT_TIMEOUT_TCP_CLOSED,
  PRODUCT_CT_TIMEOUT_ICMP_FIRST,
  PRODUCT_CT_TIMEOUT_ICMP_REPLY,
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

enum {
  PRODUCT_ICMP_EMPTY = 0,
  PRODUCT_ICMP_FIRST,
  PRODUCT_ICMP_REPLY,
};
typedef struct {
  uint8_t phase;
  uint8_t seen_request;
  uint8_t seen_reply;
} product_icmp_state_t;

/* Ordering follows the pinned OVS/pf peer-state vocabulary. This is not the
 * socket transport state and is never inferred from endpoint port ordering. */
enum {
  PRODUCT_TCP_CLOSED, PRODUCT_TCP_LISTEN, PRODUCT_TCP_SYN_SENT,
  PRODUCT_TCP_SYN_RECV, PRODUCT_TCP_ESTABLISHED, PRODUCT_TCP_CLOSE_WAIT,
  PRODUCT_TCP_FIN_WAIT_1, PRODUCT_TCP_CLOSING, PRODUCT_TCP_LAST_ACK,
  PRODUCT_TCP_FIN_WAIT_2, PRODUCT_TCP_TIME_WAIT,
};
typedef struct {
  uint32_t seqlo, seqhi;
  uint16_t max_window;
  uint8_t window_scale, phase;
  uint8_t flags_history;
} product_tcp_peer_t;
typedef struct {
  product_tcp_peer_t peer[2];
  uint8_t initialized;
  uint8_t timeout;
} product_tcp_state_t;

/* Synchronous owner-local protocol seam. Consumes the shared parser's facts;
 * no bytes, table, clock, policy or allocation. EMPTY requires the first
 * observer's ORIG direction. Invalid input never changes accepted state. */
product_tracker_result_t product_udp_update (
  product_udp_state_t *state, const product_packet_facts_t *packet,
  product_flow_direction_t direction);

/* A zeroed state is a new connection candidate. INVALID and replacement
 * requests leave its accepted state unchanged; FlowRuntime owns replacement. */
product_tracker_result_t product_tcp_update (
  product_tcp_state_t *state, const product_packet_facts_t *packet,
  product_flow_direction_t direction);

/* Echo only. First observation defines ORIG even for a reply-first pickup;
 * packet type is recorded separately and never substitutes for direction. */
product_tracker_result_t product_icmp_update (
  product_icmp_state_t *state, const product_packet_facts_t *packet,
  product_flow_direction_t direction);

#endif
