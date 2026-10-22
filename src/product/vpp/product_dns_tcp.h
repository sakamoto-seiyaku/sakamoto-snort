/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_TCP_H
#define SAKAMOTO_PRODUCT_DNS_TCP_H
#include "product_dns.h"

#define PRODUCT_DNS_TCP_FLOWS 32U
#define PRODUCT_DNS_TCP_FLOW_BYTES (192U * 1024U)

typedef struct product_dns_tcp_flow product_dns_tcp_flow_t;
typedef struct {
  uint64_t generation, allocated_bytes, high_water_bytes;
  uint64_t messages, duplicates, conflicts, gaps, midstream, capacity, expired;
  uint32_t active, high_water;
  uint8_t accepting;
  product_dns_tcp_flow_t *flows[PRODUCT_DNS_TCP_FLOWS];
} product_dns_tcp_owner_t;

/* The Adapter's existing Flow stage supplies this packet's current dynamic
 * facts synchronously. It advances an original packet at most once, including
 * when several framed messages need POST policy. No packet waits for bytes. */
typedef int (*product_dns_tcp_flow_facts_t) (void *, product_l4_policy_packet_t *,
  product_dns_identity_t *);

typedef struct {
  product_dns_context_t context;
  product_dns_identity_t identity;
  product_dns_policy_identity_t policy;
  const product_l4_policy_view_t *view; /* protected synchronous borrow */
  const uint8_t *bytes; /* copied prefix of this original segment, never retained */
  size_t copied, length;
  uint64_t token;
  uint32_t sequence;
  uint8_t flags; /* TCP wire flags; SYN anchors each direction's first byte */
  product_dns_tcp_flow_facts_t flow_facts;
  void *flow_context;
} product_dns_tcp_input_t;

typedef struct {
  product_dns_response_t facts; /* question plus actual connected aliases */
  product_l4_policy_match_result_t match;
  product_l4_policy_status_t status;
  uint64_t message_sequence;
  uint32_t sequence;
  uint8_t stage, continuation;
} product_dns_tcp_event_t;
typedef void (*product_dns_tcp_observer_t) (void *, const product_dns_tcp_event_t *);

/* Only bounded byte copies are retained. Every call finishes synchronously;
 * the caller always completes its original packet through its usual Adapter.
 * Results are per message, including each coalesced frame. A DROP affects the
 * entire current packet and later data while its retained fact still rejects
 * under the current protected policy; no cached permission is reused. */
void product_dns_tcp_start (product_dns_tcp_owner_t *, uint64_t generation);
void product_dns_tcp_stop (product_dns_tcp_owner_t *);
void product_dns_tcp_expire (product_dns_tcp_owner_t *, uint64_t now_us);
uint64_t product_dns_tcp_deadline (const product_dns_tcp_owner_t *);
void product_dns_tcp_bind (product_dns_tcp_owner_t *, product_dns_owner_t *,
  const product_dns_context_t *, const product_dns_identity_t *);
void product_dns_tcp_end (product_dns_tcp_owner_t *, uint64_t generation, uint64_t incarnation);
/* Existing Direct input/broker events bind an admitted framing incarnation.
 * Return stamps are checked against this identity, never used to create it. */
void product_dns_tcp_transport (product_dns_tcp_owner_t *, uint64_t generation,
  uint64_t incarnation, uint64_t session, uint64_t epoch, uint32_t context, int known);
void product_dns_tcp_transport_bound (product_dns_tcp_owner_t *, uint64_t generation,
  uint64_t session, uint64_t epoch, uint32_t context, int known);
void product_dns_tcp_process (product_dns_tcp_owner_t *, product_dns_owner_t *,
  const product_dns_tcp_input_t *, product_dns_tcp_observer_t, void *);
#endif
