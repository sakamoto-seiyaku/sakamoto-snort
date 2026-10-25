/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_PROXY_H
#define SAKAMOTO_PRODUCT_DNS_PROXY_H

#include "product_dns.h"
#include "sakamoto_product_rule_config.h"

#define PRODUCT_DNS_PROXY_TRANSACTIONS 64U
#define PRODUCT_DNS_PROXY_WAITERS 128U
#define PRODUCT_DNS_PROXY_SOCKETS 8U
#define PRODUCT_DNS_PROXY_REPLY_BYTES 1232U
#define PRODUCT_DNS_PROXY_ATTEMPT_US UINT64_C(3000000)
#define PRODUCT_DNS_PROXY_RETRY_US UINT64_C(1500000)

typedef sakamoto_product_dns_config_t product_dns_proxy_route_t;

typedef struct {
  uint64_t generation, token, incarnation, attempt, network_revision, route_revision;
} product_dns_proxy_key_t;

typedef enum {
  PRODUCT_DNS_PROXY_UDP = 1,
  PRODUCT_DNS_PROXY_TCP = 2,
} product_dns_proxy_transport_t;

typedef enum {
  PRODUCT_DNS_PROXY_QUERY = 0,
  PRODUCT_DNS_PROXY_UPSTREAM,
  PRODUCT_DNS_PROXY_REFUSED,
  PRODUCT_DNS_PROXY_SERVFAIL,
  PRODUCT_DNS_PROXY_FORMERR,
  PRODUCT_DNS_PROXY_NOTIMP,
  PRODUCT_DNS_PROXY_CAPACITY,
  PRODUCT_DNS_PROXY_CANCELLED,
  PRODUCT_DNS_PROXY_STOPPED,
  PRODUCT_DNS_PROXY_VIEW_CHANGED,
  PRODUCT_DNS_PROXY_NO_REPLY_IDENTITY,
} product_dns_proxy_result_t;

typedef struct {
  product_dns_context_t context;
  product_dns_identity_t identity;
  uint64_t token, route_revision;
  uint32_t slot;
  /* Actual latest capture at message admission, distinct from a session
   * caller proven by its original SYN. Never used as policy enrichment. */
  uint32_t capture_uid;
  uint8_t capture_availability, capture_present;
} product_dns_proxy_input_t;

/* A current, synchronously protected policy borrow. The Adapter supplies the
 * actual packet/flow facts for this control point; no QName becomes SNI and no
 * upstream address replaces the original DNS packet's address facts. */
typedef struct {
  product_dns_context_t context;
  const product_l4_policy_view_t *view;
  product_dns_policy_identity_t identity;
  uint64_t network_revision, route_revision;
  void *borrow;
} product_dns_proxy_snapshot_t;

typedef struct {
  product_dns_proxy_key_t key;
  product_dns_proxy_input_t input;
  product_dns_query_t query;
  product_dns_policy_identity_t query_policy, policy;
  product_l4_policy_match_result_t match;
  const product_dns_response_t *response; /* callback-duration borrow */
  product_dns_proxy_route_t route;
  uint32_t result, client_capacity, output_bytes;
  uint16_t rcode;
  uint8_t stage, transport, truncated, delivery;
} product_dns_proxy_event_t;

typedef struct {
  /* One nonblocking attempt. A TCP capacity return of zero leaves bounded
   * work queued under its original deadline; -1 is a transport failure. */
  int (*send) (void *, const product_dns_proxy_key_t *, unsigned transport,
               const uint8_t *, size_t, uint64_t deadline);
  void (*cancel) (void *, const product_dns_proxy_key_t *);
  int (*reply) (void *, const product_dns_proxy_event_t *, const uint8_t *, size_t);
  int (*acquire) (void *, const product_dns_proxy_input_t *, product_dns_proxy_snapshot_t *);
  void (*release) (void *, product_dns_proxy_snapshot_t *);
  void (*observe) (void *, const product_dns_proxy_event_t *);
} product_dns_proxy_callbacks_t;

typedef struct product_dns_proxy product_dns_proxy_t;
typedef struct {
  uint64_t owned_bytes, high_water_bytes, stale, completed, cancelled, capacity;
  uint32_t active, high_water;
  uint8_t accepting;
} product_dns_proxy_resources_t;

/* Owner-local complete-message interface. No VPP/NFQ/HEV buffer or protected
 * snapshot survives a call. The route is an explicit single ordinary IP;
 * disabled replacement has no socket or message side effect. */
product_dns_proxy_t *product_dns_proxy_open (uint64_t generation,
  const product_dns_proxy_route_t *, const product_dns_proxy_callbacks_t *, void *);
void product_dns_proxy_close (product_dns_proxy_t *);
void product_dns_proxy_stop (product_dns_proxy_t *, uint64_t now_us);
int product_dns_proxy_submit (product_dns_proxy_t *, const product_dns_proxy_input_t *,
  const uint8_t *, size_t, const product_dns_proxy_snapshot_t *);
void product_dns_proxy_answer (product_dns_proxy_t *, const product_dns_proxy_key_t *,
  unsigned transport, const uint8_t *, size_t, uint64_t now_us);
void product_dns_proxy_fail (product_dns_proxy_t *, const product_dns_proxy_key_t *, uint64_t now_us);
void product_dns_proxy_cancel (product_dns_proxy_t *, const product_dns_proxy_key_t *, uint64_t now_us);
void product_dns_proxy_end (product_dns_proxy_t *, uint64_t generation, uint64_t incarnation, uint64_t now_us);
void product_dns_proxy_session_end (product_dns_proxy_t *, uint64_t generation, uint64_t session, uint64_t now_us);
/* Admission can fail before an owner transaction exists. It still applies
 * current query policy and returns the appropriate legal local DNS result. */
int product_dns_proxy_unavailable (const product_dns_proxy_input_t *, const uint8_t *, size_t,
  const product_dns_proxy_snapshot_t *, const product_dns_proxy_route_t *,
  const product_dns_proxy_callbacks_t *, void *, product_dns_proxy_result_t);
void product_dns_proxy_advance (product_dns_proxy_t *, uint64_t now_us,
  uint64_t network_revision, uint64_t route_revision);
uint64_t product_dns_proxy_deadline (const product_dns_proxy_t *);
product_dns_proxy_resources_t product_dns_proxy_resources (const product_dns_proxy_t *);
/* Shared owner budget includes the existing original-path observation state,
 * codec/scratch work and Adapter-owned asynchronous socket/reply storage. */
void product_dns_proxy_other_bytes (product_dns_proxy_t *, uint64_t);

#endif
