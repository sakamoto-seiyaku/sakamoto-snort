/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_PROXY_H
#define SAKAMOTO_PRODUCT_DNS_PROXY_H

#include "product_dns.h"
#include "product_dns_alpn.h"
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
  uint32_t resolver_family, resolver_port, resolver_id, resolution_route;
  uint8_t resolver_address[16];
} product_dns_proxy_key_t;

typedef enum {
  PRODUCT_DNS_PROXY_UDP = 1,
  PRODUCT_DNS_PROXY_TCP = 2,
  PRODUCT_DNS_PROXY_DOT = 3,
  PRODUCT_DNS_PROXY_DOH = 4,
} product_dns_proxy_transport_t;

enum { PRODUCT_DNS_TLS_NONE, PRODUCT_DNS_TLS_HANDSHAKING, PRODUCT_DNS_TLS_AUTHENTICATED,
  PRODUCT_DNS_TLS_FAILED, PRODUCT_DNS_TLS_CACHED_DATA };
enum { PRODUCT_DNS_BOOTSTRAP_NONE, PRODUCT_DNS_BOOTSTRAP_PENDING,
  PRODUCT_DNS_BOOTSTRAP_RESOLVED, PRODUCT_DNS_BOOTSTRAP_FAILED };
enum { PRODUCT_DNS_AUTHORIZATION_NONE, PRODUCT_DNS_AUTHORIZATION_PENDING,
  PRODUCT_DNS_AUTHORIZATION_GRANTED, PRODUCT_DNS_AUTHORIZATION_FAILED };
/* DoH HTTP failure class: 1..11 are the negated product_dns_http_result_t codes,
 * 12 is an ALPN mismatch (including an HTTP/2-only endpoint). 0 means none. */
#define PRODUCT_DNS_HTTP_ERROR_ALPN 12U
typedef struct {
  uint8_t connection_address[16], bootstrap_address[16];
  uint32_t connection_family, connection_port, bootstrap_family, bootstrap_port, bootstrap_ifindex;
  int32_t error;
  uint8_t tls, bootstrap, authorization, trust_source; /* system=1, debug fixture=2 */
  uint8_t http_error, alpn; /* DoH only; alpn is PRODUCT_DNS_ALPN_* */
  uint16_t http_status;
  uint32_t http_age;
} product_dns_proxy_io_event_t;

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
  PRODUCT_DNS_PROXY_CACHE,
  PRODUCT_DNS_PROXY_ATTEMPT,
  PRODUCT_DNS_PROXY_ATTEMPT_FAILED,
  PRODUCT_DNS_PROXY_ATTEMPT_TIMEOUT,
  PRODUCT_DNS_PROXY_ATTEMPT_INVALID,
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
  sakamoto_product_dns_endpoint_t route;
  uint64_t upstream_attempt;
  uint32_t resolution_route, resolver_id;
  uint32_t result, client_capacity, output_bytes;
  uint16_t rcode;
  uint8_t stage, transport, truncated, delivery, cached;
  product_dns_proxy_io_event_t io;
} product_dns_proxy_event_t;

enum {
  PRODUCT_DNS_REPLY_REJECTED = 0,
  PRODUCT_DNS_REPLY_ACCEPTED = 1,
  PRODUCT_DNS_REPLY_CAPACITY = -1,
};

typedef struct {
  /* One nonblocking attempt. A TCP capacity return of zero leaves bounded
   * work queued under its original deadline; -1 is a transport failure. */
  int (*send) (void *, const product_dns_proxy_key_t *, unsigned transport,
               const uint8_t *, size_t, uint64_t deadline);
  void (*cancel) (void *, const product_dns_proxy_key_t *);
  /* Capacity is distinct from a stale/closed channel or transport error: it
   * retains the exact token for one bounded SERVFAIL fallback. */
  int (*reply) (void *, const product_dns_proxy_event_t *, const uint8_t *, size_t);
  int (*acquire) (void *, const product_dns_proxy_input_t *, product_dns_proxy_snapshot_t *);
  void (*release) (void *, product_dns_proxy_snapshot_t *);
  void (*observe) (void *, const product_dns_proxy_event_t *);
  /* Drop only this undeliverable transport obligation, if it still exists. */
  void (*abandon) (void *, const product_dns_proxy_event_t *);
} product_dns_proxy_callbacks_t;

typedef struct product_dns_proxy product_dns_proxy_t;
typedef struct {
  uint64_t cooldown_until;
  uint32_t failures;
  uint8_t probing;
} product_dns_proxy_health_t;
typedef struct {
  uint64_t owned_bytes, high_water_bytes, stale, completed, cancelled, capacity;
  uint32_t active, high_water, exchanges, exchange_high_water;
  uint64_t coalesced;
  uint8_t accepting;
  uint64_t cache_bytes, cache_high_water_bytes, cache_hits, cache_misses, cache_evictions, cache_skipped;
  uint32_t cache_entries, cache_high_water;
  uint64_t failed_attempts, failovers;
  product_dns_proxy_health_t health[SAKAMOTO_DNS_MAX_ENDPOINTS];
} product_dns_proxy_resources_t;

/* Owner-local complete-message interface. No VPP/NFQ/HEV buffer or protected
 * snapshot survives a call. Routes contain only explicitly configured ordinary
 * endpoints or the request's exact original network resolver;
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
/* Same live attempt's transport event. Discovery and socket authorization
 * never stand in for service authentication. */
void product_dns_proxy_io_event (product_dns_proxy_t *, const product_dns_proxy_key_t *,
  const product_dns_proxy_io_event_t *);
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
