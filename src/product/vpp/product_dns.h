/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_H
#define SAKAMOTO_PRODUCT_DNS_H

#include "product_l4_policy.h"
#include "product_domains.h"

#define PRODUCT_DNS_MESSAGE_MAX 65535U
#define PRODUCT_DNS_CODEC_BYTES (512U * 1024U)
#define PRODUCT_DNS_REQUESTS 1024U
#define PRODUCT_DNS_NAMES 33U
#define PRODUCT_DNS_REQUEST_US UINT64_C(10000000)
#define PRODUCT_DNS_WORK_BYTES (8U * 1024U * 1024U)

typedef enum {
  PRODUCT_DNS_NOT_QUERY = 0,
  PRODUCT_DNS_QUERY_COMPLETE,
  PRODUCT_DNS_MALFORMED,
  PRODUCT_DNS_UNSUPPORTED,
  PRODUCT_DNS_CAPACITY,
  PRODUCT_DNS_COPY_GAP,
  PRODUCT_DNS_TCP_PENDING,
  PRODUCT_DNS_TCP_MIDSTREAM,
  PRODUCT_DNS_TCP_GAP,
  PRODUCT_DNS_TCP_CONFLICT,
  PRODUCT_DNS_TCP_EXPIRED,
  PRODUCT_DNS_TCP_OLD_BYTES, /* completed history moved out of the retained window */
} product_dns_coverage_t;

/* Adapter-qualified normal App ownership. A known socket UID alone does
 * not establish the original DNS caller; system delegates stay Unknown. */
typedef enum {
  PRODUCT_DNS_CALLER_UNKNOWN = 0,
  PRODUCT_DNS_CALLER_PLATFORM_APP = 1,
} product_dns_caller_t;

typedef struct {
  product_l4_policy_packet_t packet;
  const product_domains_t *domains; /* synchronous protected-snapshot borrow */
  product_dns_caller_t caller;
  uint8_t domains_available; /* a valid empty snapshot may have no trie */
} product_dns_context_t;

typedef struct {
  product_l4_policy_packet_t packet;
  uint32_t codec_peak_bytes;
  uint16_t id, flags, qtype, qclass, name_length;
  uint16_t udp_capacity, edns_flags;
  uint8_t coverage, caller, edns_present;
  char name[256];
  uint64_t wire_hash, message_sequence; /* nonzero only for a framed TCP message */
  uint32_t tcp_sequence;
  uint8_t tcp_continuation;
} product_dns_query_t;

typedef struct {
  uint64_t generation, incarnation, network_revision, now_us;
  uint64_t transport_session, underlay_epoch;
  uint8_t profile; /* Root=1, VPN=2. Never part of canonical flow ownership. */
} product_dns_identity_t;
typedef struct { uint64_t generation, revision, hash, winner; } product_dns_policy_identity_t;
typedef enum {
  PRODUCT_DNS_CORRELATION_NONE = 0,
  PRODUCT_DNS_CORRELATED,
  PRODUCT_DNS_UNMATCHED,
  PRODUCT_DNS_AMBIGUOUS,
  PRODUCT_DNS_REQUEST_CAPACITY,
  PRODUCT_DNS_BINDING_UNAVAILABLE,
} product_dns_correlation_t;
typedef struct {
  product_dns_query_t query;
  product_dns_identity_t identity;
  product_dns_policy_identity_t policy;
  uint64_t token, transport_token, deadline;
  uint32_t bound_context;
  uint16_t retransmits, requests;
  uint8_t active, replied, ambiguous, bound_context_known, generated_return;
} product_dns_request_t;
typedef struct {
  uint64_t generation, overflow_until;
  uint64_t expired, capacity, retransmits, ambiguous, matched, unmatched;
  uint32_t high_water;
  uint8_t accepting;
  product_dns_request_t requests[PRODUCT_DNS_REQUESTS];
} product_dns_owner_t;
typedef struct {
  uint64_t lists;
  uint16_t length;
  uint8_t available, source; /* QName=0, actual connected CNAME=1. */
  char name[256];
} product_dns_name_t;
typedef struct {
  product_dns_query_t question;
  product_dns_policy_identity_t query_policy;
  uint64_t query_token, query_incarnation, transport_session, underlay_epoch;
  uint32_t query_uid;
  uint16_t matched_requests, retransmits, rcode;
  uint8_t correlation, name_count, chain_status, query_uid_known;
  product_dns_name_t names[PRODUCT_DNS_NAMES];
} product_dns_response_t;
_Static_assert(sizeof(product_dns_owner_t) + sizeof(product_dns_response_t) +
  sizeof(product_dns_query_t) + PRODUCT_DNS_CODEC_BYTES + 2U * 704U <= PRODUCT_DNS_WORK_BYTES,
  "DNS retained state and synchronous wire/observation work fit the owner budget");

/* Owner-local original-path observations. No datagram, codec borrow or policy
 * permission survives the call; completed/ambiguous IDs remain tombstones for
 * the finite request window. Caller evidence is never enriched retrospectively. */
void product_dns_owner_start (product_dns_owner_t *, uint64_t generation);
void product_dns_owner_stop (product_dns_owner_t *);
/* A raw generated return loses native provenance on kernel recapture. Keep an
 * anonymous, finite UDP tombstone so exact later tuple/Question reuse cannot
 * attach another original request's caller to that indistinguishable wire. */
void product_dns_generated_return (product_dns_owner_t *, const product_dns_query_t *, uint64_t now_us);
uint64_t product_dns_owner_deadline (const product_dns_owner_t *);
unsigned product_dns_owner_active (product_dns_owner_t *, uint64_t now_us);
product_dns_correlation_t product_dns_remember (product_dns_owner_t *,
  const product_dns_query_t *, const product_dns_identity_t *, uint64_t token,
  const product_dns_policy_identity_t *);
void product_dns_request_transport (product_dns_owner_t *, uint64_t generation,
  uint64_t token, uint64_t incarnation, uint64_t session, uint64_t epoch,
  uint32_t context, int context_known);
void product_dns_transport_bound (product_dns_owner_t *, uint64_t generation,
  uint64_t session, uint64_t epoch, uint32_t context, int context_known);
void product_dns_inspect_response (const uint8_t *, size_t,
  const product_dns_context_t *, const product_dns_identity_t *,
  product_dns_owner_t *, product_dns_response_t *);
/* A proxy transport already supplies one exact live request identity. The
 * complete answer still has to match its ID and full Question; this does not
 * consult or guess from the original-path correspondence table. */
void product_dns_inspect_answer (const uint8_t *, size_t,
  const product_dns_context_t *, const product_dns_query_t *, product_dns_response_t *);
product_l4_policy_status_t product_dns_response_match (
  const product_l4_policy_view_t *, const product_l4_policy_packet_t *,
  const product_dns_response_t *, product_l4_policy_position_t,
  product_l4_policy_match_result_t *);

/* Complete message observation only. No wire rewrite, retained borrow, socket,
 * permission cache, or asynchronous work. Generic packet facts stay intact. */
void product_dns_inspect_query (const uint8_t *, size_t,
                                const product_dns_context_t *,
                                product_dns_query_t *);
typedef struct { uint64_t codec_live_bytes, active_operations; } product_dns_resources_t;
product_dns_resources_t product_dns_resources (void);
#endif
