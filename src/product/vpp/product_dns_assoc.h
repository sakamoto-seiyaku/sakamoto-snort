/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_ASSOC_H
#define SAKAMOTO_PRODUCT_DNS_ASSOC_H

#include "product_dns.h"

/* Domain-IP association facts (APPLICATION_DNS_SPEC section 10).
 *
 * A pair is (QName, address) taken from an A/AAAA record in the ANSWER section
 * whose owner is the QName or a CNAME actually connected to it. Authority and
 * additional data, SVCB/HTTPS hints and text never become pairs. Each pair keeps
 * its own two-hour life, independent of the answer TTL and of every other pair.
 * Only an allowed, complete answer (wire or current-view cache) refreshes it;
 * qualification lookups and business traffic never do.
 *
 * The table is a fact store. Which Apps or profiles may consume a pair is an
 * undecided product question, so no enforcement is built here: the single
 * consumer hook below reports candidates and never acts on them. */
#define PRODUCT_DNS_ASSOC_ENTRIES 1024U
#define PRODUCT_DNS_ASSOC_PER_ANSWER 128U /* pairs one answer may admit */
#define PRODUCT_DNS_ASSOC_WINDOW_US (UINT64_C(2) * 3600U * 1000000U) /* provisional */
#define PRODUCT_DNS_ASSOC_ENFORCEMENT_ENABLED 0

typedef enum {
  PRODUCT_DNS_ASSOC_NOT_ELIGIBLE = 1, /* RCODE, truncation, broken chain or no QName */
  PRODUCT_DNS_ASSOC_NO_ADDRESS,       /* no reliable address record in the answer */
  PRODUCT_DNS_ASSOC_UNUSABLE_ONLY,    /* only unspecified/loopback/multicast addresses */
  PRODUCT_DNS_ASSOC_OVER_LIMIT,       /* more addresses than one answer may admit */
} product_dns_assoc_reason_t;

/* Facts about the answer that produced the pairs; kept per pair, never enriched
 * later. delivery: 0 unknown, 1 the reply was accepted for output, 2 it was not.
 * Neither value says the App received it. */
typedef struct {
  uint64_t generation, network_revision, route_revision, underlay_epoch, token;
  uint32_t resolver_id, resolution_route;
  uint16_t qtype, rcode;
  uint8_t caller;    /* product_dns_caller_t of the original request */
  uint8_t transport; /* product_dns_proxy_transport_t */
  uint8_t cached;    /* answer came from the data cache */
  uint8_t delivery;
} product_dns_assoc_source_t;

typedef struct {
  uint8_t admitted, refreshed, skipped, evicted, reason;
} product_dns_assoc_admission_t;

typedef struct {
  uint64_t admitted, refreshed, expired, evicted, view_dropped, skipped, rejected;
  uint32_t count, high_water;
} product_dns_assoc_stats_t;

typedef enum {
  PRODUCT_DNS_ASSOC_NO_CANDIDATE = 0,
  PRODUCT_DNS_ASSOC_ONE_CANDIDATE = 1,
  PRODUCT_DNS_ASSOC_MANY_CANDIDATES = 2,
} product_dns_assoc_status_t;

/* A single candidate is indirect evidence only, never proof of the actual
 * connection identity. Several or none means the domain is unavailable. */
typedef struct {
  uint8_t status, caller, delivery, via_cname;
  uint32_t candidates;
  uint64_t expires_us, refreshed_us;
  char name[256];
} product_dns_assoc_qualification_t;

typedef struct product_dns_assoc product_dns_assoc_t;

product_dns_assoc_t *product_dns_assoc_open (void);
void product_dns_assoc_close (product_dns_assoc_t *);
void product_dns_assoc_clear (product_dns_assoc_t *);

/* Extract and admit pairs from one allowed answer. Returns the number of pairs
 * created or refreshed. The caller must have already applied policy: a refused
 * or truncated answer is not passed here. */
unsigned product_dns_assoc_admit (product_dns_assoc_t *, const uint8_t *wire, size_t length,
  const product_dns_response_t *, const product_dns_assoc_source_t *, uint64_t now_us,
  product_dns_assoc_admission_t *);

/* Drop expired pairs and every pair whose resolver view is not the current one. */
void product_dns_assoc_advance (product_dns_assoc_t *, uint64_t now_us,
  uint64_t network_revision, uint64_t route_revision);

/* Consumption-qualification hook. Read only: it does not refresh, order or
 * remove anything. */
void product_dns_assoc_qualify (const product_dns_assoc_t *, uint64_t now_us,
  uint64_t network_revision, uint64_t route_revision, unsigned family,
  const uint8_t address[16], product_dns_assoc_qualification_t *);

product_dns_assoc_stats_t product_dns_assoc_stats (const product_dns_assoc_t *);
size_t product_dns_assoc_bytes (void);

#endif
