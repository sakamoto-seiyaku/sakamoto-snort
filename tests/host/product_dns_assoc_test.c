/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_assoc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define HOUR (UINT64_C(3600) * 1000000U)
#define NETWORK 5U
#define ROUTE 9U

typedef struct { uint8_t bytes[1024]; size_t length; } wire_t;

static void put16 (wire_t *w, unsigned v) { w->bytes[w->length++] = v >> 8; w->bytes[w->length++] = v; }
static void put_name (wire_t *w, const char *name)
{
  while (*name)
    {
      const char *dot = strchr (name, '.');
      size_t n = dot ? (size_t) (dot - name) : strlen (name);
      w->bytes[w->length++] = (uint8_t) n;
      memcpy (w->bytes + w->length, name, n); w->length += n;
      name += n + (dot ? 1 : 0);
    }
  w->bytes[w->length++] = 0;
}
static void put_rr (wire_t *w, const char *owner, unsigned type, const uint8_t *data, size_t bytes)
{
  put_name (w, owner); put16 (w, type); put16 (w, 1);
  put16 (w, 0); put16 (w, 60); put16 (w, (unsigned) bytes);
  memcpy (w->bytes + w->length, data, bytes); w->length += bytes;
}
static void put_cname (wire_t *w, const char *owner, const char *target)
{
  wire_t name = {0}; put_name (&name, target);
  put_rr (w, owner, 5, name.bytes, name.length);
}

/* Question only; id 0x1234. */
static wire_t query_wire (const char *qname, unsigned qtype)
{
  wire_t w = {0};
  put16 (&w, 0x1234); put16 (&w, 0x0100); put16 (&w, 1); put16 (&w, 0); put16 (&w, 0); put16 (&w, 0);
  put_name (&w, qname); put16 (&w, qtype); put16 (&w, 1);
  return w;
}
static void header (wire_t *w, unsigned flags, unsigned answers, unsigned authority, unsigned additional)
{
  w->bytes[2] = flags >> 8; w->bytes[3] = flags;
  w->bytes[6] = answers >> 8; w->bytes[7] = answers;
  w->bytes[8] = authority >> 8; w->bytes[9] = authority;
  w->bytes[10] = additional >> 8; w->bytes[11] = additional;
}

static product_dns_response_t inspect (const wire_t *answer, const char *qname, unsigned qtype)
{
  product_dns_context_t request = {.caller = PRODUCT_DNS_CALLER_PLATFORM_APP,
    .packet = {.uid = 10123, .uid_known = 1, .family = 4, .protocol = 17, .direction = 3, .direction_known = 1,
      .ports_available = 1, .source_port = 40000, .destination_port = 53,
      .source_address = {192, 0, 2, 2}, .destination_address = {192, 0, 2, 53}}};
  wire_t q = query_wire (qname, qtype);
  product_dns_query_t query;
  product_dns_inspect_query (q.bytes, q.length, &request, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE);
  product_dns_response_t response;
  product_dns_inspect_answer (answer->bytes, answer->length, &request, &query, &response);
  return response;
}

static product_dns_assoc_source_t source (unsigned delivery)
{
  return (product_dns_assoc_source_t) {.generation = 77, .network_revision = NETWORK, .route_revision = ROUTE,
    .underlay_epoch = 3, .token = 11, .resolver_id = 1, .resolution_route = 0, .qtype = 1,
    .caller = PRODUCT_DNS_CALLER_PLATFORM_APP, .transport = 1, .delivery = delivery};
}

static wire_t a_answer (const char *qname, const uint8_t ip[4])
{
  wire_t w = query_wire (qname, 1);
  header (&w, 0x8180, 1, 0, 0);
  put_rr (&w, qname, 1, ip, 4);
  return w;
}

static unsigned admit (product_dns_assoc_t *t, const wire_t *w, const char *qname, unsigned qtype,
  uint64_t now, unsigned delivery, product_dns_assoc_admission_t *result)
{
  product_dns_response_t response = inspect (w, qname, qtype);
  product_dns_assoc_source_t s = source (delivery);
  return product_dns_assoc_admit (t, w->bytes, w->length, &response, &s, now, result);
}

static product_dns_assoc_qualification_t qualify (product_dns_assoc_t *t, uint64_t now, const uint8_t ip[4])
{
  uint8_t address[16] = {0};
  memcpy (address, ip, 4);
  product_dns_assoc_qualification_t q;
  product_dns_assoc_qualify (t, now, NETWORK, ROUTE, 4, address, &q);
  return q;
}

static void answer_creates_pairs_with_their_source (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  const uint8_t ip[4] = {192, 0, 2, 10};
  wire_t w = a_answer ("example.com", ip);
  product_dns_assoc_admission_t r;
  assert (admit (t, &w, "example.com", 1, 1000, 1, &r) == 1 && r.admitted == 1 && !r.refreshed);
  product_dns_assoc_qualification_t q = qualify (t, 2000, ip);
  assert (q.status == PRODUCT_DNS_ASSOC_ONE_CANDIDATE && !strcmp (q.name, "example.com"));
  assert (q.caller == PRODUCT_DNS_CALLER_PLATFORM_APP && q.delivery == 1 && !q.via_cname);
  assert (q.expires_us == 1000 + 2 * HOUR);
  /* Delivery failure is its own evidence, not an App-received claim. */
  const uint8_t other[4] = {192, 0, 2, 11};
  w = a_answer ("example.com", other);
  assert (admit (t, &w, "example.com", 1, 1000, 2, &r) == 1);
  assert (qualify (t, 2000, other).delivery == 2);
  assert (qualify (t, 2000, (uint8_t[4]){192, 0, 2, 99}).status == PRODUCT_DNS_ASSOC_NO_CANDIDATE);
  product_dns_assoc_close (t);
}

static void cname_chain_connects_every_name_to_the_address (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  const uint8_t ip[4] = {198, 51, 100, 7}, stray[4] = {203, 0, 113, 9};
  wire_t w = query_wire ("www.example.com", 1);
  put_cname (&w, "www.example.com", "edge.cdn.test");
  put_rr (&w, "edge.cdn.test", 1, ip, 4);
  put_rr (&w, "unrelated.test", 1, stray, 4);          /* answer-section owner off the chain */
  header (&w, 0x8180, 3, 0, 0);
  product_dns_assoc_admission_t r;
  assert (admit (t, &w, "www.example.com", 1, 10, 1, &r) == 2 && r.admitted == 2);
  assert (qualify (t, 20, stray).status == PRODUCT_DNS_ASSOC_NO_CANDIDATE);
  /* Both the QName and the real CNAME reach this address: two names, not unique. */
  product_dns_assoc_qualification_t q = qualify (t, 20, ip);
  assert (q.status == PRODUCT_DNS_ASSOC_MANY_CANDIDATES && q.candidates == 2);
  product_dns_assoc_close (t);
}

static void authority_additional_and_hints_never_create_pairs (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  const uint8_t real[4] = {192, 0, 2, 20}, extra[4] = {192, 0, 2, 21};
  wire_t w = query_wire ("example.com", 1);
  put_rr (&w, "example.com", 1, real, 4);
  put_rr (&w, "example.com", 1, extra, 4);              /* additional section, same owner */
  header (&w, 0x8180, 1, 0, 1);
  product_dns_assoc_admission_t r;
  assert (admit (t, &w, "example.com", 1, 10, 1, &r) == 1);
  assert (qualify (t, 20, real).status == PRODUCT_DNS_ASSOC_ONE_CANDIDATE);
  assert (qualify (t, 20, extra).status == PRODUCT_DNS_ASSOC_NO_CANDIDATE);
  product_dns_assoc_close (t);
}

static void each_pair_keeps_its_own_two_hour_life (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  const uint8_t a[4] = {192, 0, 2, 30}, b[4] = {192, 0, 2, 31};
  product_dns_assoc_admission_t r;
  wire_t w = a_answer ("example.com", a);
  admit (t, &w, "example.com", 1, 9 * HOUR, 1, &r);                  /* 9:00 A */
  w = a_answer ("example.com", b);
  admit (t, &w, "example.com", 1, 10 * HOUR, 1, &r);                 /* 10:00 B */
  assert (qualify (t, 10 * HOUR, a).candidates == 1);                /* A kept independently */
  /* Lookups, however frequent, never renew. */
  for (uint64_t at = 10 * HOUR; at < 11 * HOUR; at += HOUR / 10) (void) qualify (t, at, a);
  assert (qualify (t, 11 * HOUR - 1, a).candidates == 1);
  assert (qualify (t, 11 * HOUR, a).candidates == 0);                /* A ends at 11:00 */
  assert (qualify (t, 11 * HOUR, b).candidates == 1);
  assert (qualify (t, 12 * HOUR, b).candidates == 0);                /* B ends at 12:00 */
  /* A new answer carrying only B refreshes B and leaves absent A alone. */
  w = a_answer ("example.com", a);
  admit (t, &w, "example.com", 1, 13 * HOUR, 1, &r);
  w = a_answer ("example.com", b);
  admit (t, &w, "example.com", 1, 14 * HOUR, 1, &r);
  assert (r.admitted == 1 && !r.refreshed);
  admit (t, &w, "example.com", 1, 14 * HOUR + HOUR / 2, 1, &r);
  assert (r.refreshed == 1 && !r.admitted);
  assert (qualify (t, 15 * HOUR - 1, a).candidates == 1);            /* A still ends at 15:00 */
  assert (qualify (t, 15 * HOUR, a).candidates == 0);
  assert (qualify (t, 16 * HOUR + HOUR / 2 - 1, b).candidates == 1); /* B renewed at 14:30 */
  product_dns_assoc_close (t);
}

static void view_change_excludes_old_pairs_and_expiry_is_counted (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  const uint8_t ip[4] = {192, 0, 2, 40};
  wire_t w = a_answer ("example.com", ip);
  admit (t, &w, "example.com", 1, 100, 1, NULL);
  product_dns_assoc_advance (t, 200, NETWORK, ROUTE);
  assert (qualify (t, 200, ip).candidates == 1);
  uint8_t address[16] = {192, 0, 2, 40};
  product_dns_assoc_qualification_t q;
  product_dns_assoc_qualify (t, 200, NETWORK + 1, ROUTE, 4, address, &q);
  assert (q.status == PRODUCT_DNS_ASSOC_NO_CANDIDATE);               /* wrong view is never consumed */
  product_dns_assoc_advance (t, 300, NETWORK + 1, ROUTE);
  product_dns_assoc_stats_t s = product_dns_assoc_stats (t);
  assert (s.view_dropped == 1 && s.count == 0);
  admit (t, &w, "example.com", 1, 400, 1, NULL);
  product_dns_assoc_advance (t, 400 + 2 * HOUR, NETWORK, ROUTE);
  assert (product_dns_assoc_stats (t).expired == 1 && product_dns_assoc_stats (t).count == 0);
  product_dns_assoc_close (t);
}

static void ineligible_answers_leave_only_a_reason (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  product_dns_assoc_admission_t r;
  const uint8_t ip[4] = {192, 0, 2, 50}, loop[4] = {127, 0, 0, 1};
  wire_t w = a_answer ("example.com", ip);
  w.bytes[3] = 3;                                                    /* NXDOMAIN */
  assert (admit (t, &w, "example.com", 1, 10, 1, &r) == 0 && r.reason == PRODUCT_DNS_ASSOC_NOT_ELIGIBLE);
  w = a_answer ("example.com", ip);
  w.bytes[2] |= 0x02;                                                /* truncated */
  assert (admit (t, &w, "example.com", 1, 10, 1, &r) == 0 && r.reason == PRODUCT_DNS_ASSOC_NOT_ELIGIBLE);
  w = query_wire ("example.com", 1);
  header (&w, 0x8180, 0, 0, 0);
  assert (admit (t, &w, "example.com", 1, 10, 1, &r) == 0 && r.reason == PRODUCT_DNS_ASSOC_NO_ADDRESS);
  w = a_answer ("example.com", loop);
  assert (admit (t, &w, "example.com", 1, 10, 1, &r) == 0 && r.reason == PRODUCT_DNS_ASSOC_UNUSABLE_ONLY && r.skipped == 1);
  assert (product_dns_assoc_stats (t).count == 0);
  product_dns_assoc_close (t);
}

static void aaaa_pairs_use_the_ipv6_family (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  uint8_t ip6[16] = {0x20, 0x01, 0x0d, 0xb8, [15] = 0x53};
  wire_t w = query_wire ("v6.example.com", 28);
  put_rr (&w, "v6.example.com", 28, ip6, 16);
  header (&w, 0x8180, 1, 0, 0);
  assert (admit (t, &w, "v6.example.com", 28, 10, 1, NULL) == 1);
  product_dns_assoc_qualification_t q;
  product_dns_assoc_qualify (t, 20, NETWORK, ROUTE, 6, ip6, &q);
  assert (q.status == PRODUCT_DNS_ASSOC_ONE_CANDIDATE && !strcmp (q.name, "v6.example.com"));
  product_dns_assoc_qualify (t, 20, NETWORK, ROUTE, 4, ip6, &q);
  assert (q.status == PRODUCT_DNS_ASSOC_NO_CANDIDATE);
  product_dns_assoc_close (t);
}

static void capacity_is_bounded_and_evicts_the_soonest_to_expire (void)
{
  product_dns_assoc_t *t = product_dns_assoc_open ();
  for (unsigned i = 0; i < PRODUCT_DNS_ASSOC_ENTRIES + 50U; ++i)
    {
      uint8_t ip[4] = {10, (uint8_t) (i >> 8), (uint8_t) i, 1};
      wire_t w = a_answer ("example.com", ip);
      assert (admit (t, &w, "example.com", 1, 1000 + i, 1, NULL) == 1);
    }
  product_dns_assoc_stats_t s = product_dns_assoc_stats (t);
  assert (s.count == PRODUCT_DNS_ASSOC_ENTRIES && s.high_water == PRODUCT_DNS_ASSOC_ENTRIES && s.evicted == 50);
  assert (qualify (t, 5000, (uint8_t[4]){10, 0, 0, 1}).candidates == 0);   /* oldest gone */
  unsigned last = PRODUCT_DNS_ASSOC_ENTRIES + 49U;
  assert (qualify (t, 5000, (uint8_t[4]){10, (uint8_t) (last >> 8), (uint8_t) last, 1}).candidates == 1);
  product_dns_assoc_clear (t);
  assert (product_dns_assoc_stats (t).count == 0);
  product_dns_assoc_close (t);
}

int main (void)
{
  assert (PRODUCT_DNS_ASSOC_ENFORCEMENT_ENABLED == 0);
  answer_creates_pairs_with_their_source ();
  cname_chain_connects_every_name_to_the_address ();
  authority_additional_and_hints_never_create_pairs ();
  each_pair_keeps_its_own_two_hour_life ();
  view_change_excludes_old_pairs_and_expiry_is_counted ();
  ineligible_answers_leave_only_a_reason ();
  aaaa_pairs_use_the_ipv6_family ();
  capacity_is_bounded_and_evicts_the_soonest_to_expire ();
  puts ("DNS association facts PASS");
  return 0;
}
