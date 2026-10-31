/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_l4_policy.h"
#include "product_protocol_catalog.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fixtures are datagrams a real OpenSSL 3.0 DTLS client sent with no server
 * answering (tests/host/fixtures/capture_dtls_hello.py), one hex line each. */
static const char *fixtures;
typedef struct { uint8_t bytes[8][1600]; unsigned length[8], count; } capture_t;

static capture_t load (const char *name)
{
  char path[512]; snprintf (path, sizeof (path), "%s/%s.hex", fixtures, name);
  FILE *file = fopen (path, "r"); assert (file);
  capture_t c = {0}; char line[4096];
  while (fgets (line, sizeof (line), file) && c.count < 8)
    {
      size_t n = strcspn (line, "\r\n"); if (!n) continue;
      for (size_t i = 0; i + 1 < n; i += 2) { unsigned v; sscanf (line + i, "%2x", &v); c.bytes[c.count][i / 2] = (uint8_t) v; }
      c.length[c.count++] = (unsigned) (n / 2);
    }
  fclose (file); assert (c.count); return c;
}

typedef struct { product_flow_runtime_t *pool; product_packet_facts_t f; product_flow_entry_observation_t o; uint64_t clock; } flow_t;

static void open_flow (flow_t *x, unsigned family)
{
  memset (x, 0, sizeof (*x));
  assert (!product_flow_runtime_create (&x->pool, 0, 1, 7, 1));
  x->f = (product_packet_facts_t){.l3_status = 1, .l4_status = 1, .ip_family = (uint8_t) family, .protocol = 17,
    .source_port = 40000, .destination_port = 4433, .l4_header_length = 8};
  x->f.source_address[family == 4 ? 0 : 15] = 10; x->f.destination_address[family == 4 ? 0 : 15] = 11;
  x->clock = 1;
}

static void send (flow_t *x, int reply, const uint8_t *bytes, unsigned size)
{
  product_packet_facts_t f = x->f;
  if (reply)
    {
      f.source_port = x->f.destination_port; f.destination_port = x->f.source_port;
      memcpy (f.source_address, x->f.destination_address, 16); memcpy (f.destination_address, x->f.source_address, 16);
    }
  f.transport_length = (uint16_t) (8 + size); f.packet_length = (uint16_t) (40 + 8 + size);
  product_worker_layout_t layout = {1, 1}; product_owner_assignment_t owner;
  assert (!product_owner_assign (&layout, &f, &owner));
  product_flow_entry_packet_t input = {.facts = &f, .policy = {7, 1, 1}, .uid = 17, .timestamp = x->clock++};
  assert (!product_flow_entry_observe (x->pool, &owner, &input, 0, &x->o) && x->o.entry);
  assert (!product_flow_entry_identify (x->pool, x->o.slot, 7, x->o.entry->incarnation, &f, bytes, size));
}

static const product_flow_entry_t *e (flow_t *x) { return x->o.entry; }

static void real_hello_publishes_the_name_and_dtls (void)
{
  for (unsigned family = 4; family <= 6; family += 2)
    {
      capture_t c = load ("dtls12_named");
      flow_t x; open_flow (&x, family);
      send (&x, 0, c.bytes[0], c.length[0]);
      assert (e (&x)->sni.dtls && e (&x)->sni.result == PRODUCT_SNI_NAME && !strcmp (e (&x)->sni.name, "blocked.http.test"));
      assert (e (&x)->sni.stop == PRODUCT_SNI_COMPLETE);
      assert (e (&x)->lpi.protocols & product_protocol_bit (1020));
      assert (!(e (&x)->lpi.protocols & product_protocol_bit (1004)));        /* never a QUIC fact */
      send (&x, 0, c.bytes[1], c.length[1]);                                  /* OpenSSL's own retransmission */
      assert (e (&x)->sni.result == PRODUCT_SNI_NAME && !strcmp (e (&x)->sni.name, "blocked.http.test"));
      product_flow_runtime_destroy (x.pool);
    }
  capture_t c = load ("dtls10_named");
  flow_t x; open_flow (&x, 4);
  send (&x, 0, c.bytes[0], c.length[0]);
  assert (e (&x)->sni.result == PRODUCT_SNI_NAME && !strcmp (e (&x)->sni.name, "blocked.http.test"));
  product_flow_runtime_destroy (x.pool);
  c = load ("dtls12_noname");
  open_flow (&x, 4);
  send (&x, 0, c.bytes[0], c.length[0]);
  assert (e (&x)->sni.result == PRODUCT_SNI_ABSENT && e (&x)->sni.stop == PRODUCT_SNI_COMPLETE);
  product_flow_runtime_destroy (x.pool);
}

static void fragments_in_any_order_and_retransmitted (void)
{
  capture_t c = load ("dtls12_fragmented");
  assert (c.count >= 2);
  flow_t x; open_flow (&x, 4);
  send (&x, 0, c.bytes[1], c.length[1]);               /* second fragment first */
  assert (e (&x)->sni.dtls && !e (&x)->sni.result && !e (&x)->sni.stop);
  send (&x, 0, c.bytes[1], c.length[1]);               /* duplicate */
  assert (!e (&x)->sni.result && !e (&x)->sni.stop);
  send (&x, 0, c.bytes[0], c.length[0]);
  assert (e (&x)->sni.result == PRODUCT_SNI_NAME && !strcmp (e (&x)->sni.name, "blocked.http.test"));
  product_flow_runtime_destroy (x.pool);
  open_flow (&x, 4);
  for (unsigned i = 0; i < c.count; ++i) send (&x, 0, c.bytes[i], c.length[i]);
  assert (e (&x)->sni.result == PRODUCT_SNI_NAME);
  product_flow_runtime_destroy (x.pool);
}

static unsigned stop_after (const uint8_t *bytes, unsigned size)
{
  flow_t x; open_flow (&x, 4);
  send (&x, 0, bytes, size);
  unsigned stop = e (&x)->sni.stop, result = e (&x)->sni.result;
  assert (!result);
  product_flow_runtime_destroy (x.pool);
  return stop;
}

static void malformed_conflicting_and_budgets (void)
{
  capture_t c = load ("dtls12_named");
  uint8_t b[1600];
  /* A conflicting retransmission of the same fragment bytes. */
  capture_t f = load ("dtls12_fragmented");
  flow_t x; open_flow (&x, 4);
  send (&x, 0, f.bytes[0], f.length[0]);
  memcpy (b, f.bytes[0], f.length[0]); b[f.length[0] - 1] ^= 1;
  send (&x, 0, b, f.length[0]);
  assert (e (&x)->sni.stop == PRODUCT_SNI_MALFORMED && !e (&x)->sni.result);
  product_flow_runtime_destroy (x.pool);
  /* Record length beyond the datagram. */
  memcpy (b, c.bytes[0], c.length[0]); b[11] = 0xff;
  assert (stop_after (b, c.length[0]) == PRODUCT_SNI_MALFORMED);
  /* Handshake fragment beyond its record. */
  memcpy (b, c.bytes[0], c.length[0]); b[13 + 9] = 0xff;
  assert (stop_after (b, c.length[0]) == PRODUCT_SNI_MALFORMED);
  /* Not a ClientHello. */
  memcpy (b, c.bytes[0], c.length[0]); b[13] = 2;
  assert (stop_after (b, c.length[0]) == PRODUCT_SNI_UNSUPPORTED);
  /* A non-handshake record before the ClientHello finished. */
  memcpy (b, c.bytes[0], c.length[0]); b[0] = 23;
  flow_t y; open_flow (&y, 4); send (&y, 0, b, c.length[0]);
  assert (!e (&y)->sni.dtls);                           /* never a DTLS candidate: not a handshake start */
  product_flow_runtime_destroy (y.pool);
  open_flow (&y, 4); send (&y, 0, f.bytes[1], f.length[1]);
  send (&y, 0, b, c.length[0]);
  assert (e (&y)->sni.stop == PRODUCT_SNI_UNSUPPORTED);
  product_flow_runtime_destroy (y.pool);
  /* The ClientHello's own declared length above the reserved storage. */
  memcpy (b, c.bytes[0], c.length[0]); b[13 + 1] = 0x01;   /* length 0x01xxxx */
  assert (stop_after (b, c.length[0]) == PRODUCT_SNI_BYTE_BUDGET);
  /* Packet budget: endless fragments of nothing new. */
  open_flow (&y, 4);
  for (unsigned i = 0; i < PRODUCT_SNI_MAX_PACKETS; ++i) send (&y, 0, f.bytes[1], f.length[1]);
  assert (e (&y)->sni.stop == PRODUCT_SNI_PACKET_BUDGET && !e (&y)->sni.result);
  product_flow_runtime_destroy (y.pool);
  /* Reply-direction datagrams (HelloVerifyRequest, ServerHello) never feed the client's hello. */
  open_flow (&y, 4);
  send (&y, 0, f.bytes[1], f.length[1]);
  send (&y, 1, f.bytes[0], f.length[0]);
  assert (!e (&y)->sni.result && !e (&y)->sni.stop);
  product_flow_runtime_destroy (y.pool);
}

static void quic_and_other_udp_are_unchanged (void)
{
  flow_t x; open_flow (&x, 4);
  static const uint8_t opaque[] = "not a handshake";
  send (&x, 0, opaque, sizeof (opaque));
  assert (!e (&x)->sni.dtls);
  product_flow_runtime_destroy (x.pool);
}

static void policy_applies_sni_rules_to_dtls (void)
{
  product_l4_policy_rule_t rule = {.rule_id = 7, .reason_id = 9, .uid = 17, .action = 2,
    .network_context_id = UINT32_MAX, .ifindex = UINT32_MAX,
    .source_port_last = 65535, .destination_port_last = 65535,
    .expression = {PRODUCT_EXPRESSION_DOMAIN_LIST, 0}, .expression_length = 2};
  product_l4_policy_view_t view;
  assert (!product_l4_policy_compile (&view, &rule, 1));
  product_l4_policy_packet_t p = {.uid = 17, .uid_known = 1, .family = 4, .protocol = 17,
    .protocol_set = product_protocol_bit (1020), .protocol_set_known = 1, .sni_result = PRODUCT_SNI_NAME, .domain_lists = 1};
  product_l4_policy_match_result_t result;
  assert (!product_l4_policy_match (&view, &p, &result) && result.rule_id == 7);
  /* A DTLS label without a name never matches a domain. */
  p.sni_result = PRODUCT_SNI_UNAVAILABLE;
  assert (!product_l4_policy_match (&view, &p, &result) && result.evaluation != PRODUCT_L4_POLICY_EVALUATION_MATCH);
  /* Without a TLS/QUIC/DTLS fact the SNI rule is not applicable. */
  p.sni_result = PRODUCT_SNI_NAME; p.protocol_set = 0;
  assert (!product_l4_policy_match (&view, &p, &result) && result.evaluation != PRODUCT_L4_POLICY_EVALUATION_MATCH);
}

int main (int argc, char **argv)
{
  assert (argc == 2); fixtures = argv[1];
  assert (!product_lpi_init ());
  real_hello_publishes_the_name_and_dtls ();
  fragments_in_any_order_and_retransmitted ();
  malformed_conflicting_and_budgets ();
  quic_and_other_udp_are_unchanged ();
  policy_applies_sni_rules_to_dtls ();
  puts ("DTLS ClientHello SNI PASS");
  return 0;
}
