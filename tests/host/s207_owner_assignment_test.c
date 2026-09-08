/* SPDX-License-Identifier: Apache-2.0 */
#include "product_packet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const product_worker_layout_t layout = {2, UINT64_C(0x6f776e65722d3137)};

static product_owner_assignment_t assign(const product_packet_facts_t *facts) {
  product_owner_assignment_t a;
  assert(product_owner_assign(&layout, facts, &a) == PRODUCT_PACKET_OK);
  assert(a.valid && a.execution_owner < layout.worker_count);
  return a;
}

static void reverse(product_packet_facts_t *f) {
  uint8_t address[16];
  memcpy(address, f->source_address, 16);
  memcpy(f->source_address, f->destination_address, 16);
  memcpy(f->destination_address, address, 16);
  uint16_t port = f->source_port;
  f->source_port = f->destination_port; f->destination_port = port;
}

static void same_identity(product_owner_assignment_t a, product_owner_assignment_t b) {
  assert(memcmp(&a.key, &b.key, sizeof(a.key)) == 0);
  assert(a.canonical_hash == b.canonical_hash && a.execution_owner == b.execution_owner);
}

int main(void) {
  for (unsigned family = 4; family <= 6; family += 2) {
    product_packet_facts_t f = {0};
    f.l3_status = PRODUCT_PACKET_L3_COMPLETE;
    f.ip_family = family;
    f.source_address[15] = 2; f.destination_address[15] = 1;
    if (family == 6) f.source_address[0] = f.destination_address[0] = 0x20;
    for (unsigned p = 0; p < 2; p++) {
      f.protocol = p ? 17 : 6;
      f.l4_status = PRODUCT_PACKET_L4_COMPLETE;
      f.source_port = 0; f.destination_port = 65535;
      product_owner_assignment_t a = assign(&f);
      assert(a.key.kind == PRODUCT_OWNER_KEY_L4_PORTS);
      reverse(&f);
      product_owner_assignment_t b = assign(&f);
      same_identity(a, b); assert(a.source_is_a != b.source_is_a);
      f.l4_status = PRODUCT_PACKET_L4_UNAVAILABLE;
      product_owner_assignment_t l3 = assign(&f);
      assert(l3.key.kind == PRODUCT_OWNER_KEY_L3);
      assert(memcmp(&l3.key, &a.key, sizeof(a.key)) != 0);
      f.source_port = 1234; f.destination_port = 5678;
      same_identity(l3, assign(&f));
    }
    f.protocol = family == 4 ? 1 : 58;
    f.l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL;
    f.icmp_type = family == 4 ? 8 : 128;
    f.icmp_code = 0; f.icmp_identity_known = 1; f.icmp_identifier = 0;
    product_owner_assignment_t query = assign(&f);
    assert(query.key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY);
    assert(query.key.query_class == PRODUCT_ICMP_QUERY_ECHO);
    assert(query.key.transport.query.identifier == 0);
    reverse(&f); f.icmp_type = family == 4 ? 0 : 129;
    for (unsigned sequence = 0; sequence <= 65535; sequence += 257) {
      f.icmp_sequence = sequence;
      same_identity(query, assign(&f));
    }
    f.icmp_identifier = 1;
    product_owner_assignment_t other = assign(&f);
    assert(memcmp(&query.key, &other.key, sizeof(query.key)) != 0);
    f.icmp_code = 1;
    assert(assign(&f).key.kind == PRODUCT_OWNER_KEY_L3);
    f.icmp_code = 0; f.icmp_identity_known = 0;
    assert(assign(&f).key.kind == PRODUCT_OWNER_KEY_L3);
    f.protocol = 59;
    assert(assign(&f).key.kind == PRODUCT_OWNER_KEY_L3);

    unsigned counts[2] = {0};
    f.protocol = 17; f.l4_status = PRODUCT_PACKET_L4_COMPLETE;
    f.destination_port = 40606;
    for (unsigned port = 0; port < 4096; port++) {
      f.source_port = port;
      counts[assign(&f).execution_owner]++;
    }
    assert(counts[0] == 2048 && counts[1] == 2048);
  }

  uint8_t packet[28] = {0x45,0,0,28,0,0,0,0,64,17};
  packet[12] = 127; packet[15] = 1; packet[16] = 127; packet[19] = 2;
  packet[20] = 0x75; packet[21] = 0x30; packet[22] = 0x9e; packet[23] = 0x9e;
  packet[25] = 8;
  product_packet_ingress_t ingress = {.data=packet, .length=sizeof(packet), .origin_obligation_id=1};
  product_packet_lease_t first;
  assert(product_packet_admit(&layout, &ingress, &first) == PRODUCT_PACKET_OK);
  for (unsigned i = 0; i < 64; i++) {
    ingress.current_worker = i%2;
    ingress.origin_obligation_id = 100+i;
    ingress.platform = (product_platform_packet_facts_t){i, 1000+i, 42+i, i%8, i%4, i%5, 0};
    product_packet_lease_t changed;
    assert(product_packet_admit(&layout, &ingress, &changed) == PRODUCT_PACKET_OK);
    same_identity(first.assignment, changed.assignment);
    assert(changed.primary_handoff_count == (changed.assignment.execution_owner != ingress.current_worker));
  }
  packet[0] = 0;
  product_packet_lease_t invalid;
  assert(product_packet_admit(&layout, &ingress, &invalid) != PRODUCT_PACKET_OK);
  assert(!invalid.assignment.valid && invalid.assignment.execution_owner == PRODUCT_EXECUTION_OWNER_UNKNOWN);
  assert(invalid.assignment.canonical_hash == 0 && invalid.assignment.key.kind == PRODUCT_OWNER_KEY_NONE);
  assert(invalid.primary_handoff_count == 0 && invalid.terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME);
  assert(product_packet_settle(&invalid) == PRODUCT_PACKET_OK);
  puts("S207 typed owner assignment properties: PASS");
  return 0;
}
