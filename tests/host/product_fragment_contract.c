/* SPDX-License-Identifier: Apache-2.0 */
#include "product_fragment.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void ipv6_extensions(void)
{
  /* Hop-by-hop -> Fragment -> Destination Options -> UDP identity. */
  uint8_t packet[72] = {0x60};
  packet[5] = sizeof(packet) - 40;
  packet[6] = 0;
  packet[40] = 44;
  packet[48] = 60;
  packet[51] = 1;
  packet[55] = 7;
  packet[56] = 17;
  packet[64] = 0x12; packet[65] = 0x34;
  packet[66] = 0x56; packet[67] = 0x78;
  packet[69] = 8;
  product_fragment_piece_t piece;
  product_packet_facts_t facts;
  assert(product_fragment_parse(packet, sizeof(packet), &piece, &facts) == 1);
  assert(piece.header_length == 56 && piece.length == 16);
  assert(piece.key.protocol == 60 && facts.protocol == 17);
  assert(facts.source_port == 0x1234 && facts.destination_port == 0x5678);
  product_worker_layout_t layout={ .worker_count=2, .hash_seed=1 };
  product_owner_assignment_t assignment;
  assert(product_owner_assign(&layout,&facts,&assignment)==PRODUCT_PACKET_OK);
  uint8_t assembled[64];
  memcpy(assembled,packet,48);memcpy(assembled+48,packet+56,16);
  assembled[5]=24;assembled[40]=60;
  product_packet_ingress_t ingress={ .data=assembled, .length=sizeof(assembled),
    .origin_obligation_id=1 };
  product_packet_lease_t lease;
  assert(product_packet_admit_selected(&layout,&ingress,&assignment,&lease)==PRODUCT_PACKET_OK);
  assert(lease.facts.transport_offset==56 && lease.facts.protocol==17);
  assert(lease.assignment.canonical_hash==assignment.canonical_hash);
  assert(product_packet_admit(&layout,&ingress,&lease)==PRODUCT_PACKET_OK);
  assert(lease.facts.transport_offset==56 && lease.facts.protocol==17);
  assert(lease.assignment.canonical_hash==assignment.canonical_hash);
  /* Non-first payload must not be decoded as extension headers. */
  packet[51] = 9;
  memset(packet + 56, 255, 16);
  assert(product_fragment_parse(packet, sizeof(packet), &piece, &facts) == 1);
  assert(piece.offset == 8 && facts.l3_status == PRODUCT_PACKET_L3_UNAVAILABLE);
  packet[51] = 1;
  assert(product_fragment_parse(packet, sizeof(packet), &piece, &facts) == -1);
}

static void middle_duplicate(void)
{
  product_fragment_table_t table;
  assert(product_fragment_table_init(&table, 2, 4, 1000));
  product_fragment_piece_t p = { .key = { .family=4, .protocol=17 },
    .length=8, .more=1 };
  product_fragment_bundle_t out;
  product_owner_assignment_t owner = {0};
  assert(product_fragment_push(&table, &p, &owner, 0, &out) == PRODUCT_FRAGMENT_WAIT);
  p.offset=8; p.buffer_index=1;
  assert(product_fragment_push(&table, &p, NULL, 1, &out) == PRODUCT_FRAGMENT_WAIT);
  p.buffer_index=2;
  assert(product_fragment_push(&table, &p, NULL, 2, &out) == PRODUCT_FRAGMENT_WAIT);
  p.offset=16; p.more=0; p.buffer_index=3;
  assert(product_fragment_push(&table, &p, NULL, 3, &out) == PRODUCT_FRAGMENT_COMPLETE);
  assert(out.count==4 && out.total_length==24 && table.active==0);
  for (unsigned i=0;i<4;i++) assert(out.pieces[i].buffer_index==i);
  assert(out.pieces[0].selected && !out.pieces[1].selected);
  assert(out.pieces[2].selected && out.pieces[3].selected);
  product_fragment_table_destroy(&table);
}

static void capacity_and_retirement(void)
{
  product_fragment_table_t table;
  assert(product_fragment_table_init(&table, 65, 33, 1000));
  product_fragment_piece_t p = { .key = { .family=4, .protocol=17 },
    .offset=8, .length=8, .more=1 };
  product_fragment_bundle_t out;
  for (unsigned i=0;i<65;i++) {
    p.key.identification=i; p.buffer_index=i;
    assert(product_fragment_push(&table,&p,NULL,100,&out)==PRODUCT_FRAGMENT_WAIT);
  }
  p.key.identification=65; p.buffer_index=65;
  assert(product_fragment_push(&table,&p,NULL,101,&out)==PRODUCT_FRAGMENT_CONTEXT_FULL);
  assert(out.count==1 && out.pieces[0].buffer_index==65 && table.active==65);
  assert(!product_fragment_take_expired(&table,1099,0,&out));
  unsigned expired=0;
  while (product_fragment_take_expired(&table,1100,0,&out)) {
    assert(out.count==1 && out.pieces[0].buffer_index<65); expired++;
  }
  assert(expired==65 && table.active==0);
  for (unsigned i=0;i<33;i++) {
    p.offset=(i+1)*8; p.buffer_index=i;
    assert(product_fragment_push(&table,&p,NULL,2000,&out)==PRODUCT_FRAGMENT_WAIT);
  }
  p.buffer_index=33;
  assert(product_fragment_push(&table,&p,NULL,2001,&out)==PRODUCT_FRAGMENT_BUNDLE_FULL);
  assert(out.count==34 && table.active==0);
  for (unsigned i=0;i<34;i++) assert(out.pieces[i].buffer_index==i);
  assert(product_fragment_push(&table,&p,NULL,3000,&out)==PRODUCT_FRAGMENT_WAIT);
  assert(product_fragment_take_expired(&table,3000,1,&out));
  assert(out.count==1 && !table.active);
  product_fragment_table_destroy(&table);
  assert(!product_fragment_table_init(&table,UINT32_MAX-1,UINT32_MAX-1,1000));
}

static void overlap_selection_and_placement(void)
{
  product_fragment_table_t table;
  assert(product_fragment_table_init(&table, 1, 6, 1000));
  product_fragment_piece_t p = { .key = { .family=4, .protocol=17 },
    .length=8, .more=1 };
  product_owner_assignment_t assignment={0};
  product_fragment_bundle_t out;
  assert(product_fragment_push(&table,&p,&assignment,0,&out)==PRODUCT_FRAGMENT_WAIT);
  p.offset=8; p.length=16;
  assert(product_fragment_push(&table,&p,NULL,0,&out)==PRODUCT_FRAGMENT_WAIT);
  p.length=8;
  assert(product_fragment_push(&table,&p,NULL,0,&out)==PRODUCT_FRAGMENT_WAIT);
  p.offset=16;
  assert(product_fragment_push(&table,&p,NULL,0,&out)==PRODUCT_FRAGMENT_WAIT);
  p.offset=24; p.more=0;
  assert(product_fragment_push(&table,&p,NULL,0,&out)==PRODUCT_FRAGMENT_COMPLETE);
  assert(out.count==5 && !out.pieces[1].selected);
  assert(out.pieces[0].selected && out.pieces[2].selected &&
         out.pieces[3].selected && out.pieces[4].selected);
  product_fragment_table_destroy(&table);
  product_worker_layout_t layout={ .worker_count=7 };
  p.key.source[15]=1; p.key.destination[15]=2;
  uint16_t worker=product_fragment_worker(&layout,&p.key);
  p.key.identification=UINT32_MAX; p.key.protocol=6;
  p.key.source[15]=2; p.key.destination[15]=1;
  assert(product_fragment_worker(&layout,&p.key)==worker);
  layout.worker_count=0;
  assert(product_fragment_worker(&layout,&p.key)==PRODUCT_EXECUTION_OWNER_UNKNOWN);
}

static void extension_budget(void)
{
  product_worker_layout_t layout={ .worker_count=2 };
  uint8_t packet[304]={0x60};
  packet[4]=1; packet[5]=8; packet[6]=0;
  packet[40]=17; packet[41]=31; /* exactly 256 extension bytes */
  packet[296]=0x12; packet[297]=0x34; packet[301]=8;
  product_packet_ingress_t ingress={ .data=packet, .length=sizeof(packet),
    .origin_obligation_id=1 };
  product_packet_lease_t lease;
  assert(product_packet_admit(&layout,&ingress,&lease)==PRODUCT_PACKET_OK);
  assert(lease.facts.l3_header_length==296 && lease.facts.transport_offset==296);
  assert(lease.facts.source_port==0x1234 && lease.facts.l4_status==PRODUCT_PACKET_L4_COMPLETE);
  packet[41]=32; /* over byte budget, no guessed ports */
  assert(product_packet_admit(&layout,&ingress,&lease)==PRODUCT_PACKET_OK);
  assert(lease.facts.l4_status==PRODUCT_PACKET_L4_UNAVAILABLE && !lease.facts.source_port);
  memset(packet+40,0,sizeof(packet)-40);
  packet[4]=0; packet[5]=80; ingress.length=120;
  packet[104]=17; packet[113]=1; packet[117]=8;
  assert(product_packet_admit(&layout,&ingress,&lease)==PRODUCT_PACKET_OK);
  assert(lease.facts.l4_status==PRODUCT_PACKET_L4_UNAVAILABLE);
  packet[96]=17; packet[105]=1; packet[109]=8;
  packet[5]=72; ingress.length=112;
  assert(product_packet_admit(&layout,&ingress,&lease)==PRODUCT_PACKET_OK);
  assert(lease.facts.l4_status==PRODUCT_PACKET_L4_COMPLETE && lease.facts.transport_offset==104);
}

int main(void)
{
  ipv6_extensions();
  middle_duplicate();
  capacity_and_retirement();
  overlap_selection_and_placement();
  extension_budget();
  product_fragment_table_t table;
  assert(product_fragment_table_init(&table, 65, 33, 1000));
  assert(table.capacity == 65 && table.original_limit == 33);
  product_fragment_table_destroy(&table);
  puts("fragment core contract PASS");
  return 0;
}
