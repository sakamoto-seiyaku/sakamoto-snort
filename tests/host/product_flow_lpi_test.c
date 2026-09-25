/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_flow_entry.h"
#include "product_protocol_catalog.h"
#include "product_l4_policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static void dns_budget (void)
{
  product_flow_runtime_t *pool = NULL;
  assert (product_flow_runtime_create (&pool, 0, 1, 7, 1) == 0);
  product_packet_facts_t f = { .l3_status=PRODUCT_PACKET_L3_COMPLETE,
    .l4_status=PRODUCT_PACKET_L4_COMPLETE, .ip_family=4, .protocol=17,
    .source_port=42000, .destination_port=53, .packet_length=57,
    .transport_length=37, .l4_header_length=8 };
  f.source_address[0]=10; f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};
  product_owner_assignment_t assignment;
  assert (product_owner_assign (&layout,&f,&assignment) == 0);
  product_flow_entry_packet_t p={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  assert (product_flow_entry_observe (pool,&assignment,&p,0,&o) == 0);
  assert (!o.entry->lpi.available && !o.entry->lpi.protocols);
  const uint8_t dns[]={0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
  assert (product_flow_entry_identify (pool,o.slot,7,o.entry->incarnation,&f,dns,sizeof dns) == 0);
  assert (o.entry->lpi.available && o.entry->lpi.protocols==product_protocol_bit(1001));
  assert (o.entry->lpi.attempts==1 && !o.entry->lpi.stop_reason);
  product_packet_facts_t wrong=f;
  wrong.destination_port=54;
  assert (product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&wrong,dns,sizeof dns)
          == PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  assert (product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,dns,sizeof dns-1)
          == PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  assert (o.entry->lpi.attempts==1);

  p.policy.revision=2; p.policy.snapshot_hash=2; ++p.timestamp;
  assert (product_flow_entry_observe (pool,&assignment,&p,0,&o) == 0);
  assert (o.entry->lpi.protocols==product_protocol_bit(1001) && o.entry->lpi.attempts==1);
  for(unsigned i=1;i<20;++i)
    assert (product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,dns,sizeof dns)==0);
  assert (o.entry->lpi.attempts==20 && o.entry->lpi.stop_reason==PRODUCT_LPI_STOP_PACKET_BUDGET);
  assert (product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,dns,sizeof dns)==0);
  assert (o.entry->lpi.attempts==20 && o.entry->lpi.protocols==product_protocol_bit(1001));
  assert (product_flow_entry_identify(pool,o.slot,8,o.entry->incarnation,&f,dns,sizeof dns)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert (product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation+1,&f,dns,sizeof dns)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  product_flow_runtime_destroy(pool);
  puts("owner Flow LPI immediate facts, bounded stop and publication retention: PASS");
}

static void ended (void *context, const product_flow_entry_t *entry,
                   uint32_t slot, product_flow_end_reason_t reason)
{
  (void) context; (void) slot; (void) reason;
  assert (entry->lpi.stop_reason == PRODUCT_LPI_STOP_FLOW_END
          || entry->lpi.stop_reason == PRODUCT_LPI_STOP_PACKET_BUDGET);
}
static void multi_result_and_reuse (void)
{
  product_flow_runtime_t *pool = NULL;
  assert (product_flow_runtime_create (&pool,0,1,9,1) == 0);
  assert (product_flow_runtime_set_end_callback (pool,ended,NULL) == 0);
  product_packet_facts_t f = {.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .source_port=42001,.destination_port=53,.l4_header_length=8,.transport_length=8};
  f.source_address[0]=10; f.destination_address[0]=11;
  product_worker_layout_t layout={1,1}; product_owner_assignment_t assignment;
  assert (product_owner_assign (&layout,&f,&assignment) == 0);
  product_flow_entry_packet_t p={.facts=&f,.policy={9,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  assert (product_flow_entry_observe(pool,&assignment,&p,0,&o)==0);
  uint64_t instance=o.entry->incarnation;
  assert (product_flow_entry_identify(pool,o.slot,9,instance,&f,NULL,0)==0);
  assert (!o.entry->lpi.attempts && !o.entry->lpi.available);
  const uint8_t dns[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,0,0,1,0,1};
  f.transport_length=8+sizeof dns;
  assert (product_flow_entry_identify(pool,o.slot,9,instance,&f,dns,sizeof dns)==0);
  assert (o.entry->lpi.protocols==product_protocol_bit(1001));
  /* Header-only RFC 9000 fixture: deliberately no cryptographic claim. */
  uint8_t initial[1200]={0xc0,0,0,0,1,8,1,2,3,4,5,6,7,8,0,0,0x44,0x9e};
  f.transport_length=8+sizeof initial;
  assert (product_flow_entry_identify(pool,o.slot,9,instance,&f,initial,sizeof initial)==0);
  assert (o.entry->lpi.protocols==(product_protocol_bit(1001)|product_protocol_bit(1004)));
  uint64_t published=o.entry->lpi.protocols;
  uint8_t tiny=0xfe;
  f.transport_length=9;
  assert (product_flow_entry_identify(pool,o.slot,9,instance,&f,&tiny,1)==0);
  assert (o.entry->lpi.available && o.entry->lpi.protocols==published);
  assert (product_flow_runtime_close(pool,o.slot,9,instance,PRODUCT_FLOW_END_CLOSED)==0);
  assert (product_flow_entry_identify(pool,o.slot,9,instance,&f,&tiny,1)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert (product_flow_runtime_release_end(pool,o.slot,9,instance,PRODUCT_FLOW_END_CLOSED)==0);
  ++p.timestamp;
  assert (product_flow_entry_observe(pool,&assignment,&p,0,&o)==0);
  assert (o.entry->incarnation!=instance && !o.entry->lpi.available && !o.entry->lpi.attempts);
  assert (product_flow_entry_identify(pool,o.slot,9,instance,&f,&tiny,1)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  /* A version-unknown or malformed Initial is not a comparable Unknown. */
  initial[4]=3; f.transport_length=8+sizeof initial;
  f.destination_port=53; /* A new same-tuple DNS heuristic is separate evidence. */
  initial[2]=0xff; initial[3]=0xff;
  assert (product_flow_entry_identify(pool,o.slot,9,o.entry->incarnation,&f,initial,sizeof initial)==0);
  assert (!o.entry->lpi.available && !o.entry->lpi.protocols);
  /* Exhaust byte credit before another attempt, preserving unavailable. */
  uint8_t large[32768]={0xff};
  f.transport_length=8+sizeof large;
  assert (product_flow_entry_identify(pool,o.slot,9,o.entry->incarnation,&f,large,sizeof large)==0);
  assert (o.entry->lpi.stop_reason==PRODUCT_LPI_STOP_BYTE_BUDGET && o.entry->lpi.attempts==1);
  product_flow_runtime_destroy(pool);
}

static void tls_upgrade (void)
{
  product_flow_runtime_t *pool=NULL;
  assert (product_flow_runtime_create (&pool,0,1,11,1)==0);
  product_packet_facts_t facts={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .l4_header_length=20,.tcp_flags=16,.tcp_window=65535};
  product_worker_layout_t layout={1,7};
  product_l4_policy_rule_t rules[3]={0};
  for (unsigned i=0;i<3;++i) {
    rules[i].rule_id=10+i*10; rules[i].reason_id=100+i;
    rules[i].uid=17; rules[i].priority=i+1;
    rules[i].action=i==2?1:2; rules[i].mode=i==1;
    rules[i].network_context_id=rules[i].ifindex=UINT32_MAX;
    rules[i].source_port_last=rules[i].destination_port_last=65535;
  }
  memcpy (rules[0].expression,(uint8_t[]){15,0xeb,3,0,0},5);
  rules[0].expression_length=5;
  memcpy (rules[1].expression,(uint8_t[]){15,0xeb,3,0,0,3},6);
  rules[1].expression_length=6;
  product_l4_policy_view_t view;
  assert (product_l4_policy_compile (&view,rules,3)==0);
  product_policy_cache_t cache={.capacity=1};
  uint8_t hello[69]={0x16,3,1,0,64};
  const uint8_t request[]="GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
  const uint8_t response[]="HTTP/1.1 101 Switching Protocols\r\n\r\n";
  const uint8_t *payloads[]={request,response,hello,hello};
  unsigned lengths[]={sizeof request-1,sizeof response-1,sizeof hello,sizeof hello};
  uint32_t sequence[]={1000,5000};
  product_flow_entry_observation_t observation;
  for (unsigned step=0;step<4;++step) {
    unsigned side=step%2;
    facts.source_address[0]=side?11:10; facts.destination_address[0]=side?10:11;
    facts.source_port=side?80:42002; facts.destination_port=side?42002:80;
    facts.tcp_sequence=sequence[side]; facts.tcp_acknowledgment=sequence[!side];
    facts.transport_length=20+lengths[step]; facts.packet_length=20+facts.transport_length;
    product_owner_assignment_t assignment;
    assert (product_owner_assign (&layout,&facts,&assignment)==0);
    product_flow_entry_packet_t input={.facts=&facts,.policy={11,1,10},.uid=17,
      .packet_bytes=facts.packet_length,.timestamp=step+1};
    assert (product_flow_entry_observe(pool,&assignment,&input,0,&observation)==0);
    assert (observation.entry && observation.tracker.facts.state!=PRODUCT_CT_INVALID);
    assert (product_flow_entry_identify(pool,observation.slot,11,observation.entry->incarnation,
                                       &facts,payloads[step],lengths[step])==0);
    sequence[side]+=lengths[step];
    uint64_t expected=product_protocol_bit(1002);
    if (step==3) expected|=product_protocol_bit(1003);
    assert (observation.entry->lpi.available && observation.entry->lpi.protocols==expected);
    product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=6,
      .protocol_set=observation.entry->lpi.protocols,.protocol_set_known=1};
    product_policy_cache_identity_t identity={11,1,10,observation.entry->incarnation};
    product_l4_policy_match_result_t result;
    for (unsigned repeat=0;repeat<2;++repeat) {
      assert (product_l4_policy_match_cached(&cache,&view,&packet,&identity,2,&result)==0);
      assert (result.rule_id==(step==3?10:20));
      assert (result.actual_action==(step==3?2:1));
    }
  }
  assert (cache.misses==2 && cache.hits==6);
  product_flow_runtime_destroy(pool);
}

static void quic_header_failures (void)
{
  for (unsigned scenario=0;scenario<8;++scenario) {
    product_flow_runtime_t *pool=NULL;
    assert (product_flow_runtime_create(&pool,0,1,13,1)==0);
    product_packet_facts_t facts={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
      .source_port=42003,.destination_port=443,.l4_header_length=8,.transport_length=1208};
    facts.source_address[0]=10; facts.destination_address[0]=11;
    product_worker_layout_t layout={1,1}; product_owner_assignment_t assignment;
    assert (product_owner_assign(&layout,&facts,&assignment)==0);
    product_flow_entry_packet_t input={.facts=&facts,.policy={13,1,1},.uid=17};
    product_flow_entry_observation_t observation;
    assert (product_flow_entry_observe(pool,&assignment,&input,0,&observation)==0);
    uint8_t initial[1200]={0xc0,0,0,0,1,8,1,2,3,4,5,6,7,8,0,0,0x44,0x9e};
    unsigned length=sizeof initial;
    if (scenario==1) { /* RFC 9369 v2 Initial has long type 01. */
      initial[0]=0xd0;initial[1]=0x6b;initial[2]=0x33;initial[3]=0x43;initial[4]=0xcf;
    }
    if (scenario==2) initial[0]=0x80; /* missing fixed bit */
    if (scenario==3) initial[5]=21; /* invalid CID length */
    if (scenario==4) { initial[15]=0xff;initial[16]=0xff; } /* token exceeds datagram */
    if (scenario==5) initial[16]=0x7f; /* declared payload exceeds datagram */
    if (scenario==6) --length; /* short client Initial datagram */
    if (scenario==7) initial[0]=0xd0; /* v1 0-RTT is not Initial */
    facts.transport_length=8+length;
    assert (product_flow_entry_identify(pool,observation.slot,13,observation.entry->incarnation,
                                      &facts,initial,length)==0);
    assert (observation.entry->lpi.available==(scenario<2));
    assert (observation.entry->lpi.protocols==(scenario<2?product_protocol_bit(1004):0));
    product_flow_runtime_destroy(pool);
  }
}
static void mdns_query (void)
{
  /* RFC6762 query for _services._dns-sd._udp.local PTR/IN (QU bit). */
  const uint8_t query[]={0,0,0,0,0,1,0,0,0,0,0,0,
    9,'_','s','e','r','v','i','c','e','s',7,'_','d','n','s','-','s','d',
    4,'_','u','d','p',5,'l','o','c','a','l',0,0,12,0x80,1};
  product_flow_runtime_t *pool=NULL;
  assert(product_flow_runtime_create(&pool,0,1,17,1)==0);
  assert(product_flow_runtime_set_end_callback(pool,ended,NULL)==0);
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .source_port=42004,.destination_port=5353,.l4_header_length=8,
    .transport_length=8+sizeof query};
  f.source_address[0]=10;f.destination_address[0]=224;f.destination_address[3]=251;
  product_worker_layout_t layout={1,1};product_owner_assignment_t a;
  assert(product_owner_assign(&layout,&f,&a)==0);
  product_flow_entry_packet_t p={.facts=&f,.policy={17,1,1},.uid=17};
  product_flow_entry_observation_t o;
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(product_flow_entry_identify(pool,o.slot,17,o.entry->incarnation,&f,query,sizeof query)==0);
  assert(o.entry->lpi.available && o.entry->lpi.protocols==UINT64_C(32));
  uint64_t incarnation=o.entry->incarnation;
  p.policy.revision=2;p.policy.snapshot_hash=2;
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(o.entry->incarnation==incarnation && o.entry->lpi.attempts==1);
  for(unsigned i=1;i<21;++i)
    assert(product_flow_entry_identify(pool,o.slot,17,incarnation,&f,query,sizeof query)==0);
  assert(o.entry->lpi.protocols==32 && o.entry->lpi.attempts==20 && o.entry->lpi.stop_reason==1);
  assert(product_flow_runtime_close(pool,o.slot,17,incarnation,PRODUCT_FLOW_END_CLOSED)==0);
  assert(product_flow_runtime_release_end(pool,o.slot,17,incarnation,PRODUCT_FLOW_END_CLOSED)==0);
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(o.entry->incarnation!=incarnation && !o.entry->lpi.protocols && !o.entry->lpi.attempts);
  product_flow_runtime_destroy(pool);
}

static uint64_t sample (const uint8_t *bytes, unsigned length, unsigned transport,
                        unsigned source, unsigned destination, unsigned family)
{
  product_flow_runtime_t *pool=NULL;
  assert(product_flow_runtime_create(&pool,0,1,19,1)==0);
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=family,.protocol=transport,
    .source_port=source,.destination_port=destination,.l4_header_length=transport==6?20:8,
    .tcp_flags=16,.tcp_window=65535};
  f.transport_length=f.l4_header_length+length;
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t a;
  assert(product_owner_assign(&layout,&f,&a)==0);
  product_flow_entry_packet_t p={.facts=&f,.policy={19,1,1},.uid=17};
  product_flow_entry_observation_t o;
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(product_flow_entry_identify(pool,o.slot,19,o.entry->incarnation,&f,bytes,length)==0);
  uint64_t result=o.entry->lpi.protocols;
  product_flow_runtime_destroy(pool);
  return result;
}

static void mdns_boundaries (void)
{
  /* Independent literals: query a.local A/IN, compressed answer, goodbye TTL0. */
  const uint8_t query[]={0,0,0,0,0,1,0,0,0,0,0,0,1,'a',5,'l','o','c','a','l',0,0,1,0,1};
  uint8_t answer[sizeof query+16];
  memcpy(answer,query,sizeof query);answer[2]=0x84;answer[7]=1;
  memcpy(answer+sizeof query,(uint8_t[]){0xc0,12,0,1,0x80,1,0,0,0,0,0,4,10,1,2,3},16);
  for(unsigned family=4;family<=6;family+=2) {
    assert(sample(query,sizeof query,17,42005,5353,family)==32);
    assert(sample(query,sizeof query,17,5353,42005,family)==32);
    assert(sample(answer,sizeof answer,17,5353,5353,family)==32);
  }
  /* Port alone, stream transport and unrelated port cannot manufacture mDNS. */
  for(unsigned n=1;n<sizeof query;++n) assert(!(sample(query,n,17,42005,5353,4)&32));
  assert(!(sample(query,sizeof query,17,42005,5354,4)&32));
  assert(!(sample(query,sizeof query,6,42005,5353,4)&32));
  uint8_t bad[sizeof answer+1];
  memcpy(bad,answer,sizeof answer);bad[sizeof answer]=0;
  assert(!(sample(bad,sizeof bad,17,5353,42005,4)&32));
  for(unsigned scenario=0;scenario<9;++scenario) {
    memcpy(bad,answer,sizeof answer);
    if(scenario==0) bad[2]=0x8c; /* unsupported opcode */
    if(scenario==1) bad[3]=3; /* mDNS must not carry DNS error code */
    if(scenario==2) bad[5]=65; /* finite record work */
    if(scenario==3) bad[12]=64; /* invalid label tag */
    if(scenario==4) {bad[12]=0xc0;bad[13]=12;} /* self-pointer */
    if(scenario==5) {bad[12]=0xc0;bad[13]=30;} /* forward pointer */
    if(scenario==6) bad[sizeof query+11]=5; /* truncated RDATA */
    if(scenario==7) bad[sizeof query+3]=0; /* invalid TYPE0 */
    if(scenario==8) bad[sizeof query+5]=0; /* invalid CLASS0 */
    assert(!(sample(bad,sizeof answer,17,5353,42005,4)&32));
  }
  uint8_t empty[12]={0};
  assert(!(sample(empty,sizeof empty,17,5353,5353,4)&32));
  /* Compression cannot point into a previous TYPE field or label contents. */
  uint8_t false_pointer[]={0,0,0,0,0,2,0,0,0,0,0,0,1,'a',0,0,1,0,1,0xc0,15,0,1,0,1};
  assert(!(sample(false_pointer,sizeof false_pointer,17,5353,5353,4)&32));
  false_pointer[20]=17;
  assert(!(sample(false_pointer,sizeof false_pointer,17,5353,5353,4)&32));
  false_pointer[20]=13;false_pointer[13]=0;
  assert(!(sample(false_pointer,sizeof false_pointer,17,5353,5353,4)&32));
  /* Preserve the original five independent catalog facts and heuristics. */
  const uint8_t dns[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,'a',0,0,1,0,1};
  assert(sample(dns,sizeof dns,17,42005,53,4)==1);
  assert(!(sample(dns,sizeof dns,17,42005,5300,4)&1));
  assert(sample(dns,sizeof dns,17,53,5353,4)==32); /* replace unpublished DNS guess */
  const uint8_t http[]="GET / HTTP/1.1\r\n\r\n";
  assert(sample(http,sizeof http-1,6,42005,80,4)==2);
  assert(sample(http,sizeof http-1,6,42005,8088,4)==2);
  const uint8_t not_http[]="GEX / HTTP/1.1\r\n\r\n";
  assert(!(sample(not_http,sizeof not_http-1,6,42005,80,4)&2));
  const uint8_t ssh[]="SSH-2.0-OpenSSH_9.0\r\n";
  assert(sample(ssh,sizeof ssh-1,6,22,42005,4)==16);
  assert(sample(ssh,sizeof ssh-1,6,2222,42005,4)==16);
  const uint8_t not_ssh[]="SSX-2.0-OpenSSH_9.0\r\n";
  assert(!(sample(not_ssh,sizeof not_ssh-1,6,22,42005,4)&16));
  const uint8_t tls[]={0x16,3,1,0,4,1,2,3,4};
  const uint8_t not_tls[]={0x16,4,1,0,4,1,2,3,4};
  assert(sample(tls,sizeof tls,6,42005,443,4)==4);
  assert(sample(tls,sizeof tls,6,42005,8443,4)==4);
  assert(!(sample(not_tls,sizeof not_tls,6,42005,443,4)&4));
  uint8_t initial[1200]={0xc0,0,0,0,1,8,1,2,3,4,5,6,7,8,0,0,0x44,0x9e};
  assert(sample(initial,sizeof initial,17,53,5353,4)==8);
  const uint8_t opaque[]={0xfe,0xdd,0xcc};
  for(unsigned transport=6;transport<=17;transport+=11)
    assert(sample(opaque,sizeof opaque,transport,42005,5353,4)==0);
  puts("R1 DNS/HTTP/SSH boundaries and mDNS structure, family, direction, port, malformed vectors: PASS");
}
static uint64_t nanos (void)
{
  struct timespec now;
  assert(clock_gettime(CLOCK_MONOTONIC,&now)==0);
  return (uint64_t)now.tv_sec*UINT64_C(1000000000)+(uint64_t)now.tv_nsec;
}

static void representative_cost (void)
{
  const uint8_t query[]={0,0,0,0,0,1,0,0,0,0,0,0,1,'a',5,'l','o','c','a','l',0,0,1,0,1};
  uint8_t opaque[sizeof query];memset(opaque,0xfe,sizeof opaque);
  for(unsigned shape=0;shape<3;++shape) {
    const uint8_t *payload=shape==1?opaque:query;
    uint64_t elapsed=0;
    for(unsigned repetition=0;repetition<2000;++repetition) {
      product_flow_runtime_t *pool=NULL;
      assert(product_flow_runtime_create(&pool,0,1,23,1)==0);
      product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
        .source_port=42007,.destination_port=shape==2?5354:5353,
        .l4_header_length=8,.transport_length=8+sizeof query};
      f.source_address[0]=10;f.destination_address[0]=11;
      product_worker_layout_t layout={1,1};product_owner_assignment_t a;
      assert(product_owner_assign(&layout,&f,&a)==0);
      product_flow_entry_packet_t p={.facts=&f,.policy={23,1,1},.uid=17};
      product_flow_entry_observation_t o;
      assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
      uint64_t start=nanos();
      for(unsigned attempt=0;attempt<20;++attempt)
        assert(product_flow_entry_identify(pool,o.slot,23,o.entry->incarnation,&f,payload,sizeof query)==0);
      elapsed+=nanos()-start;
      assert(o.entry->lpi.attempts==20 && o.entry->lpi.stop_reason==1);
      assert(o.entry->lpi.protocols==(shape==0?32:0));
      product_flow_runtime_destroy(pool);
    }
    printf("{\"shape\":%u,\"calls\":40000,\"elapsed_ns\":%llu,\"lpi_bytes\":%zu,\"entry_bytes\":%zu}\n",
           shape,(unsigned long long)elapsed,sizeof(product_lpi_state_t),sizeof(product_flow_entry_t));
  }
}
int main (void)
{
  assert (product_lpi_init () == 0);
  if(getenv("R1_COST")) {representative_cost();return 0;}
  dns_budget ();
  multi_result_and_reuse ();
  tls_upgrade ();
  quic_header_failures ();
  mdns_query ();
  mdns_boundaries ();
  assert (product_static_expression_validate((uint8_t[]){15,0xe8,3,0,0},5)
          == PRODUCT_L4_POLICY_STATUS_INVALID_RULE); /* reserved catalog ID */
  assert (product_static_expression_validate((uint8_t[]){15,0xef,3,0,0},5)
          == PRODUCT_L4_POLICY_STATUS_INVALID_RULE); /* absent catalog ID */
  assert (product_static_expression_validate((uint8_t[]){15,0xeb,3,0},4)
          == PRODUCT_L4_POLICY_STATUS_INVALID_RULE); /* truncated operand */
  puts ("published protocol union, no-result retention, bounded lifecycle and stale identity: PASS");
}
