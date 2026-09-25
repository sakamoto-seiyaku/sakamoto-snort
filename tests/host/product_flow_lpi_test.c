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

static void mail_banner (void)
{
  const uint8_t ftp[]="220 test FTPd ready\r\n";
  const uint8_t smtp[]="220 test ESMTP ready\r\n";
  assert(sample(ftp,sizeof ftp-1,6,2121,42005,4)==128);
  assert(sample(smtp,sizeof smtp-1,6,2525,42005,4)==64);
  assert(sample(ftp,sizeof ftp-1,6,25,42005,4)==128);
  assert(sample(ftp,sizeof ftp-1,6,20,42005,4)==128);
  const uint8_t data[]="file contents\r\n";
  assert(sample(data,sizeof data-1,6,20,42005,4)==256);
  const uint8_t tls[]={0x16,3,1,0,4,1,0,0,0};
  assert(sample(tls,sizeof tls,6,42005,990,4)==516);

}

static void mail_sequence (void)
{
  const uint8_t *payloads[]={(const uint8_t *)"220 test FTPd ready\r\n",
    (const uint8_t *)"AUTH TLS\r\n",(const uint8_t *)"234 Ready\r\n",
    (const uint8_t *)"\x16\x03\x01\0\x04\x01\0\0\0"};
  const unsigned sizes[]={21,10,11,9};
  const unsigned sides[]={1,0,1,0};
  product_flow_runtime_t *pool=NULL;
  assert(product_flow_runtime_create(&pool,0,1,27,1)==0);
  product_worker_layout_t layout={1,1};
  product_flow_entry_observation_t o;
  for(unsigned step=0;step<4;++step) {
    unsigned side=sides[step];
    product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
      .source_port=side?21:42007,.destination_port=side?42007:21,
      .l4_header_length=20,.transport_length=20+sizes[step],.tcp_flags=16,.tcp_window=65535};
    f.source_address[0]=side?11:10;f.destination_address[0]=side?10:11;
    product_owner_assignment_t a; assert(product_owner_assign(&layout,&f,&a)==0);
    product_flow_entry_packet_t p={.facts=&f,.policy={27,1,1},.uid=17,.timestamp=step+1};
    assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
    assert(product_flow_entry_identify(pool,o.slot,27,o.entry->incarnation,&f,payloads[step],sizes[step])==0);
    assert(o.entry->lpi.protocols==(step==3?644:128));
  }
  product_flow_runtime_destroy(pool);
}

typedef struct {
  const char *text;
  unsigned side;
  uint64_t expected;
} mail_step_t;

static void transcript (const mail_step_t *steps, unsigned count, unsigned port)
{
  product_flow_runtime_t *pool=NULL;
  assert(product_flow_runtime_create(&pool,0,1,29,1)==0);
  product_worker_layout_t layout={1,1};
  product_flow_entry_observation_t o;
  uint64_t incarnation=0;
  for(unsigned step=0;step<count;++step) {
    unsigned side=steps[step].side, n=(unsigned)strlen(steps[step].text);
    const uint8_t *payload=(const uint8_t *)steps[step].text;
    /* Hand-coded framing witness, not production recognition as oracle. */
    const uint8_t tls[]={22,3,1,0,4,1,0,0,0};
    if(!strcmp(steps[step].text,"TLS")) {payload=tls;n=sizeof tls;}
    product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=6,.protocol=6,
      .source_port=side?port:42008,.destination_port=side?42008:port,
      .l4_header_length=20,.transport_length=20+n,.tcp_flags=16,.tcp_window=65535};
    f.source_address[0]=side?11:10;f.destination_address[0]=side?10:11;
    product_owner_assignment_t a;assert(product_owner_assign(&layout,&f,&a)==0);
    /* Every second packet changes policy: pending detection must survive. */
    product_flow_entry_packet_t p={.facts=&f,.policy={29,1+step/2,1+step/2},.uid=17,.timestamp=step+1};
    assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
    if(step) assert(o.entry->incarnation==incarnation);
    incarnation=o.entry->incarnation;
    assert(product_flow_entry_identify(pool,o.slot,29,incarnation,&f,payload,n)==0);
    if(o.entry->lpi.protocols!=steps[step].expected)
      fprintf(stderr,"port=%u step=%u input=%s actual=%llu expected=%llu\n",port,step,
        steps[step].text,(unsigned long long)o.entry->lpi.protocols,
        (unsigned long long)steps[step].expected);
    assert(o.entry->lpi.protocols==steps[step].expected);
    assert(o.entry->lpi.available==(steps[step].expected!=0));
  }
  product_flow_runtime_destroy(pool);
}
#define TRANSCRIPT(port,...) do { const mail_step_t steps[]={__VA_ARGS__}; \
  transcript(steps,sizeof steps/sizeof steps[0],port); } while(0)

static void mail_boundaries (void)
{
  const uint8_t *negative[]={(const uint8_t *)"220 notFTPD ready\r\n",
    (const uint8_t *)"220 ESMTPish ready\r\n",(const uint8_t *)"220 FTP ESMTP\r\n",
    (const uint8_t *)"221 FTP ready\r\n",(const uint8_t *)"220 FTP ready\n",
    (const uint8_t *)"220 FTP ready",(const uint8_t *)"220 service ready\r\n"};
  for(unsigned i=0;i<sizeof negative/sizeof negative[0];++i)
    for(unsigned port=21;port<=25;port+=4)
      assert(!(sample(negative[i],(unsigned)strlen((const char *)negative[i]),6,port,42005,4)&(64|128)));
  const uint8_t banner[]="220-test esmtp ready\r\n";
  for(unsigned n=0;n<sizeof banner-1;++n)
    assert(!(sample(banner,n,6,25,42005,4)&(64|128)));
  for(unsigned family=4;family<=6;family+=2) {
    assert(sample(banner,sizeof banner-1,6,21,42005,family)==64);
    assert(sample(banner,sizeof banner-1,6,42005,2525,family)==64);
  }
  assert(!(sample(banner,sizeof banner-1,17,25,42005,4)&(64|128)));
  uint8_t long_banner[520];memset(long_banner,' ',sizeof long_banner);
  memcpy(long_banner,"220 FTP",7);long_banner[518]='\r';long_banner[519]='\n';
  assert(!(sample(long_banner,sizeof long_banner,6,21,42005,4)&128));
  const uint8_t opaque[]={0xfe,0xdd};
  assert(sample(opaque,sizeof opaque,6,42005,20,4)==256);
  assert(!(sample(opaque,sizeof opaque,6,42005,2020,4)&256));
  assert(!(sample(opaque,sizeof opaque,17,20,42005,4)&256));
  assert(!(sample(opaque,sizeof opaque,6,990,42005,4)&512));
  const uint8_t tls[]={22,3,1,0,4,1,0,0,0};
  assert(sample(tls,sizeof tls,6,990,42005,6)==516);
  assert(!(sample(tls,sizeof tls,6,989,42005,4)&512));
  assert(!(sample(tls,sizeof tls,6,443,42005,4)&512));
  for(unsigned n=0;n<sizeof tls;++n) assert(!(sample(tls,n,6,990,42005,4)&512));
  for(unsigned mutation=0;mutation<5;++mutation) {
    uint8_t bad[sizeof tls];memcpy(bad,tls,sizeof bad);
    if(mutation==0) bad[0]=23;
    if(mutation==1) bad[1]=4;
    if(mutation==2) bad[2]=4;
    if(mutation==3) bad[4]=5;
    if(mutation==4) bad[8]=1;
    assert(!(sample(bad,sizeof bad,6,990,42005,4)&512));
  }
  TRANSCRIPT(2525,{"220 service ready\r\n",1,0},{"EHLO test\r\n",0,0},
    {"250 test\r\n",1,64},{"TLS",0,68});
  TRANSCRIPT(2525,{"EHLO test\r\n",0,0},{"250 test\r\n",0,0});
  TRANSCRIPT(2525,{"EHLOX test\r\n",0,0},{"250 test\r\n",1,0});
  TRANSCRIPT(2525,{"EHLO test\r\n",0,0},{"550 test\r\n",1,0});
  TRANSCRIPT(2121,{"SYST\r\n",0,0},{"215 UNIX\r\n",1,128});
  TRANSCRIPT(2525,{"HELO test\r\n",0,0},{"250 test\r\n",1,64});
  TRANSCRIPT(2121,{"FEAT\r\n",0,0},{"211 Features\r\n",1,128});
  TRANSCRIPT(2121,{"PASV\r\n",0,0},{"227 Passive\r\n",1,128});
  TRANSCRIPT(2121,{"EPSV\r\n",0,0},{"229 Passive\r\n",1,128});
  TRANSCRIPT(2121,{"RETR file\r\n",0,0},{"150 Data\r\n",1,128});
  TRANSCRIPT(2121,{"STOR file\r\n",0,0},{"550 Refused\r\n",1,128});
  TRANSCRIPT(21,{"USER test\r\n",0,0},{"331 Password\r\n",1,128});
  TRANSCRIPT(21,{"PASS test\r\n",0,0},{"230 Login\r\n",1,128});
  TRANSCRIPT(2121,{"SYST\r\n",0,0},{"215 UNIX\r\n",0,0});
  TRANSCRIPT(2121,{"SYSTEM\r\n",0,0},{"215 UNIX\r\n",1,0});
  TRANSCRIPT(25,{"SYST\r\n",0,0},{"215 UNIX\r\n",1,0});
  TRANSCRIPT(2121,{"USER user\r\n",0,0},{"331 pass\r\n",1,0});
  TRANSCRIPT(21,{"AUTH TLS\r\n",0,0},{"234 ready\r\n",1,128},{"TLS",0,644});
  TRANSCRIPT(25,{"220 FTP ready\r\n",1,128},{"AUTH TLS\r\n",0,128},
    {"234 ready\r\n",1,128},{"TLS",0,644});
  TRANSCRIPT(110,{"220 FTP ready\r\n",1,128},{"AUTH TLS\r\n",0,128},
    {"234 ready\r\n",1,128},{"TLS",0,644});
  TRANSCRIPT(587,{"220 FTP ready\r\n",1,128},{"AUTH TLS\r\n",0,128},
    {"234 ready\r\n",1,128},{"TLS",0,644});
  TRANSCRIPT(2121,{"220 FTP ready\r\n",1,128},{"AUTH TLS\r\n",0,128},
    {"234 ready\r\n",1,128},{"TLS",0,644});
  TRANSCRIPT(21,{"AUTH TLSX\r\n",0,0},{"234 ready\r\n",1,0},{"TLS",0,0});
  TRANSCRIPT(21,{"AUTH TLS\r\n",0,0},{"234 ready\r\n",0,0},{"TLS",0,4});
  TRANSCRIPT(21,{"AUTH TLS\r\n",0,0},{"534 refused\r\n",1,128},{"TLS",0,132});
  TRANSCRIPT(21,{"AUTH TLS\r\n",0,0},{"234 ready\r\n",1,128},{"TLS",1,132});
  TRANSCRIPT(2121,{"AUTH TLS\r\n",0,0},{"234 ready\r\n",1,0},{"TLS",0,0});
  TRANSCRIPT(21,{"AUTH TLS\r\n",0,0},{"234-more text\r\n",1,128},{"TLS",0,132});
  /* Published history remains even after an incompatible later banner. */
  TRANSCRIPT(2121,{"220 SMTP ready\r\n",1,64},{"220 FTP ready\r\n",1,192});
  puts("R2 banners, bounded lines, direction, commands, data and explicit/implicit FTPS: PASS");
}

static void mail_lifecycle (void)
{
  product_flow_runtime_t *pool=NULL;
  assert(product_flow_runtime_create(&pool,0,1,31,1)==0);
  assert(product_flow_runtime_set_end_callback(pool,ended,NULL)==0);
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42009,.destination_port=21,.l4_header_length=20,.transport_length=20,.tcp_flags=16,.tcp_window=65535};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t a;
  assert(product_owner_assign(&layout,&f,&a)==0);
  product_flow_entry_packet_t p={.facts=&f,.policy={31,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  uint64_t old=o.entry->incarnation;
  const uint8_t auth[]="AUTH TLS\r\n",opaque[]={0xfe};
  f.transport_length=20+sizeof auth-1;
  assert(product_flow_entry_identify(pool,o.slot,31,old,&f,auth,sizeof auth-1)==0);
  assert(!o.entry->lpi.protocols && o.entry->lpi.attempts==1);
  for(unsigned i=1;i<20;++i) {
    f.transport_length=21;
    assert(product_flow_entry_identify(pool,o.slot,31,old,&f,opaque,sizeof opaque)==0);
  }
  assert(o.entry->lpi.stop_reason==1 && !o.entry->lpi.available);
  const uint8_t banner[]="220 FTPd ready\r\n";
  f.transport_length=20+sizeof banner-1;
  assert(product_flow_entry_identify(pool,o.slot,31,old,&f,banner,sizeof banner-1)==0);
  assert(!o.entry->lpi.protocols && o.entry->lpi.attempts==20);
  assert(product_flow_runtime_close(pool,o.slot,31,old,PRODUCT_FLOW_END_CLOSED)==0);
  assert(product_flow_runtime_release_end(pool,o.slot,31,old,PRODUCT_FLOW_END_CLOSED)==0);
  ++p.timestamp;
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(o.entry->incarnation!=old && !o.entry->lpi.attempts && !o.entry->lpi.available);
  uint64_t fresh=o.entry->incarnation;
  f.transport_length=20+sizeof auth-1;
  assert(product_flow_entry_identify(pool,o.slot,31,old,&f,auth,sizeof auth-1)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  /* A reply on the reused slot cannot satisfy the previous AUTH request. */
  f.source_port=21;f.destination_port=42009;f.source_address[0]=11;f.destination_address[0]=10;
  const uint8_t reply[]="234 Ready\r\n";
  f.transport_length=20+sizeof reply-1;
  assert(product_owner_assign(&layout,&f,&a)==0);
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(product_flow_entry_identify(pool,o.slot,31,fresh,&f,reply,sizeof reply-1)==0);
  assert(!o.entry->lpi.protocols);
  f.source_port=42009;f.destination_port=21;f.source_address[0]=10;f.destination_address[0]=11;
  const uint8_t tls[]={22,3,1,0,4,1,0,0,0};
  f.transport_length=20+sizeof tls;
  assert(product_owner_assign(&layout,&f,&a)==0);
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(product_flow_entry_identify(pool,o.slot,31,fresh,&f,tls,sizeof tls)==0);
  assert(!(o.entry->lpi.protocols&512));
  /* A new published fact survives both a rule publication and byte exhaustion. */
  f.transport_length=20+sizeof banner-1;
  assert(product_flow_entry_identify(pool,o.slot,31,fresh,&f,banner,sizeof banner-1)==0);
  uint64_t published=o.entry->lpi.protocols;assert(published&128);
  p.policy.revision=p.policy.snapshot_hash=2;
  assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
  assert(o.entry->incarnation==fresh && o.entry->lpi.protocols==published);
  uint8_t large[32768]={0xfe};f.transport_length=20+sizeof large;
  assert(product_flow_entry_identify(pool,o.slot,31,fresh,&f,large,sizeof large)==0);
  assert(o.entry->lpi.stop_reason==2 && o.entry->lpi.available && o.entry->lpi.protocols==published);
  product_flow_runtime_destroy(pool);
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
static void mail_cost (void)
{
  const uint8_t banner[]="220 mail.example.test ESMTP R2 ready\r\n";
  const uint8_t negative[]="220 mail.example.test ESMTPish ready\r\n";
  const uint8_t tls[]={22,3,1,0,4,1,0,0,0};
  for(unsigned shape=0;shape<4;++shape) {
    const uint8_t *payload=shape==0?banner:shape==1?negative:tls;
    unsigned length=shape==0?sizeof banner-1:shape==1?sizeof negative-1:sizeof tls;
    uint64_t elapsed=0;
    for(unsigned repetition=0;repetition<2000;++repetition) {
      product_flow_runtime_t *pool=NULL;
      assert(product_flow_runtime_create(&pool,0,1,33,1)==0);
      product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
        .source_port=shape<2?2525:990,.destination_port=42010,
        .l4_header_length=20,.transport_length=20+length,.tcp_flags=16,.tcp_window=65535};
      f.source_address[0]=10;f.destination_address[0]=11;
      product_worker_layout_t layout={1,1};product_owner_assignment_t a;
      assert(product_owner_assign(&layout,&f,&a)==0);
      product_flow_entry_packet_t p={.facts=&f,.policy={33,1,1},.uid=17};
      product_flow_entry_observation_t o;
      assert(product_flow_entry_observe(pool,&a,&p,0,&o)==0);
      if(shape==3) {
        for(unsigned attempt=0;attempt<20;++attempt)
          assert(product_flow_entry_identify(pool,o.slot,33,o.entry->incarnation,&f,payload,length)==0);
      }
      uint64_t start=nanos();
      for(unsigned attempt=0;attempt<20;++attempt)
        assert(product_flow_entry_identify(pool,o.slot,33,o.entry->incarnation,&f,payload,length)==0);
      elapsed+=nanos()-start;
      assert(o.entry->lpi.attempts==20 && o.entry->lpi.stop_reason==1);
      assert(o.entry->lpi.protocols==(shape==0?64:shape==1?0:516));
      product_flow_runtime_destroy(pool);
    }
    printf("{\"shape\":%u,\"calls\":40000,\"elapsed_ns\":%llu,\"lpi_bytes\":%zu,\"entry_bytes\":%zu}\n",
           shape,(unsigned long long)elapsed,sizeof(product_lpi_state_t),sizeof(product_flow_entry_t));
  }
}

int main (void)
{
  assert (product_lpi_init () == 0);
  if(getenv("R2_COST")) {mail_cost();return 0;}
  if(getenv("R1_COST")) {representative_cost();return 0;}
  dns_budget ();
  multi_result_and_reuse ();
  tls_upgrade ();
  quic_header_failures ();
  mdns_query ();
  mdns_boundaries ();
  mail_banner ();
  mail_sequence ();
  mail_boundaries ();
  mail_lifecycle ();
  assert (product_static_expression_validate((uint8_t[]){15,0xe8,3,0,0},5)
          == PRODUCT_L4_POLICY_STATUS_INVALID_RULE); /* reserved catalog ID */
  assert (product_static_expression_validate((uint8_t[]){15,0xff,3,0,0},5)
          == PRODUCT_L4_POLICY_STATUS_INVALID_RULE); /* absent catalog ID */
  assert (product_static_expression_validate((uint8_t[]){15,0xeb,3,0},4)
          == PRODUCT_L4_POLICY_STATUS_INVALID_RULE); /* truncated operand */
  puts ("published protocol union, no-result retention, bounded lifecycle and stale identity: PASS");
}
