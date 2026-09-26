/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_l4_policy.h"
#include "product_domain_consumer.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
/* RFC8446 ClientHello with TLS1.2 legacy version, one suite and null
 * compression, no extensions. Literal independent expected absence. */
static const uint8_t absent[]={22,3,1,0,45,1,0,0,41,3,3,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,2,0,0x2f,1,0};
static void named_split(void)
{
  uint8_t hello[80];memcpy(hello,absent,sizeof absent);
  const uint8_t ext[]={0,22,0,0,0,18,0,16,0,0,13,
    'E','x','a','m','p','l','e','.','t','e','s','t','s'};
  memcpy(hello+sizeof absent,ext,sizeof ext);
  unsigned n=sizeof absent+sizeof ext;hello[4]=(uint8_t)(n-5);hello[8]=(uint8_t)(n-9);
  product_flow_runtime_t *pool=NULL;assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=16,.tcp_window=65535,.tcp_sequence=100};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_observation_t o;
  for(unsigned at=0;at<n;) {
    unsigned size=n-at>7?7:n-at;
    f.transport_length=20+size;f.packet_length=20+f.transport_length;
    product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=at+1};
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));assert(o.entry);
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,hello+at,size));
    at+=size;f.tcp_sequence+=size;
    if(at<n) assert(o.entry->sni.result==PRODUCT_SNI_UNAVAILABLE);
  }
  assert(o.entry->sni.result==PRODUCT_SNI_NAME);
  assert(!strcmp(o.entry->sni.name,"example.tests"));
  domain_consumer(o.entry,PRODUCT_SNI_NAME,"example.tests",6);
  assert(!o.entry->tcp_bytes.length[0] && !o.entry->tcp_bytes.length[1]);
  product_flow_runtime_destroy(pool);
}
static void absence_rule(void)
{
  product_l4_policy_rule_t rule={.rule_id=7,.reason_id=9,.uid=17,.action=2,
    .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=65535,.destination_port_last=65535,
    .expression={16,1},.expression_length=2};
  product_l4_policy_view_t view;
  assert(!product_l4_policy_compile(&view,&rule,1));
  product_l4_policy_packet_t p={.uid=17,.uid_known=1,.family=4,.protocol=6,
    .protocol_set=4,.protocol_set_known=1,.sni_result=PRODUCT_SNI_ABSENT};
  product_l4_policy_match_result_t result;
  assert(!product_l4_policy_match(&view,&p,&result));assert(result.rule_id==7);
}
static void parser_deadline(void)
{
  product_flow_runtime_t *pool=NULL;assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=16,.tcp_window=65535,.tcp_sequence=100,.transport_length=30,.packet_length=50};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=100};
  product_flow_entry_observation_t o;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(!product_flow_runtime_set_deadline(pool,o.slot,7,o.entry->incarnation,
    60000000,PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED));
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,absent,10));
  assert(product_flow_runtime_next_deadline(pool)==100+PRODUCT_SNI_TIMEOUT_US);
  uint32_t closed=99;
  assert(!product_flow_runtime_run_due(pool,100+PRODUCT_SNI_TIMEOUT_US,1,&closed));
  assert(!closed && o.entry->linked && o.entry->deadline_us==60000000);
  assert(o.entry->sni.stop==PRODUCT_SNI_TIMEOUT && !o.entry->sni.result);
  assert(!o.entry->tcp_bytes.length[0]);
  assert(product_flow_runtime_next_deadline(pool)==60000000);
  product_flow_runtime_destroy(pool);
}

static product_sni_state_t sample(const uint8_t *bytes,unsigned length,unsigned split,
                                  int sequence_gap,int publish)
{
  product_flow_runtime_t *pool=NULL;assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=16,.tcp_window=65535,.tcp_sequence=100};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_observation_t o;
  unsigned at=0;
  do {
    unsigned count=length-at;
    if(!at && split && count>split) count=split;
    f.transport_length=20+count;f.packet_length=20+f.transport_length;
    product_flow_entry_packet_t input={.facts=&f,.policy={7,publish && at?2:1,1},.uid=17,.timestamp=at+1};
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));assert(o.entry);
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,bytes+at,count));
    at+=count;f.tcp_sequence+=count;
    if(at<length) f.tcp_sequence+=(uint32_t)sequence_gap;
  } while(at<length);
  product_sni_state_t result=o.entry->sni;
  if (result.result==PRODUCT_SNI_ABSENT) domain_consumer(o.entry,PRODUCT_SNI_ABSENT,"",6);
  if(result.stop) assert(!o.entry->tcp_bytes.length[0] && !o.entry->tcp_bytes.length[1]);
  if(result.result) assert(o.entry->lpi.protocols&4);
  assert(o.entry->linked);
  product_flow_runtime_destroy(pool);
  return result;
}
static void boundaries(void)
{
  for(unsigned split=1;split<sizeof absent;++split) {
    product_sni_state_t s=sample(absent,sizeof absent,split,0,1);
    assert(s.result==PRODUCT_SNI_ABSENT && s.stop==PRODUCT_SNI_COMPLETE);
    s=sample(absent,sizeof absent,split,1,0);
    assert(!s.result && !s.stop);
    s=sample(absent,sizeof absent,split,-1,0);
    assert(!s.result);
  }
  for(unsigned n=1;n<sizeof absent;++n) {
    product_sni_state_t s=sample(absent,n,0,0,0);
    assert(!s.result && !s.stop);
  }
  /* Every possible TLS-record split, including across handshake/vector headers. */
  for(unsigned cut=1;cut<sizeof absent-5;++cut) {
    uint8_t wire[sizeof absent+5];
    memcpy(wire,absent,5);wire[3]=0;wire[4]=(uint8_t)cut;
    memcpy(wire+5,absent+5,cut);
    memcpy(wire+5+cut,absent,5);wire[9+cut]=(uint8_t)(sizeof absent-5-cut);
    memcpy(wire+10+cut,absent+5+cut,sizeof absent-5-cut);
    product_sni_state_t s=sample(wire,sizeof wire,17,0,0);
    assert(s.result==PRODUCT_SNI_ABSENT && s.stop==PRODUCT_SNI_COMPLETE);
  }
  const unsigned offsets[]={8,43,44,45,48,49};
  const uint8_t values[]={1,33,255,1,0,1};
  for(unsigned i=0;i<sizeof offsets/sizeof offsets[0];++i) {
    uint8_t bad[sizeof absent];memcpy(bad,absent,sizeof bad);bad[offsets[i]]=values[i];
    product_sni_state_t s=sample(bad,sizeof bad,0,0,0);
    assert(!s.result && s.stop==PRODUCT_SNI_MALFORMED);
  }
  uint8_t huge[4097]={22,3,1,16,0};
  product_sni_state_t s=sample(huge,sizeof huge,0,0,0);
  assert(!s.result && s.stop==PRODUCT_SNI_BYTE_BUDGET);
  uint8_t extensions[sizeof absent+10];memcpy(extensions,absent,sizeof absent);
  /* Duplicate unknown extensions cannot confirm absence. */
  memcpy(extensions+sizeof absent,(uint8_t[]){0,8,0,40,0,0,0,40,0,0},10);
  extensions[4]+=10;extensions[8]+=10;
  s=sample(extensions,sizeof extensions,0,0,0);
  assert(!s.result && s.stop==PRODUCT_SNI_MALFORMED);
  puts("TLS truncation, malformed vectors, record/TCP splits and unsupported sequence boundaries: PASS");
}


static void budgets_and_reuse(void)
{
  product_flow_runtime_t *pool=NULL;assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=16,.tcp_window=65535,.tcp_sequence=100,.transport_length=21,.packet_length=41};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_observation_t o;
  for(unsigned i=0;i<20;++i) {
    product_flow_entry_packet_t input={.facts=&f,.policy={7,i<10?1:2,1},.uid=17,.timestamp=i+1};
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));assert(o.entry);
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,absent+i,1));
    ++f.tcp_sequence;
  }
  assert(o.entry->sni.stop==PRODUCT_SNI_PACKET_BUDGET && !o.entry->sni.result);
  assert(o.entry->sni.attempts==20 && !o.entry->tcp_bytes.length[0]);
  uint64_t old=o.entry->incarnation;
  product_sni_state_t before=o.entry->sni;
  assert(!product_flow_entry_identify(pool,o.slot,7,old,&f,absent,1));
  assert(!memcmp(&before,&o.entry->sni,sizeof before));
  assert(product_flow_entry_identify(pool,o.slot,8,old,&f,absent,1)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert(product_flow_entry_identify(pool,o.slot,7,old+1,&f,absent,1)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert(!product_flow_runtime_flush(pool));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,2,1},.uid=17,.timestamp=30};
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(o.entry->incarnation!=old && !o.entry->sni.stop && !o.entry->sni.result);
  assert(!o.entry->tcp_bytes.length[0] && !o.entry->tcp_bytes.length[1]);
  product_flow_runtime_destroy(pool);
  puts("TLS independent packet budget, policy retention and same-slot generation fence: PASS");
}
static void name_boundaries(void)
{
  const char *names[]={"a.test","xn--bcher-kva.example","EXAMPLE.TEST","-bad.test","bad-.test",
    "bad..test","bad.test.","bad_test","127.0.0.1","https://x","x\n.test"};
  for(unsigned i=0;i<sizeof names/sizeof names[0];++i) {
    unsigned n=(unsigned)strlen(names[i]);uint8_t hello[400];
    memcpy(hello,absent,sizeof absent);
    unsigned at=sizeof absent;
    hello[at++]=0;hello[at++]=(uint8_t)(n+9);hello[at++]=0;hello[at++]=0;
    hello[at++]=0;hello[at++]=(uint8_t)(n+5);hello[at++]=0;hello[at++]=(uint8_t)(n+3);
    hello[at++]=0;hello[at++]=0;hello[at++]=(uint8_t)n;
    memcpy(hello+at,names[i],n);at+=n;hello[4]=(uint8_t)(at-5);hello[8]=(uint8_t)(at-9);
    product_sni_state_t result=sample(hello,at,11,0,0);
    if(i<3) assert(result.result==PRODUCT_SNI_NAME && result.stop==PRODUCT_SNI_COMPLETE);
    else assert(!result.result && result.stop==PRODUCT_SNI_MALFORMED);
    /* Truncated extensions never publish the prefix name. */
    result=sample(hello,at-1,0,0,0);assert(!result.result);
  }
}

static void syn_gap(void)
{
  product_flow_runtime_t *pool=NULL;assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=2,.tcp_window=65535,.tcp_sequence=100,.transport_length=20,.packet_length=40};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,NULL,0));
  f.tcp_sequence=102;f.tcp_flags=16;f.transport_length=20+sizeof absent;
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,absent,sizeof absent));
  assert(!o.entry->sni.result && !o.entry->sni.stop);
  product_flow_runtime_destroy(pool);
}
static void reordered_hello(void)
{
  product_flow_runtime_t *pool=NULL;assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=2,.tcp_window=65535,.tcp_sequence=UINT32_MAX-10,
    .transport_length=20,.packet_length=40};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,NULL,0));
  const unsigned offsets[]={25,25,0}, sizes[]={25,25,25};
  for(unsigned i=0;i<3;++i) {
    f.tcp_sequence=UINT32_MAX-9+offsets[i];f.tcp_flags=16;
    f.transport_length=20+sizes[i];f.packet_length=40+sizes[i];input.timestamp++;
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,absent+offsets[i],sizes[i]));
    if(i<2) assert(!o.entry->sni.result && !o.entry->sni.stop && o.entry->sni.bytes==25);
  }
  assert(o.entry->sni.result==PRODUCT_SNI_ABSENT && o.entry->sni.bytes==50);
  assert(!o.entry->tcp_bytes.length[0] && !o.entry->tcp_bytes.length[1]);
  product_flow_runtime_destroy(pool);
}
/* Owner API transcript: independent literal wire offsets, never parser-derived. */
typedef struct {
  product_flow_runtime_t *pool;
  product_packet_facts_t facts;
  product_owner_assignment_t owner;
  product_flow_entry_observation_t observation;
  uint64_t tick;
} stream_case_t;
static void stream_send(stream_case_t *c,unsigned side,uint32_t sequence,
                        const uint8_t *data,unsigned size,unsigned flags)
{
  product_packet_facts_t f=c->facts;
  if(side) {
    f.source_address[0]=11;f.destination_address[0]=10;
    f.source_port=443;f.destination_port=42000;
  }
  f.tcp_sequence=sequence;f.tcp_flags=(uint8_t)flags;
  f.transport_length=20+size;f.packet_length=40+size;
  product_worker_layout_t layout={1,1};
  assert(!product_owner_assign(&layout,&f,&c->owner));
  product_flow_entry_packet_t packet={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=++c->tick};
  assert(!product_flow_entry_observe(c->pool,&c->owner,&packet,0,&c->observation));
  assert(!product_flow_entry_identify(c->pool,c->observation.slot,7,
    c->observation.entry->incarnation,&f,data,size));
}
static stream_case_t stream_case(void)
{
  stream_case_t c={.facts={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,.tcp_window=65535}};
  c.facts.source_address[0]=10;c.facts.destination_address[0]=11;
  product_worker_layout_t layout={1,1};assert(!product_owner_assign(&layout,&c.facts,&c.owner));
  assert(!product_flow_runtime_create(&c.pool,0,1,7,1));
  stream_send(&c,0,99,NULL,0,2);return c;
}
static void reorder_matrix(void)
{
  unsigned cases=0;
  for(unsigned a=0;a<4;++a) for(unsigned b=0;b<4;++b)
    for(unsigned d=0;d<4;++d) for(unsigned e=0;e<4;++e) {
      if(a==b || a==d || a==e || b==d || b==e || d==e) continue;
      stream_case_t c=stream_case();unsigned order[]={a,b,d,e};
      for(unsigned i=0;i<4;++i) {
        unsigned offset=order[i]*12,size=order[i]==3?14:12;
        stream_send(&c,0,100+offset,absent+offset,size,16);
        uint32_t credited=c.observation.entry->sni.bytes;
        stream_send(&c,0,100+offset,absent+offset,size,16);
        assert(c.observation.entry->sni.bytes==credited);
      }
      assert(c.observation.entry->sni.result==PRODUCT_SNI_ABSENT);
      assert(c.observation.entry->sni.bytes==50);
      domain_consumer(c.observation.entry,PRODUCT_SNI_ABSENT,"",6);
      product_flow_runtime_destroy(c.pool);++cases;
    }
  assert(cases==24);
  /* Overlapping equal bytes merge; contradictory overlap fails closed for
   * parsing only, preserving the linked Flow and its published TLS fact. */
  stream_case_t c=stream_case();
  stream_send(&c,0,100,absent,30,16);
  stream_send(&c,0,120,absent+20,30,16);
  assert(c.observation.entry->sni.result==PRODUCT_SNI_ABSENT && c.observation.entry->sni.bytes==50);
  product_flow_runtime_destroy(c.pool);
  c=stream_case();stream_send(&c,0,100,absent,30,16);
  uint8_t bad[30];memcpy(bad,absent+20,30);bad[0]^=1;
  stream_send(&c,0,120,bad,30,16);
  assert(c.observation.entry->sni.stop==PRODUCT_SNI_SEQUENCE && !c.observation.entry->sni.result);
  assert(c.observation.entry->linked && !c.observation.entry->tcp_bytes.length[0]);
  product_flow_runtime_destroy(c.pool);
  puts("24 TCP orderings, exact duplicates, equal/conflicting overlap: PASS");
}
static void sparse_and_duplex(void)
{
  stream_case_t c=stream_case();
  for(unsigned i=0;i<17;++i) stream_send(&c,0,101+2*i,absent,1,16);
  assert(c.observation.entry->sni.stop==PRODUCT_SNI_BYTE_BUDGET);
  assert(!c.observation.entry->sni.result && !c.observation.entry->tcp_bytes.length[0]);
  assert(c.observation.entry->sni.bytes==16 && c.observation.entry->linked);
  product_flow_runtime_destroy(c.pool);
  c=stream_case();stream_send(&c,0,4195,absent,1,16);
  assert(!c.observation.entry->sni.stop && c.observation.entry->sni.bytes==1);
  stream_send(&c,0,4196,absent,1,16);
  assert(c.observation.entry->sni.stop==PRODUCT_SNI_BYTE_BUDGET && !c.observation.entry->sni.result);
  product_flow_runtime_destroy(c.pool);
  c=stream_case();stream_send(&c,1,999,NULL,0,18);
  stream_send(&c,0,125,absent+25,25,16);
  stream_send(&c,1,1020,absent+20,30,16);
  assert(c.observation.entry->sni.bytes==55 && !c.observation.entry->sni.result);
  stream_send(&c,1,1000,absent,20,16);
  assert(c.observation.entry->sni.result==PRODUCT_SNI_ABSENT && c.observation.entry->sni.bytes==75);
  assert(!c.observation.entry->tcp_bytes.length[0] && !c.observation.entry->tcp_bytes.length[1]);
  product_flow_runtime_destroy(c.pool);
  puts("Independent direction spaces, 16 sparse ranges and 4096-byte span bound: PASS");
}
static void recognition_stopped_before_reassembly(void)
{
  uint8_t wire[3556]={0};memcpy(wire,absent,sizeof absent);
  wire[3]=13;wire[4]=223; /* record payload 3551 */
  wire[6]=0;wire[7]=13;wire[8]=219; /* body 3547 */
  wire[50]=13;wire[51]=176; /* extensions 3504 */
  wire[52]=0;wire[53]=42;wire[54]=13;wire[55]=172; /* padding 3500 */
  stream_case_t c=stream_case();
  for(unsigned i=0;i<10;++i) stream_send(&c,0,156,wire+56,3500,16);
  assert(c.observation.entry->lpi.stop_reason);
  assert(!c.observation.entry->sni.result && c.observation.entry->sni.bytes==3500);
  stream_send(&c,0,100,wire,56,16);
  assert(c.observation.entry->sni.result==PRODUCT_SNI_ABSENT);
  assert(c.observation.entry->lpi.available && (c.observation.entry->lpi.protocols&4));
  product_flow_runtime_destroy(c.pool);
}
static void record_split_and_pre_flow_drop(void)
{
  uint8_t wire[55];
  memcpy(wire,absent,5);wire[4]=17;memcpy(wire+5,absent+5,17);
  memcpy(wire+22,absent,5);wire[26]=28;memcpy(wire+27,absent+22,28);
  stream_case_t c=stream_case();
  stream_send(&c,0,122,wire+22,33,16);
  stream_send(&c,0,100,wire,22,16);
  assert(c.observation.entry->sni.result==PRODUCT_SNI_ABSENT && c.observation.entry->sni.bytes==55);
  product_flow_runtime_destroy(c.pool);
  c=stream_case();stream_send(&c,0,100,absent,20,16);
  const product_flow_entry_t *entry=c.observation.entry;
  uint64_t packets=entry->packets;
  product_packet_facts_t f=c.facts;f.tcp_sequence=120;f.tcp_flags=16;
  f.transport_length=50;f.packet_length=70;
  product_flow_entry_packet_t packet={.facts=&f,.policy={7,2,1},.uid=17,.timestamp=++c.tick};
  product_flow_entry_observation_t dropped;
  assert(product_flow_entry_observe(c.pool,&c.owner,&packet,PRODUCT_FLOW_ENTRY_VERDICT_DROP,&dropped)
         ==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
  assert(!dropped.entry && entry->packets==packets && entry->sni.bytes==20 && !entry->sni.result);
  stream_send(&c,0,120,absent+20,30,16);
  assert(c.observation.entry->sni.result==PRODUCT_SNI_ABSENT && entry->packets==packets+1);
  product_flow_runtime_destroy(c.pool);
}
static void overlap_work_budget(void)
{
  /* A padded 4096-byte Hello remains incomplete while long equal overlaps
   * advance its prefix one byte at a time. Work, not bytes/ranges/time/packets,
   * must terminate this attempt before the seventeenth 4000-byte comparison. */
  uint8_t wire[4096]={0};memcpy(wire,absent,sizeof absent);
  wire[3]=15;wire[4]=251;wire[7]=15;wire[8]=247;
  wire[50]=15;wire[51]=204;wire[52]=0;wire[53]=21;wire[54]=15;wire[55]=200;
  stream_case_t c=stream_case();
  stream_send(&c,0,100,wire,4000,16);
  uint64_t published=c.observation.entry->lpi.protocols;
  for(unsigned offset=1;offset<=16;++offset) stream_send(&c,0,100+offset,wire+offset,4000,16);
  assert(c.observation.entry->sni.stop==PRODUCT_SNI_BYTE_BUDGET && !c.observation.entry->sni.result);
  assert(c.observation.entry->sni.attempts==17 && c.observation.entry->sni.bytes==4015);
  assert(c.observation.entry->sni.work==128120 && c.observation.entry->linked);
  assert(c.observation.entry->lpi.protocols==published && !c.observation.entry->tcp_bytes.length[0]);
  product_flow_runtime_destroy(c.pool);
  puts("Long equal overlaps exhaust work before packet/byte/span/metadata/time limits: PASS");
}
int main(void)
{
  assert(!product_lpi_init());
  reordered_hello();
  reorder_matrix();
  sparse_and_duplex();
  recognition_stopped_before_reassembly();
  record_split_and_pre_flow_drop();
  overlap_work_budget();
  named_split();
  absence_rule();
  parser_deadline();
  boundaries();
  budgets_and_reuse();
  name_boundaries();
  syn_gap();
  product_flow_runtime_t *pool=NULL;
  assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=6,
    .source_port=42000,.destination_port=443,.l4_header_length=20,
    .tcp_flags=16,.tcp_window=65535,.tcp_sequence=100};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  f.transport_length=20+sizeof absent;f.packet_length=20+f.transport_length;
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(o.entry);
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,absent,sizeof absent));
  assert(o.entry->sni.result==PRODUCT_SNI_ABSENT);
  product_flow_runtime_destroy(pool);
  puts("TLS complete ClientHello confirms absence: PASS");
}
