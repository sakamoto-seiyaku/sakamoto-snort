/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_protocol_catalog.h"
#include "product_l4_policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "fixtures/quic-v1-rfc9001.h"

/* Literal complete winners for unavailable/name/absence. The first query
 * warms an ALLOW before the public producer updates facts on the same Flow. */
static void cache_transition(const product_flow_entry_t *entry,unsigned result)
{
  product_l4_policy_rule_t rules[3];
  for(unsigned i=0;i<3;++i) rules[i]=(product_l4_policy_rule_t){
    .rule_id=11+i,.reason_id=101+i,.priority=1+i,.order=2+i,.uid=17,
    .action=i==2?1:2,.mode=i==0?1:0,.network_context_id=UINT32_MAX,
    .ifindex=UINT32_MAX,.source_port_last=65535,.destination_port_last=65535};
  rules[0].expression_length=2;rules[0].expression[0]=16;rules[0].expression[1]=1;
  rules[1].expression_length=3;memcpy(rules[1].expression,(uint8_t[]){16,1,3},3);
  for(unsigned plan=0;plan<3;++plan) {
    product_l4_policy_compile_budget_t budget=product_l4_policy_default_budget();
    if(plan) budget.direct_entries=0;
    if(plan==2) budget.factor_rules=0;
    product_l4_policy_view_t view;
    assert(!product_l4_policy_compile_with_budget(&view,rules,3,&budget));
    product_policy_cache_t cache={0};
    product_policy_cache_identity_t identity={7,1,33,entry->incarnation};
    product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=17};
    product_l4_policy_match_result_t actual;
    for(unsigned i=0;i<2;++i) {
      assert(!product_l4_policy_match_cached(&cache,&view,&packet,&identity,0,&actual));
      assert(actual.rule_id==13 && actual.reason_id==103 && actual.actual_action==1);
    }
    assert(cache.hits==1 && cache.misses==1);
    packet.sni_result=entry->sni.result;packet.protocol_set=entry->lpi.protocols;
    packet.protocol_set_known=entry->lpi.available;
    unsigned winner=result==PRODUCT_SNI_ABSENT?0:result==PRODUCT_SNI_NAME?1:2;
    for(unsigned i=0;i<2;++i) {
      assert(!product_l4_policy_match_cached(&cache,&view,&packet,&identity,0,&actual));
      assert(actual.rule_id==11+winner && actual.reason_id==101+winner);
      assert(actual.priority==1+winner && actual.order==2+winner);
      assert(actual.winner_rank==1+winner && actual.mode==rules[winner].mode);
      assert(actual.action==rules[winner].action);
      assert(actual.actual_action==(winner==1?2:1));
    }
    if(result) assert(cache.misses==2 && cache.hits==2);
  }
}
static void unfinished_budget(void)
{
  product_flow_runtime_t *pool=NULL;
  assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .source_port=42000,.destination_port=443,.l4_header_length=8,
    .transport_length=9,.packet_length=29};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=100};
  product_flow_entry_observation_t o;
  for(unsigned i=0;i<20;++i) {
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,
                                       (const uint8_t *)"x",1));
    ++input.timestamp;
  }
  assert(o.entry->sni.stop==PRODUCT_SNI_PACKET_BUDGET && !o.entry->sni.result);
  assert(o.entry->sni.attempts==20 && o.entry->sni.bytes==0);
  assert(!product_flow_runtime_flush(pool));
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,
                                     (const uint8_t *)"x",1));
  assert(!product_flow_runtime_set_deadline(pool,o.slot,7,o.entry->incarnation,
    60000000,PRODUCT_CT_TIMEOUT_OTHER_FIRST));
  uint32_t closed=99;
  assert(!product_flow_runtime_run_due(pool,input.timestamp+PRODUCT_SNI_TIMEOUT_US,1,&closed));
  assert(!closed && o.entry->linked && o.entry->sni.stop==PRODUCT_SNI_TIMEOUT);
  assert(!o.entry->sni.result && o.entry->deadline_us==60000000);
  product_flow_runtime_destroy(pool);
}
static void benchmark(void)
{
  product_flow_runtime_t *pool=NULL;
  assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .source_port=42000,.destination_port=443,.l4_header_length=8,
    .transport_length=1208,.packet_length=1228};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  const unsigned iterations=10000;
  struct timespec start,end;
  assert(!clock_gettime(CLOCK_MONOTONIC,&start));
  for(unsigned i=0;i<iterations;++i) {
    product_flow_entry_observation_t o;
    assert(!product_flow_runtime_flush(pool));
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,rfc_initial,sizeof rfc_initial));
    assert(o.entry->sni.result==PRODUCT_SNI_NAME && !strcmp(o.entry->sni.name,"example.com"));
    ++input.timestamp;
  }
  assert(!clock_gettime(CLOCK_MONOTONIC,&end));
  uint64_t elapsed=(uint64_t)(end.tv_sec-start.tv_sec)*UINT64_C(1000000000)+end.tv_nsec-start.tv_nsec;
  printf("{\"iterations\":%u,\"elapsed_ns\":%llu,\"ns_per_flow_cycle\":%.3f,\"flow_entry_bytes\":%zu,\"sni_state_bytes\":%zu,\"tcp_cache_bytes\":%zu}\n",
    iterations,(unsigned long long)elapsed,(double)elapsed/iterations,
    sizeof(product_flow_entry_t),sizeof(product_sni_state_t),sizeof(product_tcp_byte_cache_t));
  product_flow_runtime_destroy(pool);
}

/* A sequence file carries independent per-packet expectations. The producer
 * sees borrowed scratch reused immediately after each call, like real buffers. */
static void sequence(const char *path)
{
  FILE *file=fopen(path,"rb");assert(file);
  product_flow_runtime_t *pool=NULL;
  assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .source_port=42000,.destination_port=443,.l4_header_length=8};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  unsigned size,result,stop,retained,side,advance,step=0;
  uint8_t packet[5000];
  while(fscanf(file,"%u %u %u %u %u %u\n",&size,&result,&stop,&retained,&side,&advance)==6) {
    assert(size<=sizeof packet && fread(packet,1,size,file)==size);
    input.timestamp+=advance;
    if(!size) {
      uint32_t closed=99;
      assert(!product_flow_runtime_run_due(pool,input.timestamp,1,&closed));
      assert(!closed && o.entry->linked);
    } else {
    f.source_address[0]=side?11:10;f.destination_address[0]=side?10:11;
    f.source_port=side?443:42000;f.destination_port=side?42000:443;
    assert(!product_owner_assign(&layout,&f,&owner));
    f.transport_length=(uint16_t)(size+8);f.packet_length=size+28;
    assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
    assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,packet,size));
    }
    if(!step) assert(!product_flow_runtime_set_deadline(pool,o.slot,7,o.entry->incarnation,
      60000000,PRODUCT_CT_TIMEOUT_OTHER_FIRST));
    memset(packet,0xa5,sizeof packet);
    if(o.entry->sni.result!=result || o.entry->sni.stop!=stop)
      fprintf(stderr,"%s step %u: got %u/%u wanted %u/%u\n",path,step,
        o.entry->sni.result,o.entry->sni.stop,result,stop);
    assert(o.entry->sni.result==result && o.entry->sni.stop==stop);
    assert(product_flow_sni_retained_bytes(o.entry)==retained);
    assert(!strcmp(o.entry->sni.name,result==1?"example.test":""));
    cache_transition(o.entry,result);
    /* Policy revisions retain both partial ranges and already published facts. */
    ++input.policy.revision;
    ++step;++input.timestamp;
  }
  assert(step && feof(file));fclose(file);
  product_flow_runtime_destroy(pool);
}

typedef struct { unsigned calls; } ended_t;
static void ended(void *context,const product_flow_entry_t *entry,uint32_t slot,
                  product_flow_end_reason_t reason)
{
  (void)slot;assert(reason==PRODUCT_FLOW_END_CLOSED);
  assert(!entry->linked && entry->sni.stop);
  assert(!product_flow_sni_retained_bytes(entry));
  const uint8_t *bytes=(const uint8_t *)&entry->quic_crypto;
  for(unsigned i=0;i<sizeof entry->quic_crypto;++i) assert(!bytes[i]);
  ++((ended_t *)context)->calls;
}
static uint64_t now_ns(void)
{
  struct timespec value;assert(!clock_gettime(CLOCK_MONOTONIC,&value));
  return (uint64_t)value.tv_sec*UINT64_C(1000000000)+value.tv_nsec;
}
static void load(const char *path,unsigned capacity,unsigned cycles)
{
  assert(capacity && capacity<=1024 && cycles);
  FILE *file=fopen(path,"rb");assert(file);
  struct load_step { unsigned size,result,stop,retained,side,advance;uint8_t packet[4096]; } steps[32];
  unsigned count=0;
  while(count<32) {
    struct load_step *v=&steps[count];
    if(fscanf(file,"%u %u %u %u %u %u\n",&v->size,&v->result,&v->stop,
      &v->retained,&v->side,&v->advance)!=6) break;
    assert(v->size && v->size<=4096 && !v->side && !v->advance);
    assert(fread(v->packet,1,v->size,file)==v->size);++count;
  }
  assert(count && feof(file));fclose(file);
  product_flow_runtime_t *pool=NULL;
  assert(!product_flow_runtime_create(&pool,0,1,7,capacity));
  ended_t ends={0};assert(!product_flow_runtime_set_end_callback(pool,ended,&ends));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .destination_port=443,.l4_header_length=8};
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  unsigned slots[1024];uint64_t incarnations[1024];
  uint64_t peak_retained=0,peak_work=0,max_packet_ns=0,packet_ns=0;unsigned peak_ranges=0;
  uint64_t start=now_ns();
  for(unsigned round=0;round<cycles;++round) {
    for(unsigned part=0;part<count;++part) {
      struct load_step *v=&steps[part];uint64_t total=0;
      f.transport_length=(uint16_t)(v->size+8);f.packet_length=v->size+28;
      for(unsigned i=0;i<capacity;++i) {
        f.source_port=(uint16_t)(10000+i);assert(!product_owner_assign(&layout,&f,&owner));
        product_flow_entry_observation_t o;uint64_t before=now_ns();
        assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
        if(!part) assert(o.created && !o.entry->sni.attempts && !product_flow_sni_retained_bytes(o.entry));
        else assert(!o.created && o.entry->incarnation==incarnations[i]);
        assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,v->packet,v->size));
        uint64_t elapsed=now_ns()-before;packet_ns+=elapsed;
        if(elapsed>max_packet_ns) max_packet_ns=elapsed;
        assert(o.entry->sni.result==v->result && o.entry->sni.stop==v->stop);
        assert(product_flow_sni_retained_bytes(o.entry)==v->retained);
        total+=v->retained;slots[i]=o.slot;incarnations[i]=o.entry->incarnation;
        if(o.entry->sni.work>peak_work) peak_work=o.entry->sni.work;
        if(o.entry->quic_crypto.range_count>peak_ranges) peak_ranges=o.entry->quic_crypto.range_count;
      }
      if(total>peak_retained) peak_retained=total;
      assert(product_flow_runtime_snapshot(pool).active_entries==capacity);++input.timestamp;
    }
    f.source_port=20000;assert(!product_owner_assign(&layout,&f,&owner));
    product_flow_entry_observation_t extra;
    assert(product_flow_entry_observe(pool,&owner,&input,0,&extra)==PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED);
    for(unsigned i=0;i<capacity;++i) {
      assert(!product_flow_runtime_close(pool,slots[i],7,incarnations[i],PRODUCT_FLOW_END_CLOSED));
      assert(product_flow_entry_identify(pool,slots[i],7,incarnations[i],&f,steps[0].packet,steps[0].size)
        ==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
      assert(!product_flow_runtime_release_end(pool,slots[i],7,incarnations[i],PRODUCT_FLOW_END_CLOSED));
    }
    assert(!product_flow_runtime_snapshot(pool).active_entries);++input.timestamp;
  }
  assert(ends.calls==capacity*cycles);
  product_flow_runtime_snapshot_t snapshot=product_flow_runtime_snapshot(pool);
  uint64_t elapsed=now_ns()-start;
  printf("{\"capacity\":%u,\"cycles\":%u,\"steps\":%u,\"elapsed_ns\":%llu,\"ns_per_flow_cycle\":%.3f,\"mean_packet_ns\":%.3f,\"max_packet_ns\":%llu,\"entry_bytes\":%zu,\"quic_bytes\":%zu,\"owner_bytes\":%llu,\"peak_retained\":%llu,\"peak_ranges\":%u,\"peak_work\":%llu,\"releases\":%llu}\n",
    capacity,cycles,count,(unsigned long long)elapsed,(double)elapsed/(capacity*cycles),
    (double)packet_ns/(capacity*cycles*count),(unsigned long long)max_packet_ns,
    sizeof(product_flow_entry_t),sizeof(product_quic_crypto_t),(unsigned long long)snapshot.allocated_bytes,
    (unsigned long long)peak_retained,peak_ranges,(unsigned long long)peak_work,
    (unsigned long long)snapshot.release_count);
  product_flow_runtime_destroy(pool);
}

int main(int argc,char **argv)
{
  if(argc==5 && !strcmp(argv[1],"--load")) {
    assert(!product_lpi_init());load(argv[2],(unsigned)atoi(argv[3]),(unsigned)atoi(argv[4]));return 0;
  }
  if(argc==3 && !strcmp(argv[1],"--sequence")) {
    assert(!product_lpi_init());sequence(argv[2]);return 0;
  }
  if(argc==2 && !strcmp(argv[1],"--benchmark")) {
    assert(!product_lpi_init());benchmark();return 0;
  }
  const uint8_t *wire=rfc_initial;unsigned size=sizeof rfc_initial;
  unsigned expected_result=PRODUCT_SNI_NAME,expected_stop=PRODUCT_SNI_COMPLETE;
  const char *name="example.com";uint8_t buffer[5000];
  if(argc==5) {
    FILE *file=fopen(argv[1],"rb");assert(file);
    size=(unsigned)fread(buffer,1,sizeof buffer,file);assert(!ferror(file));
    assert(feof(file));fclose(file);wire=buffer;
    expected_result=(unsigned)atoi(argv[2]);expected_stop=(unsigned)atoi(argv[3]);name=argv[4];
  } else assert(argc==1);
  assert(!product_lpi_init());
  if(argc==1) unfinished_budget();
  product_flow_runtime_t *pool=NULL;
  assert(!product_flow_runtime_create(&pool,0,1,7,1));
  product_packet_facts_t f={.l3_status=1,.l4_status=1,.ip_family=4,.protocol=17,
    .source_port=42000,.destination_port=443,.l4_header_length=8,
    .transport_length=1208,.packet_length=1228};
  f.transport_length=(uint16_t)(size+8);f.packet_length=size+28;
  f.source_address[0]=10;f.destination_address[0]=11;
  product_worker_layout_t layout={1,1};product_owner_assignment_t owner;
  assert(!product_owner_assign(&layout,&f,&owner));
  product_flow_entry_packet_t input={.facts=&f,.policy={7,1,1},.uid=17,.timestamp=1};
  product_flow_entry_observation_t o;
  /* A preceding opaque UDP payload is not confirmed absence or a permanent
   * non-TCP rejection. The later Initial can publish in the same incarnation. */
  f.transport_length=9;f.packet_length=29;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,
                                     (const uint8_t *)"x",1));
  assert(!o.entry->sni.result && !o.entry->sni.stop);
  uint64_t incarnation=o.entry->incarnation;
  f.transport_length=(uint16_t)(size+8);f.packet_length=size+28;input.timestamp=2;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(o.entry->incarnation==incarnation);
  assert(!product_flow_entry_identify(pool,o.slot,7,o.entry->incarnation,&f,
                                     wire,size));
  if(o.entry->sni.result!=expected_result || o.entry->sni.stop!=expected_stop)
    fprintf(stderr,"%s: result %u stop %u, wanted %u/%u\n",argc>1?argv[1]:"RFC",o.entry->sni.result,o.entry->sni.stop,expected_result,expected_stop);
  assert(o.entry->sni.result==expected_result);
  assert(o.entry->sni.stop==expected_stop);
  assert(!strcmp(o.entry->sni.name,name));
  if(expected_result) assert(o.entry->lpi.protocols & product_protocol_bit(1004));
  assert(!(o.entry->lpi.protocols & product_protocol_bit(1003)));
  if(expected_stop) assert(!product_flow_sni_retained_bytes(o.entry));
  cache_transition(o.entry,expected_result);
  /* Published parser state is stable across a policy revision and fenced
   * against stale identities; a reused slot starts an independent attempt. */
  product_sni_state_t saved=o.entry->sni;
  assert(product_flow_entry_identify(pool,o.slot,8,incarnation,&f,wire,size)
         ==PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert(product_flow_entry_identify(pool,o.slot,7,incarnation+1,&f,wire,size)
         ==PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  input.policy.revision=2;input.timestamp=3;
  assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(!product_flow_entry_identify(pool,o.slot,7,incarnation,&f,wire,size));
  if(saved.stop) assert(!memcmp(&saved,&o.entry->sni,sizeof saved));
  assert(!product_flow_runtime_flush(pool));
  input.timestamp=4;assert(!product_flow_entry_observe(pool,&owner,&input,0,&o));
  assert(o.entry->incarnation!=incarnation && !o.entry->sni.result && !o.entry->sni.stop);
  product_flow_runtime_destroy(pool);
  if(argc==1) puts("RFC9001 QUIC v1 Initial through the public Flow producer: PASS");
}
