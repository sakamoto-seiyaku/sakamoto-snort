/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t clock_ns(void) {
  struct timespec t; assert(clock_gettime(CLOCK_MONOTONIC,&t)==0);
  return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static uint64_t signature(uint64_t h,const product_l4_policy_match_result_t *r) {
  const uint64_t f[]={r->evaluation,r->stage_verdict,r->action,r->no_match_reason,
    r->mode,r->actual_action,r->rule_id,r->reason_id,r->priority,r->order,r->winner_rank};
  for(unsigned i=0;i<sizeof f/sizeof f[0];++i) h=(h^f[i])*UINT64_C(1099511628211);
  return h;
}
static product_l4_policy_packet_t packet(unsigned n,unsigned flows,unsigned period) {
  unsigned flow=n%flows, cycle=n/flows;
  product_l4_policy_packet_t p={.uid=17,.uid_known=1,.family=4,.protocol=17,
    .direction=3,.direction_known=1,.network_context_id=1,.network_context_known=1,
    .ports_available=1,.source_port=(uint16_t)(41000+flow),.destination_port=443,
    .ct_state=(uint8_t)(period ? 1+(cycle/period)%2 : 2),.ct_state_known=1,
    .flow_direction=1,.flow_direction_known=1};
  p.source_address[0]=10;p.source_address[3]=1;
  p.destination_address[0]=10;p.destination_address[3]=2;
  return p;
}
int main(int argc,char **argv) {
  assert(argc==7);
  unsigned shape=(unsigned)strtoul(argv[1],NULL,10),count=(unsigned)strtoul(argv[2],NULL,10);
  unsigned flows=(unsigned)strtoul(argv[3],NULL,10),capacity=(unsigned)strtoul(argv[4],NULL,10);
  unsigned period=(unsigned)strtoul(argv[5],NULL,10);
  unsigned first_arm=(unsigned)strtoul(argv[6],NULL,10);assert(first_arm<2);
  assert(shape<3 && count && count<=128 && flows && flows<=256 && capacity && capacity<=128);
  product_l4_policy_view_t *view=calloc(1,sizeof(*view));
  product_l4_policy_rule_t *rules=calloc(count,sizeof(*rules));
  product_policy_cache_t *cache=calloc(1,sizeof(*cache));assert(view && rules && cache);
  cache->capacity=capacity;
  for(unsigned i=0;i<count;++i) {
    rules[i]=(product_l4_policy_rule_t){.uid=17,.rule_id=100+i,.reason_id=100+i,
      .priority=i,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.family=4,
      .protocol=17,.source_port_last=65535,.destination_port_last=65535,
      .action=i%2?1:2,.mode=i%3==0};
    if(shape==0) rules[i].destination_port_first=rules[i].destination_port_last=(uint16_t)(443+i);
    if(shape==1) {
      const uint8_t expression[]={PRODUCT_EXPRESSION_CT_STATE,2,PRODUCT_STATIC_NETWORK,
        (uint8_t)(count-i),0,0,0,PRODUCT_STATIC_AND};
      memcpy(rules[i].expression,expression,sizeof expression);rules[i].expression_length=sizeof expression;
    }
    if(shape==2) {
      rules[i].source_port_first=1;rules[i].source_port_last=6;
      rules[i].destination_port_first=1;rules[i].destination_port_last=30;
    }
  }
  assert(product_l4_policy_compile(view,rules,count)==0);
  const unsigned queries=40000;
  uint64_t hashes[2]={UINT64_C(14695981039346656037),UINT64_C(14695981039346656037)};
  uint64_t elapsed[2];
  for(unsigned step=0;step<2;++step) {
    unsigned arm=(step+first_arm)%2;
    uint64_t began=clock_ns();
    for(unsigned n=0;n<queries;++n) {
      product_l4_policy_packet_t p=packet(n,flows,period);
      product_policy_cache_identity_t id={1,1,123,n%flows+1};
      product_l4_policy_match_result_t r;
      assert(product_l4_policy_match_cached(arm?cache:NULL,view,&p,&id,0,&r)==0);
      hashes[arm]=signature(hashes[arm],&r);
    }
    elapsed[arm]=clock_ns()-began;
  }
  assert(hashes[0]==hashes[1]);
  unsigned long hwm=0;FILE *memory=fopen("/proc/self/status","r");assert(memory);
  char line[256];while(fgets(line,sizeof line,memory)) {
    unsigned long value;if(sscanf(line,"VmHWM: %lu kB",&value)==1)hwm=value;
  }
  assert(fclose(memory)==0 && hwm);
  printf("{\"shape\":%u,\"rules\":%u,\"flows\":%u,\"capacity\":%u,\"fact_period\":%u,"
    "\"first_arm\":%u,\"queries\":%u,\"direct_ns\":%"PRIu64",\"cached_ns\":%"PRIu64","
    "\"hits\":%"PRIu64",\"misses\":%"PRIu64",\"replacements\":%"PRIu64","
    "\"occupied\":%u,\"cache_bytes\":%zu,\"entry_bytes\":%zu,\"guard_bytes\":%zu,"
    "\"management_peak_bytes\":%u,\"process_hwm_kib\":%lu,\"signature\":\"%016"PRIx64"\"}\n",
    shape,count,flows,capacity,period,first_arm,queries,elapsed[0],elapsed[1],cache->hits,cache->misses,
    cache->replacements,cache->occupied,sizeof(*cache),sizeof(cache->entries[0]),
    sizeof(product_policy_cache_guard_t),product_rule_config_compile_peak_bytes(),hwm,hashes[0]);
  free(cache);free(rules);free(view);
}
