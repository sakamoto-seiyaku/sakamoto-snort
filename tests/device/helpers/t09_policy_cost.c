/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only cost driver of the actual compiler/matcher integration seam. */
#define _POSIX_C_SOURCE 200809L
#include "product_l4_policy.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
  return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t combine(uint64_t value, uint64_t item)
{
  return (value ^ item) * UINT64_C(1099511628211);
}
static uint64_t signature(uint64_t sum, const product_l4_policy_match_result_t *r)
{
  const uint64_t values[] = {r->evaluation,r->stage_verdict,r->action,r->no_match_reason,
    r->mode,r->actual_action,r->rule_id,r->reason_id,r->priority,r->order,r->winner_rank};
  for (unsigned i=0;i<sizeof values/sizeof values[0];++i) sum=combine(sum,values[i]);
  return sum;
}
static void workload(product_l4_policy_rule_t *rules, unsigned count, unsigned kind)
{
  for (unsigned i=0;i<count;++i) {
    product_l4_policy_rule_t *r=&rules[i];
    memset(r,0,sizeof *r);
    r->uid=17;r->rule_id=1000+i;r->reason_id=2000+i;
    r->priority=i%5;r->order=count-i;r->action=1+i%2;r->mode=i%3==0;
    r->family=4;r->protocol=6;r->network_context_id=UINT32_MAX;r->ifindex=UINT32_MAX;
    r->source_port_last=r->destination_port_last=UINT16_MAX;
    if (kind==0) r->destination_port_first=r->destination_port_last=(uint16_t)(1000+i);
    if (kind==1) {
      r->destination_port_first=1000;r->destination_port_last=1999;
      r->expression_length=5;r->expression[0]=PRODUCT_STATIC_NETWORK;
      r->expression[1]=(uint8_t)i;
    }
    if (kind==3) {
      r->source_port_last=(uint16_t)((1U<<(i%16))-1);
      r->destination_port_last=(uint16_t)((1U<<(i/16))-1);
    }
  }
}
int main(void)
{
  const char *names[]={"exact-distributed","residual-last","first-hit","many-mask-miss"};
  const unsigned sizes[]={1,8,32,64,128};
  product_l4_policy_rule_t rules[128];
  product_l4_policy_view_t *view=malloc(sizeof *view);
  if (!view) return 2;
  for (unsigned k=0;k<4;++k) for (unsigned n=0;n<5;++n) {
    unsigned count=sizes[n];workload(rules,count,k);
    uint64_t start=now_ns();
    for (unsigned repeat=0;repeat<100;++repeat)
      if (product_l4_policy_compile(view,rules,count)) return 3;
    uint64_t compile_ns=now_ns()-start;
    product_l4_policy_packet_t p={0};
    p.uid=17;p.uid_known=1;p.family=4;p.protocol=6;p.direction=3;p.direction_known=1;
    p.ports_available=1;p.source_port=65535;p.network_context_known=1;p.network_context_id=count-1;
    p.source_address[0]=192;p.source_address[1]=0;p.source_address[2]=2;p.source_address[3]=1;
    product_l4_policy_match_result_t result;
    uint64_t sum=UINT64_C(1469598103934665603),probes=0,keys=0,tables=0;
    start=now_ns();
    for (unsigned repeat=0;repeat<20000;++repeat) {
      p.destination_port=k==0?(uint16_t)(1000+repeat%(count+1)):k==3?65535:1500;
      if (product_l4_policy_match(view,&p,&result)) return 4;
      sum=signature(sum,&result);probes+=result.probes;
#ifdef PRODUCT_L4_INDEX_KEY_BYTES
      keys+=result.key_probes;tables+=result.subtable_probes;
#endif
    }
    uint64_t query_ns=now_ns()-start;
    unsigned masks=0;
#ifdef PRODUCT_L4_INDEX_KEY_BYTES
    product_l4_policy_index_resources_t resources;
    product_l4_policy_index_resources(view,&resources);masks=resources.subtables;
#endif
    printf("{\"workload\":\"%s\",\"rules\":%u,\"compile_iterations\":100,\"compile_ns\":%"PRIu64
      ",\"query_iterations\":20000,\"query_ns\":%"PRIu64",\"signature\":%"PRIu64
      ",\"residual_probes\":%"PRIu64",\"key_probes\":%"PRIu64",\"table_probes\":%"PRIu64
      ",\"masks\":%u,\"view_bytes\":%zu}\n",names[k],count,compile_ns,query_ns,sum,probes,keys,tables,masks,sizeof *view);
  }
  free(view);return 0;
}
