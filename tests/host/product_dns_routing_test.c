/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_proxy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t question[] = {
  0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1,
};
static product_dns_proxy_snapshot_t snapshot;
static product_dns_proxy_key_t key;
static product_dns_proxy_event_t final;
static uint8_t sent[512], received[512];
static unsigned sends, replies;
static uint64_t deadline;
static size_t sent_length;
static unsigned sent_transport;
static product_dns_proxy_input_t input;
static product_dns_proxy_key_t attempts[256];
static product_dns_proxy_event_t observations[256];
static unsigned observation_count;

static int send_query(void *opaque,const product_dns_proxy_key_t *selected,unsigned transport,
  const uint8_t *wire,size_t length,uint64_t limit)
{
  assert(!opaque && (transport==1 || transport==2) && length>=12 && length<=sizeof(sent));
  assert(sends<256);attempts[sends]=*selected;
  ++sends; key=*selected; deadline=limit; sent_length=length;sent_transport=transport;
  memcpy(sent,wire,length); return 1;
}
static int reply(void *opaque,const product_dns_proxy_event_t *event,const uint8_t *wire,size_t length)
{
  assert(!opaque && length<=sizeof(received));
  ++replies;final=*event;memcpy(received,wire,length);return 1;
}
static int acquire(void *opaque,const product_dns_proxy_input_t *input,product_dns_proxy_snapshot_t *out)
{
  assert(!opaque && input);*out=snapshot;
  out->context.packet=input->context.packet;out->context.caller=input->context.caller;
  memcpy(out->context.packet.source_address,input->context.packet.destination_address,16);
  memcpy(out->context.packet.destination_address,input->context.packet.source_address,16);
  out->context.packet.source_port=input->context.packet.destination_port;
  out->context.packet.destination_port=input->context.packet.source_port;out->context.packet.direction=1;
  return 1;
}
static void observe(void *opaque,const product_dns_proxy_event_t *event)
{
  assert(!opaque && observation_count<256);observations[observation_count++]=*event;
}

static void primary_timeout_selects_backup(void)
{
  static product_l4_policy_view_t policy;
  assert(!product_l4_policy_compile(&policy,NULL,0));
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=15353,.address={192,0,2,53},
    .endpoint_count=2,.route_count=1,
    .endpoints={{.transport=1,.family=4,.port=15353,.address={192,0,2,53},.identity="primary.test"},
      {.transport=1,.family=4,.port=15354,.address={192,0,2,54},.identity="backup.test"}},
    .routes={{.count=2,.candidates={0,1}}}};
  product_dns_proxy_input_t input={.token=1,.route_revision=7,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.ports_available=1,.direction=3,.direction_known=1,
      .source_port=40001,.destination_port=53,.destination_address={1,1,1,1}}},
    .identity={.generation=321,.network_revision=5,.now_us=100,.profile=1}};
  snapshot=(product_dns_proxy_snapshot_t){.context=input.context,.view=&policy,
    .identity={321,1,1,0},.network_revision=5,.route_revision=7};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire};
  product_dns_proxy_t *proxy=product_dns_proxy_open(321,&route,&callbacks,NULL);
  assert(proxy && product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
  assert(sends==1 && replies==0 && deadline==3000100);
  product_dns_proxy_advance(proxy,3000100,5,7);
  assert(sends==2 && replies==0); /* One original deadline spans both candidates. */
  uint8_t answer[sizeof(question)+16];
  memcpy(answer,sent,sizeof(question));answer[2]=0x81;answer[3]=0x80;answer[7]=1;
  memcpy(answer+sizeof(question),(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,44},16);
  product_dns_proxy_answer(proxy,&key,1,answer,sizeof(answer),3000101);
  assert(replies==1 && (received[3]&15)==0 && final.route.port==15354);
  assert(!product_dns_proxy_resources(proxy).active && !product_dns_proxy_resources(proxy).exchanges);
  product_dns_proxy_close(proxy);
}

static product_dns_proxy_t *configured_proxy(unsigned candidates)
{
  static product_l4_policy_view_t policy;
  assert(!product_l4_policy_compile(&policy,NULL,0));
  sends=replies=observation_count=0;memset(&final,0,sizeof(final));
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=15353,.address={192,0,2,53},
    .endpoint_count=candidates,.route_count=1,.routes={{.count=candidates}}};
  for(unsigned i=0;i<candidates;++i) {
    route.endpoints[i]=(sakamoto_product_dns_endpoint_t){.transport=1,.family=4,.port=15353+i,
      .address={192,0,2,53}};
    snprintf((char *)route.endpoints[i].identity,256,"resolver-%u.test",i);
    route.routes[0].candidates[i]=i;
  }
  input=(product_dns_proxy_input_t){.token=1,.route_revision=7,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.ports_available=1,.direction=3,.direction_known=1,
      .source_port=40001,.destination_port=53,.destination_address={1,1,1,1}}},
    .identity={.generation=321,.network_revision=5,.now_us=100,.profile=1}};
  snapshot=(product_dns_proxy_snapshot_t){.context=input.context,.view=&policy,
    .identity={321,1,1,0},.network_revision=5,.route_revision=7};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire,.observe=observe};
  product_dns_proxy_t *proxy=product_dns_proxy_open(321,&route,&callbacks,NULL);
  assert(proxy);return proxy;
}

static void submit(product_dns_proxy_t *proxy,const uint8_t *query,uint64_t now)
{
  input.identity.now_us=now;++input.token;
  snapshot.context.packet=input.context.packet;snapshot.context.caller=input.context.caller;
  assert(product_dns_proxy_submit(proxy,&input,query,sizeof(question),&snapshot));
}
static void answer(product_dns_proxy_t *proxy,uint64_t now,unsigned rcode,unsigned positive,unsigned ttl)
{
  uint8_t wire[sizeof(sent)+16];memcpy(wire,sent,sent_length);
  wire[2]=0x81;wire[3]=0x80|rcode;wire[7]=positive;
  memcpy(wire+sent_length,(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,44},16);
  wire[sent_length+6]=ttl>>24;wire[sent_length+7]=ttl>>16;
  wire[sent_length+8]=ttl>>8;wire[sent_length+9]=ttl;
  product_dns_proxy_answer(proxy,&key,sent_transport,wire,sent_length+16U*positive,now);
}

static void valid_results_never_search_for_a_positive_answer(void)
{
  const unsigned rcodes[]={0,3,5,2};
  for(unsigned i=0;i<4;++i) {
    product_dns_proxy_t *proxy=configured_proxy(2);
    submit(proxy,question,100);
    assert(sends==1 && key.resolver_id==1);
    answer(proxy,101,rcodes[i],0,0);
    assert(replies==1 && (received[3]&15)==rcodes[i] && final.route.port==15353);
    product_dns_proxy_advance(proxy,100000000,5,7);
    product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
    assert(sends==1 && !resources.active && !resources.failed_attempts && !resources.failovers);
    assert(!resources.health[0].failures && !resources.health[0].cooldown_until);
    product_dns_proxy_close(proxy);
  }
}

static void candidate_cache_precedes_health_and_never_changes_resolver_view(void)
{
  product_dns_proxy_t *proxy=configured_proxy(2);
  uint8_t other[sizeof(question)];memcpy(other,question,sizeof(other));other[13]='x';
  submit(proxy,question,100);answer(proxy,101,0,1,60);
  assert(sends==1 && replies==1 && final.resolver_id==1 && !final.cached);
  submit(proxy,other,200);assert(key.resolver_id==1 && sends==2);
  product_dns_proxy_fail(proxy,&key,201);
  assert(sends==3 && key.resolver_id==2);answer(proxy,202,0,1,60);
  assert(final.resolver_id==2 && !final.cached);
  submit(proxy,question,203);
  assert(sends==3 && replies==3 && final.cached && final.resolver_id==1 && final.route.port==15353);
  submit(proxy,other,204);
  assert(sends==3 && replies==4 && final.cached && final.resolver_id==2 && final.route.port==15354);
  product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
  assert(resources.cache_entries==2 && resources.health[0].failures==1
    && resources.health[0].cooldown_until==5000201);
  product_dns_proxy_advance(proxy,5000202,5,7);
  assert(sends==3); /* Cooling expiry creates no background probe. */
  submit(proxy,other,5000203);
  assert(sends==4 && key.resolver_id==1 && product_dns_proxy_resources(proxy).health[0].probing);
  answer(proxy,5000204,0,1,60);
  resources=product_dns_proxy_resources(proxy);
  assert(replies==5 && !final.cached && final.resolver_id==1 && !resources.health[0].failures
    && !resources.health[0].cooldown_until && !resources.health[0].probing);
  product_dns_proxy_close(proxy);
}

static void cooldown_is_bounded_and_cancelled_probes_are_not_failures(void)
{
  product_dns_proxy_t *proxy=configured_proxy(2);
  const uint64_t cooldowns[]={5000000,10000000,20000000,30000000,30000000};
  uint64_t now=100;
  for(unsigned i=0;i<5;++i) {
    submit(proxy,question,now);assert(key.resolver_id==1);
    product_dns_proxy_key_t failed=key;
    product_dns_proxy_fail(proxy,&failed,now+1);
    assert(key.resolver_id==2);answer(proxy,now+2,0,1,0);
    product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
    assert(resources.health[0].cooldown_until==now+1+cooldowns[i]);
    unsigned count=sends;
    product_dns_proxy_fail(proxy,&failed,now+3);
    product_dns_proxy_advance(proxy,resources.health[0].cooldown_until,5,7);
    assert(sends==count && !product_dns_proxy_resources(proxy).active);
    now=resources.health[0].cooldown_until+1;
  }
  uint64_t failures=product_dns_proxy_resources(proxy).failed_attempts;
  uint64_t cooling=product_dns_proxy_resources(proxy).health[0].cooldown_until;
  submit(proxy,question,now);assert(key.resolver_id==1 && product_dns_proxy_resources(proxy).health[0].probing);
  product_dns_proxy_cancel(proxy,&key,now+1);
  product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
  assert(!resources.active && !resources.health[0].probing && resources.failed_attempts==failures
    && resources.health[0].cooldown_until==cooling);
  submit(proxy,question,now+2);assert(key.resolver_id==1 && product_dns_proxy_resources(proxy).health[0].probing);
  product_dns_proxy_stop(proxy,now+3);resources=product_dns_proxy_resources(proxy);
  assert(!resources.active && !resources.exchanges && !resources.health[0].probing
    && resources.failed_attempts==failures && resources.health[0].cooldown_until==cooling);
  product_dns_proxy_close(proxy);
}

static void attempts_share_the_original_ten_second_deadline(void)
{
  product_dns_proxy_t *proxy=configured_proxy(8);
  submit(proxy,question,100);assert(sends==1 && deadline==3000100);
  product_dns_proxy_advance(proxy,3000100,5,7);assert(sends==2 && deadline==6000100);
  product_dns_proxy_advance(proxy,6000100,5,7);assert(sends==3 && deadline==9000100);
  product_dns_proxy_advance(proxy,9000100,5,7);assert(sends==4 && deadline==10000100);
  assert(attempts[0].resolver_id==1 && attempts[1].resolver_id==2
    && attempts[2].resolver_id==3 && attempts[3].resolver_id==4);
  assert(attempts[0].attempt!=attempts[1].attempt && attempts[1].attempt!=attempts[2].attempt
    && attempts[2].attempt!=attempts[3].attempt);
  product_dns_proxy_advance(proxy,10000100,5,7);
  product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
  assert(sends==4 && replies==1 && (received[3]&15)==2 && !resources.active && !resources.exchanges);
  assert(resources.failed_attempts==4 && resources.failovers==3);
  product_dns_proxy_close(proxy);
}

static void exception_suffix_requires_a_real_wire_label_boundary(void)
{
  product_dns_proxy_t *proxy=configured_proxy(2);product_dns_proxy_close(proxy);
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=15353,.address={192,0,2,53},
    .endpoint_count=2,.route_count=2,.exception_count=1,
    .endpoints={{.transport=1,.family=4,.port=15353,.address={192,0,2,53},.identity="public.test"},
      {.transport=1,.family=4,.port=15354,.address={192,0,2,54},.identity="local.test"}},
    .routes={{.count=1,.candidates={0}},{.count=1,.candidates={1}}},
    .exceptions={{.match=1,.target=1,.route=1,.length=11,.name="example.com"}}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire};
  proxy=product_dns_proxy_open(321,&route,&callbacks,NULL);assert(proxy);
  const uint8_t ordinary[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
    3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
  assert(product_dns_proxy_submit(proxy,&input,ordinary,sizeof(ordinary),&snapshot));
  assert(key.resolver_id==2);product_dns_proxy_close(proxy);
  proxy=product_dns_proxy_open(321,&route,&callbacks,NULL);assert(proxy);
  const uint8_t literal_dot[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
    11,'w','w','w','.','e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
  assert(product_dns_proxy_submit(proxy,&input,literal_dot,sizeof(literal_dot),&snapshot));
  assert(key.resolver_id==1); /* A dot inside one wire label is not a suffix boundary. */
  product_dns_proxy_close(proxy);
}

static size_t named_question(const char *name,uint8_t wire[512])
{
  memcpy(wire,question,12);size_t at=12;
  while(*name) {
    const char *end=strchr(name,'.');size_t length=end?(size_t)(end-name):strlen(name);
    assert(length && length<=63 && at+length+6<=512);
    wire[at++]=length;memcpy(wire+at,name,length);at+=length;
    if(!end)break;
    name=end+1;
  }
  memcpy(wire+at,(uint8_t[]){0,0,1,0,1},5);return at+5;
}

static void exact_and_longest_suffix_routes_preserve_explicit_local_resolution(void)
{
  product_dns_proxy_t *proxy=configured_proxy(3);product_dns_proxy_close(proxy);
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=15353,.address={192,0,2,53},
    .endpoint_count=3,.route_count=3,.exception_count=4,
    .endpoints={{.transport=1,.family=4,.port=15353,.address={192,0,2,53},.identity="public.test"},
      {.transport=1,.family=4,.port=15354,.address={192,0,2,54},.identity="local.test"},
      {.transport=1,.family=4,.port=15355,.address={192,0,2,55},.identity="narrow.test"}},
    .routes={{.count=1,.candidates={0}},{.count=1,.candidates={1}},{.count=1,.candidates={2}}},
    .exceptions={{.match=1,.target=1,.route=1,.length=11,.name="example.com"},
      {.match=1,.target=1,.route=2,.length=15,.name="sub.example.com"},
      {.match=0,.target=1,.route=0,.length=20,.name="host.sub.example.com"},
      {.match=0,.target=0,.length=20,.name="original.example.com"}}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire};
  proxy=product_dns_proxy_open(321,&route,&callbacks,NULL);assert(proxy);
  const char *names[]={"example.com","a.sub.example.com","host.sub.example.com", "notexample.com",
    "printer.local","EXAMPLE.COM","original.example.com","public.test","host.sub.example.com"};
  const unsigned ids[]={2,3,1,1,1,2,0,0,1};
  const unsigned routes[]={1,2,0,0,0,1,UINT32_MAX,UINT32_MAX,0};
  for(unsigned i=0;i<9;++i) {
    uint8_t wire[512];size_t length=named_question(names[i],wire);
    if(i==7)memcpy(input.context.packet.destination_address,(uint8_t[]){10,0,0,53},4);
    input.identity.now_us=100+i*10;++input.token;snapshot.context=input.context;
    assert(product_dns_proxy_submit(proxy,&input,wire,length,&snapshot));
    assert(key.resolver_id==ids[i] && key.resolution_route==routes[i]);
    if(!ids[i])assert(key.resolver_port==53 && !memcmp(key.resolver_address,input.context.packet.destination_address,16));
    answer(proxy,input.identity.now_us+1,0,1,0);
    assert(final.resolver_id==ids[i] && final.resolution_route==routes[i]);
  }
  product_dns_proxy_close(proxy);
}

static void normal_attempt_observations_preserve_request_and_selected_candidate(void)
{
  product_dns_proxy_t *proxy=configured_proxy(2);
  submit(proxy,question,100);
  assert(observation_count==2 && observations[0].stage==1 && observations[1].stage==5);
  assert(observations[1].result==12 && observations[1].resolver_id==1
    && observations[1].resolution_route==0 && observations[1].upstream_attempt==attempts[0].attempt);
  product_dns_proxy_advance(proxy,3000100,5,7);
  assert(observation_count==4 && observations[2].stage==5 && observations[2].result==14
    && observations[3].stage==5 && observations[3].result==12);
  assert(observations[2].upstream_attempt==attempts[0].attempt && observations[3].resolver_id==2
    && observations[3].upstream_attempt==attempts[1].attempt);
  for(unsigned i=1;i<4;++i) {
    assert(observations[i].input.token==observations[0].input.token);
    assert(observations[i].key.attempt==observations[0].key.attempt);
    assert(!observations[i].policy.generation && !observations[i].delivery && !observations[i].rcode);
  }
  answer(proxy,3000101,0,1,0);
  assert(replies==1 && final.upstream_attempt==attempts[1].attempt && final.resolver_id==2);
  product_dns_proxy_close(proxy);
}

int main(void)
{
  primary_timeout_selects_backup();
  valid_results_never_search_for_a_positive_answer();
  candidate_cache_precedes_health_and_never_changes_resolver_view();
  cooldown_is_bounded_and_cancelled_probes_are_not_failures();
  attempts_share_the_original_ten_second_deadline();
  exception_suffix_requires_a_real_wire_label_boundary();
  exact_and_longest_suffix_routes_preserve_explicit_local_resolution();
  normal_attempt_observations_preserve_request_and_selected_candidate();
  puts("ordered DNS: primary timeout selects configured backup");
  return 0;
}
