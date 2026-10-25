/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_proxy.h"
#include "product_cares.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t question[] = {
  0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1,
};
static unsigned sends, replies;
static uint8_t received[PRODUCT_DNS_MESSAGE_MAX];
static size_t received_length;
static product_dns_proxy_event_t completed;
static product_dns_proxy_key_t sent_key;
static uint8_t sent[PRODUCT_DNS_MESSAGE_MAX];
static size_t sent_length;
static product_dns_proxy_snapshot_t current_snapshot;
static unsigned sent_transport;
static uint64_t sent_deadline;
static unsigned cancellations;
static product_dns_proxy_t *cancel_during_reply;

static int send_query (void *context, const product_dns_proxy_key_t *key,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t deadline)
{
  assert (!context && key && transport && wire && length && deadline);
  assert (length <= sizeof (sent));
  memcpy (sent, wire, length); sent_length = length; sent_key = *key;
  sent_transport=transport; sent_deadline=deadline;
  ++sends; return 1;
}
static int reply (void *context, const product_dns_proxy_event_t *event,
  const uint8_t *wire, size_t length)
{
  assert (!context && event && length <= sizeof (received));
  memcpy (received, wire, length); received_length = length;
  completed = *event; ++replies;
  if (cancel_during_reply)
    {
      product_dns_proxy_t *proxy=cancel_during_reply;cancel_during_reply=NULL;
      product_dns_proxy_cancel(proxy,&event->key,event->input.identity.now_us+1);
    }
  return 1;
}

static void cancel (void *context, const product_dns_proxy_key_t *key)
{
  assert (!context && key && key->attempt); ++cancellations;
}

static int acquire (void *context, const product_dns_proxy_input_t *input,
  product_dns_proxy_snapshot_t *snapshot)
{
  assert (!context);
  *snapshot = current_snapshot;
  snapshot->context.packet = input->context.packet;
  product_l4_policy_packet_t *packet = &snapshot->context.packet;
  memcpy (packet->source_address, input->context.packet.destination_address, 16);
  memcpy (packet->destination_address, input->context.packet.source_address, 16);
  packet->source_port = input->context.packet.destination_port;
  packet->destination_port = input->context.packet.source_port;
  packet->direction = 1;
  snapshot->context.caller = input->context.caller;
  return 1;
}

static void denied_query_replies_refused_without_dispatch (void)
{
  static product_l4_policy_view_t view;
  sakamoto_product_domains_t lists = {.list_count=1,.entry_count=1,
    .entries={{.length=11,.name="example.com"}}};
  product_domains_t *domains = NULL;
  assert (!product_domains_build (&lists, &domains));
  product_l4_policy_rule_t rule = {.uid=10123,.rule_id=315,.reason_id=315,.action=2,
    .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  product_l4_policy_status_t compiled = product_l4_policy_compile (&view, &rule, 1);
  if (compiled) fprintf (stderr, "proxy fixture rule compile status=%u reason=%u\n", compiled, rule.reason_id);
  assert (!compiled);
  product_dns_proxy_input_t input = {
    .context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP,
      .packet={.uid=10123,.uid_known=1,.family=4,.protocol=17,
        .direction=3,.direction_known=1,.ports_available=1,
        .source_port=40000,.destination_port=53,
        .source_address={192,0,2,2},.destination_address={192,0,2,53}}},
    .identity={.generation=77,.network_revision=5,.now_us=100,.profile=1},
    .token=17,.route_revision=3,.slot=UINT32_MAX,
  };
  product_dns_proxy_snapshot_t snapshot = {.context=input.context,.view=&view,
    .identity={77,3,123,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  snapshot.context.domains=domains; snapshot.context.domains_available=1;
  product_dns_proxy_route_t route = {.enabled=1,.family=4,.port=53,
    .address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks = {.send=send_query,.reply=reply,.acquire=acquire};
  product_dns_proxy_t *proxy = product_dns_proxy_open (77, &route, &callbacks, NULL);
  assert (proxy);
  assert (product_dns_proxy_submit (proxy, &input, question, sizeof (question), &snapshot));
  assert (sends == 0 && replies == 1 && received_length >= 12);
  assert (received[0] == 0x12 && received[1] == 0x34);
  assert ((received[2] & 0x80) && (received[3] & 15) == 5);
  assert (completed.result == PRODUCT_DNS_PROXY_REFUSED && completed.match.rule_id == 315);
  assert (completed.input.context.packet.destination_address[3] == 53);
  assert (completed.route.address[0] == 198 && completed.input.context.packet.uid == 10123);
  assert (!product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES));
  ares_dns_record_t *record = NULL;
  assert (!product_cares_parse (received, received_length, &record));
  assert (ares_dns_record_get_id (record) == 0x1234 && ares_dns_record_get_rcode (record) == 5);
  assert (ares_dns_record_rr_cnt (record, ARES_SECTION_ANSWER) == 0);
  ares_dns_record_destroy (record);
  size_t unreleased = 0; (void) product_cares_memory_end (&unreleased); assert (!unreleased);
  /* Socket UID still exists, but it does not prove a delegated request's App.
   * This request must enter the configured upstream with its wire intact. */
  input.token = 18; input.context.caller = PRODUCT_DNS_CALLER_UNKNOWN;
  snapshot.context.caller = PRODUCT_DNS_CALLER_UNKNOWN;
  assert (product_dns_proxy_submit (proxy, &input, question, sizeof (question), &snapshot));
  assert (sends == 1 && replies == 1 && sent_length == sizeof (question));
  assert (!memcmp (sent + 2, question + 2, sizeof (question) - 2));
  assert (sent_key.generation == 77 && sent_key.token == 18 && sent_key.attempt);
  uint8_t answer[sizeof (question) + 16];
  memcpy (answer, sent, sizeof (question)); answer[2]=0x81; answer[3]=0x80; answer[7]=1;
  memcpy (answer + sizeof (question), (uint8_t[]) {
    0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9}, 16);
  current_snapshot = snapshot;
  product_dns_proxy_answer (proxy, &sent_key, PRODUCT_DNS_PROXY_UDP, answer, sizeof (answer), 101);
  assert (replies == 2 && sends == 1 && received_length == sizeof (answer));
  assert (received[0] == 0x12 && received[1] == 0x34 && (received[3] & 15) == 0);
  assert (!memcmp (received + 2, answer + 2, sizeof (answer) - 2));
  assert (completed.result == PRODUCT_DNS_PROXY_UPSTREAM && completed.query.caller == 0);
  /* A completed query permission cannot freeze policy while transport waits. */
  rule.action=1; assert (!product_l4_policy_compile (&view, &rule, 1));
  input.token=19; input.context.caller=PRODUCT_DNS_CALLER_PLATFORM_APP;
  snapshot.context.caller=PRODUCT_DNS_CALLER_PLATFORM_APP; snapshot.identity.revision=4;
  assert (product_dns_proxy_submit (proxy, &input, question, sizeof (question), &snapshot));
  assert (sends == 2 && replies == 2);
  memcpy (answer, sent, sizeof (question)); answer[2]=0x81; answer[3]=0x80; answer[7]=1;
  rule.action=2; rule.rule_id=316; rule.reason_id=316;
  assert (!product_l4_policy_compile (&view, &rule, 1));
  current_snapshot=snapshot; current_snapshot.identity.revision=5;
  product_dns_proxy_answer (proxy, &sent_key, PRODUCT_DNS_PROXY_UDP, answer, sizeof (answer), 201);
  assert (replies == 3 && sends == 2 && (received[3] & 15) == 5);
  assert (completed.result == PRODUCT_DNS_PROXY_REFUSED && completed.match.rule_id == 316);
  assert (completed.query_policy.revision == 4 && completed.policy.revision == 5);
  product_dns_proxy_close (proxy); product_domains_destroy (domains);
}

static void malformed_and_opcode_errors_keep_their_source (void)
{
  static product_l4_policy_view_t view;
  assert (!product_l4_policy_compile (&view, NULL, 0));
  product_dns_proxy_input_t input = {.identity={.generation=78,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40001,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot = {.context=input.context,.view=&view,
    .identity={78,1,456,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  product_dns_proxy_route_t route = {.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks = {.send=send_query,.reply=reply};
  product_dns_proxy_t *proxy = product_dns_proxy_open (78, &route, &callbacks, NULL);
  assert (proxy);
  unsigned before_sends=sends, before_replies=replies;
  uint8_t wire[sizeof (question)]; memcpy (wire, question, sizeof (wire));
  wire[5]=2;
  assert (product_dns_proxy_submit (proxy, &input, wire, sizeof (wire), &snapshot));
  assert (sends==before_sends && replies==++before_replies && (received[3]&15)==1);
  assert (completed.result==PRODUCT_DNS_PROXY_FORMERR);
  wire[5]=1; wire[2]=0x79; ++input.token;
  assert (product_dns_proxy_submit (proxy, &input, wire, sizeof (wire), &snapshot));
  assert (sends==before_sends && replies==++before_replies && (received[3]&15)==4);
  assert ((received[2]&0x78)==0x78 && completed.result==PRODUCT_DNS_PROXY_NOTIMP);
  wire[2]=1; ++input.token;
  assert (product_dns_proxy_submit (proxy, &input, wire, 12, &snapshot));
  assert (sends==before_sends && replies==++before_replies && (received[3]&15)==1);
  assert (received_length==12 && completed.result==PRODUCT_DNS_PROXY_FORMERR);
  ++input.token;
  assert (product_dns_proxy_submit (proxy, &input, wire, 1, &snapshot));
  assert (sends==before_sends && replies==before_replies);
  product_dns_proxy_close (proxy);
}

static void udp_tc_continues_same_request_and_respects_client_capacity (void)
{
  static product_l4_policy_view_t view;
  assert (!product_l4_policy_compile (&view, NULL, 0));
  product_dns_proxy_input_t input = {.identity={.generation=79,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40002,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot = {.context=input.context,.view=&view,
    .identity={79,1,789,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  product_dns_proxy_route_t route = {.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks = {.send=send_query,.reply=reply,.acquire=acquire};
  product_dns_proxy_t *proxy = product_dns_proxy_open (79, &route, &callbacks, NULL);
  assert (proxy);
  unsigned before_sends=sends, before_replies=replies;
  uint8_t wire[sizeof (question)]; memcpy (wire, question, sizeof (wire));
  wire[sizeof (wire)-4]=0xff; wire[sizeof (wire)-3]=0;
  assert (product_dns_proxy_submit (proxy, &input, wire, sizeof (wire), &snapshot));
  assert (sends==before_sends+1 && sent_transport==PRODUCT_DNS_PROXY_UDP);
  product_dns_proxy_key_t first=sent_key; uint64_t original_deadline=sent_deadline;
  uint8_t tc[sizeof (question)]; memcpy (tc, sent, sizeof (tc)); tc[2]=0x83; tc[3]=0x80;
  current_snapshot=snapshot;
  product_dns_proxy_answer (proxy, &first, PRODUCT_DNS_PROXY_UDP, tc, sizeof (tc), 200);
  assert (sends==before_sends+2 && replies==before_replies && sent_transport==PRODUCT_DNS_PROXY_TCP);
  assert (!memcmp (&first,&sent_key,sizeof (first)) && sent_deadline==original_deadline);
  assert (!memcmp (sent+2,wire+2,sizeof (wire)-2));
  uint8_t answer[sizeof (question)+12+600];
  memcpy (answer,sent,sizeof (question)); answer[2]=0x81; answer[3]=0x80; answer[7]=1;
  memcpy (answer+sizeof (question),(uint8_t[]){0xc0,12,0xff,0,0,1,0,0,0,30,2,88},12);
  memset (answer+sizeof (question)+12,0xa5,600);
  product_dns_proxy_answer (proxy, &first, PRODUCT_DNS_PROXY_TCP, answer, sizeof (answer), 300);
  assert (replies==before_replies+1 && received_length<=512 && (received[2]&2));
  assert (received[0]==0x12 && received[1]==0x34 && completed.truncated);
  assert (completed.result==PRODUCT_DNS_PROXY_UPSTREAM && completed.transport==PRODUCT_DNS_PROXY_TCP);
  assert (!product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES));
  ares_dns_record_t *record=NULL;
  assert (!product_cares_parse (received,received_length,&record));
  assert (ares_dns_record_query_cnt (record)==1 && ares_dns_record_rr_cnt (record,ARES_SECTION_ANSWER)==0);
  assert (ares_dns_record_get_flags (record)&ARES_FLAG_TC);
  ares_dns_record_destroy (record);
  size_t unreleased=0; (void) product_cares_memory_end (&unreleased); assert (!unreleased);
  uint8_t edns[sizeof (question)+15];
  memcpy (edns,wire,sizeof (wire)); edns[3]=0x10; edns[11]=1;
  memcpy (edns+sizeof (wire),(uint8_t[]){0,0,41,16,0,0,0,0x80,0,0,4,0xfd,0xe9,0,0},15);
  ++input.token;
  assert (product_dns_proxy_submit (proxy,&input,edns,sizeof (edns),&snapshot));
  assert (sent_length==sizeof (edns) && !memcmp (sent+2,edns+2,sizeof (edns)-2));
  memcpy (answer,sent,sizeof (question)); answer[2]=0x81; answer[3]=0x90; answer[7]=1; answer[11]=0;
  first=sent_key;
  product_dns_proxy_answer (proxy,&first,PRODUCT_DNS_PROXY_UDP,answer,sizeof (answer),400);
  assert (replies==before_replies+2 && received_length==sizeof (answer) && !completed.truncated);
  assert (completed.client_capacity==1232 && !memcmp (received+2,answer+2,sizeof (answer)-2));
  /* A client retries its legal UDP TC reply on TCP. Its TCP capacity is
   * independent of its absent EDNS UDP advertisement, and the complete answer
   * must retain the original ID and every unknown-RR byte. */
  ++input.token; input.context.packet.protocol=6; input.identity.transport_session=317;
  snapshot.context=input.context;
  assert (product_dns_proxy_submit (proxy,&input,wire,sizeof (wire),&snapshot));
  first=sent_key; memcpy(answer,sent,sizeof(question));
  answer[2]=0x81; answer[3]=0x80; answer[7]=1; answer[11]=0;
  current_snapshot=snapshot;
  product_dns_proxy_answer(proxy,&first,PRODUCT_DNS_PROXY_UDP,answer,sizeof(answer),500);
  assert (replies==before_replies+3 && received_length==sizeof(answer));
  assert (!completed.truncated && completed.client_capacity==65535);
  assert (received[0]==0x12 && received[1]==0x34 && !memcmp(received+2,answer+2,sizeof(answer)-2));
  product_dns_proxy_close (proxy);
}

static void request_lifetime_is_bounded_and_late_events_are_inert (void)
{
  static product_l4_policy_view_t view;
  assert (!product_l4_policy_compile (&view,NULL,0));
  product_dns_proxy_input_t input = {.identity={.generation=80,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40003,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot = {.context=input.context,.view=&view,
    .identity={80,1,789,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  product_dns_proxy_route_t route = {.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks = {.send=send_query,.reply=reply,.cancel=cancel,.acquire=acquire};
  product_dns_proxy_t *proxy=product_dns_proxy_open (80,&route,&callbacks,NULL);
  unsigned before_replies=replies, before_cancellations=cancellations;
  assert (proxy && product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  product_dns_proxy_key_t old=sent_key;
  product_dns_proxy_resources_t resources=product_dns_proxy_resources (proxy);
  assert (resources.active==1 && resources.high_water==1 && resources.accepting && resources.owned_bytes);
  product_dns_proxy_key_t wrong=old; ++wrong.generation;
  product_dns_proxy_cancel (proxy,&wrong,101);
  product_dns_proxy_cancel (proxy,&old,102);
  product_dns_proxy_cancel (proxy,&old,103);
  product_dns_proxy_answer (proxy,&old,PRODUCT_DNS_PROXY_UDP,question,sizeof (question),104);
  resources=product_dns_proxy_resources (proxy);
  assert (!resources.active && resources.cancelled==1 && resources.stale==3 && replies==before_replies);
  assert (cancellations==before_cancellations+1);
  ++input.token; input.identity.now_us=200;
  assert (product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  product_dns_proxy_key_t live=sent_key; unsigned first_sends=sends;
  uint64_t deadline=sent_deadline;
  assert (product_dns_proxy_deadline (proxy)==200+PRODUCT_DNS_PROXY_RETRY_US);
  product_dns_proxy_advance (proxy,200+PRODUCT_DNS_PROXY_RETRY_US,0,1);
  assert (sends==first_sends+1 && !memcmp (&live,&sent_key,sizeof (live)) && sent_deadline==deadline);
  product_dns_proxy_advance (proxy,deadline,0,1);
  product_dns_proxy_advance (proxy,deadline+1,0,1);
  assert (replies==before_replies+1 && (received[3]&15)==2 && completed.result==PRODUCT_DNS_PROXY_SERVFAIL);
  assert (!product_dns_proxy_resources (proxy).active && cancellations==before_cancellations+2);
  ++input.token; input.identity.now_us=deadline+2;
  assert (product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  old=sent_key; product_dns_proxy_stop (proxy,deadline+3);
  resources=product_dns_proxy_resources (proxy);
  assert (!resources.active && !resources.accepting && replies==before_replies+1);
  assert (cancellations==before_cancellations+3);
  assert (!product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  product_dns_proxy_answer (proxy,&old,PRODUCT_DNS_PROXY_UDP,question,sizeof (question),deadline+4);
  assert (!product_dns_proxy_resources (proxy).active && replies==before_replies+1);
  product_dns_proxy_close (proxy);
  assert (cancellations==before_cancellations+3);
}

static void capacity_returns_failure_and_never_relabels_policy (void)
{
  static product_l4_policy_view_t view;
  assert (!product_l4_policy_compile (&view,NULL,0));
  product_dns_proxy_input_t input={.identity={.generation=81,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .uid=10123,.uid_known=1,.ports_available=1,.source_port=40004,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot={.context=input.context,.view=&view,.identity={81,1,789,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.cancel=cancel,.acquire=acquire};
  product_dns_proxy_t *proxy=product_dns_proxy_open (81,&route,&callbacks,NULL);
  assert (proxy);
  unsigned before_sends=sends, before_replies=replies;
  for (unsigned i=0;i<PRODUCT_DNS_PROXY_TRANSACTIONS;++i)
    {
      input.token=i+1;
      assert (product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
    }
  assert (sends==before_sends+PRODUCT_DNS_PROXY_TRANSACTIONS && replies==before_replies);
  ++input.token;
  assert (product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  assert (replies==before_replies+1 && sends==before_sends+PRODUCT_DNS_PROXY_TRANSACTIONS);
  assert ((received[3]&15)==2 && completed.result==PRODUCT_DNS_PROXY_CAPACITY && !completed.match.rule_id);
  product_dns_proxy_resources_t resources=product_dns_proxy_resources (proxy);
  assert (resources.active==64 && resources.high_water==64 && resources.capacity==1);
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=315,.reason_id=315,.action=2,
    .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX};
  assert (!product_l4_policy_compile (&view,&deny,1));
  ++input.token;
  assert (product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  assert (replies==before_replies+2 && completed.result==PRODUCT_DNS_PROXY_REFUSED && (received[3]&15)==5);
  assert (sends==before_sends+64 && product_dns_proxy_resources (proxy).capacity==1);
  product_dns_proxy_stop (proxy,200); product_dns_proxy_close (proxy);
  assert (!product_l4_policy_compile (&view,NULL,0));
  proxy=product_dns_proxy_open (81,&route,&callbacks,NULL);
  product_dns_proxy_other_bytes (proxy,PRODUCT_DNS_WORK_BYTES);
  assert (product_dns_proxy_submit (proxy,&input,question,sizeof (question),&snapshot));
  assert (replies==before_replies+3 && completed.result==PRODUCT_DNS_PROXY_CAPACITY && sends==before_sends+64);
  assert (!product_dns_proxy_resources (proxy).active);
  product_dns_proxy_close (proxy);
}

static void completed_response_wins_same_round_cancel (void)
{
  static product_l4_policy_view_t view;assert(!product_l4_policy_compile(&view,NULL,0));
  product_dns_proxy_input_t input={.identity={.generation=82,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40005,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot={.context=input.context,.view=&view,.identity={82,1,789,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.cancel=cancel,.acquire=acquire};
  product_dns_proxy_t *proxy=product_dns_proxy_open(82,&route,&callbacks,NULL);assert(proxy);
  unsigned before_cancellations=cancellations,before_replies=replies;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
  uint8_t answer[sizeof(question)];memcpy(answer,sent,sizeof(answer));answer[2]=0x81;answer[3]=0x80;
  current_snapshot=snapshot;cancel_during_reply=proxy;
  product_dns_proxy_answer(proxy,&sent_key,PRODUCT_DNS_PROXY_UDP,answer,sizeof(answer),101);
  product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
  assert(!resources.active && resources.completed==1 && !resources.cancelled && resources.stale==1);
  assert(cancellations==before_cancellations+1 && replies==before_replies+1);
  product_dns_proxy_close(proxy);
}

static void upstream_ids_are_retired_for_the_whole_request_window (void)
{
  static product_l4_policy_view_t view;assert(!product_l4_policy_compile(&view,NULL,0));
  product_dns_proxy_input_t input={.identity={.generation=83,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40006,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot={.context=input.context,.view=&view,.identity={83,1,789,0},.network_revision=input.identity.network_revision,.route_revision=input.route_revision};
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.cancel=cancel,.acquire=acquire};
  product_dns_proxy_t *proxy=product_dns_proxy_open(83,&route,&callbacks,NULL);assert(proxy);
  uint8_t seen[8192]={0};unsigned before_sends=sends,before_replies=replies;
  for(unsigned i=0;i<65536;++i)
    {
      input.token=i+1;
      assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
      unsigned id=((unsigned)sent[0]<<8)|sent[1];
      assert(!(seen[id/8]&(1U<<(id%8))));seen[id/8]|=1U<<(id%8);
      product_dns_proxy_cancel(proxy,&sent_key,101);
    }
  ++input.token;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
  assert(sends==before_sends+65536 && replies==before_replies+1 && completed.result==PRODUCT_DNS_PROXY_CAPACITY);
  input.identity.now_us+=PRODUCT_DNS_PROXY_ATTEMPT_US+PRODUCT_DNS_REQUEST_US+1;
  ++input.token;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
  assert(sends==before_sends+65537 && product_dns_proxy_resources(proxy).active==1);
  product_dns_proxy_close(proxy);
}

static void valid_query_codec_capacity_returns_servfail (void)
{
  static product_l4_policy_view_t view;
  assert(!product_l4_policy_compile(&view,NULL,0));
  product_dns_proxy_input_t input={.identity={.generation=84,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40007,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot={.context=input.context,.view=&view,
    .identity={84,1,789,0},.route_revision=1};
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply};
  product_dns_proxy_t *proxy=product_dns_proxy_open(84,&route,&callbacks,NULL);assert(proxy);
  /* Structurally valid QUERY +5000 opaque, empty additional RRs is below the
   * wire limit but exceeds the explicitly bounded mature codec workspace. */
  uint8_t wire[sizeof(question)+5000*11];memcpy(wire,question,sizeof(question));
  wire[10]=5000>>8;wire[11]=5000&255;
  for(unsigned i=0;i<5000;++i)
    memcpy(wire+sizeof(question)+i*11,(uint8_t[]){0,0xff,0xfe,0,1,0,0,0,0,0,0},11);
  product_dns_query_t inspected;
  product_dns_inspect_query(wire,sizeof(wire),&input.context,&inspected);
  assert(inspected.coverage==PRODUCT_DNS_CAPACITY);
  unsigned before_sends=sends,before_replies=replies;
  assert(product_dns_proxy_submit(proxy,&input,wire,sizeof(wire),&snapshot));
  assert(sends==before_sends&&replies==before_replies+1);
  assert(received_length>=12&&received[0]==0x12&&received[1]==0x34&&(received[3]&15)==2);
  assert(completed.result==PRODUCT_DNS_PROXY_CAPACITY&&!completed.match.rule_id);
  product_dns_resources_t resources=product_dns_resources();assert(!resources.codec_live_bytes&&!resources.active_operations);
  product_dns_proxy_close(proxy);
}

static void assert_edns_local_reply (unsigned before, unsigned qtype,
  unsigned rcode, int truncated)
{
  assert(replies==before+1 && received_length>=12 && received_length<=1232);
  assert(received[0]==0x12 && received[1]==0x34);
  assert((received[3]&15)==rcode && !!(received[2]&2)==truncated);
  assert((received[2]&1) && (received[3]&0x10));
  if(completed.delivery!=1 || completed.output_bytes!=received_length)
    fprintf(stderr,"EDNS local delivery=%u bytes=%u captured=%zu result=%u\n",
      completed.delivery,completed.output_bytes,received_length,completed.result);
  assert(completed.delivery==1 && completed.output_bytes==received_length);
  assert(!product_cares_memory_begin(PRODUCT_DNS_CODEC_BYTES));
  ares_dns_record_t *record=NULL;
  assert(!product_cares_parse(received,received_length,&record));
  const char *name=NULL; ares_dns_rec_type_t type; ares_dns_class_t qclass;
  assert(ares_dns_record_query_cnt(record)==1);
  assert(!ares_dns_record_query_get(record,0,&name,&type,&qclass));
  assert(!strcmp(name,"example.com") && (unsigned)type==qtype && qclass==ARES_CLASS_IN);
  assert(ares_dns_record_rr_cnt(record,ARES_SECTION_ANSWER)==0);
  assert(ares_dns_record_rr_cnt(record,ARES_SECTION_ADDITIONAL)==1);
  const ares_dns_rr_t *opt=ares_dns_record_rr_get_const(record,ARES_SECTION_ADDITIONAL,0);
  assert(ares_dns_rr_get_type(opt)==ARES_REC_TYPE_OPT);
  assert(ares_dns_rr_get_u16(opt,ARES_RR_OPT_UDP_SIZE)==1232);
  assert(ares_dns_rr_get_u16(opt,ARES_RR_OPT_FLAGS)==0x8000);
  ares_dns_record_destroy(record);
  size_t unreleased=0; (void)product_cares_memory_end(&unreleased); assert(!unreleased);
}

static void observe_completed (void *context, const product_dns_proxy_event_t *event)
{
  assert(!context && event);
  completed=*event;
}

static void edns_local_errors_and_truncation_remain_deliverable (void)
{
  static product_l4_policy_view_t view;
  assert(!product_l4_policy_compile(&view,NULL,0));
  product_dns_proxy_input_t input={.identity={.generation=85,.profile=1,.now_us=100},
    .token=1,.route_revision=1,.slot=UINT32_MAX,
    .context={.packet={.family=4,.protocol=17,.direction=3,.direction_known=1,
      .ports_available=1,.source_port=40008,.destination_port=53}}};
  product_dns_proxy_snapshot_t snapshot={.context=input.context,.view=&view,
    .identity={85,1,789,0},.route_revision=1};
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
  product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire,
    .observe=observe_completed};
  product_dns_proxy_t *proxy=product_dns_proxy_open(85,&route,&callbacks,NULL); assert(proxy);
  uint8_t wire[sizeof(question)+11]; memcpy(wire,question,sizeof(question));
  wire[3]=0x10; wire[11]=1;
  memcpy(wire+sizeof(question),(uint8_t[]){0,0,41,4,208,0,0,0x80,0,0,0},11);
  const unsigned qtypes[]={1,28,16,15,33,65,65000};
  for(unsigned i=0;i<sizeof(qtypes)/sizeof(qtypes[0]);++i)
    {
      unsigned before=replies;
      wire[sizeof(question)-4]=qtypes[i]>>8; wire[sizeof(question)-3]=qtypes[i];
      assert(product_dns_proxy_submit(proxy,&input,wire,sizeof(wire),&snapshot));
      assert(product_dns_proxy_resources(proxy).active==1);
      product_dns_proxy_advance(proxy,input.identity.now_us+PRODUCT_DNS_PROXY_ATTEMPT_US,0,1);
      assert_edns_local_reply(before,qtypes[i],2,0);
      assert(!product_dns_proxy_resources(proxy).active);
      ++input.token;
    }
  /* A valid opaque answer larger than the EDNS capacity needs a local TC
   * envelope carrying the same question and OPT, rather than silence. */
  unsigned before=replies;
  assert(product_dns_proxy_submit(proxy,&input,wire,sizeof(wire),&snapshot));
  uint8_t answer[sizeof(question)+12+1300];
  memcpy(answer,sent,sizeof(question)); answer[2]=0x81; answer[3]=0x90; answer[7]=1; answer[11]=0;
  memcpy(answer+sizeof(question),(uint8_t[]){0xc0,12,0xfd,0xe8,0,1,0,0,0,30,5,20},12);
  memset(answer+sizeof(question)+12,0xa5,1300);
  current_snapshot=snapshot;
  product_dns_proxy_answer(proxy,&sent_key,PRODUCT_DNS_PROXY_UDP,answer,sizeof(answer),101);
  assert_edns_local_reply(before,65000,0,1);
  assert(completed.result==PRODUCT_DNS_PROXY_UPSTREAM && !product_dns_proxy_resources(proxy).active);
  ++input.token; before=replies;
  assert(product_dns_proxy_unavailable(&input,wire,sizeof(wire),&snapshot,&route,&callbacks,NULL,
    PRODUCT_DNS_PROXY_CAPACITY));
  assert_edns_local_reply(before,65000,2,0);
  assert(completed.result==PRODUCT_DNS_PROXY_CAPACITY);
  product_dns_proxy_close(proxy);
}

int main (void)
{
  if(getenv("SAKAMOTO_DNS_PROXY_CODEC_CAPACITY")){
    valid_query_codec_capacity_returns_servfail();puts("valid query codec-capacity SERVFAIL: PASS");return 0;
  }
  if(getenv("SAKAMOTO_DNS_PROXY_EDNS_LOCAL")){
    edns_local_errors_and_truncation_remain_deliverable();puts("EDNS local errors and truncation: PASS");return 0;
  }
  denied_query_replies_refused_without_dispatch ();
  malformed_and_opcode_errors_keep_their_source ();
  udp_tc_continues_same_request_and_respects_client_capacity ();
  request_lifetime_is_bounded_and_late_events_are_inert ();
  capacity_returns_failure_and_never_relabels_policy ();
  completed_response_wins_same_round_cancel ();
  upstream_ids_are_retired_for_the_whole_request_window ();
  valid_query_codec_capacity_returns_servfail ();
  edns_local_errors_and_truncation_remain_deliverable ();
  puts ("shared DNS proxy REFUSED/no-dispatch behavior: PASS");
}
