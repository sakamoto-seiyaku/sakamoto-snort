/* SPDX-License-Identifier: Apache-2.0 */
/* Source-linked Host Adapter fixture. Socket readiness/native graph calls are
 * controlled dependencies; this does not claim Android or raw-socket delivery. */
#define _GNU_SOURCE
#include <assert.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "product_dns_proxy.h"
#include "product_vpn_flow_stack.h"
#define SAKAMOTO_PRODUCT_VPN_TUN_MTU 10000
#include "product_root_dns_io.h"
#include "product_dns_tcp.h"
#include "product_flow_entry.h"
#include "product_packet_completion.h"
#include "sakamoto_product_observation.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uword;
typedef struct { unsigned thread_index; } vlib_main_t;
typedef struct { u32 current_length; u8 opaque[128], data[2048]; } vlib_buffer_t;
typedef char clib_error_t;
typedef int unformat_input_t;
typedef struct { const char *path, *short_help; void *function; } vlib_cli_command_t;
typedef struct { const char *name; unsigned index, type, state; } vlib_node_registration_t;
typedef int vlib_node_runtime_t;
typedef int vlib_frame_t;
typedef struct clib_file clib_file_t;
struct clib_file {
 int file_descriptor, polling_thread_index, dont_close;
 uword private_data; unsigned flags; void *description;
 clib_error_t *(*read_function)(clib_file_t *), *(*write_function)(clib_file_t *), *(*error_function)(clib_file_t *);
};
#define PRODUCT_GRAPH_WORKERS 2
#define VLIB_NODE_TYPE_INPUT 1
#define VLIB_NODE_STATE_INTERRUPT 1
#define UNIX_FILE_DATA_AVAILABLE_TO_WRITE 1
#define VLIB_NODE_FN(name) static uword name##_function
#define VLIB_REGISTER_NODE(name) vlib_node_registration_t name
#define VLIB_CLI_COMMAND(name,storage) storage vlib_cli_command_t name
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define clib_panic(...) do {fprintf(stderr,__VA_ARGS__);fputc('\n',stderr);abort();}while(0)
static char file_main;
static vlib_main_t worker={1};
static vlib_buffer_t buffers[132];
static unsigned allocated[132], submitted[132], freed, submit_allowed=1;
static u64 now_us=100;
static struct {u64 revision;} network={5};
static unsigned raw_created, raw_closed, raw_sent, raw_fail, raw_setup_fail;
static unsigned sends, cancelled, watches, ready_calls;
static uint8_t last_wire[65535], emitted_wire[2048];
static size_t last_length, emitted_length;
static product_dns_proxy_key_t last_key;
static unsigned last_transport;
static u64 last_deadline, last_cookie;
static clib_file_t watched;
static product_platform_packet_facts_t admitted_platform[132];
static product_adapter_obligation_t admitted_obligation[132];
static product_dns_observation_record_t records[4096];
static unsigned record_count;
static unsigned start_profile=1;
static product_flow_entry_t entry;
typedef struct {
 u64 generation, dns_revision;
 product_domains_t *domains;
 product_l4_policy_view_t view;
 product_dns_proxy_route_t dns;
} fixture_bank_t;
static fixture_bank_t bank;
typedef struct {
 fixture_bank_t *bank;
 struct {u64 generation,revision,snapshot_hash;} identity;
 u64 domain_lists;
 u8 domain_source,domain_available;
 product_dns_response_t *dns_response;
} product_policy_snapshot_t;
static product_policy_snapshot_t snapshot;
typedef struct {
 u64 generation;
 product_adapter_obligation_kind_t adapter_kind;
 product_dns_owner_t dns_requests[2];
 product_dns_tcp_owner_t dns_tcp[2];
 product_flow_runtime_t *flow_pools[2];
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
typedef struct {
 u64 generation,revision,snapshot_hash,rule_id;
 u8 matched,declared_action,actual_action,mode;
} product_packet_graph_policy_evaluation_t;
typedef struct {
 product_platform_packet_facts_t platform;
 product_adapter_obligation_t obligation;
} product_buffer_platform_metadata_t;
static unsigned vlib_get_worker_index(unsigned thread) {assert(thread==1);return 0;}
static unsigned vlib_get_worker_thread_index(unsigned index) {return index+1;}
static unsigned vlib_get_thread_index(void) {return 1;}
static vlib_main_t *vlib_get_main(void) {return &worker;}
static vlib_main_t *vlib_get_main_by_index(unsigned index) {assert(index==1);return &worker;}
static double vlib_time_now(vlib_main_t *vm) {assert(vm==&worker);return now_us/1000000.0;}
static unsigned vlib_buffer_get_default_data_size(vlib_main_t *vm) {(void)vm;return 2048;}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm,u32 index) {assert(vm==&worker&&index<132);return &buffers[index];}
static void *vlib_buffer_get_current(vlib_buffer_t *buffer) {return buffer->data;}
static unsigned vlib_buffer_alloc(vlib_main_t *vm,u32 *out,unsigned count) {
 assert(vm==&worker&&count==1);for(unsigned i=1;i<132;++i)if(!allocated[i]){allocated[i]=1;memset(&buffers[i],0,sizeof(buffers[i]));*out=i;return 1;}return 0;
}
static void vlib_buffer_free(vlib_main_t *vm,u32 *indices,unsigned count) {
 assert(vm==&worker);for(unsigned i=0;i<count;++i){assert(allocated[indices[i]]);allocated[indices[i]]=0;++freed;}
}
static void vlib_node_set_interrupt_pending(vlib_main_t *vm,unsigned index) {(void)index;assert(vm==&worker);}
static char cli_output[32768];
static void vlib_cli_output(vlib_main_t *vm,const char *fmt,...) {
 (void)vm;va_list args;va_start(args,fmt);
 size_t used=strlen(cli_output);vsnprintf(cli_output+used,sizeof(cli_output)-used,fmt,args);va_end(args);
}
static void *format(void *first,const char *fmt,...) {(void)first;(void)fmt;return NULL;}
static uword clib_file_add(void *main,clib_file_t *file) {assert(main==&file_main);watched=*file;++watches;return 1;}
static void clib_file_del_by_index(void *main,uword index) {assert(main==&file_main&&index==1);--watches;}
static void clib_file_set_data_available_to_write(void *main,uword index,int yes) {(void)yes;assert(main==&file_main&&index==1);}
static __typeof__(network) *product_network_snapshot_current(void) {return &network;}
uint64_t product_flow_entry_current_incarnation(product_flow_runtime_t *pool,
 const product_owner_assignment_t *assignment,uint64_t generation,uint64_t now) {
 (void)pool;(void)assignment;assert(generation==product_packet_graph_main.generation&&now==now_us);return entry.incarnation;
}
static int product_vpn_tun_return_context(u64 generation,u64 token,u64 *inc,u64 *session,u64 *epoch) {
 (void)generation;(void)token;(void)inc;(void)session;(void)epoch;return 0;
}
static void product_policy_snapshot_acquire(product_packet_graph_main_t *graph,product_policy_snapshot_t *out) {assert(graph==&product_packet_graph_main);*out=snapshot;}
static void product_policy_snapshot_release(product_packet_graph_main_t *graph,product_policy_snapshot_t *out) {assert(graph==&product_packet_graph_main&&out->bank==&bank);}
const product_flow_entry_t *product_flow_runtime_entry(const product_flow_runtime_t *pool,uint32_t slot) {(void)pool;assert(slot==3);return &entry;}
static int product_packet_graph_enabled(void) {return 1;}
static int product_packet_graph_accepting(void) {return 1;}
static void product_flow_expiry_changed(vlib_main_t *vm) {assert(vm==&worker);}
static void product_observation_dns(vlib_main_t *vm,const product_dns_observation_record_t *record) {
 assert(vm==&worker&&record_count<4096);records[record_count]=*record;
 records[record_count].length=sizeof(*record);records[record_count].version=PRODUCT_OBSERVATION_VERSION;
 records[record_count].flags=PRODUCT_OBSERVATION_DNS;records[record_count].mono_us=now_us;
 records[record_count].activity_utc_us=(uint64_t)time(NULL)*1000000;++record_count;
}
static int product_packet_graph_submit_external(vlib_main_t *vm,u32 buffer,
 const product_platform_packet_facts_t *platform,const product_adapter_obligation_t *obligation) {
 assert(vm==&worker&&allocated[buffer]);if(!submit_allowed)return 0;
 admitted_platform[buffer]=*platform;admitted_obligation[buffer]=*obligation;submitted[buffer]=1;
 product_buffer_platform_metadata_t metadata={*platform,*obligation};memcpy(buffers[buffer].opaque,&metadata,sizeof(metadata));return 1;
}
static int fixture_socket(int domain,int type,int protocol) {(void)domain;(void)type;(void)protocol;return 100+(int)++raw_created;}
static int fixture_setsockopt(int fd,int level,int option,const void *value,socklen_t length) {(void)fd;(void)level;(void)option;(void)value;(void)length;return raw_setup_fail?-1:0;}
static int fixture_close(int fd) {assert(fd>=100);++raw_closed;return 0;}
static ssize_t fixture_sendto(int fd,const void *wire,size_t length,int flags,const struct sockaddr *address,socklen_t address_length) {
 assert(fd>=100&&flags&&address&&address_length);
 if(address->sa_family==AF_INET6){
  assert(address_length==sizeof(struct sockaddr_in6));
  const struct sockaddr_in6 *route=(const struct sockaddr_in6 *)address;
  assert(IN6_IS_ADDR_LOOPBACK(&route->sin6_addr));
  assert(length>=40);
 }
 ++raw_sent;memcpy(emitted_wire,wire,length);emitted_length=length;return raw_fail?-1:(ssize_t)length;
}
struct product_root_dns_io {
 int live, authorized;
 uint64_t last_activity;
 int idle_expired;
 product_root_dns_io_callbacks_t callbacks;
 void *context;
 uint64_t cookie;
};
static struct product_root_dns_io fixture_io;
static int product_vpn_flow_stack_driver_ready(void) { return 1; }
static uint64_t product_vpn_flow_stack_driver_dns_reservation(unsigned index) {assert(!index);return 100000;}
static int product_vpn_flow_stack_driver_dns_authorize(vlib_main_t *vm,u64 generation,u64 cookie,int fd)
{ assert(vm==&worker&&generation&&cookie&&fd==50); return 0; }
static int product_vpn_flow_stack_driver_local_reply_context(vlib_main_t *,u64,u64,const u8 *,size_t,const product_vpn_flow_stack_transport_t *);
static product_vpn_flow_stack_input_result_t product_vpn_flow_stack_driver_local_udp(
 vlib_main_t *vm,const u8 *l3,size_t bytes,const product_platform_packet_facts_t *platform,
 u64 generation,u64 incarnation,u64 *session,u8 *message,size_t capacity,size_t *length)
{
 assert(vm==&worker&&generation&&incarnation==8&&platform->provenance==PRODUCT_PACKET_PROVENANCE_VPN_TUN);
 size_t offset=(l3[0]>>4)==6?48:28; assert(bytes>=offset&&capacity>=bytes-offset);
 memcpy(message,l3+offset,bytes-offset);*length=bytes-offset;*session=71;return PRODUCT_VPN_FLOW_STACK_ACCEPTED;
}
int product_root_dns_io_authorized(product_root_dns_io_t *io,u64 generation,u64 cookie,int success,u64 now)
{
 assert(io==&fixture_io&&generation&&cookie&&now==now_us);
 io->authorized=success;
 if(success)assert(io->callbacks.watch(io->context,50,PRODUCT_ROOT_DNS_READ,io->cookie));
 else {io->live=0;assert(io->callbacks.watch(io->context,50,0,io->cookie));}
 return 0;
}
int product_root_dns_vpn_return_known(vlib_main_t *,u32);

product_root_dns_io_t *product_root_dns_io_open(uint64_t generation,const product_dns_proxy_route_t *route,uint32_t mark,
 uint64_t *sequence,const product_root_dns_io_callbacks_t *callbacks,void *context,uint64_t now) {
 assert(generation&&route->enabled&&(mark==PRODUCT_ROOT_DNS_SOCKET_MARK||callbacks->authorize)&&now==now_us);
 last_cookie=++*sequence;
 fixture_io=(struct product_root_dns_io){.live=1,.authorized=!callbacks->authorize,
  .callbacks=*callbacks,.context=context,.cookie=last_cookie,.last_activity=now};
 if(callbacks->authorize)assert(!callbacks->authorize(context,50,last_cookie));
 else assert(callbacks->watch(context,50,PRODUCT_ROOT_DNS_READ,last_cookie));
 return &fixture_io;
}
void product_root_dns_io_close(product_root_dns_io_t *io) {
 if(io&&io->live){assert(io->callbacks.watch(io->context,50,0,io->cookie));io->live=0;}
}
int product_root_dns_io_send(product_root_dns_io_t *io,const product_dns_proxy_key_t *key,unsigned transport,
 const uint8_t *wire,size_t length,uint64_t deadline,uint64_t now) {
 assert(io==&fixture_io&&io->live&&now==now_us);++sends;last_key=*key;last_transport=transport;last_length=length;last_deadline=deadline;memcpy(last_wire,wire,length);return 1;
}
void product_root_dns_io_cancel(product_root_dns_io_t *io,const product_dns_proxy_key_t *key) {assert(io==&fixture_io&&key);++cancelled;}
void product_root_dns_io_ready(product_root_dns_io_t *io,uint64_t generation,uint64_t cookie,int fd,unsigned events,uint64_t now) {
 assert(io==&fixture_io&&generation&&fd==50&&events&&now==now_us);if(cookie==last_cookie)++ready_calls;
}
uint64_t product_root_dns_io_deadline(const product_root_dns_io_t *io) {(void)io;return UINT64_MAX;}
void product_root_dns_io_expire(product_root_dns_io_t *io,uint64_t now) {
 assert(now==now_us);
 if(io&&io->live&&now>=io->last_activity+PRODUCT_ROOT_DNS_IDLE_US) {
  assert(io->callbacks.watch(io->context,50,0,io->cookie));
  io->idle_expired=io->authorized;io->live=0;io->authorized=0;
 }
}
product_root_dns_io_status_t product_root_dns_io_status(const product_root_dns_io_t *io) {
 return (product_root_dns_io_status_t){.sockets=io&&io->live,.udp_ready=io&&io->live&&io->authorized,
  .authorizing=io&&io->live&&!io->authorized,
  .udp_state=!io?PRODUCT_ROOT_DNS_UDP_NONE:io->idle_expired?PRODUCT_ROOT_DNS_UDP_IDLE:
   io->live?(io->authorized?PRODUCT_ROOT_DNS_UDP_AUTHORIZED:PRODUCT_ROOT_DNS_UDP_AUTHORIZING):PRODUCT_ROOT_DNS_UDP_FAILED};
}
uint64_t product_root_dns_io_reservation(void) {return 1024*1024;}
void product_root_dns_adapter_expire(vlib_main_t *,uint64_t);
#include "root_dns_projection.inc"
#include "product_root_dns_admission.h"
#define socket fixture_socket
#define setsockopt fixture_setsockopt
#define close fixture_close
#define sendto fixture_sendto
#include "product_root_dns_adapter.inc"
#undef socket
#undef setsockopt
#undef close
#undef sendto

static int product_vpn_flow_stack_driver_local_reply_context(vlib_main_t *vm,u64 generation,u64 session,
 const u8 *message,size_t length,const product_vpn_flow_stack_transport_t *binding)
{
 (void)binding;assert(vm==&worker&&generation==product_packet_graph_main.generation&&session==71);
 if(!submit_allowed)return -1;
 u32 index;assert(vlib_buffer_alloc(vm,&index,1));
 buffers[index].current_length=length;memcpy(buffers[index].data,message,length);
 product_adapter_obligation_t obligation={.token=(UINT64_C(1)<<63)|index,
  .queue_generation=generation,.kind=PRODUCT_ADAPTER_OBLIGATION_VPN_TUN,.packet_id=1};
 product_platform_packet_facts_t platform={.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN,.direction=1,.uid=10123,.availability=PRODUCT_PLATFORM_UID_KNOWN};
 product_root_dns_vpn_return_admit(vm,index,&obligation,&platform);
 assert(product_packet_graph_submit_external(vm,index,&platform,&obligation));return 0;
}

static const uint8_t question[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
 7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
static product_packet_lease_t lease;
static product_flow_entry_observation_t flow;
static u64 original_token=17;
static void initialize(uint64_t generation,unsigned family) {
 product_packet_graph_main.adapter_kind=start_profile==2?PRODUCT_ADAPTER_OBLIGATION_VPN_TUN:PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE;
 product_packet_graph_main.generation=generation;bank.generation=generation;bank.dns_revision=3;
 bank.dns=(product_dns_proxy_route_t){.enabled=1,.family=4,.port=53,.address={198,51,100,53}};
 snapshot=(product_policy_snapshot_t){.bank=&bank,.identity={generation,3,123}};
 assert(product_root_dns_adapter_start(&worker,generation,1));
 product_root_dns_adapter_expire(&worker,now_us);if(start_profile==1)assert(product_root_dns_adapter_ready());
 entry=(product_flow_entry_t){.linked=1,.policy_generation=generation,.incarnation=8};flow=(product_flow_entry_observation_t){.entry=&entry,.slot=3};
 flow.tracker.facts.state=PRODUCT_CT_NEW;flow.tracker.facts.direction=PRODUCT_FLOW_DIRECTION_ORIG;
 lease=(product_packet_lease_t){.policy_owner_ready=1,.origin_obligation_id=original_token};original_token+=10000;lease.assignment.valid=1;
 lease.platform=(product_platform_packet_facts_t){.uid=10123,.availability=9,.direction=3,.provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE};
 lease.facts=(product_packet_facts_t){.protocol=17,.ip_family=family,.l3_status=PRODUCT_PACKET_L3_COMPLETE,
  .l4_status=PRODUCT_PACKET_L4_COMPLETE,.source_port=40000,.destination_port=53,
  .transport_offset=family==4?20:40,.l4_header_length=8,.transport_length=8+sizeof(question)};
 if(family==4){memcpy(lease.facts.source_address+12,(uint8_t[]){192,0,2,2},4);memcpy(lease.facts.destination_address+12,(uint8_t[]){192,0,2,53},4);}
 else{lease.facts.source_address[0]=lease.facts.destination_address[0]=0x20;lease.facts.source_address[1]=lease.facts.destination_address[1]=1;lease.facts.source_address[15]=2;lease.facts.destination_address[15]=53;}
 buffers[0].current_length=lease.facts.transport_offset+8+sizeof(question);memcpy(buffers[0].data+lease.facts.transport_offset+8,question,sizeof(question));
}
static unsigned pending(void) {for(unsigned i=1;i<132;++i)if(submitted[i])return i;return 0;}
static void finish(unsigned deny,unsigned write_failure) {
 unsigned index=pending();assert(index);product_packet_completion_frame_t completion={.obligation=admitted_obligation[index],
  .terminal_intent=deny?PRODUCT_PACKET_INTENT_DROP_RUNTIME:PRODUCT_PACKET_INTENT_PASS_ADAPTER,.runtime_drop_reason=deny?PRODUCT_PACKET_DROP_POLICY_L4:0};
 product_packet_lease_t returning={.platform=admitted_platform[index]};
 product_packet_graph_policy_evaluation_t policy={.generation=product_packet_graph_main.generation,.revision=7,.snapshot_hash=789,
  .matched=deny,.rule_id=deny?999:0,.declared_action=deny?2:1,.actual_action=deny?2:1};
 root_dns_return_policy(&worker,index,&returning,&policy);
 unsigned before=raw_sent;raw_fail=write_failure;product_root_dns_reply_complete(&worker,index,&completion);raw_fail=0;
 assert(raw_sent==before+!deny);assert(root_dns_owners[0].replies);
 completion.flags=PRODUCT_COMPLETION_REPLAY_PROBE;product_root_dns_reply_complete(&worker,index,&completion);assert(raw_sent==before+!deny);
 completion.flags=0;vlib_buffer_free(&worker,&index,1);product_root_dns_reply_freed(&worker,index,&completion);submitted[index]=0;
}
static void consume(void) {assert(root_dns_intercept(&worker,0,&lease,&snapshot,&flow));assert(lease.terminal_intent==PRODUCT_PACKET_INTENT_DROP_RUNTIME);}
static void reset_terminal(void) {lease.terminal_intent=lease.terminal_count=0;lease.runtime_drop_reason=0;++lease.origin_obligation_id;++now_us;}
static void answer(unsigned rcode) {
 uint8_t wire[sizeof(question)+16];memcpy(wire,last_wire,sizeof(question));wire[2]=0x81;wire[3]=0x80|rcode;wire[7]=1;
 memcpy(wire+sizeof(question),(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
 root_dns_owners[0].current_upstream_session=last_cookie;root_dns_io_answer(&root_dns_owners[0],&last_key,last_transport,wire,sizeof(wire),++now_us);root_dns_owners[0].current_upstream_session=0;
}
static void close_owner(void) {while(pending())finish(0,0);product_root_dns_adapter_stop(&worker);assert(!root_dns_owner_count&&!watches);}
static void crossover(void) {
 for(unsigned family=4;family<=6;family+=2)for(unsigned replied=0;replied<2;++replied){
  initialize(77,family);bank.dns.enabled=0;++bank.dns_revision;
  product_root_dns_adapter_expire(&worker,++now_us);
  product_dns_owner_t *requests=&product_packet_graph_main.dns_requests[0];
  product_dns_owner_start(requests,77);product_dns_tcp_start(&product_packet_graph_main.dns_tcp[0],77);
  memset(lease.facts.source_address,0,16);memset(lease.facts.destination_address,0,16);
  if(family==4)memcpy(lease.facts.source_address+12,(uint8_t[]){127,0,0,1},4);
  else lease.facts.source_address[15]=1;
  memcpy(lease.facts.destination_address,lease.facts.source_address,16);
  lease.platform.availability=15;lease.platform.linux_ifindex=1;lease.platform.network_context_id=9;
  product_dns_context_t context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP};
  product_packet_graph_l4_packet_projection(&lease,&context.packet);
  product_dns_query_t query;product_dns_inspect_query(question,sizeof(question),&context,&query);
  product_dns_identity_t identity=product_packet_graph_dns_identity(&worker,&lease);
  product_dns_policy_identity_t policy={77,3,123,0};
  assert(product_dns_remember(requests,&query,&identity,lease.origin_obligation_id,&policy)==PRODUCT_DNS_CORRELATED);
  product_dns_query_t tcp=query;tcp.packet.protocol=6;tcp.message_sequence=1;
  assert(product_dns_remember(requests,&tcp,&identity,lease.origin_obligation_id+1,&policy)==PRODUCT_DNS_CORRELATED);
  uint8_t ordinary[sizeof(question)];memcpy(ordinary,question,sizeof(ordinary));ordinary[2]=0x81;ordinary[3]=0x80;
  product_dns_context_t returning=context;returning.packet.direction=1;
  returning.packet.source_port=53;returning.packet.destination_port=40000;
  product_dns_response_t response;
  if(replied){product_dns_inspect_response(ordinary,sizeof(ordinary),&returning,&identity,requests,&response);assert(response.correlation==PRODUCT_DNS_CORRELATED);}
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,.entries={{.length=11,.name="example.com"}}};
  assert(!product_domains_build(&source,&bank.domains));
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=315,.reason_id=315,.action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
   .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,.expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&bank.view,&deny,1));
  bank.dns.enabled=1;++bank.dns_revision;consume();assert(pending());finish(0,0);
  unsigned ip=family==4?20:40;assert((emitted_wire[ip+11]&15)==5);
  /* Recapture the actual Adapter-produced error after native metadata is lost. */
  memcpy(buffers[0].data,emitted_wire,emitted_length);buffers[0].current_length=emitted_length;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;lease.platform.uid=0;lease.platform.availability=7;
  lease.facts.source_port=53;lease.facts.destination_port=40000;lease.facts.transport_length=emitted_length-ip;
  int observed;product_packet_graph_dns_response_prepare(&worker,0,&lease,&snapshot,&response,&observed);
  assert(observed);
  product_l4_policy_match_result_t match;product_l4_policy_packet_t packet;
  product_packet_graph_l4_packet_projection(&lease,&packet);
  assert(!product_dns_response_match(&bank.view,&packet,&response,PRODUCT_L4_POLICY_POSITION_ALL,&match));
  fprintf(stderr,"recaptured REFUSED family=%u old_replied=%u correlation=%u caller=%u query_uid=%u matched=%u winner=%llu action=%u\n",
   family,replied,response.correlation,response.question.caller,response.query_uid,!!match.evaluation,
   (unsigned long long)match.rule_id,match.actual_action);
  assert(response.correlation!=PRODUCT_DNS_CORRELATED&&!match.evaluation);
  /* The unaffected original TCP correspondence still recovers its App. */
  returning.packet.protocol=6;product_dns_inspect_response(ordinary,sizeof(ordinary),&returning,&identity,requests,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED&&response.query_uid==10123);
  /* Independent generic INPUT policy remains applicable to generated returns. */
  deny.uid=0;deny.direction=1;deny.expression_length=0;
  assert(!product_l4_policy_compile(&bank.view,&deny,1));
  product_packet_graph_dns_response_prepare(&worker,0,&lease,&snapshot,&response,&observed);
  assert(!product_dns_response_match(&bank.view,&packet,&response,PRODUCT_L4_POLICY_POSITION_ALL,&match)&&match.evaluation);
  /* Exact UDP reuse remains ambiguous while generated wire can still arrive.
   * A fresh identity after disabling is correlated normally. */
  assert(!product_l4_policy_compile(&bank.view,NULL,0));
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_OUTPUT;lease.platform.uid=10123;lease.platform.availability=15;
  lease.facts.source_port=40000;lease.facts.destination_port=53;
  memcpy(buffers[0].data+ip+8,question,sizeof(question));buffers[0].current_length=ip+8+sizeof(question);
  lease.facts.transport_length=8+sizeof(question);reset_terminal();bank.dns.enabled=0;++bank.dns_revision;
  assert(!root_dns_intercept(&worker,0,&lease,&snapshot,&flow));
  identity.now_us=now_us;assert(product_dns_remember(requests,&query,&identity,lease.origin_obligation_id,&policy)==PRODUCT_DNS_AMBIGUOUS);
  ++query.id;++ordinary[1];
  assert(product_dns_remember(requests,&query,&identity,lease.origin_obligation_id+1,&policy)==PRODUCT_DNS_CORRELATED);
  product_root_dns_adapter_expire(&worker,++now_us);identity.now_us=now_us;returning.packet.protocol=17;
  product_dns_inspect_response(ordinary,sizeof(ordinary),&returning,&identity,requests,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED&&response.query_uid==10123);
  close_owner();product_domains_destroy(bank.domains);bank.domains=NULL;
  assert(!product_l4_policy_compile(&bank.view,NULL,0));
 }
 puts("Original UDP pending/tombstone to proxy REFUSED recapture, TCP preservation and generic INPUT policy: PASS");
}
static void reverse_crossover(void) {
 for(unsigned family=4;family<=6;family+=2)for(unsigned queued=0;queued<2;++queued)for(unsigned delayed=0;delayed<2;++delayed){
  initialize(77,family);product_dns_owner_t *requests=&product_packet_graph_main.dns_requests[0];product_dns_owner_start(requests,77);
  memset(lease.facts.source_address,0,16);memset(lease.facts.destination_address,0,16);
  if(family==4)memcpy(lease.facts.source_address+12,(uint8_t[]){127,0,0,1},4);else lease.facts.source_address[15]=1;
  memcpy(lease.facts.destination_address,lease.facts.source_address,16);
  lease.platform.availability=15;lease.platform.linux_ifindex=1;lease.platform.network_context_id=9;
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,.entries={{.length=11,.name="example.com"}}};
  assert(!product_domains_build(&source,&bank.domains));
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=315,.reason_id=315,.action=2,.direction=1,
   .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
   .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&bank.view,&deny,1));consume();assert(!pending());
  if(queued){answer(0);assert(pending());}
  reset_terminal();bank.dns.enabled=0;++bank.dns_revision;
  assert(!root_dns_intercept(&worker,0,&lease,&snapshot,&flow)&&pending());
  product_dns_context_t context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP};product_packet_graph_l4_packet_projection(&lease,&context.packet);
  product_dns_query_t query;product_dns_inspect_query(question,sizeof(question),&context,&query);
  if(delayed){now_us+=PRODUCT_DNS_REQUEST_US+1;++entry.incarnation;++network.revision;}
  product_dns_identity_t identity=product_packet_graph_dns_identity(&worker,&lease);product_dns_policy_identity_t policy={77,3,123,0};
  product_dns_correlation_t correlation=product_dns_remember(requests,&query,&identity,lease.origin_obligation_id,&policy);
  assert(correlation==PRODUCT_DNS_CORRELATED||correlation==PRODUCT_DNS_AMBIGUOUS);finish(0,0);
  unsigned ip=family==4?20:40;assert((emitted_wire[ip+11]&15)==(queued?5:2));
  memcpy(buffers[0].data,emitted_wire,emitted_length);buffers[0].current_length=emitted_length;
  lease.platform.direction=1;lease.platform.uid=0;lease.platform.availability=7;
  lease.facts.source_port=53;lease.facts.destination_port=40000;lease.facts.transport_length=emitted_length-ip;
  product_dns_response_t response;int observed;product_packet_graph_dns_response_prepare(&worker,0,&lease,&snapshot,&response,&observed);
  product_l4_policy_packet_t packet;product_packet_graph_l4_packet_projection(&lease,&packet);
  product_l4_policy_match_result_t match;assert(!product_dns_response_match(&bank.view,&packet,&response,PRODUCT_L4_POLICY_POSITION_ALL,&match));
  fprintf(stderr,"reverse recaptured family=%u already_queued=%u delayed_new_view=%u correlation=%u caller=%u matched=%u winner=%llu action=%u\n",
   family,queued,delayed,response.correlation,response.question.caller,match.evaluation,(unsigned long long)match.rule_id,match.actual_action);
  assert(observed&&response.correlation!=PRODUCT_DNS_CORRELATED&&!match.evaluation);
  close_owner();product_domains_destroy(bank.domains);bank.domains=NULL;assert(!product_l4_policy_compile(&bank.view,NULL,0));
 }
 /* Exhausting the shared table must qualify correspondence as unavailable,
  * including TCP, rather than silently losing a generated-return guard. */
 initialize(77,4);product_dns_owner_t *requests=&product_packet_graph_main.dns_requests[0];product_dns_owner_start(requests,77);
 product_dns_context_t context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP};product_packet_graph_l4_packet_projection(&lease,&context.packet);
 product_dns_query_t udp;product_dns_inspect_query(question,sizeof(question),&context,&udp);
 product_dns_query_t tcp=udp;tcp.packet.protocol=6;
 product_dns_identity_t identity=product_packet_graph_dns_identity(&worker,&lease);product_dns_policy_identity_t policy={77,3,123,0};
 for(unsigned i=0;i<PRODUCT_DNS_REQUESTS;++i){tcp.id=i;tcp.message_sequence=i+1;assert(product_dns_remember(requests,&tcp,&identity,i+1,&policy)==PRODUCT_DNS_CORRELATED);}
 product_dns_generated_return(requests,&udp,now_us);assert(requests->capacity==1&&requests->overflow_until>now_us);
 uint8_t wire[sizeof(question)];memcpy(wire,question,sizeof(wire));wire[0]=wire[1]=0;wire[2]=0x81;wire[3]=0x80;
 context.packet.protocol=6;context.packet.direction=1;context.packet.source_port=53;context.packet.destination_port=40000;
 memcpy(context.packet.source_address,udp.packet.destination_address,16);memcpy(context.packet.destination_address,udp.packet.source_address,16);
 product_dns_response_t response;product_dns_inspect_response(wire,sizeof(wire),&context,&identity,requests,&response);
 assert(response.correlation==PRODUCT_DNS_REQUEST_CAPACITY&&!response.query_uid_known);close_owner();
 puts("Active proxy or queued REFUSED to fresh original query before recapture: PASS");
 puts("Generated-return guard table capacity explicitly withholds unsafe TCP/UDP correlation: PASS");
}
static void vpn_authority(void)
{
 start_profile=2;initialize(77,4);
 assert(!product_root_dns_adapter_ready()&&!root_dns_owners[0].ready);
 u64 first=last_cookie;
 assert(!product_root_dns_vpn_authorized(&worker,77,first,2,0,0,0));
 assert(!product_root_dns_adapter_ready()&&root_dns_owners[0].last_error==2);
 close_owner();
 initialize(78,4);assert(!product_root_dns_adapter_ready());
 assert(!product_root_dns_vpn_authorized(&worker,78,last_cookie,0,99,9,1));
 assert(product_root_dns_adapter_ready()&&!root_dns_owners[0].last_error);
 assert(product_root_dns_vpn_authorized(&worker,77,first,0,98,9,1)<0);
 assert(product_root_dns_adapter_ready());close_owner();start_profile=1;
 puts("VPN effective route: pending/denied protect not ready; success ready and stale generation rejected PASS");
}
static void vpn_returns(void)
{
 vlib_main_t tun_io={2};
 for(unsigned delivery=2;delivery<=5;++delivery) {
  initialize(77,4);
  root_dns_owner_t *owner=&root_dns_owners[0];root_dns_close_raw(owner);owner->profile=2;
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;buffers[0].data[0]=0x45;
  consume();answer(0);unsigned index=pending();assert(index&&product_root_dns_adapter_pending(0)==1);
  product_packet_completion_frame_t completion={.obligation=admitted_obligation[index]};
  unsigned before=record_count;
  product_root_dns_vpn_reply_complete(&tun_io,index,&completion,delivery);
  assert(record_count==before&&owner->reply[0].state==2);
  product_root_dns_vpn_reply_complete(&tun_io,index,&completion,delivery==2?4:2);
  assert(owner->reply[0].state==2&&owner->reply[0].record.delivery==delivery);
  vlib_buffer_free(&worker,&index,1);submitted[index]=0;
  product_root_dns_vpn_reply_freed(&tun_io,index,&completion);
  assert(record_count==before&&product_root_dns_adapter_pending(0)==1&&owner->reply[0].state==3);
  product_root_dns_vpn_reply_complete(&tun_io,index,&completion,delivery==2?4:2);
  product_root_dns_vpn_reply_freed(&tun_io,index,&completion);
  assert(owner->reply[0].state==3&&owner->reply[0].record.delivery==delivery);
  product_root_dns_adapter_expire(&worker,++now_us);
  assert(record_count==before+1&&!product_root_dns_adapter_pending(0));
  const product_dns_observation_record_t *record=&records[record_count-1];
  assert(record->stage==4&&record->adapter_profile==2&&record->return_provenance==3);
  assert(record->transport_session==71&&record->return_packet_uid==10123&&record->delivery==delivery);
  product_root_dns_vpn_reply_complete(&tun_io,index,&completion,delivery);
  product_root_dns_vpn_reply_freed(&tun_io,index,&completion);
  product_root_dns_adapter_expire(&worker,++now_us);assert(record_count==before+1);
  close_owner();assert(raw_created==raw_closed);
 }
 puts("VPN TUN complete/native free -> original owner normal export; four delivery outcomes and stale events: PASS");
}
static void assert_cli_route_ready(int expected) {
 cli_output[0]=0;root_dns_status_cli(&worker,NULL,NULL);
 assert(strstr(cli_output,expected?" route_ready=1 ":" route_ready=0 "));
}
static void root_idle_health(void) {
 /* Android Root publishes its first platform snapshot after Adapter startup.
  * Revision zero is the current initial Unknown network, not an old epoch. */
 start_profile=1;network.revision=0;initialize(76,4);
 assert(product_root_dns_adapter_ready());assert_cli_route_ready(1);
 ++network.revision;assert(!product_root_dns_adapter_ready());assert_cli_route_ready(0);
 product_root_dns_adapter_expire(&worker,++now_us);assert(product_root_dns_adapter_ready());
 close_owner();network.revision=5;
 for(unsigned profile=1;profile<=2;++profile) {
  start_profile=profile;initialize(77+profile,4);
  if(profile==2) {
   assert(!product_root_dns_adapter_ready());
   assert(!product_root_dns_vpn_authorized(&worker,79,last_cookie,0,99,9,1));
  }
  assert(product_root_dns_adapter_ready());
  now_us+=PRODUCT_ROOT_DNS_IDLE_US+1;
  product_root_dns_adapter_expire(&worker,now_us);
  assert(fixture_io.idle_expired&&!product_root_dns_io_status(&fixture_io).udp_ready);
  product_root_dns_adapter_expire(&worker,++now_us);
  fprintf(stderr,"idle-health profile=%u route_ready=%d socket_ready=%u io_idle=%d\n",
   profile,product_root_dns_adapter_ready(),product_root_dns_io_status(&fixture_io).udp_ready,fixture_io.idle_expired);
  assert(product_root_dns_adapter_ready());
  /* A historical failure does not undo the current clean-idle capability. */
  root_dns_owners[0].last_error=17;
  product_root_dns_adapter_expire(&worker,++now_us);assert(product_root_dns_adapter_ready());
  assert_cli_route_ready(1);
  /* A current policy bank cannot qualify an owner from the prior generation. */
  ++bank.generation;++product_packet_graph_main.generation;
  assert(!product_root_dns_adapter_ready());assert_cli_route_ready(0);
  --bank.generation;--product_packet_graph_main.generation;
  assert(product_root_dns_adapter_ready());assert_cli_route_ready(1);
  ++network.revision;
  assert(!product_root_dns_adapter_ready());assert_cli_route_ready(0);
  product_root_dns_adapter_expire(&worker,++now_us);
  assert(!fixture_io.idle_expired); /* The old epoch's idle proof cannot survive reconfiguration. */
  if(profile==2) {
   assert(!product_root_dns_adapter_ready());
   assert(!product_root_dns_vpn_authorized(&worker,79,last_cookie,7,0,0,0));
   assert(!product_root_dns_adapter_ready());
  } else assert(product_root_dns_adapter_ready());
  bank.dns.enabled=0;++bank.dns_revision;
  assert_cli_route_ready(0);
  product_root_dns_adapter_expire(&worker,++now_us);
  assert(product_root_dns_adapter_ready()&&!product_root_dns_io_status(root_dns_owners[0].io).udp_ready);
  assert_cli_route_ready(1);
  ++network.revision;assert_cli_route_ready(0);
  product_root_dns_adapter_expire(&worker,++now_us);assert_cli_route_ready(1);
  bank.dns.enabled=1;++bank.dns_revision;
  product_root_dns_adapter_expire(&worker,++now_us);
  if(profile==2)assert(!product_root_dns_adapter_ready());
  product_root_dns_adapter_quiesce(&worker);assert(!product_root_dns_adapter_ready());
  product_root_dns_adapter_stop(&worker);assert(raw_created==raw_closed);
 }
 start_profile=2;initialize(90,4);
 now_us+=PRODUCT_ROOT_DNS_IDLE_US+1;
 product_root_dns_adapter_expire(&worker,now_us);
 assert(!fixture_io.idle_expired&&!product_root_dns_adapter_ready());
 close_owner();
 start_profile=1;
 puts("Root/VPN idle route health, current authorization, network/config/stop invalidation: PASS");
}

int main(int argc,char **argv) {
 assert(!product_l4_policy_compile(&bank.view,NULL,0));
 if(argc>1&&!strcmp(argv[1],"idle-health")){root_idle_health();return 0;}
 if(argc>1&&!strcmp(argv[1],"vpn-authority")){vpn_authority();return 0;}
 if(argc>1&&!strcmp(argv[1],"vpn-return")){vpn_returns();return 0;}
 if(argc>1&&!strcmp(argv[1],"crossover")){crossover();return 0;}
 if(argc>1&&!strcmp(argv[1],"reverse-crossover")){reverse_crossover();return 0;}
 if(argc>1&&!strcmp(argv[1],"generation")){
  initialize(70000,4);clib_file_t old=watched;u64 cookie=last_cookie;close_owner();
  initialize(UINT64_C(0x1000000000000001),4);assert(last_cookie>cookie);
  unsigned before=ready_calls;root_dns_file_read(&old);assert(ready_calls==before);close_owner();
  puts("Root DNS full generation and previous-generation reused-fd readiness: PASS");return 0;
 }
 for(unsigned family=4;family<=6;family+=2){
  initialize(77,family);unsigned before=sends;consume();assert(sends==before+1&&!pending());
  assert(!memcmp(last_wire+2,question+2,sizeof(question)-2));answer(3);assert(pending());
  unsigned index=pending(),ip=family==4?20:40;vlib_buffer_t *reply=&buffers[index];
  assert(reply->data[0]==(family==4?0x45:0x60)&&reply->data[ip]==0&&reply->data[ip+1]==53);
  assert(reply->data[ip+2]==0x9c&&reply->data[ip+3]==0x40&&reply->data[ip+8]==0x12&&reply->data[ip+9]==0x34);
  assert((reply->data[ip+11]&15)==3);finish(0,0);assert(!root_dns_owners[0].replies);
  const product_dns_observation_record_t *r=&records[record_count-1];assert(r->stage==4&&r->delivery==PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED);
  assert(r->uid==10123&&r->return_packet_uid==geteuid()&&r->return_provenance==5&&r->return_policy_revision==7);
  assert(r->id==0x1234&&r->rcode==3&&r->reply_rcode==3&&r->upstream_address[0]==198&&r->return_token);
  reset_terminal();lease.platform.availability=1;consume();answer(0);finish(1,0);
  assert(records[record_count-1].caller==0&&records[record_count-1].delivery==PRODUCT_DNS_DELIVERY_POLICY_DROP);
  reset_terminal();consume();answer(0);finish(0,1);assert(records[record_count-1].delivery==PRODUCT_DNS_DELIVERY_WRITE_FAILED);
  reset_terminal();submit_allowed=0;before=freed;consume();answer(0);assert(!pending()&&freed==before+1);submit_allowed=1;
  reset_terminal();consume();product_dns_proxy_key_t stale=last_key;
  product_dns_proxy_end(root_dns_owners[0].proxy,77,8,++now_us);unsigned old=record_count;
  product_dns_proxy_answer(root_dns_owners[0].proxy,&stale,1,last_wire,last_length,now_us);assert(record_count==old&&!pending());
  close_owner();assert(raw_created==raw_closed);
 }
 initialize(77,4);
 product_platform_packet_facts_t admission_platform={.uid=10123,.availability=9,
  .direction=PRODUCT_PACKET_DIRECTION_OUTPUT,.provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE};
 product_root_dns_admission_facts_t admission={.family=4,.dns_header_present=1,
  .source_address={192,0,2,2},.resolver_address={192,0,2,53},
  .source_port=40000,.resolver_port=53,.id=0x1234,.query_flags=0x0100,.packet_length=4000};
 unsigned admission_before=record_count;
 product_root_dns_adapter_admission_observe(&worker,900,&admission_platform,&admission,
  PRODUCT_DNS_COPY_GAP,PRODUCT_DNS_DELIVERY_RESOURCE_DROP);
 assert(record_count==admission_before+1);
 const product_dns_observation_record_t *admission_record=&records[record_count-1];
 assert(admission_record->token==900&&admission_record->stage==3&&admission_record->coverage==PRODUCT_DNS_COPY_GAP);
 assert(admission_record->delivery==PRODUCT_DNS_DELIVERY_RESOURCE_DROP&&admission_record->proxy_result==PRODUCT_DNS_PROXY_CAPACITY);
 assert(admission_record->proxy_flags==(PRODUCT_DNS_PROXY_RECORD|PRODUCT_DNS_PROXY_ADMISSION_RESOURCE));
 assert(!admission_record->request_attempt&&!admission_record->upstream_transport&&!admission_record->reply_capacity);
 close_owner();
 initialize(77,4);lease.platform.availability=9;
 sakamoto_product_domains_t source={.list_count=1,.entry_count=1,.entries={{.length=11,.name="example.com"}}};assert(!product_domains_build(&source,&bank.domains));
 product_l4_policy_rule_t deny={.uid=10123,.rule_id=315,.reason_id=315,.action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
  .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,.expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
 assert(!product_l4_policy_compile(&bank.view,&deny,1));unsigned before=sends;consume();assert(sends==before&&pending());finish(0,0);
 assert((emitted_wire[31]&15)==5&&records[record_count-1].reply_rcode==5&&records[record_count-1].winner==315);
 assert(!product_l4_policy_compile(&bank.view,NULL,0));
 reset_terminal();consume();deny.rule_id=316;assert(!product_l4_policy_compile(&bank.view,&deny,1));snapshot.identity.revision=5;answer(0);finish(0,0);
 assert(records[record_count-1].query_policy_revision==3&&records[record_count-1].policy_revision==5&&records[record_count-1].winner==316);
 assert(!product_l4_policy_compile(&bank.view,NULL,0));
 reset_terminal();bank.dns.enabled=0;assert(!root_dns_intercept(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent);bank.dns.enabled=1;
 clib_file_t stale_file=watched;reset_terminal();++bank.dns_revision;product_root_dns_adapter_expire(&worker,++now_us);
 before=ready_calls;root_dns_file_read(&stale_file);assert(ready_calls==before);
 unsigned semantic_records=record_count;
 for(unsigned i=0;i<ROOT_DNS_REPLIES+1;++i){reset_terminal();consume();answer(0);}
 assert(root_dns_owners[0].replies==ROOT_DNS_REPLIES&&root_dns_owners[0].reply_rejected>=1);
 product_root_dns_adapter_quiesce(&worker);while(pending())finish(0,0);product_root_dns_adapter_stop(&worker);
 assert(raw_created==raw_closed&&!root_dns_owners[0].replies);
 product_domains_destroy(bank.domains);
 if(argc>1){FILE *out=fopen(argv[1],"wb");assert(out);assert(fwrite(records,sizeof(records[0]),semantic_records,out)==semantic_records);assert(!fclose(out));}
 printf("Root DNS actual Adapter wire/verdict/return/policy/capacity/cancel/stop/stale fixture: PASS records=%u semantic_export=%u\n",record_count,semantic_records);
}
