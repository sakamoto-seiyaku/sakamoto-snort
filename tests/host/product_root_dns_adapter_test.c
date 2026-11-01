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
#include "product_dns_assoc.h"
#include "product_vpn_flow_stack.h"
#define SAKAMOTO_PRODUCT_VPN_TUN_MTU 10000
#include "product_root_dns_io.h"
#include "product_root_dns_tcp_io.h"
#include "product_dns_tcp.h"
#include "product_flow_entry.h"
#include "product_packet_completion.h"
#include "sakamoto_product_observation.h"
#include "sakamoto_product_network.h"

/* A single real malloc failure, armed only at the public request/answer
 * boundary. Equal wire lengths distinguish cache scratch from output by
 * allocation order; the checks below require the actual emitted semantics. */
void *__real_malloc(size_t);
static size_t fault_bytes;
static unsigned fault_nth, fault_matches, fault_failures;
void *__wrap_malloc(size_t bytes) {
 if(fault_nth&&bytes==fault_bytes&&++fault_matches==fault_nth) {
  fault_nth=0;++fault_failures;return NULL;
 }
 return __real_malloc(bytes);
}

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uintptr_t uword;
typedef struct { unsigned thread_index; } vlib_main_t;
typedef struct { u32 current_length, flags, flow_id; u8 opaque[128], data[2048]; } vlib_buffer_t;
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
#define UNIX_FILE_EVENT_EDGE_TRIGGERED 2
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
static sakamoto_product_network_snapshot_t network={.revision=5};
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
static int vpn_tcp_fixture_enabled;
static uint8_t vpn_tcp_reply_wire[65535];
static size_t vpn_tcp_reply_length;
static u64 vpn_tcp_reply_token;
static unsigned vpn_tcp_reply_count;
static product_flow_entry_t entry, second_entry;
static unsigned dual_channels;
static struct {u64 session,token;unsigned id,rcode;uint32_t uid;unsigned calls;} channel_replies[2];
static void channel_reply(u64 session,u64 token,const uint8_t *wire,size_t length) {
 if(!dual_channels)return;
 unsigned i=session==72||session==902;assert(session==(i?72:71)||session==(i?902:901));
 assert(length>=12&&!channel_replies[i].calls);
 channel_replies[i].session=session;channel_replies[i].token=token;
 channel_replies[i].id=(unsigned)wire[0]*256+wire[1];channel_replies[i].rcode=wire[3]&15;
 channel_replies[i].uid=10123+i;++channel_replies[i].calls;
}
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
 product_dns_assoc_t *dns_assoc[2];
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
const product_flow_entry_t *product_flow_runtime_entry(const product_flow_runtime_t *pool,uint32_t slot) {
 (void)pool;if(dual_channels&&slot==4)return &second_entry;assert(slot==3);return &entry;
}
static int product_packet_graph_enabled(void) {return 1;}
static int product_packet_graph_accepting(void) {return 1;}
static void product_flow_expiry_changed(vlib_main_t *vm) {assert(vm==&worker);}
static void product_observation_dns(vlib_main_t *vm,const product_dns_observation_record_t *record) {
 assert(vm==&worker&&record_count<4096);records[record_count]=*record;
 records[record_count].length=product_dns_observation_wire_bytes(record);records[record_count].version=product_dns_observation_wire_version(record);
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
 assert(vm==&worker&&generation&&(incarnation==8||(dual_channels&&incarnation==9))&&platform->provenance==PRODUCT_PACKET_PROVENANCE_VPN_TUN);
 size_t offset=(l3[0]>>4)==6?48:28; assert(bytes>=offset&&capacity>=bytes-offset);
 memcpy(message,l3+offset,bytes-offset);*length=bytes-offset;*session=dual_channels&&incarnation==9?72:71;return PRODUCT_VPN_FLOW_STACK_ACCEPTED;
}
/* Controlled HEV local-TCP boundary. Actual framing/lwIP is exercised by
 * hev_owner_local_tcp_test and the ordinary Android App qualification. */
static product_vpn_flow_stack_snapshot_t product_vpn_flow_stack_driver_tcp_status(unsigned index)
{ assert(!index);return (product_vpn_flow_stack_snapshot_t){0}; }
static product_vpn_flow_stack_input_result_t product_vpn_flow_stack_driver_local_tcp(
 vlib_main_t *vm,const u8 *l3,size_t bytes,const product_platform_packet_facts_t *platform,
 u64 generation,u64 incarnation,u64 *session)
{ (void)vm;(void)l3;(void)bytes;(void)platform;(void)generation;(void)incarnation;
  *session=vpn_tcp_fixture_enabled?(dual_channels&&incarnation==9?72:71):0;
  return vpn_tcp_fixture_enabled?PRODUCT_VPN_FLOW_STACK_ACCEPTED:PRODUCT_VPN_FLOW_STACK_NOT_RUNNING; }
static void product_vpn_flow_stack_driver_tcp_drain(vlib_main_t *vm) { (void)vm; }
static int product_vpn_flow_stack_driver_tcp_reply(vlib_main_t *vm,u64 generation,u64 session,u64 token,
 const u8 *wire,size_t length,const product_vpn_flow_stack_transport_t *binding)
{ (void)binding;
  if(!vpn_tcp_fixture_enabled)return -1;
  assert(vm==&worker&&generation==77&&(session==71||(dual_channels&&session==72))&&length<=sizeof(vpn_tcp_reply_wire));
  channel_reply(session,token,wire,length);
  memcpy(vpn_tcp_reply_wire,wire,length);vpn_tcp_reply_length=length;
  vpn_tcp_reply_token=token;++vpn_tcp_reply_count;return 0; }
static int product_vpn_flow_stack_driver_tcp_abandon(vlib_main_t *vm,u64 generation,u64 session,u64 token)
{ (void)vm;(void)generation;(void)session;(void)token;return 0; }
#ifndef PRODUCT_ROOT_DNS_REAL_IO
int product_root_dns_io_authorized(product_root_dns_io_t *io,u64 generation,u64 cookie,int success,u64 now)
{
 assert(io==&fixture_io&&generation&&cookie&&now==now_us);
 io->authorized=success;
 if(success)assert(io->callbacks.watch(io->context,50,PRODUCT_ROOT_DNS_READ,io->cookie));
 else {io->live=0;assert(io->callbacks.watch(io->context,50,0,io->cookie));}
 return 0;
}
#endif
int product_root_dns_vpn_return_known(vlib_main_t *,u32);
#ifndef PRODUCT_ROOT_DNS_REAL_IO

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
uint64_t product_root_dns_io_config_reservation(const product_dns_proxy_route_t *route) {(void)route;return product_root_dns_io_reservation();}
#endif
/* TCP sockets are a controlled transport dependency in this source-linked
 * Adapter fixture. Real kernel framing/SAVED_SYN is tested separately. */
struct product_root_dns_tcp_io { int live; };
static struct product_root_dns_tcp_io fixture_tcp_io;
static int tcp_reply_accept;
static uint8_t tcp_reply_wire[65535];
static size_t tcp_reply_length;
static u64 tcp_reply_token;
static unsigned tcp_reply_count;
static unsigned fixture_tcp_clients;
product_root_dns_tcp_io_t *product_root_dns_tcp_io_open(uint64_t generation,uint16_t port,
 uint64_t *sequence,const product_root_dns_tcp_callbacks_t *cb,void *context,uint64_t now) {
 (void)sequence;(void)context;assert(generation&&port==15353&&cb&&now==now_us);
 fixture_tcp_io.live=1;return &fixture_tcp_io;
}
void product_root_dns_tcp_io_close(product_root_dns_tcp_io_t *io,uint64_t now){(void)now;if(io)io->live=0;}
void product_root_dns_tcp_io_quiesce(product_root_dns_tcp_io_t *io,uint64_t now){(void)now;if(io)io->live=0;}
int product_root_dns_tcp_io_resume(product_root_dns_tcp_io_t *io,uint64_t now){assert(io&&now==now_us);io->live=1;return 1;}
int product_root_dns_tcp_io_ready(product_root_dns_tcp_io_t *io,uint64_t generation,uint64_t cookie,int fd,unsigned events,uint64_t now){(void)io;(void)generation;(void)cookie;(void)fd;(void)events;(void)now;return 0;}
int product_root_dns_tcp_io_reply(product_root_dns_tcp_io_t *io,uint64_t session,uint64_t token,const uint8_t *wire,size_t length,uint64_t now){
 assert(io&&session&&token&&length<=sizeof(tcp_reply_wire)&&now==now_us);
 channel_reply(session,token,wire,length);
 memcpy(tcp_reply_wire,wire,length);tcp_reply_length=length;tcp_reply_token=token;++tcp_reply_count;return tcp_reply_accept;
}
int product_root_dns_tcp_io_abandon(product_root_dns_tcp_io_t *io,uint64_t session,uint64_t token,uint64_t now)
{ (void)io;(void)session;(void)token;(void)now;return 0; }
void product_root_dns_tcp_io_expire(product_root_dns_tcp_io_t *io,uint64_t now){(void)io;(void)now;}
uint64_t product_root_dns_tcp_io_deadline(const product_root_dns_tcp_io_t *io){(void)io;return UINT64_MAX;}
product_root_dns_tcp_status_t product_root_dns_tcp_io_status(const product_root_dns_tcp_io_t *io){return(product_root_dns_tcp_status_t){.accepting=io&&io->live,.clients=fixture_tcp_clients};}
int product_flow_entry_take_root_dns_tcp(product_flow_runtime_t *pool,uint32_t slot,u64 generation,u64 incarnation) {
 (void)pool;product_flow_entry_t *target=dual_channels&&slot==4?&second_entry:&entry;
 assert((slot==3||(dual_channels&&slot==4))&&generation==product_packet_graph_main.generation&&incarnation==target->incarnation);
 target->root_dns_tcp_taken=1;return 1;
}
int product_flow_entry_select_vpn_dns_tcp(product_flow_runtime_t *pool,uint32_t slot,
 u64 generation,u64 incarnation,int local)
{
 (void)pool;product_flow_entry_t *target=dual_channels&&slot==4?&second_entry:&entry;
 assert((slot==3||(dual_channels&&slot==4))&&generation==product_packet_graph_main.generation&&incarnation==target->incarnation);
 if(target->vpn_dns_tcp_decided)return target->vpn_dns_tcp_taken==!!local;
 target->vpn_dns_tcp_decided=1;target->vpn_dns_tcp_taken=!!local;return 1;
}
static void product_packet_graph_set_platform_facts(vlib_buffer_t *buffer,const product_platform_packet_facts_t *platform,u64 generation) {
 product_buffer_platform_metadata_t metadata;memcpy(&metadata,buffer->opaque,sizeof(metadata));
 metadata.platform=*platform;metadata.obligation.queue_generation=generation;memcpy(buffer->opaque,&metadata,sizeof(metadata));
}
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
 (void)binding;assert(vm==&worker&&generation==product_packet_graph_main.generation&&(session==71||(dual_channels&&session==72)));
 if(dual_channels)channel_reply(session,0,message,length);
 if(!submit_allowed)return -1;
 u32 index;assert(vlib_buffer_alloc(vm,&index,1));
 buffers[index].current_length=length;memcpy(buffers[index].data,message,length);
 product_adapter_obligation_t obligation={.token=(UINT64_C(1)<<63)|index,
  .queue_generation=generation,.kind=PRODUCT_ADAPTER_OBLIGATION_VPN_TUN,.packet_id=1};
 product_platform_packet_facts_t platform={.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN,.direction=1,.uid=dual_channels&&session==72?10124:10123,.availability=PRODUCT_PLATFORM_UID_KNOWN};
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
static void answer_ttl(unsigned rcode,unsigned ttl) {
 uint8_t wire[sizeof(question)+16];memcpy(wire,last_wire,sizeof(question));wire[2]=0x81;wire[3]=0x80|rcode;wire[7]=1;
 memcpy(wire+sizeof(question),(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,0,0,4,192,0,2,9},16);
 wire[sizeof(question)+9]=ttl;
 root_dns_owners[0].current_upstream_session=last_cookie;root_dns_io_answer(&root_dns_owners[0],&last_key,last_transport,wire,sizeof(wire),++now_us);root_dns_owners[0].current_upstream_session=0;
}
/* Transport cancellation/fault tests require an actual new upstream request.
 * Explicit TTL0 keeps that prerequisite after answer caching is enabled. */
static void answer(unsigned rcode) { answer_ttl(rcode,0); }
static void close_owner(void) {while(pending())finish(0,0);product_root_dns_adapter_stop(&worker);assert(!root_dns_owner_count&&!watches);}
static void cache_records(void) {
 start_profile=1;
 for(unsigned family=4;family<=6;family+=2) {
  initialize(77,family);unsigned before=sends;consume();answer_ttl(0,30);assert(pending());finish(0,0);
  assert(sends==before+1 && product_dns_proxy_resources(root_dns_owners[0].proxy).cache_entries==1);
  reset_terminal();unsigned at=lease.facts.transport_offset+8;
  buffers[0].data[at]=0xab;buffers[0].data[at+1]=0xcd;
  consume();assert(sends==before+1 && pending());
  unsigned returned=pending(),ip=family==4?20:40;
  assert(buffers[returned].data[ip+8]==0xab && buffers[returned].data[ip+9]==0xcd);
  const product_dns_observation_record_t *r=&records[record_count-1];
  assert(r->stage==2 && r->proxy_result==PRODUCT_DNS_PROXY_CACHE && r->upstream_session==0);
  assert(r->proxy_flags== (PRODUCT_DNS_PROXY_RECORD|PRODUCT_DNS_PROXY_CACHE_ANSWER));
  finish(0,0);r=&records[record_count-1];
  assert(r->stage==4 && r->delivery==PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED && r->id==0xabcd);
  assert(r->proxy_flags&PRODUCT_DNS_PROXY_CACHE_ANSWER);
  close_owner();assert(raw_created==raw_closed);
 }
 puts("Source-linked Root IPv4/IPv6 cached data: current request identity, normal return and cache source PASS");
}
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
 for(unsigned change=0;change<2;++change) {
  start_profile=2;initialize(80+change,4);
  u64 old=last_cookie;
  if(change)++network.revision;
  else {++bank.dns_revision;bank.dns.address[3]=54;}
  /* The ordinary broker callback is delivered before an owner timer/file
   * event gets a chance to refresh this newly authoritative view. */
  assert(product_root_dns_vpn_authorized(&worker,80+change,old,0,98,9,1)<0);
  assert(last_cookie!=old && !fixture_io.authorized && !product_root_dns_adapter_ready());
  assert(root_dns_owners[0].route_revision==bank.dns_revision
    && root_dns_owners[0].network_revision==network.revision);
  assert(!product_root_dns_vpn_authorized(&worker,80+change,last_cookie,0,99,9,1));
  assert(product_root_dns_adapter_ready());close_owner();
 }
 start_profile=1;
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

static void tcp_proxy_identity(void) {
 tcp_reply_accept=1;
 for(unsigned family=4;family<=6;family+=2) {
  initialize(77,family);
  lease.facts.protocol=6;lease.facts.l4_header_length=lease.facts.transport_length=20;
  lease.facts.tcp_flags=2;lease.facts.tcp_sequence=0x12345678;
  lease.platform.reserved=PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE|PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID;
  memset(buffers[0].data,0,sizeof(buffers[0].data));
  unsigned at=family==4?20:40;
  buffers[0].current_length=at+20;buffers[0].data[0]=family==4?0x45:0x60;
  buffers[0].data[family==4?9:6]=6;
  buffers[0].data[at+2]=0;buffers[0].data[at+3]=53;buffers[0].data[at+13]=2;
  buffers[0].flow_id=0x1007b;
  assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent&&entry.root_dns_tcp_taken);
  assert((lease.platform.reserved&PRODUCT_PLATFORM_ADMISSION_DNS_TCP_OWNER_MASK)==2);
  assert(buffers[0].flow_id==0x1007b);
  root_dns_owner_t *owner=&root_dns_owners[0];
  root_dns_tcp_binding_t *binding=&owner->tcp_bindings[0];
  product_root_dns_tcp_endpoint_t endpoint={.family=family,.saved_syn=1,.source_port=40000,.resolver_port=53,.syn_sequence=0x12345679};
  memcpy(endpoint.source_address,binding->input.context.packet.source_address,16);
  memcpy(endpoint.resolver_address,binding->input.context.packet.destination_address,16);
  assert(!root_dns_tcp_accepted(owner,901,&endpoint));--endpoint.syn_sequence;
  assert(root_dns_tcp_accepted(owner,901,&endpoint));assert(!root_dns_tcp_accepted(owner,902,&endpoint));
  /* A later packet without UID retains the exact SYN caller, but its actual
   * capture is separately Unknown in the normal observation. */
  lease.facts.tcp_flags=0x10;lease.platform.uid=0;lease.platform.availability=0;
  lease.platform.reserved=PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE|PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID;
  buffers[0].data[at+13]=0x10;buffers[0].flow_id=1U<<PRODUCT_ROOT_DNS_TCP_MARK_SHIFT;
  flow.tracker.facts.state=PRODUCT_CT_ESTABLISHED;
  assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent);
  assert(binding->input.context.packet.uid==10123 && binding->input.context.packet.uid_known && binding->input.context.caller==1);
  assert(binding->input.capture_uid==UINT32_MAX && binding->input.capture_availability==0);
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,.entries={{.length=11,.name="example.com"}}};
  assert(!product_domains_build(&source,&bank.domains));
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=317,.reason_id=317,.action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,.expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&bank.view,&deny,1));
  unsigned before=sends;u64 token=(UINT64_C(1)<<63)|(family*100U+1U);
  root_dns_tcp_query(owner,901,token,question,sizeof(question),++now_us);
  assert(sends==before && tcp_reply_token==token && (tcp_reply_wire[3]&15)==5);
  root_dns_tcp_delivered(owner,token,1);
  assert(records[record_count-1].uid==10123 && records[record_count-1].caller==1 && records[record_count-1].packet_uid==UINT32_MAX);
  assert(records[record_count-1].protocol==6 && records[record_count-1].message_sequence==token && records[record_count-1].winner==317);
  assert(!product_l4_policy_compile(&bank.view,NULL,0));
  root_dns_tcp_query(owner,901,++token,question,sizeof(question),++now_us);assert(sends==before+1);answer(0);
  assert(tcp_reply_length==sizeof(question)+16 && (tcp_reply_wire[3]&15)==0);root_dns_tcp_delivered(owner,token,1);
  root_dns_tcp_query(owner,901,++token,question,sizeof(question),++now_us);product_dns_proxy_key_t old=last_key;
  bank.dns.port=53053;++bank.dns_revision;
  product_root_dns_adapter_expire(&worker,++now_us);
  assert(owner->tcp_io && fixture_tcp_io.live && !product_dns_proxy_resources(owner->proxy).active);
  assert(tcp_reply_token==token && (tcp_reply_wire[3]&15)==2);root_dns_tcp_delivered(owner,token,1);
  before=tcp_reply_count;product_dns_proxy_answer(owner->proxy,&old,1,last_wire,last_length,++now_us);assert(tcp_reply_count==before);
  root_dns_tcp_query(owner,901,++token,question,sizeof(question),++now_us);answer(0);root_dns_tcp_delivered(owner,token,1);
  assert(owner->route.port==53053 && !owner->replies);
  lease.platform.uid=20234;lease.platform.availability=1;reset_terminal();
  assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&lease.terminal_intent==PRODUCT_PACKET_INTENT_DROP_RUNTIME);
  assert(binding->input.context.packet.uid==10123 && binding->input.context.caller==1);
  /* Config-off keeps the existing selected transport local, while a new
   * ordinary off-path incarnation has no Root takeover selection. */
  fixture_tcp_clients=1;
  bank.dns.enabled=0;++bank.dns_revision;product_root_dns_adapter_expire(&worker,++now_us);
  reset_terminal();lease.platform.uid=0;lease.platform.availability=0;
  assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent);
  entry.root_dns_tcp_taken=0;lease.platform.reserved=0;reset_terminal();
  assert(!root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent);
  bank.dns.enabled=1;++bank.dns_revision;product_root_dns_adapter_expire(&worker,++now_us);
  assert(owner->tcp_io && product_root_dns_tcp_io_status(owner->tcp_io).accepting && product_root_dns_adapter_ready());
  fixture_tcp_clients=0;
  root_dns_tcp_ended(owner,901,now_us);product_domains_destroy(bank.domains);bank.domains=NULL;
  close_owner();
 }
 tcp_reply_accept=0;
 puts("Root TCP source-linked captured SYN identity, Unknown later capture, per-query refusal/continue, view-failure drain, stale answer and off/closing selection: PASS");
}

static void tcp_unknown_caller(void) {
 tcp_reply_accept=1;
 for(unsigned family=4;family<=6;family+=2)for(unsigned known_uid=0;known_uid<=1;++known_uid) {
  initialize(77,family);
  lease.facts.protocol=6;lease.facts.l4_header_length=lease.facts.transport_length=20;
  lease.facts.tcp_flags=2;lease.facts.tcp_sequence=0x12345678;
  lease.platform.uid=10123;lease.platform.availability=known_uid?PRODUCT_PLATFORM_UID_KNOWN:0;
  lease.platform.reserved=PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE|PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID;
  buffers[0].flow_id=0x1007b;
  memset(buffers[0].data,0,sizeof(buffers[0].data));unsigned at=family==4?20:40;
  buffers[0].current_length=at+20;buffers[0].data[0]=family==4?0x45:0x60;
  buffers[0].data[family==4?9:6]=6;buffers[0].data[at+3]=53;buffers[0].data[at+13]=2;
  assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent);
  root_dns_owner_t *owner=&root_dns_owners[0];root_dns_tcp_binding_t *binding=&owner->tcp_bindings[0];
  product_root_dns_tcp_endpoint_t endpoint={.family=family,.saved_syn=1,.source_port=40000,.resolver_port=53,.syn_sequence=0x12345678};
  memcpy(endpoint.source_address,binding->input.context.packet.source_address,16);
  memcpy(endpoint.resolver_address,binding->input.context.packet.destination_address,16);
  assert(root_dns_tcp_accepted(owner,903,&endpoint));
  /* A later reliable capture is a new packet fact, not permission to invent
   * an original caller for the already admitted kernel socket. */
  lease.facts.tcp_flags=0x10;buffers[0].data[at+13]=0x10;
  lease.platform.availability=PRODUCT_PLATFORM_UID_KNOWN|PRODUCT_PLATFORM_DNS_APP_RELIABLE;
  buffers[0].flow_id=1U<<PRODUCT_ROOT_DNS_TCP_MARK_SHIFT;
  assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow)&&!lease.terminal_intent);
  assert(binding->input.context.caller==PRODUCT_DNS_CALLER_UNKNOWN);
  assert(binding->input.context.packet.uid_known==known_uid);
  assert(binding->input.capture_uid==10123 && binding->input.capture_availability==9);
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,.entries={{.length=11,.name="example.com"}}};
  assert(!product_domains_build(&source,&bank.domains));
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=317,.reason_id=317,.action=2,
   .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,
   .destination_port_last=UINT16_MAX,.expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&bank.view,&deny,1));
  unsigned before=sends;u64 token=(UINT64_C(1)<<63)|(family*100U+20U+known_uid);
  root_dns_tcp_query(owner,903,token,question,sizeof(question),++now_us);
  assert(sends==before+1);answer(0);
  assert(tcp_reply_token==token && (tcp_reply_wire[3]&15)==0);root_dns_tcp_delivered(owner,token,1);
  const product_dns_observation_record_t *record=&records[record_count-1];
  assert(record->caller==0 && record->uid==(known_uid?10123:UINT32_MAX));
  assert(!(record->availability&PRODUCT_PLATFORM_DNS_APP_RELIABLE) && !record->domain_available && !record->winner);
  assert(record->packet_uid==10123 && record->packet_availability==9);
  assert(record->protocol==6 && record->message_sequence==token && record->reply_capacity==65535);
  root_dns_tcp_ended(owner,903,now_us);product_domains_destroy(bank.domains);bank.domains=NULL;close_owner();
 }
 tcp_reply_accept=0;
 puts("Root TCP source-linked Unknown SYN caller stays Unknown after reliable capture and bypasses App DNS refusal: PASS");
}

static void vpn_tcp_off_records(int current_view) {
 vpn_tcp_fixture_enabled=1;start_profile=2;
 for(unsigned family=4;family<=6;family+=2) {
  unsigned first_record=record_count;
  initialize(77,family);
  assert(!product_root_dns_vpn_authorized(&worker,77,last_cookie,0,99,9,1));
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  lease.facts.protocol=6;lease.facts.l4_header_length=lease.facts.transport_length=20;
  lease.facts.tcp_flags=2;
  assert(vpn_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
  assert(entry.vpn_dns_tcp_decided&&entry.vpn_dns_tcp_taken);
  root_dns_owner_t *owner=&root_dns_owners[0];
  assert(owner->tcp_bindings[0].session==71);
  unsigned before=sends;
  product_root_dns_vpn_tcp_query(&worker,77,71,11,question,sizeof(question));
  assert(sends==before+1);answer(0);
  assert(vpn_tcp_reply_token==11&&vpn_tcp_reply_length==sizeof(question)+16);
  product_root_dns_vpn_tcp_done(&worker,77,71,11,1);
  product_dns_observation_record_t historical=records[first_record];
  product_root_dns_vpn_tcp_query(&worker,77,71,12,question,sizeof(question));
  assert(sends==before+2);
  product_dns_proxy_key_t old_pending=last_key;
  uint8_t old_answer[sizeof(question)+16];memcpy(old_answer,last_wire,sizeof(question));
  old_answer[2]=0x81;old_answer[3]=0x80;old_answer[7]=1;
  memcpy(old_answer+sizeof(question),(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
  bank.dns=(product_dns_proxy_route_t){0};++bank.dns_revision;
  product_root_dns_adapter_expire(&worker,++now_us);
  assert(vpn_tcp_reply_token==12&&(vpn_tcp_reply_wire[3]&15)==2);
  product_root_dns_vpn_tcp_done(&worker,77,71,12,1);
  before=sends;
  product_root_dns_vpn_tcp_query(&worker,77,71,13,question,sizeof(question));
  assert(sends==before&&vpn_tcp_reply_token==13&&(vpn_tcp_reply_wire[3]&15)==2);
  product_root_dns_vpn_tcp_done(&worker,77,71,13,1);
  assert(record_count==first_record+9);
  assert(!memcmp(&records[first_record],&historical,sizeof(historical)));
  for(unsigned i=record_count-3;i<record_count;++i) {
   assert(records[i].token==13&&records[i].protocol==6&&records[i].adapter_profile==2);
   assert(records[i].upstream_family==0&&records[i].upstream_port==0&&records[i].upstream_session==0);
   assert(!memcmp(records[i].upstream_address,(uint8_t[16]){0},16));
   assert(records[i].transport_session==71&&records[i].incarnation==8&&records[i].caller==1&&records[i].uid==10123);
  }
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,.entries={{.length=11,.name="example.com"}}};
  assert(!product_domains_build(&source,&bank.domains));
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=318,.reason_id=318,.action=2,
   .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
   .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&bank.view,&deny,1));
  product_root_dns_vpn_tcp_query(&worker,77,71,14,question,sizeof(question));
  assert(sends==before&&vpn_tcp_reply_token==14&&(vpn_tcp_reply_wire[3]&15)==5);
  product_root_dns_vpn_tcp_done(&worker,77,71,14,1);
  assert(!product_l4_policy_compile(&bank.view,NULL,0));
  uint8_t malformed[12]={0x12,0x34,1,0};
  product_root_dns_vpn_tcp_query(&worker,77,71,15,malformed,sizeof(malformed));
  assert(sends==before&&vpn_tcp_reply_token==15&&(vpn_tcp_reply_wire[3]&15)==1);
  product_root_dns_vpn_tcp_done(&worker,77,71,15,1);
  uint8_t opcode[sizeof(question)];memcpy(opcode,question,sizeof(opcode));opcode[2]=9;
  product_root_dns_vpn_tcp_query(&worker,77,71,16,opcode,sizeof(opcode));
  assert(sends==before&&vpn_tcp_reply_token==16&&(vpn_tcp_reply_wire[3]&15)==4);
  product_root_dns_vpn_tcp_done(&worker,77,71,16,1);
  unsigned before_reply=vpn_tcp_reply_count;
  product_root_dns_vpn_tcp_query(&worker,77,71,17,(uint8_t[]){0x12},1);
  assert(sends==before&&vpn_tcp_reply_count==before_reply&&records[record_count-1].proxy_result==PRODUCT_DNS_PROXY_NO_REPLY_IDENTITY);
  assert(record_count==first_record+16);
  product_domains_destroy(bank.domains);bank.domains=NULL;
  if(current_view) {
   u64 captured_route=owner->tcp_bindings[0].input.route_revision;
   u64 captured_network=owner->tcp_bindings[0].input.identity.network_revision;
   bank.dns=(product_dns_proxy_route_t){.enabled=1,.family=6,.port=53053,.address={0x20,1,0,0,0,0,0,0,0,0,0,0,0,0,0,53}};
   ++bank.dns_revision;++network.revision;++snapshot.identity.revision;++snapshot.identity.snapshot_hash;
   product_root_dns_adapter_expire(&worker,++now_us);
   assert(!product_root_dns_vpn_authorized(&worker,77,last_cookie,0,100,10,1));
   before=sends;
   product_root_dns_vpn_tcp_query(&worker,77,71,18,question,sizeof(question));
   assert(sends==before+1); /* A new message must use the current route/network. */
   assert(last_key.route_revision==bank.dns_revision&&last_key.network_revision==network.revision);
   answer(0);product_root_dns_vpn_tcp_done(&worker,77,71,18,1);
   product_root_dns_vpn_tcp_query(&worker,77,71,19,question,sizeof(question));
   assert(sends==before+2);
   unsigned delivered=vpn_tcp_reply_count;
   product_dns_proxy_answer(owner->proxy,&old_pending,1,old_answer,sizeof(old_answer),++now_us);
   assert(vpn_tcp_reply_count==delivered&&product_dns_proxy_resources(owner->proxy).active==1);
   answer(0);product_root_dns_vpn_tcp_done(&worker,77,71,19,1);
   assert(record_count==first_record+22);
   assert(owner->tcp_bindings[0].input.route_revision==captured_route&&owner->tcp_bindings[0].input.identity.network_revision==captured_network);
   for(unsigned i=record_count-6;i<record_count;++i) {
    assert(records[i].route_revision==bank.dns_revision&&records[i].network_revision==network.revision);
    assert(records[i].transport_session==71&&records[i].incarnation==8&&records[i].caller==1&&records[i].uid==10123);
    assert(records[i].upstream_family==6&&records[i].upstream_port==53053);
   }
   assert(!memcmp(&records[first_record],&historical,sizeof(historical)));
  }
  close_owner();
 }
 start_profile=1;vpn_tcp_fixture_enabled=0;
 puts("VPN selected TCP OFF: real no-upstream query/error/delivery observations, no dispatch and historical facts retained: PASS");
}

static void cache_resource_query(int protocol,u64 token,const uint8_t *wire) {
 if(protocol==17) {
  reset_terminal();memcpy(buffers[0].data+lease.facts.transport_offset+8,wire,sizeof(question));consume();
 } else if(start_profile==2)
  product_root_dns_vpn_tcp_query(&worker,77,71,token,wire,sizeof(question));
 else root_dns_tcp_query(&root_dns_owners[0],901,token,wire,sizeof(question),++now_us);
}
static void cache_resource_finish(int protocol,u64 token) {
 if(protocol==6&&start_profile==1)root_dns_tcp_delivered(&root_dns_owners[0],token,1);
 else if(protocol==6)product_root_dns_vpn_tcp_done(&worker,77,71,token,1);
 else if(start_profile==1){assert(pending());finish(0,0);}
 else {
  unsigned index=pending();assert(index);vlib_main_t tun_io={2};
  product_packet_completion_frame_t completion={.obligation=admitted_obligation[index],
   .terminal_intent=PRODUCT_PACKET_INTENT_PASS_ADAPTER};
  product_packet_lease_t returning={.platform=admitted_platform[index]};
  product_packet_graph_policy_evaluation_t policy={.generation=77,.revision=7,.snapshot_hash=789,
   .declared_action=1,.actual_action=1};
  root_dns_return_policy(&worker,index,&returning,&policy);
  product_root_dns_vpn_reply_complete(&tun_io,index,&completion,PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED);
  vlib_buffer_free(&worker,&index,1);submitted[index]=0;
  product_root_dns_vpn_reply_freed(&tun_io,index,&completion);
  product_root_dns_adapter_expire(&worker,++now_us);
 }
}
static void cache_resource_records(void) {
 for(start_profile=1;start_profile<=2;++start_profile)
  for(unsigned family=4;family<=6;family+=2)
   for(int protocol=17;protocol>=6;protocol-=11) {
    unsigned first=record_count,before=sends;
    vpn_tcp_fixture_enabled=start_profile==2&&protocol==6;tcp_reply_accept=1;
    initialize(77,family);buffers[0].data[0]=family==4?0x45:0x60;
    uint64_t baseline_bytes=product_dns_proxy_resources(root_dns_owners[0].proxy).owned_bytes;
    if(start_profile==2) {
     assert(!product_root_dns_vpn_authorized(&worker,77,last_cookie,0,99,9,1));
     lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
    }
    if(protocol==6) {
     lease.facts.protocol=6;lease.facts.l4_header_length=lease.facts.transport_length=20;
     lease.facts.tcp_flags=2;lease.facts.tcp_sequence=0x12345678;
     if(start_profile==2)assert(vpn_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
     else {
      lease.platform.reserved=PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE|PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID;
      memset(buffers[0].data,0,sizeof(buffers[0].data));unsigned at=family==4?20:40;
      buffers[0].current_length=at+20;buffers[0].data[0]=family==4?0x45:0x60;
      buffers[0].data[family==4?9:6]=6;buffers[0].data[at+3]=53;buffers[0].data[at+13]=2;
      assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
      root_dns_tcp_binding_t *binding=&root_dns_owners[0].tcp_bindings[0];
      product_root_dns_tcp_endpoint_t endpoint={.family=family,.saved_syn=1,.source_port=40000,.resolver_port=53,.syn_sequence=0x12345678};
      memcpy(endpoint.source_address,binding->input.context.packet.source_address,16);
      memcpy(endpoint.resolver_address,binding->input.context.packet.destination_address,16);
      assert(root_dns_tcp_accepted(&root_dns_owners[0],901,&endpoint));
     }
    }
    uint8_t wire[sizeof(question)];memcpy(wire,question,sizeof(wire));
    for(unsigned scenario=0;scenario<5;++scenario) {
     u64 token=(start_profile==1?UINT64_C(1)<<63:0)|(100+scenario);
     unsigned start=record_count,failed=fault_failures;
     wire[1]=(uint8_t)(0x34+scenario);
     /* The last case is an uncached question, with only output allocation
      * armed after the genuine upstream request has already been sent. */
     if(scenario==4)wire[13]='z';
     fault_bytes=sizeof(question)+16;fault_matches=0;
     fault_nth=scenario==2?1:scenario==3?2:0;
     cache_resource_query(protocol,token,wire);
     if(scenario==0||scenario==4) {
      assert(sends==before+1+(scenario==4));
      if(scenario==4)fault_nth=1;
      answer_ttl(0,30);
     } else assert(sends==before+1);
     assert(!fault_nth&&fault_failures==failed+(scenario>=2));
     assert(record_count==start+2);
     const product_dns_observation_record_t *r=&records[record_count-1];
     assert(r->stage==(scenario>=2?3:2));
     assert(r->proxy_result==(scenario>=2?PRODUCT_DNS_PROXY_CAPACITY:scenario==1?PRODUCT_DNS_PROXY_CACHE:PRODUCT_DNS_PROXY_UPSTREAM));
     unsigned expected_flags=PRODUCT_DNS_PROXY_RECORD|
      (scenario==1||scenario==3?PRODUCT_DNS_PROXY_CACHE_ANSWER:scenario==0||scenario==4?PRODUCT_DNS_PROXY_UPSTREAM_ANSWER:0);
     assert(r->proxy_flags==expected_flags&&r->reply_rcode==(scenario>=2?2:0));
     assert(r->actual_action==(scenario==2?0:PRODUCT_L4_POLICY_ACTION_ALLOW));
     /* Scratch failure occurs before parsing/acquiring a current response;
      * only the later output failures have actual response-policy facts. */
     assert(!r->winner && r->policy_revision==(scenario==2?0:snapshot.identity.revision) &&
       r->policy_hash==(scenario==2?0:snapshot.identity.snapshot_hash));
     assert(r->output_bytes==(scenario>=2?sizeof(question):sizeof(question)+16));
     assert(r->delivery==(protocol==6?PRODUCT_DNS_DELIVERY_SOCKET_QUEUED:PRODUCT_DNS_DELIVERY_GRAPH_ACCEPTED));
     assert(r->direction==(scenario>=2?3:1));
     assert(r->id==((uint16_t)wire[0]<<8|wire[1]));
     cache_resource_finish(protocol,token);
     assert(record_count==start+3&&records[record_count-1].stage==4);
     assert(records[record_count-1].proxy_flags==expected_flags);
     assert(records[record_count-1].proxy_result==r->proxy_result);
     product_dns_proxy_resources_t resources=product_dns_proxy_resources(root_dns_owners[0].proxy);
     assert(!resources.active&&resources.owned_bytes==baseline_bytes&&resources.cache_entries>=1);
    }
    assert(record_count==first+15);close_owner();assert(raw_created==raw_closed);
   }
 start_profile=1;vpn_tcp_fixture_enabled=0;tcp_reply_accept=0;
 assert(fault_failures==24);
 puts("Root/VPN UDP/TCP dual-stack real cache scratch/output and upstream output malloc failures: PASS");
}

/* Exercise the existing real Adapter entry/return/normal observation ABI.
 * Only VPP and platform/socket dependencies are controlled here; these are
 * Host records, never ordinary Android App or real-kernel wire claims. */
static void coalescing_setup(unsigned family,int protocol) {
 vpn_tcp_fixture_enabled=start_profile==2&&protocol==6;tcp_reply_accept=1;
 initialize(77,family);buffers[0].data[0]=family==4?0x45:0x60;
 if(start_profile==2) {
  assert(!product_root_dns_vpn_authorized(&worker,77,last_cookie,0,99,9,1));
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
 }
 if(protocol==6) {
  lease.facts.protocol=6;lease.facts.l4_header_length=lease.facts.transport_length=20;
  lease.facts.tcp_flags=2;lease.facts.tcp_sequence=0x12345678;
  if(start_profile==2)assert(vpn_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
  else {
   lease.platform.reserved=PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE|PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID;
   memset(buffers[0].data,0,sizeof(buffers[0].data));unsigned at=family==4?20:40;
   buffers[0].current_length=at+20;buffers[0].data[0]=family==4?0x45:0x60;
   buffers[0].data[family==4?9:6]=6;buffers[0].data[at+3]=53;buffers[0].data[at+13]=2;
   assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
   root_dns_tcp_binding_t *binding=&root_dns_owners[0].tcp_bindings[0];
   product_root_dns_tcp_endpoint_t endpoint={.family=family,.saved_syn=1,.source_port=40000,.resolver_port=53,.syn_sequence=0x12345678};
   memcpy(endpoint.source_address,binding->input.context.packet.source_address,16);
   memcpy(endpoint.resolver_address,binding->input.context.packet.destination_address,16);
   assert(root_dns_tcp_accepted(&root_dns_owners[0],901,&endpoint));
  }
 }
}

static void ordered_routing_records(void) {
 for(start_profile=1;start_profile<=2;++start_profile)
  for(unsigned family=4;family<=6;family+=2)
   for(int protocol=17;protocol>=6;protocol-=11) {
    coalescing_setup(family,protocol);
    bank.dns=(product_dns_proxy_route_t){.enabled=1,.family=4,.port=15353,.address={198,51,100,53},
      .endpoint_count=2,.route_count=1,
      .endpoints={{.transport=1,.family=4,.port=15353,.address={198,51,100,53},.identity="primary.test"},
        {.transport=1,.family=4,.port=15354,.address={198,51,100,54},.identity="backup.test"}},
      .routes={{.count=2,.candidates={0,1}}}};
    ++bank.dns_revision;product_root_dns_adapter_expire(&worker,++now_us);
    if(start_profile==2)assert(!product_root_dns_vpn_authorized(&worker,77,last_cookie,0,99,9,1));
    unsigned first=record_count,before=sends;
    u64 token=(start_profile==1?UINT64_C(1)<<63:0)|13;
    cache_resource_query(protocol,token,question);
    assert(sends==before+1 && record_count==first+2 && last_key.resolver_id==1);
    u64 primary=last_key.attempt;now_us+=PRODUCT_DNS_PROXY_ATTEMPT_US;
    product_root_dns_adapter_expire(&worker,now_us);
    assert(sends==before+2 && record_count==first+4 && last_key.resolver_id==2);
    assert(last_key.resolver_port==15354 && last_key.resolver_address[3]==54);
    u64 backup=last_key.attempt;assert(backup!=primary);
    answer(0);cache_resource_finish(protocol,token);
    assert(record_count==first+6);
    const unsigned stages[]={1,5,5,5,2,4},resolvers[]={1,1,1,2,2,2};
    for(unsigned i=0;i<6;++i) {
      const product_dns_observation_record_t *record=&records[first+i];
      assert(record->stage==stages[i] && record->resolver_id==resolvers[i] && record->resolution_route==0);
      assert(record->length==720 && record->version==9 && record->adapter_profile==start_profile
        && record->protocol==protocol && record->family==family && record->uid==10123 && record->caller==1);
      assert(record->token==records[first].token && record->request_attempt==records[first].request_attempt);
      assert(record->upstream_attempt==(i==0?0:i<3?primary:backup));
      if(record->stage==5)assert(record->proxy_result==(i==2?14:12) && !record->actual_action
        && !record->declared_action && !record->delivery && !record->policy_generation && !record->upstream_session);
    }
    assert(!product_dns_proxy_resources(root_dns_owners[0].proxy).active && !pending());
    close_owner();assert(raw_created==raw_closed);
   }
 start_profile=1;vpn_tcp_fixture_enabled=0;tcp_reply_accept=0;
 assert(record_count==48);
 puts("Root/VPN UDP/TCP dual-stack ordered attempts: 48 actual normal view/timeout/delivery records PASS");
}
static product_dns_proxy_key_t record_key(const product_dns_observation_record_t *r) {
 return(product_dns_proxy_key_t){.generation=r->generation,.token=r->token,.incarnation=r->incarnation,
  .attempt=r->request_attempt,.network_revision=r->network_revision,.route_revision=r->route_revision};
}
/* Separate trusted App channels are created before either query. No live
 * session changes its caller, and the one shared answer never carries policy. */
static void coalescing_independent_app_channels(void) {
 for(start_profile=1;start_profile<=2;++start_profile)
  for(unsigned family=4;family<=6;family+=2)
   for(int protocol=17;protocol>=6;protocol-=11) {
    dual_channels=1;memset(channel_replies,0,sizeof(channel_replies));
    assert(!product_l4_policy_compile(&bank.view,NULL,0));coalescing_setup(family,protocol);
    second_entry=entry;second_entry.incarnation=9;second_entry.root_dns_tcp_taken=0;
    second_entry.vpn_dns_tcp_decided=second_entry.vpn_dns_tcp_taken=0;
    product_flow_entry_observation_t second_flow=flow;second_flow.entry=&second_entry;second_flow.slot=4;
    product_packet_lease_t second_lease=lease;
    /* A second SYN is a fresh original packet obligation. The first VPN SYN
     * was already consumed; copying its terminal state is not a new input. */
    second_lease.terminal_intent=second_lease.terminal_count=0;second_lease.runtime_drop_reason=0;
    second_lease.platform.uid=10124;second_lease.facts.source_port=40001;
    second_lease.facts.tcp_sequence=0x22345678;second_lease.origin_obligation_id+=5000;
    if(protocol==6) {
     if(start_profile==2)assert(vpn_dns_tcp_capture(&worker,0,&second_lease,&snapshot,&second_flow));
     else {
      assert(root_dns_tcp_capture(&worker,0,&second_lease,&snapshot,&second_flow));
      root_dns_tcp_binding_t *binding=&root_dns_owners[0].tcp_bindings[1];
      product_root_dns_tcp_endpoint_t endpoint={.family=family,.saved_syn=1,.source_port=40001,.resolver_port=53,.syn_sequence=0x22345678};
      memcpy(endpoint.source_address,binding->input.context.packet.source_address,16);
      memcpy(endpoint.resolver_address,binding->input.context.packet.destination_address,16);
      assert(root_dns_tcp_accepted(&root_dns_owners[0],902,&endpoint));
     }
    }
    unsigned first=record_count,before=sends,before_cancel=cancelled;
    u64 prefix=start_profile==1?UINT64_C(1)<<63:0,first_token=prefix|500,second_token=prefix|501;
    cache_resource_query(protocol,first_token,question);
    uint8_t follow[sizeof(question)];memcpy(follow,question,sizeof(follow));follow[0]=0xab;follow[1]=0xcd;
    if(protocol==17){
     second_lease.terminal_intent=second_lease.terminal_count=0;
     memcpy(buffers[0].data+second_lease.facts.transport_offset+8,follow,sizeof(follow));
     assert(root_dns_intercept(&worker,0,&second_lease,&snapshot,&second_flow));
    } else if(start_profile==2)product_root_dns_vpn_tcp_query(&worker,77,72,second_token,follow,sizeof(follow));
    else root_dns_tcp_query(&root_dns_owners[0],902,second_token,follow,sizeof(follow),++now_us);
    assert(record_count==first+2&&sends==before+1&&!pending());
    product_dns_proxy_resources_t state=product_dns_proxy_resources(root_dns_owners[0].proxy);
    assert(state.active==2&&state.exchanges==1&&!state.cache_entries);
    assert(records[first].uid==10123&&records[first+1].uid==10124);
    assert(records[first].source_port==40000&&records[first+1].source_port==40001);
    if(protocol==6){assert(records[first].transport_session==(start_profile==1?901:71));
     assert(records[first+1].transport_session==(start_profile==1?902:72));}
    else if(start_profile==2)assert(records[first].transport_session==71&&records[first+1].transport_session==72);
    product_l4_policy_rule_t deny={.uid=10123,.rule_id=320,.reason_id=320,.action=2,
     .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX};
    assert(!product_l4_policy_compile(&bank.view,&deny,1));++snapshot.identity.revision;
    answer_ttl(0,30);assert(cancelled==before_cancel+1&&sends==before+1);
    if(protocol==6||start_profile==2){
     for(unsigned i=0;i<2;++i){assert(channel_replies[i].calls==1);
      assert(channel_replies[i].id==(i?0xabcd:0x1234)&&channel_replies[i].rcode==(i?0:5));
      assert(channel_replies[i].uid==10123+i);
      if(protocol==6)assert(channel_replies[i].token==(i?second_token:first_token));}
    }
    if(protocol==17){
     for(unsigned i=0;i<2;++i){unsigned index=pending();assert(index&&admitted_platform[index].uid==10123+i);
      if(start_profile==1){unsigned ip=family==4?20:40;const uint8_t *wire=buffers[index].data;
       assert(((unsigned)wire[ip+2]*256+wire[ip+3])==40000+i);
       assert(((unsigned)wire[ip+8]*256+wire[ip+9])==(i?0xabcd:0x1234));assert((wire[ip+11]&15)==(i?0:5));}
      cache_resource_finish(protocol,0);}
    } else if(start_profile==1){root_dns_tcp_delivered(&root_dns_owners[0],first_token,1);root_dns_tcp_delivered(&root_dns_owners[0],second_token,1);}
    else{product_root_dns_vpn_tcp_done(&worker,77,71,first_token,1);product_root_dns_vpn_tcp_done(&worker,77,72,second_token,1);}
    assert(record_count==first+6&&!pending());
    unsigned stages[5]={0};
    for(unsigned i=first;i<record_count;++i){const product_dns_observation_record_t *r=&records[i];unsigned app=r->id==0xabcd;
     assert(r->id==(app?0xabcd:0x1234)&&r->uid==10123+app&&r->caller==1&&r->source_port==40000+app);
     assert(r->incarnation==8+app&&r->adapter_profile==start_profile&&r->protocol==protocol&&r->family==family);
     assert(r->token==records[first+app].token&&r->transport_session==records[first+app].transport_session);
     /* Both independent channels were captured with known reliable SYN/input
      * facts and no later Unknown capture; preserve those actual facts. */
     if(r->packet_uid!=10123+app||r->packet_availability!=9)
      fprintf(stderr,"cross-channel actual capture profile=%u protocol=%d id=%u packet_uid=%u availability=%u\n",
       start_profile,protocol,r->id,r->packet_uid,r->packet_availability);
     assert(r->packet_uid==10123+app&&r->packet_availability==9);
     if(r->stage==2||r->stage==4){assert(r->query_token==r->token&&r->query_incarnation==r->incarnation);
      assert(r->query_policy_revision==3&&r->policy_revision==4&&r->reply_rcode==(app?0:5));
      assert(r->proxy_result==(app?PRODUCT_DNS_PROXY_UPSTREAM:PRODUCT_DNS_PROXY_REFUSED));}
     if(r->stage==4)assert(r->delivery==2);
     ++stages[r->stage];
    }
    assert(stages[1]==2&&stages[2]==2&&stages[4]==2);
    assert(product_dns_proxy_resources(root_dns_owners[0].proxy).cache_entries==1);
    close_owner();assert(raw_created==raw_closed);dual_channels=0;
   }
 start_profile=1;vpn_tcp_fixture_enabled=0;tcp_reply_accept=0;
 puts("PASS8 controlled actual Adapter independent reliableApp/channel groups:10123 REFUSED/10124 allowed fromoneexchange aftercurrentpolicy publication");
}

static void coalescing_records(void) {
 for(start_profile=1;start_profile<=2;++start_profile)
  for(unsigned family=4;family<=6;family+=2)
   for(int protocol=17;protocol>=6;protocol-=11)
    for(unsigned scenario=0;scenario<8;++scenario) {
     assert(!product_l4_policy_compile(&bank.view,NULL,0));coalescing_setup(family,protocol);
     root_dns_owner_t *owner=&root_dns_owners[0];product_dns_proxy_t *proxy=owner->proxy;
     uint64_t baseline_bytes=product_dns_proxy_resources(proxy).owned_bytes;
     unsigned first=record_count,before=sends,before_cancel=cancelled;
     uint8_t follow[sizeof(question)];memcpy(follow,question,sizeof(follow));follow[0]=0xab;follow[1]=0xcd;
     const u64 prefix=start_profile==1?UINT64_C(1)<<63:0;
     /* Each scenario is an independent controlled owner lifetime. Keep its
      * TCP tokens unique in the combined normal-store evidence as well. */
     const u64 token_first=prefix|(100+2*scenario),token_second=prefix|(101+2*scenario);
     cache_resource_query(protocol,token_first,question);uint64_t original_deadline=last_deadline;
     product_dns_proxy_key_t first_key=record_key(&records[first]);
     cache_resource_query(protocol,token_second,follow);product_dns_proxy_key_t second_key=record_key(&records[first+1]);
     assert(record_count==first+2&&sends==before+1&&!pending());
     assert(records[first].stage==1&&records[first+1].stage==1&&first_key.token!=second_key.token);
     product_dns_proxy_resources_t r=product_dns_proxy_resources(proxy);
     assert(r.active==2&&r.exchanges==1&&r.coalesced==1&&r.cache_entries==0);
     assert(r.owned_bytes==baseline_bytes+sizeof(question));
     unsigned cancelled_waiters=0,outputs=2;
     if(scenario==1){product_dns_proxy_cancel(proxy,&first_key,++now_us);cancelled_waiters=1;outputs=1;
      assert(product_dns_proxy_resources(proxy).active==1&&cancelled==before_cancel);}
     else if(scenario==2){product_dns_proxy_cancel(proxy,&first_key,++now_us);product_dns_proxy_cancel(proxy,&second_key,++now_us);
      cancelled_waiters=2;outputs=0;}
     else if(scenario==3){product_root_dns_adapter_quiesce(&worker);cancelled_waiters=2;outputs=0;}
     else if(scenario==4){product_dns_proxy_advance(proxy,++now_us,5,4);}
     else if(scenario==5){now_us=original_deadline;product_dns_proxy_advance(proxy,now_us,5,3);}
     else if(scenario==6){product_l4_policy_rule_t deny={.uid=10123,.rule_id=320,.reason_id=320,.action=2,
       .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX};
      assert(!product_l4_policy_compile(&bank.view,&deny,1));++snapshot.identity.revision;}
     else if(scenario==7){uint8_t tc[sizeof(question)];memcpy(tc,last_wire,sizeof(tc));tc[2]=0x83;tc[3]=0x80;
      product_dns_proxy_answer(proxy,&last_key,1,tc,sizeof(tc),++now_us);
      assert(sends==before+2&&last_transport==2&&last_deadline==original_deadline);}
     if(scenario==0||scenario==1||scenario==6||scenario==7)answer_ttl(0,30);
     assert(product_dns_proxy_resources(proxy).active==0&&product_dns_proxy_resources(proxy).exchanges==0);
     assert(cancelled==before_cancel+1);
     if(outputs){
      if(scenario!=1)cache_resource_finish(protocol,token_first);
      cache_resource_finish(protocol,token_second);
     }
     assert(!pending());r=product_dns_proxy_resources(proxy);
     assert(r.owned_bytes==baseline_bytes&&r.cancelled==cancelled_waiters);
     unsigned stages[5]={0},ids[2]={0};
     for(unsigned i=first;i<record_count;++i){
      const product_dns_observation_record_t *record=&records[i];assert(record->stage<5);++stages[record->stage];
      assert(record->generation==77&&record->adapter_profile==start_profile&&record->family==family&&record->protocol==protocol);
      assert(record->id==0x1234||record->id==0xabcd);++ids[record->id==0xabcd];
      if(record->stage==2||record->stage==3){
       assert(record->query_token==record->token&&record->query_incarnation==record->incarnation);
       if(scenario==6){assert(record->proxy_result==PRODUCT_DNS_PROXY_REFUSED&&record->reply_rcode==5);
        assert(record->policy_revision>record->query_policy_revision&&record->winner==320);}
       if(scenario==4)assert(record->proxy_result==PRODUCT_DNS_PROXY_VIEW_CHANGED&&record->reply_rcode==2);
       if(scenario==5)assert(record->proxy_result==PRODUCT_DNS_PROXY_SERVFAIL&&record->reply_rcode==2);
      }
     }
     assert(stages[1]==2&&stages[4]==outputs&&stages[2]+stages[3]==2);
     assert(ids[0]==(scenario==1?2U:outputs?3U:2U)&&ids[1]==(outputs?3U:2U));
     unsigned completed=record_count;answer_ttl(0,30);product_dns_proxy_fail(proxy,&first_key,++now_us);
     product_dns_proxy_cancel(proxy,&second_key,++now_us);
     assert(record_count==completed&&!pending()&&cancelled==before_cancel+1);
     assert(r.cache_entries==(scenario==0||scenario==1||scenario==6||scenario==7));
     close_owner();assert(raw_created==raw_closed);
    }
 start_profile=1;vpn_tcp_fixture_enabled=0;tcp_reply_accept=0;
 puts("PASS64 controlled Root/VPN Adapter dualstack UDP/TCP coalescing/currentpolicy/cancel/allcancel/Stop/view/strictcandidate/TC normal ABI groups");
}

static void shutdown_prefix_records(void) {
 for(start_profile=1;start_profile<=2;++start_profile)
  for(unsigned family=4;family<=6;family+=2)
   for(int protocol=17;protocol>=6;protocol-=11) {
    unsigned first=record_count,before=sends;
    vpn_tcp_fixture_enabled=start_profile==2&&protocol==6;
    initialize(77,family);
    buffers[0].data[0]=family==4?0x45:0x60;
    if(start_profile==2) {
     assert(!product_root_dns_vpn_authorized(&worker,77,last_cookie,0,99,9,1));
     lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
    }
    if(protocol==17)consume();
    else {
     lease.facts.protocol=6;lease.facts.l4_header_length=lease.facts.transport_length=20;
     lease.facts.tcp_flags=2;lease.facts.tcp_sequence=0x12345678;
     if(start_profile==2) {
      assert(vpn_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
      product_root_dns_vpn_tcp_query(&worker,77,71,13,question,sizeof(question));
     } else {
      lease.platform.reserved=PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE|PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID;
      memset(buffers[0].data,0,sizeof(buffers[0].data));unsigned at=family==4?20:40;
      buffers[0].current_length=at+20;buffers[0].data[0]=family==4?0x45:0x60;
      buffers[0].data[family==4?9:6]=6;buffers[0].data[at+3]=53;buffers[0].data[at+13]=2;
      assert(root_dns_tcp_capture(&worker,0,&lease,&snapshot,&flow));
      root_dns_owner_t *owner=&root_dns_owners[0];root_dns_tcp_binding_t *binding=&owner->tcp_bindings[0];
      product_root_dns_tcp_endpoint_t endpoint={.family=family,.saved_syn=1,.source_port=40000,.resolver_port=53,.syn_sequence=0x12345678};
      memcpy(endpoint.source_address,binding->input.context.packet.source_address,16);
      memcpy(endpoint.resolver_address,binding->input.context.packet.destination_address,16);
      assert(root_dns_tcp_accepted(owner,901,&endpoint));
      root_dns_tcp_query(owner,901,UINT64_C(1)<<63|13,question,sizeof(question),++now_us);
     }
    }
    assert(sends==before+1&&product_dns_proxy_resources(root_dns_owners[0].proxy).active==1);
    product_dns_proxy_key_t key=last_key;
    product_root_dns_adapter_quiesce(&worker);
    assert(record_count==first+2);
    const product_dns_observation_record_t *query=&records[first],*stopped=&records[first+1];
    assert(query->stage==1&&stopped->stage==3&&stopped->proxy_result==PRODUCT_DNS_PROXY_STOPPED);
    assert(query->token==stopped->token&&query->incarnation==stopped->incarnation&&query->source_port==stopped->source_port);
    assert(query->protocol==protocol&&stopped->adapter_profile==start_profile&&stopped->family==family);
    assert(!product_dns_proxy_resources(root_dns_owners[0].proxy).active&&!pending());
    unsigned count=record_count;product_dns_proxy_answer(root_dns_owners[0].proxy,&key,1,last_wire,last_length,++now_us);
    assert(record_count==count&&!pending());close_owner();
   }
 start_profile=1;vpn_tcp_fixture_enabled=0;
 puts("Root/VPN UDP/TCP dual-stack pending Stop: exact QUERY/STOPPED identity, no delivery or late replay: PASS");
}

#ifdef PRODUCT_ROOT_DNS_REAL_IO
#include "product_root_dns_tls_view_test.inc"
#endif

int main(int argc,char **argv) {
#ifdef PRODUCT_ROOT_DNS_REAL_IO
 if(argc>1&&!strcmp(argv[1],"tls-view")) {tls_view_replacement();return 0;}
#endif
 assert(!product_l4_policy_compile(&bank.view,NULL,0));
 if(argc>1&&!strcmp(argv[1],"routing")) {
  ordered_routing_records();
  if(argc>2){
   FILE *out=fopen(argv[2],"wb");assert(out);
   for(unsigned i=0;i<record_count;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);
   assert(!fclose(out));
  }
  return 0;
 }
 if(argc>1&&!strcmp(argv[1],"coalescing")) {
  coalescing_records();coalescing_independent_app_channels();
  if(argc>2){FILE *out=fopen(argv[2],"wb");assert(out);for(unsigned i=0;i<record_count;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);assert(!fclose(out));}
  printf("Root/VPN coalescing normal records=%u\n",record_count);return 0;
 }
 if(argc>1&&!strcmp(argv[1],"cache-resource")) {
  cache_resource_records();assert(record_count==120);
  if(argc>2){FILE *out=fopen(argv[2],"wb");assert(out);for(unsigned i=0;i<record_count;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);assert(!fclose(out));}
  printf("Root/VPN allocation normal records=%u\n",record_count);return 0;
 }
 if(argc>1&&!strcmp(argv[1],"shutdown-prefix")) {
  shutdown_prefix_records();assert(record_count==16);
  if(argc>2){FILE *out=fopen(argv[2],"wb");assert(out);for(unsigned i=0;i<record_count;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);assert(!fclose(out));}
  printf("Root/VPN STOP normal records=%u\n",record_count);return 0;
 }
 if(argc>1&&(!strcmp(argv[1],"vpn-tcp-off")||!strcmp(argv[1],"vpn-tcp-view"))) {
  vpn_tcp_off_records(!strcmp(argv[1],"vpn-tcp-view"));
  if(argc>2){FILE *out=fopen(argv[2],"wb");assert(out);for(unsigned i=0;i<record_count;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);assert(!fclose(out));}
  printf("VPN TCP OFF normal records=%u\n",record_count);return 0;
 }
 if(argc>1&&!strcmp(argv[1],"tcp-proxy")){
  tcp_proxy_identity();
  if(argc>2){FILE *out=fopen(argv[2],"wb");assert(out);for(unsigned i=0;i<record_count;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);assert(!fclose(out));}
  printf("Root TCP normal records=%u\n",record_count);return 0;
 }
 if(argc>1&&!strcmp(argv[1],"cache")){cache_records();return 0;}
 if(argc>1&&!strcmp(argv[1],"tcp-unknown")){tcp_unknown_caller();return 0;}
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
 if(argc>1){FILE *out=fopen(argv[1],"wb");assert(out);for(unsigned i=0;i<semantic_records;++i)assert(fwrite(&records[i],1,records[i].length,out)==records[i].length);assert(!fclose(out));}
 printf("Root DNS actual Adapter wire/verdict/return/policy/capacity/cancel/stop/stale fixture: PASS records=%u semantic_export=%u\n",record_count,semantic_records);
}
