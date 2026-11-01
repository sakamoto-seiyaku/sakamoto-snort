#!/usr/bin/env python3
"""Exercise the actual VPN UID broker client through its socket/lookup seam.

Only VPP registration, time and the admitted-flow incarnation dependency are
controlled. Real nonblocking SEQPACKET messages carry the Product envelopes.
This is host lifecycle evidence, not Android getConnectionOwnerUid evidence.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'src/product/vpp/product_vpn_uid_resolver.c').read_text()
source = re.sub(r'^#include[^\n]*\n', '', source, flags=re.M)



prefix = r'''
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "product_packet.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { int unused; } product_flow_runtime_t;
typedef const char clib_error_t;
typedef struct clib_file_s clib_file_t;
struct clib_file_s {
  int file_descriptor;
  u32 polling_thread_index;
  u64 private_data;
  clib_error_t *(*read_function)(clib_file_t *);
  clib_error_t *(*error_function)(clib_file_t *);
  char *description;
};
#define PRODUCT_VPN_RETURN_WORKERS 2
#define clib_net_to_host_u64 be64toh
#define clib_host_to_net_u64 htobe64
#define format(...) NULL
static int file_main;
static clib_file_t registered[2];
static unsigned registered_count, closed_count, enrichments;
static u64 timestamp=UINT64_C(10000000000), incarnation=1;
static u64 live_generation=77;
static int fixture_clock_gettime(clockid_t which, struct timespec *value) {
  assert(which==CLOCK_MONOTONIC);
  value->tv_sec=timestamp/UINT64_C(1000000000);
  value->tv_nsec=timestamp%UINT64_C(1000000000); return 0;
}
#define clock_gettime fixture_clock_gettime
static double vlib_time_now(vlib_main_t *vm) { assert(vm->thread_index==1); return timestamp/1e9; }
static u32 vlib_get_worker_index(u32 thread) { assert(thread); return thread-1; }
static u32 vlib_get_worker_thread_index(u32 owner) { return owner+1; }
static u32 product_packet_graph_worker_count(void) { return 2; }
static int product_vpn_tun_product_mode(void) { return 1; }
static u32 clib_file_add(int *files, clib_file_t *file) {
  assert(files==&file_main && registered_count<2);
  registered[registered_count]=*file; return registered_count++;
}
static void clib_file_del_by_index(int *files, u32 index) {
  assert(files==&file_main && index<registered_count);
  assert(close(registered[index].file_descriptor)==0); ++closed_count;
}
static u64 product_flow_entry_current_incarnation(product_flow_runtime_t *pool,
  const product_owner_assignment_t *assignment, u64 generation, u64 now) {
  assert(pool && assignment->valid && now);
  return generation==live_generation ? incarnation : 0;
}
static int product_flow_entry_enrich_uid(product_flow_runtime_t *pool,
  const product_owner_assignment_t *assignment, u64 generation, u64 flow,
  u32 uid, u64 now) {
  assert(pool && assignment->valid && generation==live_generation && flow==incarnation && now && uid!=UINT32_MAX);
  ++enrichments; return uid==20000 ? 2 : 1;   /* 20000: the tuple now belongs to another App */
}
'''

suffix = r'''
static uid_request_t receive_request(int peer) {
  uid_request_t request;
  assert(recv(peer,&request,sizeof(request),MSG_DONTWAIT)==sizeof(request));
  assert(ntohl(request.magic)==UID_MAGIC && ntohl(request.kind)==UID_REQUEST);
  return request;
}
static void respond(int peer, uid_request_t request, u32 uid) {
  uid_response_t response={.magic=htonl(UID_MAGIC),.kind=htonl(UID_RESPONSE),
    .generation=request.generation,.request=request.request,.uid=htonl(uid)};
  assert(send(peer,&response,sizeof(response),MSG_DONTWAIT)==sizeof(response));
  registered[0].read_function(&registered[0]);
}
static product_platform_packet_facts_t lookup(vlib_main_t *vm,product_flow_runtime_t *pool,
  product_owner_assignment_t *assignment,product_packet_facts_t *facts) {
  product_platform_packet_facts_t platform={.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN,
    .direction=PRODUCT_PACKET_DIRECTION_OUTPUT};
  assert(product_vpn_uid_resolver_identify(vm,pool,assignment,facts,&platform,live_generation)==1);
  return platform;
}
static void processed(vlib_main_t *vm,product_flow_runtime_t *pool,
  product_owner_assignment_t *assignment,product_packet_facts_t *facts,u64 observed) {
  product_platform_packet_facts_t platform={.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN,
    .direction=PRODUCT_PACKET_DIRECTION_OUTPUT};
  product_vpn_uid_resolver_flow_processed(vm,pool,assignment,facts,&platform,live_generation,observed);
}
static int nothing_sent(int peer) {
  uid_request_t request;
  return recv(peer,&request,sizeof(request),MSG_DONTWAIT)<0 && (errno==EAGAIN||errno==EWOULDBLOCK);
}
int main(void) {
  int channels[2][2];
  vlib_main_t vm={1}; product_flow_runtime_t pool={0};
  product_owner_assignment_t assignment={.valid=1,.execution_owner=0};
  product_packet_facts_t facts={.ip_family=4,.protocol=17,
    .source_port=40000,.destination_port=53,.l4_status=PRODUCT_PACKET_L4_COMPLETE};
  facts.source_address[12]=10; facts.source_address[15]=2;
  facts.destination_address[12]=192; facts.destination_address[15]=53;
  product_vpn_uid_resolver_start(live_generation);
  for(unsigned i=0;i<2;++i) {
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,channels[i]));
    assert(!product_vpn_uid_resolver_attach(channels[i][0],i));
  }
  assert(product_vpn_uid_resolver_ready());
  /* Product mode identifies device-origin packets only; a return packet is left untouched. */
  product_platform_packet_facts_t inbound={.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN,
    .direction=PRODUCT_PACKET_DIRECTION_INPUT,.availability=PRODUCT_PLATFORM_DNS_APP_RELIABLE};
  assert(!product_vpn_uid_resolver_identify(&vm,&pool,&assignment,&facts,&inbound,live_generation));
  assert(inbound.availability==PRODUCT_PLATFORM_DNS_APP_RELIABLE);
  /* A packet dropped before any Flow exists creates no query state and sends nothing. */
  u64 admitted=incarnation; incarnation=0;
  processed(&vm,&pool,&assignment,&facts,0);
  assert(nothing_sent(channels[0][1]));
  incarnation=admitted;
  product_platform_packet_facts_t cold=lookup(&vm,&pool,&assignment,&facts);
  assert(!cold.availability); /* Lookup neither waits nor initiates work. */
  processed(&vm,&pool,&assignment,&facts,incarnation);
  uid_request_t request=receive_request(channels[0][1]);
  assert(request.family==4 && request.protocol==17 && ntohs(request.local_port)==40000);
  assert(ntohs(request.remote_port)==53 && !memcmp(request.remote,facts.destination_address,16));
  respond(channels[0][1],request,10123);
  unsigned enriched=enrichments;
  product_platform_packet_facts_t app=lookup(&vm,&pool,&assignment,&facts);
  assert(enrichments==enriched+1); /* identify records the known UID on the current Flow */
  assert(app.uid==10123 && (app.availability&PRODUCT_PLATFORM_UID_KNOWN));
  assert(app.availability&PRODUCT_PLATFORM_DNS_APP_RELIABLE);
  assert(!cold.availability); /* The completed cold query remains Unknown. */
  for(unsigned i=0;i<7;++i) {
    const u32 system[]={1000,1051,2000,9999,90000,99000,UINT32_MAX};
    timestamp+=UINT64_C(300000000);
    processed(&vm,&pool,&assignment,&facts,incarnation);
    request=receive_request(channels[0][1]);
    assert(!lookup(&vm,&pool,&assignment,&facts).availability);
    respond(channels[0][1],request,system[i]);
    product_platform_packet_facts_t delegated=lookup(&vm,&pool,&assignment,&facts);
    assert(((delegated.availability&PRODUCT_PLATFORM_UID_KNOWN)!=0) == (system[i]!=UINT32_MAX));
    if(system[i]!=UINT32_MAX) assert(delegated.uid==system[i]);
    assert(!(delegated.availability&PRODUCT_PLATFORM_DNS_APP_RELIABLE));
  }
  timestamp+=UINT64_C(300000000);
  processed(&vm,&pool,&assignment,&facts,incarnation);
  request=receive_request(channels[0][1]);
  ++incarnation; unsigned before=enrichments;
  respond(channels[0][1],request,10123);
  assert(enrichments==before && !lookup(&vm,&pool,&assignment,&facts).availability);
  processed(&vm,&pool,&assignment,&facts,incarnation);
  timestamp+=UINT64_C(300000000);
  processed(&vm,&pool,&assignment,&facts,incarnation);
  request=receive_request(channels[0][1]);
  timestamp+=UINT64_C(3000000000);
  assert(!lookup(&vm,&pool,&assignment,&facts).availability); /* Bounded broker timeout. */
  respond(channels[0][1],request,10123); /* A timed-out result cannot revive identity. */
  assert(!lookup(&vm,&pool,&assignment,&facts).availability);
  product_platform_packet_facts_t diagnostic={.uid=10123,
    .provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN,.direction=PRODUCT_PACKET_DIRECTION_OUTPUT,
    .availability=PRODUCT_PLATFORM_UID_KNOWN|PRODUCT_PLATFORM_DNS_APP_RELIABLE};
  assert(product_vpn_uid_resolver_identify(&vm,&pool,&assignment,&facts,&diagnostic,live_generation)==1);
  assert(!(diagnostic.availability&PRODUCT_PLATFORM_DNS_APP_RELIABLE));
  /* An identity conflict retires the cached identity; it is not reused for the old Flow. */
  timestamp+=UINT64_C(300000000);
  processed(&vm,&pool,&assignment,&facts,incarnation);
  request=receive_request(channels[0][1]);
  respond(channels[0][1],request,20000);
  assert(!lookup(&vm,&pool,&assignment,&facts).availability);
  /* A fresh TCP SYN never inherits an identity cached for an earlier connection on the tuple. */
  product_packet_facts_t tcp=facts; tcp.protocol=6; tcp.tcp_flags=0x02;
  product_packet_facts_t established=tcp; established.tcp_flags=0x10;
  timestamp+=UINT64_C(300000000);
  processed(&vm,&pool,&assignment,&established,incarnation);
  request=receive_request(channels[0][1]);
  respond(channels[0][1],request,10123);
  assert(lookup(&vm,&pool,&assignment,&established).uid==10123);
  assert(!lookup(&vm,&pool,&assignment,&tcp).availability);
  /* A Flow observed on this packet is used as is; without one the current admitted Flow is. */
  timestamp+=UINT64_C(300000000);
  processed(&vm,&pool,&assignment,&facts,0);
  assert(!nothing_sent(channels[0][1]));
  product_vpn_uid_resolver_stop();
  assert(closed_count==2 && !product_vpn_uid_resolver_ready());
  /* Without a broker a controlled provider's UID is still recorded on the current Flow. */
  product_platform_packet_facts_t controlled={.uid=10777,.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN,
    .direction=PRODUCT_PACKET_DIRECTION_OUTPUT,.availability=PRODUCT_PLATFORM_UID_KNOWN};
  unsigned before_controlled=enrichments;
  assert(product_vpn_uid_resolver_identify(&vm,&pool,&assignment,&facts,&controlled,live_generation)==1);
  assert(enrichments==before_controlled+1 && controlled.uid==10777);
  assert(!lookup(&vm,&pool,&assignment,&facts).availability);
  registered[0].read_function(&registered[0]); /* Old fd callback is harmless. */
  for(unsigned i=0;i<2;++i) close(channels[i][1]);
  registered_count=0; ++live_generation;
  product_vpn_uid_resolver_start(live_generation);
  for(unsigned i=0;i<2;++i) {
    assert(!socketpair(AF_UNIX,SOCK_SEQPACKET,0,channels[i]));
    assert(!product_vpn_uid_resolver_attach(channels[i][0],i));
  }
  processed(&vm,&pool,&assignment,&facts,incarnation);
  uid_request_t current=receive_request(channels[0][1]);
  /* Even a reused request number cannot accept an older runtime's result. */
  current.generation=request.generation;
  respond(channels[0][1],current,10123);
  assert(!product_vpn_uid_resolver_ready() && closed_count==3);
  product_vpn_uid_resolver_stop(); assert(closed_count==4);
  for(unsigned i=0;i<2;++i) close(channels[i][1]);
  puts("VPN UID resolver identity, admitted-flow refresh, no hold and late lifecycle: PASS");
}
'''

with tempfile.TemporaryDirectory(prefix='sakamoto-vpn-uid-dns-') as temporary:
    test, binary = Path(temporary) / 'test.c', Path(temporary) / 'test'
    test.write_text(prefix + source + suffix)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(ROOT / 'src/product/vpp'), str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
