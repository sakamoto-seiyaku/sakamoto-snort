#!/usr/bin/env python3
"""Drive the actual Root recv callback through DNS admission fallbacks.

Kernel recv, VPP storage/publication, native verdict send and observation
transport are controlled seams. The production callback, netlink parser,
CAP_LEN guard, receive/pending ledgers, batch flush and unadmitted selector run
unchanged.
"""

from pathlib import Path
import os
import re
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
SOURCE = (PRODUCT / "product_root_nfqueue_adapter.c").read_text()


def function(name):
    match = re.search(r"(?m)^" + re.escape(name) + r"\s*\(", SOURCE)
    assert match, name
    start = SOURCE.rfind("\n", 0, match.start() - 1) + 1
    opening = SOURCE.index("{", match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    return SOURCE[start:end] + "\n"


def declaration(name, kind="struct"):
    end = SOURCE.index("} " + name + ";") + len("} " + name + ";")
    return SOURCE[SOURCE.rfind("typedef " + kind, 0, end):end] + "\n"


prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include "product_packet.h"
#include "product_packet_completion.h"
#include "product_packet_batch.h"
#include "product_root_receive_pool.h"
#include "product_root_dns_admission.h"
#include "product_dns.h"
#include "sakamoto_product_observation.h"
typedef uint8_t u8; typedef uint16_t u16; typedef int16_t i16;
typedef uint32_t u32; typedef uint64_t u64; typedef unsigned long uword;
typedef struct {u32 thread_index;} vlib_main_t;
typedef struct {u32 file_descriptor,polling_thread_index;uword private_data;} clib_file_t;
typedef int clib_error_t;
typedef struct {
 u8 data[2048],opaque[40],opaque2[56];u32 ref_count,flags,template,trace_handle;
 u32 total_length_not_including_first_buffer,buffer_pool_index;i16 current_data;u16 current_length;
} vlib_buffer_t;
typedef struct {u32 buffer_index;product_platform_packet_facts_t platform;product_adapter_obligation_t obligation;} product_packet_graph_external_item_t;
typedef struct {u32 count;struct {u32 linux_ifindex,context;} entries[1];u64 revision,event_elapsed_ns;} sakamoto_product_network_snapshot_t;
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define PRODUCT_ROOT_NFQUEUE_READ_BUDGET 64U
#define PRODUCT_VERDICT_SUCCEEDED 0
#define PRODUCT_VERDICT_FAILED_DEFINITE 1
#define PRODUCT_VERDICT_OUTCOME_UNKNOWN 2
#define SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT 1
#define SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS 1
#define VLIB_BUFFER_NEXT_PRESENT 1
#define PREDICT_FALSE(x) (x)
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define clib_max(a,b) ((a)>(b)?(a):(b))
#define clib_min(a,b) ((a)<(b)?(a):(b))
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,n) __atomic_fetch_sub((p),(n),__ATOMIC_RELAXED)
#define clib_atomic_store_rel_n(p,n) __atomic_store_n((p),(n),__ATOMIC_RELEASE)
#define uword_to_pointer(x,t) ((t)(x))
#define ARRAY_LEN(a) (sizeof(a)/sizeof((a)[0]))
#define ASSERT assert
#define clib_panic(message) do{fputs((message),stderr);assert(0);}while(0)
static clib_error_t error_value=1;
#define clib_error_return(...) (&error_value)
#define clib_error_return_unix(...) (&error_value)
static vlib_main_t vm={1};
static vlib_main_t *vlib_get_main(void){return &vm;}
static u32 vlib_get_thread_index(void){return vm.thread_index;}
static u32 vlib_get_worker_thread_index(u32 worker){return worker+1;}
static __attribute__((unused)) u32 vlib_get_worker_index(u32 thread){return thread-1;}
static u32 product_packet_graph_trace_limit(void){return 0;}
static vlib_buffer_t buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
static struct {u32 buffer_template;} buffer_pool;
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *v,u32 index){assert(v==&vm&&index<PRODUCT_ROOT_RECEIVE_TOTAL);return &buffers[index];}
#define vlib_get_buffer_pool(v,index) (&buffer_pool)
#define vlib_buffer_get_current(buffer) ((buffer)->data+(buffer)->current_data)
static u32 vlib_buffer_get_default_data_size(vlib_main_t *v){assert(v==&vm);return 2048;}
'''

types = "".join(declaration(name, kind) for name, kind in (
    ("product_root_nfqueue_fault_mode_t", "enum"),
    ("product_root_nfqueue_packet_t", "struct"),
    ("product_root_buffer_platform_metadata_t", "struct"),
    ("product_root_nfqueue_pending_t", "struct"),
    ("product_root_nfqueue_lane_t", "struct"),
    ("product_root_nfqueue_main_t", "struct"),
    ("product_root_input_batch_t", "struct"),
))

deps = r'''
static product_root_nfqueue_main_t product_root_nfqueue_main;
static sakamoto_product_network_snapshot_t network={.count=1,.entries={{7,9}},.revision=3};
static const sakamoto_product_network_snapshot_t *product_network_snapshot_current(void){return &network;}
static unsigned input_mode, physical_reads, queued, publications, reject_publication;
static int replacement_active;
static u32 verdict_count,last_verdict,observed,basic_failures;
static int product_root_dns_adapter_enabled(void){return replacement_active;}
static void product_root_dns_adapter_admission_observe(vlib_main_t *v,u64 token,
 const product_platform_packet_facts_t *platform,const product_root_dns_admission_facts_t *facts,
 u8 coverage,u8 delivery){
 assert(v==&vm&&token&&platform&&facts&&facts->resolver_port==53);
 assert(platform->uid==10123&&(platform->availability&7)==7);
 assert(platform->linux_ifindex==7&&platform->network_context_id==9);
 assert(coverage==PRODUCT_DNS_COPY_GAP||coverage==PRODUCT_DNS_CAPACITY);
 assert(delivery==PRODUCT_DNS_DELIVERY_RESOURCE_DROP);observed++;
}
static void product_observation_basic(vlib_main_t *v,unsigned outcome,u32 bytes){assert(v==&vm&&outcome==2&&bytes);basic_failures++;}
static u32 product_root_nfqueue_send_counted_verdict(product_root_nfqueue_main_t *nm,
 product_root_nfqueue_lane_t *lane,u32 packet,u32 verdict){
 assert(nm&&lane&&packet==73);verdict_count++;last_verdict=verdict;
 return PRODUCT_VERDICT_SUCCEEDED;
}
static u32 add_attr(u8 *wire,u32 offset,u16 type,const void *value,u16 copied,u16 declared){
 struct nfattr *attr=(struct nfattr *)(wire+offset);attr->nfa_type=type;attr->nfa_len=NFA_LENGTH(declared);
 memcpy(NFA_DATA(attr),value,copied);return offset+NFA_ALIGN(NFA_LENGTH(copied));
}
static ssize_t fake_recv(int fd,void *target,size_t capacity,int flags){
 assert(fd==27&&flags==(MSG_DONTWAIT|MSG_TRUNC));physical_reads++;
 if(physical_reads>1){errno=EAGAIN;return -1;}
 assert(target&&capacity==2048);u8 *wire=target;memset(wire,0,capacity);
 struct nlmsghdr *nlh=(struct nlmsghdr *)wire;nlh->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
 struct nfgenmsg *nfgen=NLMSG_DATA(nlh);nfgen->version=NFNETLINK_V0;nfgen->res_id=htons(176);
 u32 offset=NLMSG_LENGTH(sizeof(*nfgen));
 struct nfqnl_msg_packet_hdr header={.packet_id=htonl(73),.hook=NF_INET_LOCAL_OUT};
 offset=add_attr(wire,offset,NFQA_PACKET_HDR,&header,sizeof(header),sizeof(header));
 u32 uid=htonl(10123);offset=add_attr(wire,offset,NFQA_UID,&uid,sizeof(uid),sizeof(uid));
 u32 outdev=htonl(7);offset=add_attr(wire,offset,NFQA_IFINDEX_OUTDEV,&outdev,sizeof(outdev),sizeof(outdev));
 u8 packet[1984]={0};u32 bytes=48;u16 destination=input_mode==5?443:53;
 if(input_mode==6||input_mode==7){
   bytes=sizeof(packet);packet[0]=0x60;packet[4]=0x0f;packet[5]=0xa0;packet[6]=0;packet[7]=64;
   packet[40]=17;packet[41]=255; /* final protocol/port beyond visible prefix */
 } else if(input_mode==4){
   bytes=324;packet[0]=0x60;packet[4]=1;packet[5]=28;packet[6]=0;packet[7]=64;
   packet[40]=17;packet[41]=32;packet[304]=0x9c;packet[305]=0x40;
   packet[306]=destination>>8;packet[307]=destination;packet[308]=0;packet[309]=20;
   packet[312]=0x12;packet[313]=0x34;packet[314]=1;
 } else {
   packet[0]=0x45;packet[2]=input_mode==1?15:0;packet[3]=input_mode==1?160:48;
   packet[8]=64;packet[9]=17;packet[12]=192;packet[15]=2;packet[16]=192;packet[19]=53;
   packet[20]=0x9c;packet[21]=0x40;packet[22]=destination>>8;packet[23]=destination;
   packet[24]=input_mode==1?15:0;packet[25]=input_mode==1?140:28;
   packet[28]=0x12;packet[29]=0x34;packet[30]=1;
 }
 u32 cap=htonl((input_mode==2||input_mode==6||input_mode==7)?4000:bytes);
 offset=add_attr(wire,offset,NFQA_CAP_LEN,&cap,sizeof(cap),sizeof(cap));
 u16 declared=(input_mode==1||input_mode==4||input_mode==5||input_mode==7)?4000:bytes;
 offset=add_attr(wire,offset,NFQA_PAYLOAD,packet,bytes,declared);
 nlh->nlmsg_len=(input_mode==1||input_mode==4||input_mode==5||input_mode==7)?offset+declared-bytes:offset;
 return (input_mode==1||input_mode==4||input_mode==5||input_mode==7)?nlh->nlmsg_len:offset;
}
#define recv fake_recv
static int product_root_nfqueue_transient_errno(int e){return e==EAGAIN||e==EWOULDBLOCK||e==EINTR||e==ENOBUFS;}
static void product_root_nfqueue_mark_lane_fault(product_root_nfqueue_main_t *nm,product_root_nfqueue_lane_t *lane,const char *cause,int e){(void)lane;assert(nm&&cause&&e);nm->fault_latched=1;}
static int product_root_nfqueue_consume_control(product_root_nfqueue_lane_t *lane,const u8 *data,u32 length){(void)lane;(void)data;(void)length;return 0;}
static void product_diagnostic_write_hex(FILE *stream,const u8 *data,u32 length){(void)stream;(void)data;(void)length;}
static u32 product_packet_graph_submit_external_batch(vlib_main_t *v,
 const product_packet_graph_external_item_t *items,u32 count,u8 *accepted){
 assert(v==&vm&&count==1&&items);publications++;
 accepted[0]=!reject_publication;queued+=accepted[0];return accepted[0];
}
'''

production = "\n".join(function(name) for name in (
    "product_root_nfqueue_pending_find",
    "product_root_nfqueue_pending_deactivate",
    "product_root_nfqueue_reserve",
    "product_root_nfqueue_next_observation_token",
    "product_root_nfqueue_parse_packet",
    "product_root_nfqueue_capture_complete",
    "product_root_nfqueue_packet_id_seen",
    "product_root_nfqueue_unadmitted_dns_query",
    "product_root_nfqueue_accept_unadmitted",
    "product_root_nfqueue_return_receive",
    "product_root_input_batch_flush",
    "product_root_nfqueue_read_dispatch",
    "product_root_nfqueue_read_ready",
))

suffix = r'''
static clib_file_t file;
static product_root_nfqueue_lane_t *lane;
static void reset(unsigned mode,int active,int reject,int reserve){
 memset(&product_root_nfqueue_main,0,sizeof(product_root_nfqueue_main));
 product_root_nfqueue_main.generation=42;product_root_nfqueue_main.lane_count=1;
 lane=&product_root_nfqueue_main.lanes[0];lane->generation=42;lane->fd=27;lane->socket_ready=1;
 lane->queue_id=176;lane->worker_index=0;lane->read_budget=1;
 u32 indices[PRODUCT_ROOT_RECEIVE_TOTAL];
 for(u32 i=0;i<PRODUCT_ROOT_RECEIVE_TOTAL;i++){indices[i]=i;memset(&buffers[i],0,sizeof(buffers[i]));buffers[i].ref_count=1;}
 assert(product_root_receive_pool_init_capacity(&lane->receive_pool,42,indices,64));
 if(reserve)lane->receive_pool.normal_free=0;
 file=(clib_file_t){27,1,(uword)lane};vm.thread_index=1;
 input_mode=mode;replacement_active=active;reject_publication=reject;
 physical_reads=queued=publications=verdict_count=observed=basic_failures=0;last_verdict=UINT32_MAX;
}
static void release_queued(void){
 for(u32 i=0;i<PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY;i++)if(lane->pending[i].active){
   product_root_nfqueue_pending_t *pending=&lane->pending[i];
   product_root_nfqueue_pending_deactivate(&product_root_nfqueue_main,lane,pending);
   product_root_nfqueue_return_receive(lane,pending->receive_slot,pending->buffer_index);
 }
}
static void run(unsigned mode,int active,int reject,int reserve,u32 expected,int submitted){
 reset(mode,active,reject,reserve);assert(!product_root_nfqueue_read_ready(&file));
 assert(queued==(u32)submitted&&verdict_count==(u32)!submitted);
 if(!submitted)assert(last_verdict==expected);
 u32 typed=(expected==NF_DROP&&!submitted&&mode!=6&&mode!=7);
 assert(observed==typed);assert(basic_failures==(expected==NF_DROP&&!submitted));
 release_queued();assert(!lane->pending_count&&!product_root_nfqueue_main.pending_count);
}
int main(void){
 run(0,1,0,0,NF_ACCEPT,1);            /* ordinary active query reaches graph */
 run(1,1,0,0,NF_DROP,0);             /* oversized IPv4 */
 run(1,0,0,0,NF_ACCEPT,0);           /* replacement off */
 run(2,1,0,0,NF_DROP,0);             /* independent CAP_LEN gap */
 run(0,1,0,1,NF_DROP,0);             /* reserve-only receive */
 run(0,1,1,0,NF_DROP,0);             /* batch publication rejection */
 run(4,1,0,0,NF_DROP,0);             /* IPv6 query after264-byte extension */
 run(5,1,0,0,NF_ACCEPT,0);           /* unrelated truncated UDP */
 run(6,1,0,0,NF_DROP,0);             /* complete envelope, CAP_LEN hides final protocol/port */
 run(7,1,0,0,NF_DROP,0);             /* MSG_TRUNC hides final protocol/port */
 puts("Root DNS actual receiver: recv/MSG_TRUNC/CAP_LEN/reserve/batch rejection v4/v6 active/off/non-DNS PASS");
}
'''

with tempfile.TemporaryDirectory(prefix="product-root-dns-receiver-") as temp:
    path = Path(temp)
    source = path / "test.c"
    binary = path / "test"
    source.write_text(prefix + types + deps + production + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-I", str(PRODUCT), "-I", str(ROOT / "src/product/include"),
        str(source), "-o", str(binary),
    ], check=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    subprocess.run([str(binary)], check=True, timeout=15,
                   env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0:handle_segv=0"))
