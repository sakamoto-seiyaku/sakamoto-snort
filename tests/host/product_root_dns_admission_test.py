#!/usr/bin/env python3
"""Exercise the real Root pre-graph NFQUEUE admission verdict boundary.

The fixture supplies complete and receive-truncated netlink envelopes and
observes the one physical verdict selected by the Product adapter. It does not
claim kernel delivery, VPP graph execution, or Android qualification.
"""

from pathlib import Path
import os
import re
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
LEGACY_SOURCE = os.environ.get("SAKAMOTO_ROOT_ADMISSION_LEGACY_SOURCE")
SOURCE = Path(LEGACY_SOURCE).read_text() if LEGACY_SOURCE else (
    ROOT / "src/product/vpp/product_root_nfqueue_adapter.c").read_text()


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


prefix = f"#define LEGACY_SOURCE {int(bool(LEGACY_SOURCE))}\n" + r'''
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "product_packet.h"
#include "product_dns.h"
#include "sakamoto_product_observation.h"
#include "product_root_dns_admission.h"
#include "product_root_dns_tcp_io.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define ARRAY_LEN(a) (sizeof(a)/sizeof((a)[0]))
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES 4
#define PRODUCT_VERDICT_SUCCEEDED 0
#define PRODUCT_VERDICT_FAILED_DEFINITE 1
#define PRODUCT_VERDICT_OUTCOME_UNKNOWN 2
#define clib_min(a,b) ((a)<(b)?(a):(b))
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
typedef struct {
  u64 graph_submit_fail_opens, ingress_identity_missing;
} product_root_nfqueue_main_t;
typedef struct {
  u32 packet_id, uid; u8 hook, ip_family, protocol, uid_present, identity_present;
  u8 indev_present, outdev_present; u32 indev, outdev, skb_info, captured_length;
  u8 skb_info_present, captured_length_present; u32 mark; u8 *payload; u32 payload_length;
} product_root_nfqueue_packet_t;
typedef struct {
  u32 lane_index, queue_id; u64 next_obligation_token;
  u64 generation, ingress_accepts, ingress_dns_drop_attempts;
  u64 ingress_normal_exhausted, ingress_envelope_rejected;
  u64 ingress_completion_rejected, ingress_graph_rejected;
  u64 identity_losses;
} product_root_nfqueue_lane_t;
typedef struct {u32 thread_index;} vlib_main_t;
typedef struct {u32 count;struct {u32 linux_ifindex,context;} entries[1];} sakamoto_product_network_snapshot_t;
static sakamoto_product_network_snapshot_t network;
static const sakamoto_product_network_snapshot_t *product_network_snapshot_current(void){return &network;}
static vlib_main_t vm={1};
static int replacement_active, verdict_count;
static u32 observed, basic_failures, verdict_outcome;
static u8 last_delivery;
static u32 last_packet, last_verdict;
static int product_root_dns_adapter_enabled(void) { return replacement_active; }
static u32 product_packet_graph_trace_limit(void) { return 0; }
static u32 vlib_get_thread_index(void) { return 1; }
static __attribute__((unused)) vlib_main_t *vlib_get_main(void) { return &vm; }
static __attribute__((unused)) void product_root_dns_adapter_admission_observe(vlib_main_t *v,u64 token,
 const product_platform_packet_facts_t *platform,
 const product_root_dns_admission_facts_t *facts,u8 coverage,u8 delivery) {
 assert(v==&vm && token && platform && facts && facts->resolver_port==53);
 assert(coverage==PRODUCT_DNS_COPY_GAP || coverage==PRODUCT_DNS_CAPACITY);
 assert(delivery==PRODUCT_DNS_DELIVERY_RESOURCE_DROP ||
   delivery==PRODUCT_DNS_DELIVERY_WRITE_FAILED ||
   delivery==PRODUCT_DNS_DELIVERY_OUTCOME_UNKNOWN);
 observed++;last_delivery=delivery;
}
static __attribute__((unused)) void product_observation_basic(vlib_main_t *v,unsigned outcome,u32 bytes) {
 assert(v==&vm && outcome==2 && bytes);basic_failures++;
}
static u32 product_root_nfqueue_send_counted_verdict(product_root_nfqueue_main_t *nm,
 product_root_nfqueue_lane_t *lane,u32 packet,u32 verdict) {
 (void)nm;(void)lane;verdict_count++;last_packet=packet;last_verdict=verdict;
 return LEGACY_SOURCE?1:verdict_outcome;
}
'''

production_names = (
    "product_root_nfqueue_packet_id_seen",
    "product_root_nfqueue_accept_unadmitted",
) if LEGACY_SOURCE else (
    "product_root_nfqueue_parse_packet",
    "product_root_nfqueue_capture_complete",
    "product_root_nfqueue_next_observation_token",
    "product_root_nfqueue_packet_id_seen",
    "product_root_nfqueue_unadmitted_dns_query",
    "product_root_nfqueue_accept_unadmitted",
)
production = "".join(function(name) for name in production_names)

suffix = r'''
static u32 put_attr(u8 *wire,u32 offset,u16 type,const void *value,u16 length,u16 declared) {
 struct nfattr *attr=(struct nfattr *)(wire+offset);
 attr->nfa_type=type;attr->nfa_len=NFA_LENGTH(declared);
 memcpy(NFA_DATA(attr),value,length);
 return offset+NFA_ALIGN(NFA_LENGTH(length));
}
static u32 envelope(u8 *wire,u32 packet_id,u16 destination,int truncated,u32 cap_len) {
 memset(wire,0,256);
 struct nlmsghdr *nlh=(struct nlmsghdr *)wire;
 nlh->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
 struct nfgenmsg *nfgen=NLMSG_DATA(nlh);nfgen->nfgen_family=AF_INET;
 nfgen->version=NFNETLINK_V0;nfgen->res_id=htons(176);
 u32 offset=NLMSG_LENGTH(sizeof(*nfgen));
 struct nfqnl_msg_packet_hdr header={.packet_id=htonl(packet_id),.hook=NF_INET_LOCAL_OUT};
 offset=put_attr(wire,offset,NFQA_PACKET_HDR,&header,sizeof(header),sizeof(header));
 u32 captured=htonl(cap_len);offset=put_attr(wire,offset,NFQA_CAP_LEN,&captured,sizeof(captured),sizeof(captured));
 u8 packet[48]={0x45};packet[2]=0;packet[3]=48;packet[8]=64;packet[9]=IPPROTO_UDP;
 packet[20]=0x9c;packet[21]=0x40;packet[22]=destination>>8;packet[23]=destination;
 packet[24]=0;packet[25]=28;packet[28]=0x12;packet[29]=0x34;packet[30]=1;
 u16 declared=truncated?4000:sizeof(packet);
 offset=put_attr(wire,offset,NFQA_PAYLOAD,packet,sizeof(packet),declared);
 nlh->nlmsg_len=truncated?offset+declared-sizeof(packet):offset;
 return offset;
}
static u32 envelope6(u8 *wire,u32 packet_id,u16 destination,int truncated) {
 memset(wire,0,256);
 struct nlmsghdr *nlh=(struct nlmsghdr *)wire;
 nlh->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
 struct nfgenmsg *nfgen=NLMSG_DATA(nlh);nfgen->nfgen_family=AF_INET6;
 nfgen->version=NFNETLINK_V0;nfgen->res_id=htons(176);
 u32 offset=NLMSG_LENGTH(sizeof(*nfgen));
 struct nfqnl_msg_packet_hdr header={.packet_id=htonl(packet_id),.hook=NF_INET_LOCAL_OUT};
 offset=put_attr(wire,offset,NFQA_PACKET_HDR,&header,sizeof(header),sizeof(header));
 u32 captured=htonl(4000);offset=put_attr(wire,offset,NFQA_CAP_LEN,&captured,sizeof(captured),sizeof(captured));
 u8 packet[68]={0x60};packet[5]=28;packet[6]=44;packet[7]=64;
 packet[40]=17;packet[43]=1;packet[48]=0x9c;packet[49]=0x40;
 packet[50]=destination>>8;packet[51]=destination;packet[52]=0;packet[53]=20;
 packet[56]=0x12;packet[57]=0x34;packet[58]=1;
 u16 declared=truncated?4000:sizeof(packet);
 offset=put_attr(wire,offset,NFQA_PAYLOAD,packet,sizeof(packet),declared);
 nlh->nlmsg_len=truncated?offset+declared-sizeof(packet):offset;
 return offset;
}
static u32 envelope6_long(u8 *wire,u32 packet_id,int truncated) {
 memset(wire,0,512);
 struct nlmsghdr *nlh=(struct nlmsghdr *)wire;
 nlh->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
 struct nfgenmsg *nfgen=NLMSG_DATA(nlh);nfgen->nfgen_family=AF_INET6;
 nfgen->version=NFNETLINK_V0;nfgen->res_id=htons(176);
 u32 offset=NLMSG_LENGTH(sizeof(*nfgen));
 struct nfqnl_msg_packet_hdr header={.packet_id=htonl(packet_id),.hook=NF_INET_LOCAL_OUT};
 offset=put_attr(wire,offset,NFQA_PACKET_HDR,&header,sizeof(header),sizeof(header));
 u8 packet[324]={0x60};packet[4]=1;packet[5]=28;packet[6]=0;packet[7]=64;
 packet[40]=17;packet[41]=32; /* one valid 264-byte Hop-by-Hop header */
 packet[304]=0x9c;packet[305]=0x40;packet[306]=0;packet[307]=53;
 packet[308]=0;packet[309]=20;packet[312]=0x12;packet[313]=0x34;packet[314]=1;
 u32 captured=htonl(sizeof(packet));
 offset=put_attr(wire,offset,NFQA_CAP_LEN,&captured,sizeof(captured),sizeof(captured));
 u16 declared=truncated?4000:sizeof(packet);
 offset=put_attr(wire,offset,NFQA_PAYLOAD,packet,sizeof(packet),declared);
 nlh->nlmsg_len=truncated?offset+declared-sizeof(packet):offset;
 return offset;
}
static u32 envelope6_hidden(u8 *wire,u32 packet_id,int loss) {
 memset(wire,0,2304);
 struct nlmsghdr *nlh=(struct nlmsghdr *)wire;
 nlh->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
 struct nfgenmsg *nfgen=NLMSG_DATA(nlh);nfgen->nfgen_family=AF_INET6;
 nfgen->version=NFNETLINK_V0;nfgen->res_id=htons(176);
 u32 offset=NLMSG_LENGTH(sizeof(*nfgen));
 struct nfqnl_msg_packet_hdr header={.packet_id=htonl(packet_id),.hook=NF_INET_LOCAL_OUT};
 offset=put_attr(wire,offset,NFQA_PACKET_HDR,&header,sizeof(header),sizeof(header));
 u8 packet[1984]={0x60};packet[4]=0x0f;packet[5]=0xa0;packet[6]=0;packet[7]=64;
 packet[40]=17;packet[41]=255; /* UDP begins after a 2048-byte extension header. */
 u32 captured=htonl(loss?4000:sizeof(packet));
 offset=put_attr(wire,offset,NFQA_CAP_LEN,&captured,sizeof(captured),sizeof(captured));
 u16 declared=loss==1?4000:sizeof(packet);
 offset=put_attr(wire,offset,NFQA_PAYLOAD,packet,sizeof(packet),declared);
 nlh->nlmsg_len=loss==1?offset+declared-sizeof(packet):offset;
 return offset;
}
static void check(int active,u16 destination,int truncated,u32 expected) {
 u8 wire[256];u32 visible=envelope(wire,73,destination,truncated,truncated?4000:48);
 product_root_nfqueue_main_t nm={0};
 product_root_nfqueue_lane_t lane={.generation=9,.queue_id=176};
 replacement_active=active;verdict_count=0;last_packet=last_verdict=0;
 observed=basic_failures=last_delivery=0;verdict_outcome=PRODUCT_VERDICT_SUCCEEDED;
 product_root_nfqueue_accept_unadmitted(&nm,&lane,wire,visible,"unadmitted_envelope");
 assert(verdict_count==1 && last_packet==73 && last_verdict==expected);
 assert(lane.ingress_accepts==(expected==NF_ACCEPT));
 assert(lane.ingress_dns_drop_attempts==(expected==NF_DROP));
 assert(observed==(expected==NF_DROP));assert(basic_failures==(expected==NF_DROP));
}
static void check6(int active,u16 destination,int truncated,u32 expected) {
 u8 wire[256];u32 visible=envelope6(wire,74,destination,truncated);
 product_root_nfqueue_main_t nm={0};
 product_root_nfqueue_lane_t lane={.generation=9,.queue_id=176};
 replacement_active=active;verdict_count=0;last_packet=last_verdict=0;
 observed=basic_failures=last_delivery=0;verdict_outcome=PRODUCT_VERDICT_SUCCEEDED;
 product_root_nfqueue_accept_unadmitted(&nm,&lane,wire,visible,"unadmitted_envelope");
 assert(verdict_count==1 && last_packet==74 && last_verdict==expected);
 assert(observed==(expected==NF_DROP));assert(basic_failures==(expected==NF_DROP));
}
static void check6long(int active,int truncated,u32 expected) {
 u8 wire[512];u32 visible=envelope6_long(wire,75,truncated);
 product_root_nfqueue_main_t nm={0};
 product_root_nfqueue_lane_t lane={.generation=9,.queue_id=176};
 replacement_active=active;verdict_count=0;last_packet=last_verdict=0;
 observed=basic_failures=last_delivery=0;verdict_outcome=PRODUCT_VERDICT_SUCCEEDED;
 product_root_nfqueue_accept_unadmitted(&nm,&lane,wire,visible,"unadmitted_envelope");
 assert(verdict_count==1 && last_packet==75 && last_verdict==expected);
 assert(observed==(expected==NF_DROP));assert(basic_failures==(expected==NF_DROP));
}
static void check6hidden(int active,int loss,u32 expected) {
 u8 wire[2304];u32 visible=envelope6_hidden(wire,76,loss);
 product_root_nfqueue_main_t nm={0};
 product_root_nfqueue_lane_t lane={.generation=9,.queue_id=176};
 replacement_active=active;verdict_count=0;last_packet=last_verdict=0;
 observed=basic_failures=last_delivery=0;verdict_outcome=PRODUCT_VERDICT_SUCCEEDED;
 product_root_nfqueue_accept_unadmitted(&nm,&lane,wire,visible,"unadmitted_envelope");
 assert(verdict_count==1 && last_packet==76 && last_verdict==expected);
 /* The hidden final protocol/port cannot truthfully produce a typed DNS row. */
 assert(!observed);assert(basic_failures==(expected==NF_DROP));
}
static void check_outcome(u32 outcome,u8 delivery) {
 u8 wire[256];u32 visible=envelope(wire,77,53,1,4000);
 product_root_nfqueue_main_t nm={0};
 product_root_nfqueue_lane_t lane={.generation=9,.queue_id=176};
 replacement_active=1;verdict_count=0;last_packet=last_verdict=0;
 observed=basic_failures=last_delivery=0;verdict_outcome=outcome;
 product_root_nfqueue_accept_unadmitted(&nm,&lane,wire,visible,"unadmitted_envelope");
 assert(verdict_count==1&&last_verdict==NF_DROP&&observed==1&&basic_failures==1);
 assert(last_delivery==delivery);
}
int main(void) {
 (void)product_root_dns_adapter_enabled();
#if !LEGACY_SOURCE
 u8 captured[256];product_root_nfqueue_packet_t parsed;
 u32 captured_bytes=envelope(captured,72,53,0,4000);
 assert(product_root_nfqueue_parse_packet(captured,captured_bytes,&parsed));
 assert(!product_root_nfqueue_capture_complete(&parsed));
 captured_bytes=envelope(captured,72,53,0,48);
 assert(product_root_nfqueue_parse_packet(captured,captured_bytes,&parsed));
 assert(product_root_nfqueue_capture_complete(&parsed));
#endif
 check(0,53,1,NF_ACCEPT);
 check(1,443,1,NF_ACCEPT);
 check(1,53,0,NF_DROP);
 check(1,53,1,NF_DROP);
 check6(1,443,1,NF_ACCEPT);
 check6(1,53,1,NF_DROP);
 check6long(1,1,NF_DROP);
 check6hidden(1,1,NF_DROP);
 check6hidden(1,2,NF_DROP);
 check6hidden(1,0,NF_ACCEPT);
#if !LEGACY_SOURCE
 check_outcome(PRODUCT_VERDICT_OUTCOME_UNKNOWN,PRODUCT_DNS_DELIVERY_OUTCOME_UNKNOWN);
 check_outcome(PRODUCT_VERDICT_FAILED_DEFINITE,PRODUCT_DNS_DELIVERY_WRITE_FAILED);
#endif
 puts("Root DNS admission: replacement prevents complete/truncated UDP53 fail-open; off/non-DNS controls PASS");
}
'''

with tempfile.TemporaryDirectory(prefix="product-root-dns-admission-") as temp:
    path = Path(temp)
    source = path / "test.c"
    binary = path / "test"
    source.write_text(prefix + production + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
        "-I", str(ROOT / "src/product/vpp"), "-I", str(ROOT / "src/product/include"),
        str(source), "-o", str(binary),
    ], check=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:handle_segv=0")
    subprocess.run([str(binary)], check=True, env=environment, timeout=15)
