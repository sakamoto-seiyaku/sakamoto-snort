#!/usr/bin/env python3
"""Execute the Product DNS graph boundary with controlled VPP buffer storage.

The inspector is a dependency seam; shared message/policy behavior is covered by
product_dns_query_test.c. This exercises the actual graph eligibility, original
wire bounds, context projection and snapshot fact handoff for both Adapters.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'src/product/vpp/product_packet_graph.c').read_text()


def function(name, result):
    match = re.search(r'\n' + name + r'\s*\([^;]*?\n\{', SOURCE, re.S)
    assert match, name
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(SOURCE, match.end() - 1):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return result + '\n' + SOURCE[match.start() + 1:token.end()] + '\n'
    raise AssertionError(name)


prefix = r'''
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "product_packet.h"
#include "product_dns.h"
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { unsigned thread_index; } vlib_main_t;
typedef struct { u32 current_length; u8 data[256]; } vlib_buffer_t;
static vlib_buffer_t buffer;
typedef struct {
  u64 observed, complete, unknown_caller, allowed, dropped, unchecked;
  u64 malformed, unsupported, capacity, copy_gap;
  u32 codec_peak_bytes;
} product_dns_owner_status_t;
typedef struct {
  u64 generation;
  unsigned enabled, accepting, adapter_kind;
  product_dns_owner_status_t dns[2];
  product_dns_owner_t dns_requests[2];
  void *flow_pools[2];
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main = {.generation=77};
typedef struct { u64 generation; product_domains_t *domains; } bank_t;
typedef struct {
  bank_t *bank;
  struct {u64 revision, snapshot_hash;} identity;
  u8 domain_source, domain_available;
  u64 domain_lists;
  const product_dns_response_t *dns_response;
} product_policy_snapshot_t;
#define clib_memset memset
#define clib_memcpy_fast memcpy
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm, u32 index) {
  assert(vm->thread_index == 1 && index == 3); return &buffer;
}
static void *vlib_buffer_get_current(vlib_buffer_t *b) { return b->data; }
typedef char clib_error_t;
typedef int unformat_input_t;
typedef int vlib_cli_command_t;
static unsigned status_enabled;
static unsigned product_packet_graph_worker_count(void) { return 2; }
static void product_policy_snapshot_acquire(void *graph, product_policy_snapshot_t *snapshot) {
  assert(graph==&product_packet_graph_main); memset(snapshot,0,sizeof(*snapshot));
}
static void product_policy_snapshot_release(void *graph, product_policy_snapshot_t *snapshot) {
  assert(graph==&product_packet_graph_main && snapshot);
}
static double vlib_time_now(vlib_main_t *vm) { assert(vm->thread_index==1); return 1.0; }
static unsigned vlib_get_worker_index(unsigned thread) { assert(thread==1); return 0; }
static struct { u64 revision; } network={.revision=5};
static __typeof__(network) *product_network_snapshot_current(void) { return &network; }
static u64 product_flow_entry_current_incarnation(void *pool, const void *assignment, u64 generation, u64 now) {
  assert(pool==product_packet_graph_main.flow_pools[0] && assignment && generation==77 && now==1000000); return 8;
}
static int product_vpn_tun_return_context(u64 generation, u64 token, u64 *inc, u64 *session, u64 *epoch) {
  assert(generation==77 && token==42); *inc=8;*session=55;*epoch=7;return 1;
}
unsigned product_dns_owner_active(product_dns_owner_t *owner, uint64_t now) { assert(owner && now==1000000); return 0; }
product_dns_resources_t product_dns_resources(void) { return (product_dns_resources_t){0}; }
static void vlib_cli_output(vlib_main_t *vm, const char *format, ...) {
  assert(vm->thread_index==1);
  if(!strncmp(format,"dns.profile=",12)) {
    va_list arguments; va_start(arguments,format); status_enabled=va_arg(arguments,unsigned); va_end(arguments);
  }
}
static unsigned inspected;
static product_dns_context_t last_context;
void product_dns_inspect_query(const uint8_t *wire, size_t size,
  const product_dns_context_t *context, product_dns_query_t *query) {
  ++inspected; last_context = *context;
  assert((!wire && !size) || (wire == buffer.data + 48 && size == 19));
  memset(query, 0, sizeof(*query)); query->packet = context->packet;
  query->coverage = PRODUCT_DNS_QUERY_COMPLETE;
  query->packet.domain_source = PRODUCT_POLICY_DOMAIN_DNS_QNAME;
  query->packet.domain_available = context->caller != PRODUCT_DNS_CALLER_UNKNOWN;
  query->packet.domain_lists = query->packet.domain_available ? 4 : 0;
}
static unsigned response_inspected;
static product_dns_identity_t response_identity;
void product_dns_inspect_response(const uint8_t *wire, size_t size,
  const product_dns_context_t *context, const product_dns_identity_t *identity,
  product_dns_owner_t *owner, product_dns_response_t *response) {
  ++response_inspected; response_identity=*identity;last_context=*context;
  assert(owner==&product_packet_graph_main.dns_requests[0]);
  assert((!wire && !size) || (wire==buffer.data+48 && size==19));
  memset(response,0,sizeof(*response));response->question.packet=context->packet;
  response->question.coverage=PRODUCT_DNS_QUERY_COMPLETE;
}
'''

suffix = r'''
int main(void) {
  vlib_main_t vm = {1};
  bank_t bank = {77, NULL};
  product_packet_lease_t lease = {0};
  lease.facts = (product_packet_facts_t){.protocol=17, .ip_family=6,
    .destination_port=53, .source_port=40000,
    .l4_status=PRODUCT_PACKET_L4_COMPLETE, .transport_offset=40,
    .l4_header_length=8, .transport_length=27};
  lease.platform = (product_platform_packet_facts_t){.uid=10123,
    .availability=PRODUCT_PLATFORM_UID_KNOWN|PRODUCT_PLATFORM_DNS_APP_RELIABLE,
    .direction=PRODUCT_PACKET_DIRECTION_OUTPUT};
  buffer.current_length = 70; /* Three bytes of IP padding are outside UDP. */
  for(unsigned provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
      provenance<=PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED; ++provenance) {
    lease.platform.provenance=provenance;
    for(unsigned direction=PRODUCT_PACKET_DIRECTION_INPUT;
        direction<=PRODUCT_PACKET_DIRECTION_OUTPUT; ++direction) {
      lease.platform.direction=direction;
      product_policy_snapshot_t snapshot={.bank=&bank};
      product_dns_query_t query;
      int observed=99; unsigned before=inspected;
      assert(product_packet_graph_dns_prepare(&vm,3,&lease,&snapshot,&query,&observed)==PRODUCT_PACKET_OK);
      int eligible=(provenance==PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE ||
        provenance==PRODUCT_PACKET_PROVENANCE_VPN_TUN) && direction==PRODUCT_PACKET_DIRECTION_OUTPUT;
      assert(observed==eligible && inspected==before+(unsigned)eligible);
      if(eligible) {
        assert(snapshot.domain_source==PRODUCT_POLICY_DOMAIN_DNS_QNAME);
        assert(snapshot.domain_available && snapshot.domain_lists==4);
        assert(last_context.packet.destination_port==53 && last_context.packet.source_port==40000);
      }
    }
  }
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_OUTPUT;
  lease.platform.availability=PRODUCT_PLATFORM_UID_KNOWN;
  product_policy_snapshot_t snapshot={.bank=&bank}; product_dns_query_t query; int observed;
  product_packet_graph_dns_prepare(&vm,3,&lease,&snapshot,&query,&observed);
  assert(observed && last_context.caller==PRODUCT_DNS_CALLER_UNKNOWN);
  assert(!snapshot.domain_available && !snapshot.domain_lists);
  lease.facts.destination_port=5353; unsigned before=inspected;
  product_packet_graph_dns_prepare(&vm,3,&lease,&snapshot,&query,&observed);
  assert(!observed && inspected==before);
  lease.facts.destination_port=53; buffer.current_length=60;
  product_packet_graph_dns_prepare(&vm,3,&lease,&snapshot,&query,&observed);
  assert(observed && query.coverage==PRODUCT_DNS_COPY_GAP);
  assert(snapshot.domain_source==PRODUCT_POLICY_DOMAIN_DNS_QNAME);
  lease.facts.source_port=53;lease.facts.destination_port=40000;buffer.current_length=70;
  lease.origin_obligation_id=42;
  for(unsigned provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
      provenance<=PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED;++provenance) {
    lease.platform.provenance=provenance;
    for(unsigned direction=PRODUCT_PACKET_DIRECTION_INPUT;
        direction<=PRODUCT_PACKET_DIRECTION_OUTPUT;++direction) {
      lease.platform.direction=direction;
      product_policy_snapshot_t current={.bank=&bank};product_dns_response_t response;
      int reply_observed=99;unsigned before_response=response_inspected;
      product_packet_graph_dns_response_prepare(&vm,3,&lease,&current,&response,&reply_observed);
      int eligible=(provenance==PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE ||
        provenance==PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN) && direction==PRODUCT_PACKET_DIRECTION_INPUT;
      assert(reply_observed==eligible && response_inspected==before_response+(unsigned)eligible);
      if(eligible) {
        assert(current.dns_response==&response && current.domain_source==PRODUCT_POLICY_DOMAIN_DNS_QNAME);
        assert(response_identity.generation==77 && response_identity.incarnation==8 && response_identity.network_revision==5);
        assert(response_identity.profile==(provenance==PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE ? 1 : 2));
        if(provenance==PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN)
          assert(response_identity.transport_session==55 && response_identity.underlay_epoch==7);
        assert(last_context.packet.source_port==53 && last_context.packet.destination_port==40000);
      }
    }
  }
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;buffer.current_length=60;
  product_dns_response_t response;
  product_packet_graph_dns_response_prepare(&vm,3,&lease,&snapshot,&response,&observed);
  assert(observed && response.question.coverage==PRODUCT_DNS_COPY_GAP);
  for(unsigned kind=PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE;
      kind<=PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;++kind) {
    product_packet_graph_main.adapter_kind=kind;
    product_packet_graph_main.enabled=product_packet_graph_main.accepting=1;
    product_dns_status_cli(&vm,NULL,NULL);
    assert(status_enabled==(kind==PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE || kind==PRODUCT_ADAPTER_OBLIGATION_VPN_TUN));
    product_packet_graph_main.accepting=0;
    product_dns_status_cli(&vm,NULL,NULL); assert(!status_enabled);
  }
  puts("Root/VPN original UDP DNS graph boundary and status: PASS");
}
'''

with tempfile.TemporaryDirectory(prefix='sakamoto-dns-graph-') as tmp:
    source, binary = Path(tmp) / 'test.c', Path(tmp) / 'test'
    source.write_text(prefix + function('product_packet_graph_l4_direction_from_platform', 'static void')
                      + function('product_packet_graph_l4_packet_projection', 'static void')
                      + function('product_packet_graph_dns_prepare', 'static product_packet_result_t')
                      + function('product_packet_graph_dns_identity', 'static product_dns_identity_t')
                      + function('product_packet_graph_dns_response_prepare', 'static void')
                      + function('product_dns_status_cli', 'static clib_error_t *')
                      + suffix)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(ROOT / 'src/product/vpp'),
                    '-I' + str(ROOT / 'src/product/include'), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
