#!/usr/bin/env python3
"""Actual stop callback: an exit before adapter start has no worker graph."""
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'src/product/vpp/product_packet_graph.c').read_text()
begin = source.index('product_packet_graph_stop_external (vlib_main_t *vm)')
body = source.index('{', begin)
depth = 1
end = body + 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
callback = 'static void\n' + source[begin:end]
code = r'''
#include <assert.h>
#include <stdio.h>
typedef struct { int thread_index; } vlib_main_t;
typedef struct { unsigned active; } product_dns_owner_t;
typedef struct { unsigned active; unsigned long long allocated_bytes; } product_dns_tcp_owner_t;
typedef struct { unsigned codec_live_bytes, active_operations; } product_dns_resources_t;
typedef struct { unsigned pairs; } product_dns_assoc_t;
typedef struct {
  unsigned accepting, enabled, generation;
  product_dns_owner_t dns_requests[2];
  product_dns_tcp_owner_t dns_tcp[2];
  product_dns_assoc_t *dns_assoc[2];
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
static int workers_ready, calls, debt, dns_stops, tcp_stops, dns_adapter_stops, assoc_clears;
static unsigned product_packet_graph_worker_count(void) { return 2; }
static void product_dns_owner_stop(product_dns_owner_t *owner) {
  assert(owner->active); owner->active=0; ++dns_stops;
}
static void product_dns_tcp_stop(product_dns_tcp_owner_t *owner) {
  assert(owner->active && owner->allocated_bytes);owner->active=0;owner->allocated_bytes=0;++tcp_stops;
}
static void product_dns_assoc_clear(product_dns_assoc_t *table) { if (table) table->pairs=0; ++assoc_clears; }
static product_dns_resources_t product_dns_resources(void) { return (product_dns_resources_t){0}; }
#define PREDICT_FALSE(x) (x)
#define clib_atomic_store_rel_n(p,v) (*(p)=(v))
static void product_flow_end_quiesce(vlib_main_t *vm) {
  assert(vm && workers_ready); ++calls;
}
static void product_root_dns_adapter_stop(vlib_main_t *vm) {
  assert(vm && workers_ready); ++dns_adapter_stops;
}
static void product_observation_quiesce(void) { ++calls; }
static void product_fragment_abort(void) { ++calls; }
static int product_packet_graph_buffer_debt(void) { ++calls; return debt; }
static void clib_panic(const char *s) { (void)s; assert(!"live carrier stop"); }
static void product_packet_graph_policy_writer_lock(product_packet_graph_main_t *g) { (void)g; ++calls; }
static void product_packet_graph_flow_pools_flush(product_packet_graph_main_t *g) { (void)g; ++calls; }
static void product_policy_domains_clear(product_packet_graph_main_t *g) { (void)g; ++calls; }
static void product_packet_graph_policy_writer_unlock(product_packet_graph_main_t *g) { (void)g; ++calls; }
''' + callback + r'''
int main(void) {
  /* Root exit uses its NULL vlib_main if startup has not run. Worker VMs are
   * unavailable here, as in the actual early-exit crash, rather than mocked
   * as valid pools with no packets. */
  product_packet_graph_stop_external(0);
  assert(calls==0 && dns_stops==0 && tcp_stops==0 && !product_packet_graph_main.enabled);
  assert(dns_adapter_stops==0 && assoc_clears==0);
  vlib_main_t vm={0}; workers_ready=1;
  product_dns_assoc_t tables[2]={{3},{4}};
  product_packet_graph_main.dns_assoc[0]=&tables[0];
  product_packet_graph_main.dns_assoc[1]=&tables[1];
  product_packet_graph_main.accepting=product_packet_graph_main.enabled=1;
  product_packet_graph_main.generation=77;
  product_packet_graph_main.dns_requests[0].active=1;
  product_packet_graph_main.dns_requests[1].active=1;
  for(unsigned n=0;n<2;++n) {
    product_packet_graph_main.dns_tcp[n].active=3;
    product_packet_graph_main.dns_tcp[n].allocated_bytes=192*1024;
  }
  product_packet_graph_stop_external(&vm);
  assert(calls==8 && !product_packet_graph_main.accepting && !product_packet_graph_main.enabled);
  assert(dns_adapter_stops==1);
  assert(assoc_clears==2 && !tables[0].pairs && !tables[1].pairs);
  assert(dns_stops==2 && !product_packet_graph_main.dns_requests[0].active
    && !product_packet_graph_main.dns_requests[1].active);
  assert(tcp_stops==2 && !product_packet_graph_main.dns_tcp[0].active
    && !product_packet_graph_main.dns_tcp[1].active && !product_packet_graph_main.dns_tcp[0].allocated_bytes
    && !product_packet_graph_main.dns_tcp[1].allocated_bytes);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='product-stop-before-start-') as folder:
    path = Path(folder)
    (path/'test.c').write_text(code)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(path/'test.c'), '-o', str(path/'test')], check=True)
    subprocess.run([str(path/'test')], check=True)
print('PASS actual stop callback: pre-start exit skips unavailable worker graph; normal stop unchanged')
