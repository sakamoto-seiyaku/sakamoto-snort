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
typedef struct { int thread_index; } vlib_main_t;
typedef struct { unsigned accepting, enabled; } product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
static int workers_ready, calls, debt;
#define PREDICT_FALSE(x) (x)
#define clib_atomic_store_rel_n(p,v) (*(p)=(v))
static void product_flow_end_quiesce(vlib_main_t *vm) {
  assert(vm && workers_ready); ++calls;
}
static void product_observation_quiesce(void) { ++calls; }
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
  assert(calls==0 && !product_packet_graph_main.enabled);
  vlib_main_t vm={0}; workers_ready=1;
  product_packet_graph_main.accepting=product_packet_graph_main.enabled=1;
  product_packet_graph_stop_external(&vm);
  assert(calls==7 && !product_packet_graph_main.accepting && !product_packet_graph_main.enabled);
  return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='product-stop-before-start-') as folder:
    path = Path(folder)
    (path/'test.c').write_text(code)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(path/'test.c'), '-o', str(path/'test')], check=True)
    subprocess.run([str(path/'test')], check=True)
print('PASS actual stop callback: pre-start exit skips unavailable worker graph; normal stop unchanged')
