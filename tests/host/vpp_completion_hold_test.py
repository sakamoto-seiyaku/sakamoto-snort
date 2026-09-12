#!/usr/bin/env python3
"""Execute the actual native completion retry loop with controlled readiness.

Tests the validation-only hold seam's bounded scan, not VPP queue publication.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'src/product/vpp/product_packet_graph.c').read_text()
start = source.index('VLIB_NODE_FN (product_packet_completion_retry_node)')
end = source.index('VLIB_REGISTER_NODE (product_packet_completion_retry_node)', start)
function = source[start:end]
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
typedef unsigned long uword;
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { u32 node_index; } vlib_node_runtime_t;
typedef struct { u32 unused; } vlib_frame_t;
typedef struct { u32 returned; } product_packet_completion_frame_t;
typedef struct { unsigned char opaque2[32]; } buffer_t;
typedef struct { u32 completion_retry_attempts, completion_pending_returns; } product_packet_graph_main_t;
#define PRODUCT_GRAPH_WORKERS 2
#define PRODUCT_COMPLETION_RETURN_CAPACITY 512
typedef struct { u32 buffers[512], head, count; } product_completion_return_queue_t;
static product_packet_graph_main_t product_packet_graph_main;
static product_completion_return_queue_t product_completion_returns[3];
static buffer_t storage[512];
static unsigned held, congested, attempts, delivered, scheduled, hold_checks;
#define VLIB_NODE_FN(n) uword n
#define ASSERT(x) assert(x)
#define clib_min(a,b) ((a)<(b)?(a):(b))
#define clib_memcpy_fast memcpy
#define clib_atomic_fetch_add_relax(p,n) (*(p)+=(n))
#define clib_atomic_fetch_sub_relax(p,n) (*(p)-=(n))
static buffer_t *vlib_get_buffer(vlib_main_t *vm, u32 bi) { (void)vm; return &storage[bi]; }
static int product_vpn_tun_return_held(vlib_main_t *vm, const product_packet_completion_frame_t *c) {
  (void)vm; ++hold_checks; return held && c->returned;
}
static int product_completion_return_try(vlib_main_t *vm, vlib_node_runtime_t *node,
  u32 bi, const product_packet_completion_frame_t *c, int retry) {
  (void)vm; (void)node; (void)bi; assert(retry); ++attempts;
  assert(!(held && c->returned));
  if (congested) return 0;
  ++delivered; return 1;
}
static int vlib_node_is_scheduled(vlib_main_t *vm, u32 node) { (void)vm; (void)node; return scheduled; }
static void vlib_node_schedule(vlib_main_t *vm, u32 node, double seconds) {
  (void)vm; (void)node; assert(seconds == .001); ++scheduled;
}
'''
suffix = r'''
static void add(unsigned index, unsigned returned) {
  product_completion_return_queue_t *q = &product_completion_returns[1];
  product_packet_completion_frame_t c = {.returned = returned};
  memcpy(storage[index].opaque2, &c, sizeof(c));
  q->buffers[(q->head + q->count++) % 512] = index;
  ++product_packet_graph_main.completion_pending_returns;
}
int main(void) {
  vlib_main_t vm = {.thread_index = 1}; vlib_node_runtime_t node = {0};
  product_completion_return_queue_t *q = &product_completion_returns[1];
  q->head = 470; /* Exercise wraparound while rotating held native indices. */
  for (unsigned i = 0; i < 192; ++i) add(i, i < 128);
  held = 1;
  for (unsigned i = 0; i < 3; ++i) {
    unsigned before = hold_checks; scheduled = 0;
    uword done = product_packet_completion_retry_node(&vm, &node, 0);
    assert(done == (i == 2 ? 64 : 0));
    assert(hold_checks - before <= 64 && scheduled == 1);
  }
  assert(delivered == 64 && attempts == 64 && q->count == 128);
  assert(product_packet_graph_main.completion_pending_returns == 128);
  held = 0; congested = 1; scheduled = 0;
  unsigned head = q->head;
  assert(product_packet_completion_retry_node(&vm, &node, 0) == 0);
  assert(attempts == 65 && q->head == head && q->count == 128 && scheduled == 1);
  congested = 0;
  for (unsigned i = 0; i < 2; ++i) {
    scheduled = 0;
    assert(product_packet_completion_retry_node(&vm, &node, 0) == 64);
    assert(scheduled == (i == 0));
  }
  assert(delivered == 192 && q->count == 0);
  assert(product_packet_graph_main.completion_pending_returns == 0);
  puts("PASS actual retry loop: 64-scan bound, held returns, original progress, wraparound, native congestion, drain");
}
'''
with tempfile.TemporaryDirectory(prefix='s239-completion-hold-') as temporary:
    source = Path(temporary) / 'test.c'
    binary = Path(temporary) / 'test'
    source.write_text(prefix + function + suffix)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=3)
