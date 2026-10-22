#!/usr/bin/env python3
"""Execute the actual TUN callback with bounded native/read dependencies."""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
source = (PRODUCT / "product_vpn_tun_adapter.c").read_text()
header = (PRODUCT / "product_packet_graph.h").read_text()


def function(name):
    match = re.search(r"(?:static )?(?:void|clib_error_t \*)\s*" + name + r"\s*\(", source)
    assert match, name
    opening = source.index("{", match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


item_end = header.index("} product_packet_graph_external_item_t;") + len("} product_packet_graph_external_item_t;")
item_begin = header.rfind("typedef struct", 0, item_end)
prefix = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "product_packet.h"
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef double f64;
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { u32 file_descriptor; } clib_file_t;
typedef struct { u8 opaque[40], opaque2[56], data[256]; u16 current_length; } vlib_buffer_t;
typedef struct { u64 revision, event_elapsed_ns; } sakamoto_product_network_snapshot_t;
typedef const char clib_error_t;
typedef struct { u64 value; int valid, trailing; } unformat_input_t;
typedef struct { int unused; } vlib_cli_command_t;
typedef struct { u64 token; u32 buffer; u8 active; } tun_pending_t;
#define clib_error_return(unused,message) (message)
#define UNFORMAT_END_OF_INPUT 0
#define TUN_PENDING 128
#define TUN_CAPTURE_BUDGET 64
#define TUN_CAPTURE_BATCH_CAPACITY 64
#define clib_memset memset
static struct {
  u64 generation, next_token, captured, submitted, completed;
  u64 errors, capture_callbacks, capture_alloc_attempts, capture_alloc_failures;
  u64 fault_capture_alloc_at, pregraph_returns, transport_unavailable;
  u64 capture_batch_calls, capture_batch_packets, capture_batch_max;
  u64 capture_budget_exits, capture_callback_ns, capture_callback_max_ns;
  u32 origin_worker, pending, test_uid, snapshot_interface, capture_batch_limit;
  u8 draining, test_uid_known, enabled, stop_started, graph_quiesced;
  int tun_fd;
  tun_pending_t obligations[TUN_PENDING];
} tun;
static vlib_main_t vm = {.thread_index = 3};
static vlib_buffer_t buffers[256];
static unsigned allocated, freed[256], accepted[256], attempts[256], pauses;
static unsigned input_count, reads, fail_read_at, reject_odd;
static unsigned submit_calls, submit_sizes[256], submit_buffers[256], submit_count;
static u64 debts[4];
static unsigned configured;
static int unformat(unformat_input_t *input, const char *format, u64 *value) {
  assert(!strcmp(format, "%llu")); *value = input->value; return input->valid;
}
static int unformat_check_input(unformat_input_t *input) { return input->trailing; }
static u32 product_packet_graph_enabled(void) { return 1; }
static u64 product_packet_graph_obligation_debt(void) { return debts[0]; }
static u64 product_packet_graph_buffer_debt(void) { return debts[1]; }
static u64 product_packet_graph_handoff_debt(void) { return debts[2]; }
static u64 product_packet_graph_completion_frame_debt(void) { return debts[3]; }
static void vlib_cli_output(vlib_main_t *main, const char *format, ...) {
  assert(main->thread_index == 3 && format); ++configured;
}
static vlib_main_t *vlib_get_main(void) { return &vm; }
static u32 vlib_get_thread_index(void) { return vm.thread_index; }
static u32 vlib_get_worker_thread_index(u32 worker) { return worker + 1; }
static u64 trace_monotonic_ns(void) { static u64 now; return ++now; }
static void tun_pause_reads(vlib_main_t *main, int fault) {
  assert(main == &vm && (fault == 0 || fault == 1)); ++pauses;
}
static int vlib_buffer_alloc(vlib_main_t *main, u32 *index, unsigned count) {
  assert(main == &vm && count == 1 && allocated < 256);
  *index = allocated++; return 1;
}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *main, u32 index) {
  assert(main == &vm && index < allocated && !freed[index]); return &buffers[index];
}
static void vlib_buffer_reset(vlib_buffer_t *buffer) { buffer->current_length = 0; }
static void *vlib_buffer_get_current(vlib_buffer_t *buffer) { return buffer->data; }
static u32 vlib_buffer_get_default_data_size(vlib_main_t *main) { assert(main == &vm); return 256; }
static void vlib_buffer_free(vlib_main_t *main, u32 *index, unsigned count) {
  assert(main == &vm && count == 1 && *index < allocated);
  assert(!accepted[*index] && !freed[*index]); ++freed[*index];
}
static ssize_t fake_read(int fd, void *data, size_t capacity) {
  assert(fd == 19 && capacity == 256);
  if (reads == fail_read_at || reads == input_count) { errno = EAGAIN; return -1; }
  memset(data, (int)(++reads), 32); return 32;
}
#define read fake_read
static u32 product_network_snapshot_context(u32 interface) { assert(interface == 9); return 4; }
static const sakamoto_product_network_snapshot_t *product_network_snapshot_current(void) {
  static const sakamoto_product_network_snapshot_t snapshot = {0}; return &snapshot;
}
static u64 product_packet_graph_trace_limit(void) { return 0; }
'''.replace("typedef uint32_t u32;", "typedef uint16_t u16;\ntypedef uint32_t u32;")

dependencies = r'''
static unsigned submit_item(const product_packet_graph_external_item_t *item) {
  u32 index = item->buffer_index;
  assert(index < allocated && !freed[index] && !attempts[index]++);
  assert(item->obligation.kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  assert(item->obligation.queue_generation == tun.generation);
  assert(item->obligation.origin_worker == 2 && item->obligation.origin_lane == 0);
  assert(item->platform.provenance == PRODUCT_PACKET_PROVENANCE_VPN_TUN);
  assert(item->platform.uid == 10456 && item->platform.network_context_id == 4);
  unsigned token = (unsigned)item->obligation.token;
  assert(tun.obligations[token % TUN_PENDING].active);
  assert(tun.obligations[token % TUN_PENDING].buffer == index);
  for (unsigned byte = 0; byte < 32; ++byte) assert(buffers[index].data[byte] == (u8)token);
  if (reject_odd && (token & 1)) return 0;
  accepted[index] = 1;
  submit_buffers[submit_count++] = index;
  return 1;
}
static u32 product_packet_graph_submit_external_batch(vlib_main_t *main,
  const product_packet_graph_external_item_t *items, u32 count, u8 *mask) {
  assert(main == &vm && count && count <= TUN_CAPTURE_BATCH_CAPACITY);
  submit_sizes[submit_calls++] = count;
  unsigned total = 0;
  for (u32 i = 0; i < count; ++i) total += mask[i] = submit_item(&items[i]);
  return total;
}
static int product_packet_graph_submit_external(vlib_main_t *main, u32 index,
  const product_platform_packet_facts_t *platform, const product_adapter_obligation_t *obligation) {
  assert(main == &vm);
  submit_sizes[submit_calls++] = 1;
  product_packet_graph_external_item_t item = {.buffer_index = index, .platform = *platform, .obligation = *obligation};
  return submit_item(&item);
}
'''

suffix = r'''
static void reset(unsigned limit, unsigned count) {
  memset(&tun, 0, sizeof(tun)); memset(buffers, 0, sizeof(buffers));
  memset(freed, 0, sizeof(freed)); memset(accepted, 0, sizeof(accepted));
  memset(attempts, 0, sizeof(attempts)); memset(submit_sizes, 0, sizeof(submit_sizes));
  tun.generation = 8041; tun.origin_worker = 2; tun.tun_fd = 19;
  tun.capture_batch_limit = limit; tun.test_uid = 10456; tun.test_uid_known = 1;
  tun.snapshot_interface = 9; allocated = reads = submit_calls = submit_count = pauses = 0;
  input_count = count; fail_read_at = UINT32_MAX; reject_odd = 0;
  tun.enabled = 1; memset(debts, 0, sizeof(debts)); configured = 0;
}
static void callback(void) { clib_file_t file = {.file_descriptor = 19}; assert(!tun_read_ready(&file)); }
static void audit(unsigned captured, unsigned delivered) {
  assert(tun.captured == captured && reads == captured && tun.submitted == delivered);
  assert(tun.pending == delivered && submit_count == delivered);
  unsigned ledger = 0, released = 0;
  for (unsigned i = 0; i < allocated; ++i) {
    assert(!(accepted[i] && freed[i])); released += freed[i];
    if (i < captured) assert(attempts[i] == 1);
  }
  for (unsigned i = 0; i < TUN_PENDING; ++i) ledger += tun.obligations[i].active;
  assert(ledger == delivered && released == allocated - delivered);
}
int main(void) {
  for (unsigned limit = 1; limit <= 64; ++limit) {
    reset(1, 0); unformat_input_t input = {.value = limit, .valid = 1};
    assert(!tun_capture_batch_cli(&vm, &input, 0));
    assert(tun.capture_batch_limit == limit && configured == 1);
  }
  const u64 invalid[] = {0, 65, UINT64_C(4294967297), UINT64_MAX};
  for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
    reset(16, 0); unformat_input_t input = {.value = invalid[i], .valid = 1};
    assert(tun_capture_batch_cli(&vm, &input, 0));
    assert(tun.capture_batch_limit == 16 && !configured);
  }
  for (unsigned mode = 0; mode < 11; ++mode) {
    reset(16, 0); unformat_input_t input = {.value = 64, .valid = 1};
    if (mode < 4) debts[mode] = 1;
    else if (mode == 4) tun.pending = 1;
    else if (mode == 5) tun.draining = 1;
    else if (mode == 6) tun.stop_started = 1;
    else if (mode == 7) tun.graph_quiesced = 1;
    else if (mode == 8) tun.enabled = 0;
    else if (mode == 9) input.valid = 0;
    else input.trailing = 1;
    assert(tun_capture_batch_cli(&vm, &input, 0));
    assert(tun.capture_batch_limit == 16 && !configured);
  }
  for (unsigned limit = 1; limit <= 64; ++limit) {
    reset(limit, 64); callback(); audit(64, 64);
    assert(tun.capture_budget_exits == 1);
    assert(submit_calls == (64 + limit - 1) / limit);
    for (unsigned i = 0; i < submit_calls; ++i) assert(submit_sizes[i] <= limit);
  }
  reset(64, 3); callback(); audit(3, 3); assert(submit_calls == 1 && submit_sizes[0] == 3);
  reset(64, 64); tun.fault_capture_alloc_at = 4; callback(); audit(3, 3);
  assert(tun.capture_alloc_failures == 1 && pauses == 1 && submit_sizes[0] == 3);
  reset(64, 64); reject_odd = 1; callback(); audit(64, 32);
  assert(tun.pregraph_returns == 32 && tun.transport_unavailable == 32);
  reset(16, 128); callback(); callback(); audit(128, 128); assert(pauses == 1 && submit_calls == 8);
  callback(); audit(128, 128); assert(reads == 128);
  reset(64, 3); tun.draining = 1; callback(); audit(0, 0); assert(!allocated && !submit_calls);
  puts("PASS actual TUN callback: all 1..64 limits, original buffer/index/metadata, partial EAGAIN/allocation, mixed rejection settlement, capture128 bound, drain");
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="sakamoto-vpn-capture-") as temporary:
    directory = Path(temporary)
    c_source, executable = directory / "capture.c", directory / "capture"
    c_source.write_text(prefix + header[item_begin:item_end] + dependencies
                        + function("tun_submit_captured") + function("tun_read_ready")
                        + function("tun_capture_batch_cli") + suffix)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(PRODUCT), str(c_source), "-o", str(executable)], check=True, timeout=30)
    subprocess.run([str(executable)], check=True, timeout=5)
print("tun_source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
