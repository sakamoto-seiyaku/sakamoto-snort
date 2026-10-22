#!/usr/bin/env python3
"""Execute actual TUN startup/callback with bounded native/read dependencies."""

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
    match = re.search(r"(?:static )?(?:void|int|clib_error_t \*)\s*" + name + r"\s*\(", source)
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
#include <sys/socket.h>
#include <sys/un.h>
#include "product_runtime_topology.h"
#include "product_packet.h"
#include "product_packet_batch.h"
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef double f64;
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct clib_file_s clib_file_t;
struct clib_file_s { u32 file_descriptor, polling_thread_index; const char *(*read_function)(clib_file_t *); char *description; };
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
#define TUN_CONTROL_SLOTS 2
#define PRODUCT_VPN_RETURN_WORKERS 2
#define PRODUCT_VPN_RETURN_CAPACITY 128
#define clib_warning(...) ((void)0)
#define format(...) ((char *)"tun-control")
#if TEST_TCP_BATCH
#define SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT 1
#endif
typedef struct {u32 file; int fd;} tun_control_t;
#define clib_memset memset
static struct {
  u64 generation, next_token, captured, submitted, completed;
  u64 errors, capture_callbacks, capture_alloc_attempts, capture_alloc_failures;
  u64 fault_capture_alloc_at, pregraph_returns, transport_unavailable;
  u64 capture_batch_calls, capture_batch_packets, capture_batch_max;
  u64 capture_budget_exits, capture_callback_ns, capture_callback_max_ns;
  u32 origin_worker, pending, test_uid, snapshot_interface, capture_batch_limit;
  u8 draining, test_uid_known, enabled, stop_started, graph_quiesced;
  int tun_fd, listener_fd;
  u32 listener_file;
  char path[108];
  vlib_main_t *vm;
  tun_control_t controls[TUN_CONTROL_SLOTS];
  tun_pending_t obligations[TUN_PENDING];
} tun;
static vlib_main_t vm = {.thread_index = 3};
static vlib_buffer_t buffers[256];
static unsigned allocated, freed[256], accepted[256], attempts[256], successful_read[256], pauses;
static unsigned input_count, reads, fail_read_at, reject_odd;
static int read_error, read_eof;
static unsigned native_alloc_fail_at;
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
  if(allocated==native_alloc_fail_at)return 0;
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
  if (reads == fail_read_at) { errno = read_error; return read_eof ? 0 : -1; }
  if (reads == input_count) { errno = EAGAIN; return -1; }
  assert(allocated && data==buffers[allocated-1].data);
  successful_read[allocated-1]=1;
  memset(data, (int)(++reads), 32); return 32;
}
#define read fake_read
static u32 product_network_snapshot_context(u32 interface) { assert(interface == 9); return 4; }
static const sakamoto_product_network_snapshot_t *product_network_snapshot_current(void) {
  static const sakamoto_product_network_snapshot_t snapshot = {0}; return &snapshot;
}
static u64 product_packet_graph_trace_limit(void) { return 0; }
static struct { u64 credit; struct {u64 generation;} stamps; u32 next_stamp_slot; } returns[2];
static unsigned graph_starts, return_inits, listener_adds, snapshot_starts, driver_starts;
static int file_main;
static u32 active_owner_count(void) { return 2; }
static int product_vpn_tun_enabled(void) { return 1; }
static u32 vlib_num_workers(void) { return 3; }
static int product_vpn_tun_product_mode(void) { return 0; }
static int product_vpn_return_credit_init(u64 *credit,u64 generation,u32 capacity) {
  assert(generation && capacity==PRODUCT_VPN_RETURN_CAPACITY);*credit=generation;++return_inits;return 0;
}
static int fake_socket(int domain,int type,int protocol) {
  assert(domain==AF_UNIX && type==(SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC) && !protocol);return 27;
}
static int fake_bind(int fd,const struct sockaddr *address,socklen_t length) {
  assert(fd==27 && address->sa_family==AF_UNIX && length==sizeof(struct sockaddr_un));return 0;
}
static int fake_listen(int fd,int backlog) { assert(fd==27 && backlog==4);return 0; }
static int fake_close(int fd) { assert(fd==27);return 0; }
static int fake_unlink(const char *path) { assert(path && *path);return 0; }
#define socket fake_socket
#define bind fake_bind
#define listen fake_listen
#define close fake_close
#define unlink fake_unlink
static int product_packet_graph_start_external(vlib_main_t *main,u64 generation,product_adapter_obligation_kind_t kind) {
  assert(main==&vm && generation && kind==PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);++graph_starts;return 1;
}
static void product_packet_graph_stop_external(vlib_main_t *main) { assert(main==&vm); }
static int product_vpn_flow_stack_driver_start(vlib_main_t *main,u64 generation) {
  assert(main==&vm && generation);++driver_starts;return 1;
}
static void product_vpn_uid_resolver_start(u64 generation) { assert(generation); }
static void product_network_snapshot_start(u64 generation) { assert(generation);++snapshot_starts; }
static clib_error_t *tun_control_accept(clib_file_t *file) { (void)file;return 0; }
static u32 clib_file_add(int *main,clib_file_t *file) {
  assert(main==&file_main && file->file_descriptor==27 && !file->polling_thread_index);
  assert(file->read_function==tun_control_accept && file->description);return ++listener_adds;
}
'''.replace("typedef uint32_t u32;", "typedef uint16_t u16;\ntypedef uint32_t u32;")

# Compile with the actual production constants so a changed threshold or READY
# budget must satisfy the behavioral assertions below rather than fixture values.
for constant in ("TUN_CAPTURE_BUDGET", "TUN_CAPTURE_BATCH_CAPACITY"):
    definition = re.search(r"^#define " + constant + r" ([A-Z_0-9]+)$", source, re.M)
    assert definition, constant
    prefix = re.sub(r"^#define " + constant + r" \d+$", definition.group(0), prefix, flags=re.M)

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
  memset(attempts, 0, sizeof(attempts)); memset(successful_read, 0, sizeof(successful_read)); memset(submit_sizes, 0, sizeof(submit_sizes));
  tun.generation = 8041; tun.origin_worker = 2; tun.tun_fd = 19;
  tun.capture_batch_limit = limit; tun.test_uid = 10456; tun.test_uid_known = 1;
  tun.snapshot_interface = 9; allocated = reads = submit_calls = submit_count = pauses = 0;
  input_count = count; fail_read_at = UINT32_MAX; reject_odd = 0; read_error = EAGAIN; read_eof = 0; native_alloc_fail_at = UINT32_MAX;
  tun.enabled = 1; memset(debts, 0, sizeof(debts)); configured = 0;
}
static void callback(void) { clib_file_t file = {.file_descriptor = 19}; assert(!tun_read_ready(&file)); }
static void audit(unsigned captured, unsigned delivered) {
  assert(tun.captured == captured && reads == captured && tun.submitted == delivered);
  assert(tun.pending == delivered && submit_count == delivered);
  unsigned ledger = 0, released = 0;
  for (unsigned i = 0; i < allocated; ++i) {
    assert(!(accepted[i] && freed[i])); released += freed[i];
    assert(attempts[i] == successful_read[i]);
  }
  for (unsigned i = 0; i < TUN_PENDING; ++i) ledger += tun.obligations[i].active;
  assert(ledger == delivered && released == allocated - delivered);
}
static void generation_defaults(void) {
  reset(1,0); tun.enabled=0;
  assert(setenv("SAKAMOTO_VPP_RUNTIME_DIR","/tmp/capture-start-seam",1)==0);
  assert(setenv("SAKAMOTO_PRODUCT_OWNER_COUNT","2",1)==0);
  assert(setenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID","3",1)==0);
  assert(product_vpn_tun_start(&vm,9001));
  assert(tun.capture_batch_limit==64 && tun.generation==9001 && tun.enabled);
  assert(graph_starts==1 && driver_starts==1 && snapshot_starts==1 && listener_adds==1 && return_inits==2);
  unformat_input_t scalar={.value=1,.valid=1};
  assert(!tun_capture_batch_cli(&vm,&scalar,0) && tun.capture_batch_limit==1);
  assert(!product_vpn_tun_start(&vm,9002) && tun.capture_batch_limit==1);
  /* The lifecycle dependency has completed an empty generation: startup itself
   * must overwrite the old scalar diagnostic override for the next one. */
  tun.enabled=0;
  assert(product_vpn_tun_start(&vm,9002));
  assert(tun.capture_batch_limit==64 && tun.generation==9002);
  assert(graph_starts==2 && driver_starts==2 && snapshot_starts==2 && listener_adds==2 && return_inits==4);
  for(unsigned i=0;i<2;i++)assert(returns[i].stamps.generation==9002 && returns[i].credit==9002);
}
int main(void) {
  generation_defaults();
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
  for(unsigned mode=0;mode<3;mode++) {
    reset(64,10); fail_read_at=3;
    read_eof=mode==0; read_error=mode==2 ? EINTR : EIO;
    callback(); audit(3,3);
    assert(submit_calls==1 && submit_sizes[0]==3);
    assert(tun.draining==(mode!=2) && tun.errors==(mode!=2));
    unsigned before=allocated;
    if(mode!=2) { callback(); audit(3,3); assert(allocated==before); }
    else {
      fail_read_at=UINT32_MAX; callback(); audit(10,10);
      assert(submit_calls==2 && submit_sizes[1]==7 && !tun.draining && !tun.errors);
    }
  }
  reset(64,125); callback(); callback(); audit(125,125);
  assert(submit_calls==2 && submit_sizes[0]==64 && submit_sizes[1]==61);
  input_count=128; callback(); audit(128,128);
  assert(submit_calls==3 && submit_sizes[2]==3 && pauses==1);
  unsigned full_allocated=allocated; callback(); audit(128,128); assert(allocated==full_allocated);
  reset(64, 64); tun.fault_capture_alloc_at = 4; callback(); audit(3, 3);
  assert(tun.capture_alloc_failures == 1 && pauses == 1 && submit_sizes[0] == 3);
  reset(64,64); native_alloc_fail_at=3; callback(); audit(3,3);
  assert(tun.capture_alloc_failures==1 && pauses==1 && submit_calls==1 && submit_sizes[0]==3);
  reset(64, 64); reject_odd = 1; callback(); audit(64, 32);
  assert(tun.pregraph_returns == 32 && tun.transport_unavailable == 32);
  reset(16, 128); callback(); callback(); audit(128, 128); assert(pauses == 1 && submit_calls == 8);
  callback(); audit(128, 128); assert(reads == 128);
  reset(64, 3); tun.draining = 1; callback(); audit(0, 0); assert(!allocated && !submit_calls);
  puts("PASS actual TUN generation default64/reset independent of TCP mode; callback all1..64 overrides, original buffer/index/metadata, partial EAGAIN/EINTR/EOF/EIO/allocation, mixed rejection settlement, callback64/capture128 bounds, drain");
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="sakamoto-vpn-capture-") as temporary:
    directory = Path(temporary)
    c_source, executable = directory / "capture.c", directory / "capture"
    c_source.write_text(prefix + header[item_begin:item_end] + dependencies
                        + function("tun_submit_captured") + function("tun_read_ready")
                        + function("tun_capture_batch_cli") + function("product_vpn_tun_start") + suffix)
    for mode in (0, 1):
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        f"-DTEST_TCP_BATCH={mode}", "-I", str(PRODUCT), str(c_source),
                        str(PRODUCT / "product_runtime_topology.c"), "-o", str(executable)], check=True, timeout=30)
        subprocess.run([str(executable)], check=True, timeout=5)
print("tun_source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
