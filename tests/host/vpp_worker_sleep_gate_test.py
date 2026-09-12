#!/usr/bin/env python3
"""Execute the real pinned VPP pre-epoll decision with controlled readiness.

The extracted source ends at epoll_wait: this checks the chosen timeout, not
kernel wake behavior. It supplements, never replaces, Pixel integration tests.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True)
args = parser.parse_args()
source_text = args.source.read_text()
start = source_text.index('void\nvlib_file_poll (vlib_main_t *vm)')
end = source_text.index('  n_fds_ready = epoll_wait', start)
decision = source_text[start:end]
prefix = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct { unsigned pending; } interrupt_t;
typedef struct {
  unsigned input_node_counts_by_state[3];
  interrupt_t *node_interrupts[3];
  struct { unsigned length; } pending_frames, sched_node_pending;
} vlib_node_main_t;
typedef struct {
  vlib_node_main_t node_main;
  unsigned thread_index, api_queue_nonempty, thread_sleeps, wakeup_pending;
  unsigned file_poll_skip_loops, file_poll_no_sleep_epolls;
  unsigned check_frame_queues;
  double time_last_barrier_release;
} vlib_main_t;
typedef struct { unsigned poll_sleep_usec; } unix_main_t;
static unix_main_t unix_main;
static vlib_main_t main_vm;
static unsigned barrier;
static struct { unsigned *wait_at_barrier; } workers = {&barrier};
static __attribute__((unused)) void *vlib_worker_threads_unused;
#define vlib_worker_threads (&workers)
static int selected_timeout;
/* This test observes the sleep decision, not the separate notifier protocol. */
static __attribute__((unused)) void vlib_worker_wake_ack(vlib_main_t *vm) { (void)vm; }
#define SAKAMOTO_VPP_ANDROID_IDLE_PROFILE 1
#define SAKAMOTO_ANDROID_WORKER_IDLE_IGNORES_RECENT_BARRIER_HOLDOFF 1
#define VLIB_NODE_STATE_POLLING 1
#define VLIB_N_NODE_TYPE 3
#define VLIB_TW_TICKS_PER_SECOND 1000
#define TW_SLOTS_PER_RING 1024
#define PREDICT_FALSE(x) (x)
#define PREDICT_TRUE(x) (x)
#define clib_min(a,b) ((a)<(b)?(a):(b))
#define vec_len(v) ((v).length)
#define _vec_len(v) ((v).length)
static unsigned vlib_last_vectors_per_main_loop(vlib_main_t *vm) { (void)vm; return 0; }
static unsigned clib_interrupt_is_any_pending(interrupt_t *i) { return i->pending; }
static unsigned vlib_tw_timer_first_expires_in_ticks(vlib_main_t *vm) { (void)vm; return TW_SLOTS_PER_RING; }
static __attribute__((unused)) vlib_main_t *vlib_get_first_main(void) { return &main_vm; }
static __attribute__((unused)) double vlib_time_now(vlib_main_t *vm) { (void)vm; return 10; }
'''
suffix = r'''
  /* Observe the real pre-wait decision, without running VPP fd callbacks. */
  (void)e; (void)epoll_events; (void)n_fds_ready;
  selected_timeout = timeout_ms;
}
int main(void) {
  unsigned failures = 0;
  const char *names[] = {"idle", "node_interrupt", "local_pending_frame", "published_remote_frame", "due_scheduled_node", "runnable_poll_node"};
  for (unsigned scenario = 0; scenario < 6; ++scenario) {
    vlib_main_t vm = {.thread_index = 1};
    interrupt_t interrupt = {.pending = 1};
    if (scenario == 1) vm.node_main.node_interrupts[0] = &interrupt;
    if (scenario == 2) vm.node_main.pending_frames.length = 1;
    if (scenario == 3) vm.check_frame_queues = 1;
    if (scenario == 4) vm.node_main.sched_node_pending.length = 1;
    if (scenario == 5) vm.node_main.input_node_counts_by_state[VLIB_NODE_STATE_POLLING] = 1;
    vlib_file_poll(&vm);
    int expected = scenario ? 0 : 1000;
    int passed = selected_timeout == expected;
    printf("%s scenario=%s selected_timeout_ms=%d expected_ms=%d\n",
           passed ? "PASS" : "FAIL", names[scenario], selected_timeout, expected);
    failures += !passed;
  }
  return failures ? 1 : 0;
}
'''
with tempfile.TemporaryDirectory(prefix='s239-vpp-sleep-gate-') as temporary:
    source = Path(temporary) / 'test.c'
    binary = Path(temporary) / 'test'
    source.write_text(prefix + decision + suffix)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(binary)], check=True)
    result = subprocess.run([str(binary)], timeout=3)
    raise SystemExit(result.returncode)
