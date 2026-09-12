#!/usr/bin/env python3
"""Execute the selected VPP initial-barrier function against a sleeping worker.

Extracts actual source; substitutes only VPP types/clock and worker environment.
This is a timing-seam regression, not proof of the full Android startup path.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
a = p.parse_args()
text = a.source.read_text()
start = text.index('void\nvlib_worker_thread_initial_barrier_sync_and_release (')
end = text.index('\n}', start) + 2
function = text[start:end]
notify_source = a.source.with_name('file.c').read_text()
notify_signature = 'void\nvlib_thread_wakeup ('
notify_function = ''
if notify_signature in notify_source:
    notify_start = notify_source.index(notify_signature)
    notify_function = notify_source[notify_start:notify_source.index('\n}', notify_start) + 2]
prefix = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
typedef double f64;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned clib_thread_index_t;
typedef struct { int wakeup_fd; uint8_t wakeup_pending; } vlib_main_t;
static vlib_main_t mains[2];
static _Atomic unsigned waiting, arrived, armed;
static struct { _Atomic unsigned *wait_at_barrier, *workers_at_barrier; }
  threads = { &waiting, &arrived }, *vlib_worker_threads = &threads;
static unsigned vlib_get_n_threads(void) { return 2; }
static __attribute__((unused)) vlib_main_t *vlib_get_main_by_index(unsigned i) { return &mains[i]; }
static double vlib_time_now(vlib_main_t *vm) {
  (void)vm; struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec * 1e-9;
}
#define BARRIER_SYNC_TIMEOUT 0.1
#define CLIB_PAUSE() sched_yield()
#define fformat fprintf
#define os_panic() exit(42)
#define clib_panic(...) abort()
#define SAKAMOTO_VPP_ANDROID_IDLE_PROFILE 1
'''
suffix = r'''
static void *worker(void *arg) {
  (void)arg;
  int ep = epoll_create1(EPOLL_CLOEXEC);
  assert(ep >= 0);
  struct epoll_event event = { .events = EPOLLIN, .data.fd = mains[1].wakeup_fd };
  assert(!epoll_ctl(ep, EPOLL_CTL_ADD, mains[1].wakeup_fd, &event));
  /* Worker already passed its barrier check; no conditional sleep flag yet.
   * Eventfd must retain a wake even if main wins the race to epoll_wait. */
  atomic_store(&armed, 1);
  assert(epoll_wait(ep, &event, 1, 1000) == 1);
  assert(atomic_load(&waiting));
  atomic_store(&arrived, 1);
  while (atomic_load(&waiting)) sched_yield();
  close(ep);
  return 0;
}
int main(void) {
  mains[1].wakeup_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  assert(mains[1].wakeup_fd >= 0);
  pthread_t thread; assert(!pthread_create(&thread, 0, worker, 0));
  while (!atomic_load(&armed)) sched_yield();
  vlib_worker_thread_initial_barrier_sync_and_release(&mains[0]);
  assert(!pthread_join(thread, 0));
  close(mains[1].wakeup_fd);
  puts("initial barrier wakes sleeping worker PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='vpp-initial-barrier-') as temporary:
    source = Path(temporary) / 'test.c'
    binary = Path(temporary) / 'test'
    source.write_text(prefix + notify_function + '\n' + function + suffix)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=3)
