#!/usr/bin/env python3
"""Exercise the actual VPP notifier/ack functions with real eventfd and epoll.

Controlled types/publication payload isolate the notification seam. VPP queue
integration, teardown supervision and Android scheduling require device tests.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--emit-c', type=Path)
args = parser.parse_args()
text = args.source.read_text()
def function(signature):
    start = text.index(signature)
    return text[start:text.index('\n}', start) + 2]
functions = function('void\nvlib_thread_wakeup (') + '\n' + function('static void\nvlib_worker_wake_ack (')
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
#include <unistd.h>
typedef uint64_t u64;
typedef unsigned clib_thread_index_t;
typedef struct { int wakeup_fd; unsigned thread_index; uint8_t wakeup_pending; } vlib_main_t;
static vlib_main_t mains[1];
static vlib_main_t *vlib_get_main_by_index(unsigned i) { assert(i == 0); return &mains[0]; }
#define clib_panic(...) abort()
static _Atomic unsigned writes, delay_writer, write_entered, allow_write, interrupt_write;
static ssize_t notified_write(int fd, const void *data, size_t length) {
  atomic_fetch_add(&writes, 1);
  if (atomic_exchange(&interrupt_write, 0)) { errno = EINTR; return -1; }
  if (atomic_load(&delay_writer)) {
    atomic_store(&write_entered, 1);
    while (!atomic_load(&allow_write)) sched_yield();
  }
  return write(fd, data, length);
}
#define write notified_write
'''
suffix = r'''
#undef write
static _Atomic unsigned published[2], done[2];
enum { ROUNDS = 50000 };
static void *producer(void *arg) {
  unsigned index = (uintptr_t)arg;
  for (unsigned i = 1; i <= ROUNDS; ++i) {
    atomic_store_explicit(&published[index], i, memory_order_release);
    vlib_thread_wakeup(0);
  }
  atomic_store(&done[index], 1);
  vlib_thread_wakeup(0);
  return NULL;
}
static void *once(void *arg) { (void)arg; vlib_thread_wakeup(0); return NULL; }
int main(void) {
  mains[0].wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  assert(mains[0].wakeup_fd >= 0);
  int ep = epoll_create1(EPOLL_CLOEXEC);
  assert(ep >= 0);
  struct epoll_event event = {.events = EPOLLIN, .data.fd = mains[0].wakeup_fd};
  assert(!epoll_ctl(ep, EPOLL_CTL_ADD, mains[0].wakeup_fd, &event));
  vlib_worker_wake_ack(&mains[0]); /* empty nonblocking read */
  assert(epoll_wait(ep, &event, 1, 0) == 0);
  for (unsigned i = 0; i < 100; ++i) vlib_thread_wakeup(0);
  assert(atomic_load(&writes) == 1); /* user-space syscall coalescing */
  assert(epoll_wait(ep, &event, 1, 20) == 1); /* write before wait is retained */
  assert(epoll_wait(ep, &event, 1, 0) == 1); /* LT until acknowledgement */
  vlib_worker_wake_ack(&mains[0]);
  assert(epoll_wait(ep, &event, 1, 0) == 0);
  atomic_store(&interrupt_write, 1);
  vlib_thread_wakeup(0);
  assert(epoll_wait(ep, &event, 1, 20) == 1);
  vlib_worker_wake_ack(&mains[0]);
  /* Counter saturation is existing readability, not an unreported wake. */
  u64 full = UINT64_MAX - 1;
  assert(write(mains[0].wakeup_fd, &full, sizeof(full)) == sizeof(full));
  vlib_thread_wakeup(0);
  assert(epoll_wait(ep, &event, 1, 20) == 1);
  vlib_worker_wake_ack(&mains[0]);
  /* First writer pauses after winning the latch. Consumer can acknowledge
   * already-visible work before its syscall; its late write stays harmless. */
  atomic_store(&delay_writer, 1);
  pthread_t delayed;
  assert(!pthread_create(&delayed, NULL, once, NULL));
  while (!atomic_load(&write_entered)) sched_yield();
  vlib_thread_wakeup(0); /* coalesced behind delayed notifier */
  vlib_worker_wake_ack(&mains[0]);
  atomic_store(&allow_write, 1);
  assert(!pthread_join(delayed, NULL));
  atomic_store(&delay_writer, 0);
  assert(epoll_wait(ep, &event, 1, 20) == 1);
  vlib_worker_wake_ack(&mains[0]);
  pthread_t threads[2];
  for (uintptr_t i = 0; i < 2; ++i)
    assert(!pthread_create(&threads[i], NULL, producer, (void *)i));
  unsigned observed[2] = {0};
  for (;;) {
    vlib_worker_wake_ack(&mains[0]);
    unsigned now[2] = {atomic_load_explicit(&published[0], memory_order_acquire),
                       atomic_load_explicit(&published[1], memory_order_acquire)};
    if (now[0] == ROUNDS && now[1] == ROUNDS && atomic_load(&done[0]) && atomic_load(&done[1])) break;
    if (now[0] != observed[0] || now[1] != observed[1]) {
      observed[0] = now[0]; observed[1] = now[1];
      continue; /* known runnable work never blocks */
    }
    assert(epoll_wait(ep, &event, 1, 1000) == 1); /* timeout is failure, not rescue */
  }
  for (unsigned i = 0; i < 2; ++i) assert(!pthread_join(threads[i], NULL));
  vlib_worker_wake_ack(&mains[0]);
  assert(epoll_wait(ep, &event, 1, 0) == 0);
  close(ep); close(mains[0].wakeup_fd); /* all publishers joined before fd close */
  printf("PASS native notifier: LT retention, coalescing, EINTR/EAGAIN, late writer, two producers; writes=%u\n", atomic_load(&writes));
}
'''
code = prefix + functions + suffix
if args.emit_c:
    args.emit_c.write_text(code)
with tempfile.TemporaryDirectory(prefix='s239-vpp-notify-') as temporary:
    source = Path(temporary) / 'test.c'
    binary = Path(temporary) / 'test'
    source.write_text(code)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread',
                    str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
