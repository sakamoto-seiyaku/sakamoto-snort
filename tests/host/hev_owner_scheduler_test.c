/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <hev-task.h>
#include <hev-task-system.h>
#include "kern/core/hev-task-system-private.h"
#include "kern/task/hev-task-private.h"

typedef struct { unsigned turns, done, parked; } job_t;
static unsigned io_scans;
int epoll_wait(int fd, struct epoll_event *events, int count, int timeout)
{
  ++io_scans;
  return (int)syscall(SYS_epoll_wait, fd, events, count, timeout);
}
static void yield_job (void *opaque)
{
  job_t *job = opaque;
  for (unsigned i = 0; i < 12; i++)
    {
      job->turns++;
      hev_task_yield (HEV_TASK_YIELD);
    }
  job->done = 1;
}
static void parked_job (void *opaque)
{
  job_t *job = opaque;
  job->parked = 1;
  hev_task_yield (HEV_TASK_WAITIO);
  job->done = 1;
}
static void timer_job (void *opaque)
{
  job_t *job = opaque;
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
  HevTask *self = hev_task_self();
  self->diagnostic_enabled = 1;
  self->diagnostic_origin = HEV_TASK_WAKE_OTHER;
#endif
  hev_task_sleep (20);
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
  assert(self->diagnostic_ready_ns && self->diagnostic_origin == HEV_TASK_WAKE_TIMER);
#endif
  job->done = 1;
}
typedef struct { int read_fd, write_fd; unsigned done; } io_job_t;
static void reader_job(void *opaque)
{
  io_job_t *job = opaque;
  HevTask *self = hev_task_self();
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
  self->diagnostic_enabled = 1;
  self->diagnostic_ready_ns = 0;
  self->diagnostic_origin = HEV_TASK_WAKE_OTHER;
#endif
  assert(!hev_task_add_fd(self, job->read_fd, POLLIN));
  hev_task_yield(HEV_TASK_WAITIO);
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT
  assert(self->diagnostic_ready_ns && self->diagnostic_origin == HEV_TASK_WAKE_IO);
#endif
  char value;
  assert(read(job->read_fd, &value, 1) == 1 && value == 'x');
  hev_task_del_fd(self, job->read_fd);
  ++job->done;
}
static void writer_job(void *opaque)
{
  io_job_t *job = opaque;
  hev_task_sleep(5);
  assert(write(job->write_fd, "x", 1) == 1);
}

int main (void)
{
  alarm (5); /* A WAITING external turn must not enter a blocking scheduler. */
  assert (!hev_task_system_init ());
  HevTaskSystemContext *context = hev_task_system_get_context ();
  job_t a = { 0 }, b = { 0 };
  HevTask *ta = hev_task_new (32768), *tb = hev_task_new (32768);
  assert (ta && tb);
  hev_task_run (ta, yield_job, &a); hev_task_run (tb, yield_job, &b);
  for (unsigned turn = 0; turn < 30 && (!a.done || !b.done); turn++)
    {
      unsigned used = hev_task_system_step (3, 20000);
      assert (used <= 3 && context->current_task == NULL);
    }
  assert (a.done && b.done && a.turns == 12 && b.turns == 12);
  assert (!context->total_task_count && !context->running_task_count);

  job_t parked = { 0 };
  HevTask *task = hev_task_new (32768); assert (task);
  hev_task_run (task, parked_job, &parked);
  assert (hev_task_system_step (1, 20000) == 1 && parked.parked && !parked.done);
  for (unsigned i = 0; i < 8; i++)
    assert (hev_task_system_step (4, 20000) == 0 && !parked.done);
  /* One waiting connection plus one runnable connection is the normal mixed
   * load. A bounded one-quantum turn scans at entry and after yielding, but
   * must not scan again at task selection without an intervening task. */
  job_t mixed = {0};
  HevTask *mixed_task = hev_task_new(32768); assert(mixed_task);
  hev_task_run(mixed_task, yield_job, &mixed);
  unsigned scans_before = io_scans;
  assert(hev_task_system_step(1, 20000) == 1 && mixed.turns == 1);
  printf("mixed runnable/waiting one-quantum turn: epoll scans=%u\n", io_scans - scans_before);
  fflush(stdout);
  assert(io_scans - scans_before == 2);
  while (!mixed.done) assert(hev_task_system_step(3, 20000) <= 3);
  hev_task_wakeup (task);
  assert (hev_task_system_step (1, 20000) == 1 && parked.done);

  job_t timer = { 0 }; task = hev_task_new (32768); assert (task);
  hev_task_run (task, timer_job, &timer);
  assert (hev_task_system_step (1, 20000) == 1 && !timer.done);
  assert (hev_task_timer_get_timeout (context->timer) >= 0);
  usleep (30000);
  assert (hev_task_system_step (2, 20000) == 1 && timer.done);
  assert (!context->total_task_count && !context->running_task_count);
  assert (hev_task_timer_get_timeout (context->timer) == -1);
  /* The external path still consumes real fd readiness. */
  int fds[2]; assert(!pipe(fds));
  io_job_t io = {fds[0], fds[1], 0};
  task = hev_task_new(32768); assert(task);
  hev_task_run(task, reader_job, &io);
  assert(hev_task_system_step(1, 20000) == 1);
  assert(write(fds[1], "x", 1) == 1);
  assert(hev_task_system_step(2, 20000) == 1 && io.done == 1);
  /* The standalone path must retain its blocking I/O and timer polling. */
  task = hev_task_new(32768); assert(task);
  hev_task_run(task, reader_job, &io);
  task = hev_task_new(32768); assert(task);
  hev_task_run(task, writer_job, &io);
  hev_task_system_run();
  assert(io.done == 2 && !context->total_task_count);
  close(fds[0]); close(fds[1]);
  hev_task_system_fini ();
  assert (hev_task_system_get_context () == NULL);
  puts ("S237 real HEV external scheduler: bounded quanta, wait, timer and cleanup PASS");
  return 0;
}
