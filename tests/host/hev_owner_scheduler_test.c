/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <hev-task.h>
#include <hev-task-system.h>
#include "kern/core/hev-task-system-private.h"

typedef struct { unsigned turns, done, parked; } job_t;
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
  hev_task_sleep (20);
  job->done = 1;
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
  hev_task_system_fini ();
  assert (hev_task_system_get_context () == NULL);
  puts ("S237 real HEV external scheduler: bounded quanta, wait, timer and cleanup PASS");
  return 0;
}
