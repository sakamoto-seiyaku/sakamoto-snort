#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef CPU_SETSIZE
#define CPU_SETSIZE 1024
#endif

typedef int (*pthread_setaffinity_np_fn) (pthread_t, size_t,
                                          const cpu_set_t *);

typedef struct worker_state
{
  pthread_t thread;
  pthread_mutex_t lock;
  pthread_cond_t cond;
  int ready;
  int go;
  pid_t tid;
  int target_cpu;
  int hist[CPU_SETSIZE];
  cpu_set_t initial_mask;
  cpu_set_t final_mask;
  int final_cpu;
} worker_state_t;

static void
format_cpu_set (const cpu_set_t *set, char *buf, size_t len)
{
  size_t off = 0;
  int first = 1;

  if (len == 0)
    return;
  buf[0] = 0;

  for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
    {
      if (!CPU_ISSET (cpu, set))
        continue;
      int n = snprintf (buf + off, off < len ? len - off : 0, "%s%d",
                        first ? "" : ",", cpu);
      if (n < 0)
        break;
      off += (size_t) n;
      first = 0;
      if (off + 1 >= len)
        break;
    }

  if (first)
    snprintf (buf, len, "<empty>");
}

static void
print_mask (const char *label, const cpu_set_t *set)
{
  char buf[4096];
  format_cpu_set (set, buf, sizeof (buf));
  printf ("%s%s\n", label, buf);
}

static void
sleep_1ms (void)
{
  const struct timespec ts = {
    .tv_sec = 0,
    .tv_nsec = 1000000,
  };
  nanosleep (&ts, NULL);
}

static void *
worker_main (void *arg)
{
  worker_state_t *worker = (worker_state_t *) arg;

  worker->tid = gettid ();
  sched_getaffinity (0, sizeof (worker->initial_mask), &worker->initial_mask);

  pthread_mutex_lock (&worker->lock);
  worker->ready = 1;
  pthread_cond_signal (&worker->cond);
  while (!worker->go)
    pthread_cond_wait (&worker->cond, &worker->lock);
  pthread_mutex_unlock (&worker->lock);

  for (int i = 0; i < 2000; i++)
    {
      int cpu = sched_getcpu ();
      if (cpu >= 0 && cpu < CPU_SETSIZE)
        worker->hist[cpu]++;
      sleep_1ms ();
    }

  worker->final_cpu = sched_getcpu ();
  sched_getaffinity (0, sizeof (worker->final_mask), &worker->final_mask);
  return NULL;
}

static int
collect_allowed_cpus (int *cpus, int max_cpus)
{
  cpu_set_t allowed;
  if (sched_getaffinity (0, sizeof (allowed), &allowed) != 0)
    {
      printf ("sched_getaffinity current failed errno=%d %s\n", errno,
              strerror (errno));
      return 0;
    }

  print_mask ("main allowed mask: ", &allowed);

  int count = 0;
  for (int cpu = 0; cpu < CPU_SETSIZE && count < max_cpus; cpu++)
    if (CPU_ISSET (cpu, &allowed))
      cpus[count++] = cpu;
  return count;
}

static void
print_worker_hist (const worker_state_t *worker)
{
  printf ("worker tid=%d target_cpu=%d final_cpu=%d hist:",
          worker->tid, worker->target_cpu, worker->final_cpu);
  for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
    if (worker->hist[cpu] > 0)
      printf (" %d=%d", cpu, worker->hist[cpu]);
  printf ("\n");
  print_mask ("  initial mask: ", &worker->initial_mask);
  print_mask ("  final mask: ", &worker->final_mask);
}

int
main (int argc, char **argv)
{
  int cpus[CPU_SETSIZE];
  int worker_count = 2;

  if (argc > 1)
    {
      worker_count = atoi (argv[1]);
      if (worker_count <= 0)
        worker_count = 2;
    }
  if (worker_count > 8)
    worker_count = 8;

  printf ("android_api=%d\n", __ANDROID_API__);
#if defined(__ANDROID_API__) && __ANDROID_API__ >= 36
  printf ("compile_pthread_affinity=1\n");
#else
  printf ("compile_pthread_affinity=0\n");
#endif
  printf ("pid=%d main_tid=%d nproc_conf=%ld nproc_onln=%ld\n", getpid (),
          gettid (), sysconf (_SC_NPROCESSORS_CONF),
          sysconf (_SC_NPROCESSORS_ONLN));

  pthread_setaffinity_np_fn dyn_pthread_setaffinity_np =
    (pthread_setaffinity_np_fn) dlsym (RTLD_DEFAULT,
                                       "pthread_setaffinity_np");
  printf ("runtime_pthread_setaffinity_np=%s\n",
          dyn_pthread_setaffinity_np ? "present" : "missing");

  int allowed_count = collect_allowed_cpus (cpus, CPU_SETSIZE);
  printf ("allowed_count=%d\n", allowed_count);
  if (allowed_count == 0)
    return 2;
  if (worker_count > allowed_count)
    worker_count = allowed_count;

  worker_state_t *workers = calloc ((size_t) worker_count, sizeof (*workers));
  if (!workers)
    return 2;

  for (int i = 0; i < worker_count; i++)
    {
      worker_state_t *worker = &workers[i];
      worker->target_cpu = cpus[i % allowed_count];
      pthread_mutex_init (&worker->lock, NULL);
      pthread_cond_init (&worker->cond, NULL);
      int rc = pthread_create (&worker->thread, NULL, worker_main, worker);
      if (rc != 0)
        {
          printf ("pthread_create worker=%d rc=%d %s\n", i, rc,
                  strerror (rc));
          return 2;
        }
    }

  for (int i = 0; i < worker_count; i++)
    {
      worker_state_t *worker = &workers[i];
      pthread_mutex_lock (&worker->lock);
      while (!worker->ready)
        pthread_cond_wait (&worker->cond, &worker->lock);
      pthread_mutex_unlock (&worker->lock);

      pid_t pthread_tid = pthread_gettid_np (worker->thread);
      printf ("worker[%d] pthread_gettid_np=%d reported_tid=%d\n", i,
              pthread_tid, worker->tid);

      cpu_set_t one_cpu;
      CPU_ZERO (&one_cpu);
      CPU_SET (worker->target_cpu, &one_cpu);

      errno = 0;
      int sched_rc = sched_setaffinity (worker->tid, sizeof (one_cpu),
                                        &one_cpu);
      printf ("worker[%d] sched_setaffinity tid=%d cpu=%d rc=%d errno=%d %s\n",
              i, worker->tid, worker->target_cpu, sched_rc, errno,
              sched_rc == 0 ? "ok" : strerror (errno));

      if (dyn_pthread_setaffinity_np)
        {
          int pthread_rc = dyn_pthread_setaffinity_np (
            worker->thread, sizeof (one_cpu), &one_cpu);
          printf ("worker[%d] dlsym pthread_setaffinity_np cpu=%d rc=%d %s\n",
                  i, worker->target_cpu, pthread_rc,
                  pthread_rc == 0 ? "ok" : strerror (pthread_rc));
        }
    }

  for (int i = 0; i < worker_count; i++)
    {
      worker_state_t *worker = &workers[i];
      pthread_mutex_lock (&worker->lock);
      worker->go = 1;
      pthread_cond_signal (&worker->cond);
      pthread_mutex_unlock (&worker->lock);
    }

  for (int i = 0; i < worker_count; i++)
    {
      pthread_join (workers[i].thread, NULL);
      print_worker_hist (&workers[i]);
    }

  free (workers);
  return 0;
}
