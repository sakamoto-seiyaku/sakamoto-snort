/* SPDX-License-Identifier: Apache-2.0 */
/* Read-only interval sampler, running outside the measured VPP process. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned long long now (clockid_t clock)
{
  struct timespec ts;
  if (clock_gettime (clock, &ts)) { perror ("clock"); exit (1); }
  return (unsigned long long) ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void record (const char *path)
{
  FILE *file = fopen (path, "r");
  printf ("S226_FILE %s\n", path);
  if (!file) printf ("S226_ERROR %d\n", errno);
  else {
    char line[4096];
    while (fgets (line, sizeof (line), file)) fputs (line, stdout);
    fclose (file);
  }
  puts ("S226_END_FILE");
}

static void sample (const char *label, unsigned pid)
{
  printf ("S226_SAMPLE %s monotonic_ns=%llu boottime_ns=%llu ticks=%ld sampler=%ld\n",
    label, now (CLOCK_MONOTONIC), now (CLOCK_BOOTTIME), sysconf (_SC_CLK_TCK), (long) getpid ());
  char path[512];
  snprintf (path, sizeof (path), "/proc/%u/stat", pid); record (path);
  snprintf (path, sizeof (path), "/proc/%u/status", pid); record (path);
  snprintf (path, sizeof (path), "/proc/%u/task", pid);
  DIR *tasks = opendir (path);
  if (!tasks) { perror ("tasks"); exit (1); }
  struct dirent *task;
  while ((task = readdir (tasks))) {
    char *end;
    unsigned long tid = strtoul (task->d_name, &end, 10);
    if (*end || !tid) continue;
    const char *names[] = {"stat", "status", "schedstat"};
    for (unsigned i = 0; i < 3; i++) {
      snprintf (path, sizeof (path), "/proc/%u/task/%lu/%s", pid, tid, names[i]);
      record (path);
    }
  }
  closedir (tasks);
  record ("/proc/meminfo");
  record ("/sys/bus/iio/devices/iio:device0/energy_value");
  record ("/sys/bus/iio/devices/iio:device1/energy_value");
  record ("/sys/class/power_supply/battery/temp");
  record ("/sys/class/power_supply/battery/status");
  record ("/sys/class/power_supply/battery/current_now");
  record ("/sys/class/power_supply/battery/voltage_now");
  record ("/sys/class/power_supply/usb/online");
  puts ("S226_END_SAMPLE");
  fflush (stdout);
}

int main (int argc, char **argv)
{
  if (argc != 3) return 2;
  unsigned pid = strtoul (argv[1], NULL, 10), milliseconds = strtoul (argv[2], NULL, 10);
  if (!pid || !milliseconds || milliseconds > 120000) return 2;
  sample ("begin", pid);
  struct timespec duration = {milliseconds / 1000, (milliseconds % 1000) * 1000000L};
  while (nanosleep (&duration, &duration)) if (errno != EINTR) { perror ("nanosleep"); return 1; }
  sample ("end", pid);
  return 0;
}
