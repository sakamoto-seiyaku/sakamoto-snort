/* Test-only one-shot WAL sync delay. Never linked into Product. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static void delay_wal(int fd)
{
    const char *arm = getenv("SAKAMOTO_QUERY_DELAY_ARM");
    char proc[64], target[PATH_MAX], hit[PATH_MAX];
    if (!arm) return;
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, target, sizeof(target) - 1);
    if (n < 0) return;
    target[n] = 0;
    if (!strstr(target, "overall.sqlite3-wal")) return;
    snprintf(hit, sizeof(hit), "%s.hit", arm);
    if (rename(arm, hit) != 0) return;
    struct timespec duration = {3, 0};
    while (nanosleep(&duration, &duration) != 0) {}
}
int fsync(int fd)
{
    int (*real_sync)(int) = dlsym(RTLD_NEXT, "fsync");
    delay_wal(fd);
    return real_sync(fd);
}
int fdatasync(int fd)
{
    int (*real_sync)(int) = dlsym(RTLD_NEXT, "fdatasync");
    delay_wal(fd);
    return real_sync(fd);
}
