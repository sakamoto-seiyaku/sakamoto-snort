/* Test-only boundary between the real C wait's empty check and poll. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int poll(struct pollfd *fds, nfds_t count, int timeout) {
  int (*next)(struct pollfd *, nfds_t, int) = dlsym(RTLD_NEXT, "poll");
  if (!next) _exit(120);
  const char *directory = getenv("SAKAMOTO_SHUTDOWN_WAIT_DIR");
  char arm[PATH_MAX], captured[PATH_MAX], ready[PATH_MAX], release[PATH_MAX], result[PATH_MAX];
  if (!directory || count != 6) return next(fds, count, timeout);
  char name[16];
  if(pthread_getname_np(pthread_self(),name,sizeof(name)) || strcmp(name,"flow-observatio"))
    return next(fds,count,timeout);
  if (snprintf(arm,sizeof(arm),"%s/arm",directory)>=(int)sizeof(arm)
      || snprintf(captured,sizeof(captured),"%s/captured",directory)>=(int)sizeof(captured)
      || snprintf(ready,sizeof(ready),"%s/ready",directory)>=(int)sizeof(ready)
      || snprintf(release,sizeof(release),"%s/release",directory)>=(int)sizeof(release)
      || snprintf(result,sizeof(result),"%s/poll-result.json",directory)>=(int)sizeof(result))
    return next(fds,count,timeout);
  if (rename(arm,captured)) return next(fds,count,timeout);
  struct timespec start,now,pause={.tv_nsec=1000000};
  if(clock_gettime(CLOCK_MONOTONIC,&start)) _exit(121);
  int fd=open(ready,O_WRONLY|O_CREAT|O_EXCL,0600);
  if(fd<0) _exit(122);
  if(write(fd,"READY\n",6)!=6 || close(fd)) _exit(123);
  while(access(release,F_OK)) {
    if(clock_gettime(CLOCK_MONOTONIC,&now)) _exit(124);
    if(now.tv_sec-start.tv_sec>=5) _exit(125);
    nanosleep(&pause,NULL);
  }
  int rv=next(fds,count,timeout);
  FILE *output=fopen(result,"wx");if(!output)_exit(126);
  fprintf(output,"{\"nfds\":%lu,\"poll_result\":%d,\"socket_revents\":%d,\"event_revents\":%d,\"interrupt_revents\":%d}\n",
    (unsigned long)count,rv,fds[count-2].revents,fds[0].revents,fds[count-1].revents);
  if(fclose(output))_exit(127);
  return rv;
}
