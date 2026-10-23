/* Bounded real shell-UID socket fixture; not Android resolver IPC. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long long now_ms(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) _exit(3);
  return (long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int wait_ready(int fd, short events, long long deadline)
{
  for (;;) {
    long long left = deadline - now_ms();
    if (left <= 0) { errno = ETIMEDOUT; return -1; }
    struct pollfd pending = {.fd = fd, .events = events};
    int result = poll(&pending, 1, left > INT_MAX ? INT_MAX : (int)left);
    if (result > 0) return 0; /* recv/send retain the precise socket error. */
    if (!result) { errno = ETIMEDOUT; return -1; }
    if (errno != EINTR) return -1;
  }
}

static int transfer(int fd, unsigned char *bytes, size_t size, int writing, long long deadline)
{
  while (size) {
    if (wait_ready(fd, writing ? POLLOUT : POLLIN, deadline)) return -1;
    ssize_t count = writing ? send(fd, bytes, size, MSG_NOSIGNAL) : recv(fd, bytes, size, 0);
    if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
    if (count <= 0) { if (!count) errno = ECONNRESET; return -1; }
    bytes += count; size -= (size_t)count;
  }
  return 0;
}

static int nibble(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

int main(int argc, char **argv)
{
  if (argc != 6 || getuid() != 2000) return 2;
  int tcp = !strcmp(argv[1], "tcp"), family = strchr(argv[2], ':') ? AF_INET6 : AF_INET;
  if (!tcp && strcmp(argv[1], "udp")) return 2;
  unsigned port = strtoul(argv[3], NULL, 10);
  if (port < 1024 || port > 65535) return 2;
  unsigned char queries[2][4098]; size_t sizes[2];
  for (int item = 0; item < 2; ++item) {
    size_t chars = strlen(argv[item + 4]);
    if (!chars || chars > 8192 || chars % 2) return 2;
    sizes[item] = chars / 2;
    queries[item][0] = (unsigned char)(sizes[item] >> 8);
    queries[item][1] = (unsigned char)sizes[item];
    for (size_t at = 0; at < sizes[item]; ++at) {
      int high = nibble(argv[item + 4][at * 2]), low = nibble(argv[item + 4][at * 2 + 1]);
      if (high < 0 || low < 0) return 2;
      queries[item][at + 2] = (unsigned char)(high * 16 + low);
    }
  }
  alarm(8); /* Hard process bound even if a platform call misbehaves. */
  long long total_deadline = now_ms() + 6000;
  printf("{\"phase\":\"ready\",\"uid\":%u,\"pid\":%u,\"source_port\":%u}\n",
         (unsigned)getuid(), (unsigned)getpid(), port);
  fflush(stdout);
  struct sockaddr_storage local = {0}, remote = {0}; socklen_t length;
  if (family == AF_INET) {
    struct sockaddr_in *l = (void *)&local, *r = (void *)&remote;
    l->sin_family = r->sin_family = AF_INET;
    l->sin_port = htons(port); r->sin_port = htons(53); length = sizeof(*l);
    if (inet_pton(family, argv[2], &r->sin_addr) != 1) return 2;
  } else {
    struct sockaddr_in6 *l = (void *)&local, *r = (void *)&remote;
    l->sin6_family = r->sin6_family = AF_INET6;
    l->sin6_port = htons(port); r->sin6_port = htons(53); length = sizeof(*l);
    if (inet_pton(family, argv[2], &r->sin6_addr) != 1) return 2;
  }
  int error = 0, fd = socket(family, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  const char *operation = "socket";
  if (fd < 0) error = errno;
  else if (bind(fd, (void *)&local, length)) { operation = "bind"; error = errno; }
  else if (connect(fd, (void *)&remote, length)) {
    operation = "connect"; error = errno;
    if (error == EINPROGRESS) {
      socklen_t size = sizeof(error);
      if (wait_ready(fd, POLLOUT, now_ms() + 1200)) error = errno;
      else if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size)) error = errno;
    }
  }
  printf("{\"phase\":\"finished\",\"uid\":%u,\"pid\":%u,\"source_port\":%u,\"connect_errno\":%d,\"connect_operation\":\"%s\",\"exchanges\":[",
         (unsigned)getuid(), (unsigned)getpid(), port, error, error ? operation : "complete");
  for (int item = 0; item < 2; ++item) {
    unsigned char reply[8192], prefix[2];
    if (item) usleep(300000);
    long long deadline = now_ms() + 1200;
    if (deadline > total_deadline) deadline = total_deadline;
    int sent = 0, received = -1, item_error = error;
    operation = error ? "connect" : "send";
    if (!item_error) {
      if (tcp) sent = !transfer(fd, queries[item], sizes[item] + 2, 1, deadline);
      else if (!wait_ready(fd, POLLOUT, deadline))
        sent = send(fd, queries[item] + 2, sizes[item], MSG_NOSIGNAL) == (ssize_t)sizes[item];
      if (!sent) item_error = errno ? errno : EIO;
      else if (tcp) {
        operation = "receive_prefix";
        if (transfer(fd, prefix, 2, 0, deadline)) item_error = errno;
        else {
          unsigned count = (unsigned)prefix[0] * 256 + prefix[1];
          operation = "receive_body";
          if (count > sizeof(reply)) item_error = EMSGSIZE;
          else if (transfer(fd, reply, count, 0, deadline)) item_error = errno;
          else received = (int)count;
        }
      } else {
        operation = "receive_datagram";
        if (wait_ready(fd, POLLIN, deadline)) item_error = errno;
        else {
          received = (int)recv(fd, reply, sizeof(reply), 0);
          if (received < 0) item_error = errno;
        }
      }
    }
    printf("%s{\"sent\":%s,\"timed_out\":%s,\"operation\":\"%s\",\"errno\":%d,\"reply_hex\":\"",
           item ? "," : "", sent ? "true" : "false", item_error == ETIMEDOUT ? "true" : "false",
           item_error ? operation : "complete", item_error);
    for (int at = 0; at < received; ++at) printf("%02x", reply[at]);
    printf("\"}");
  }
  puts("]}"); fflush(stdout); if (fd >= 0) close(fd); return 0;
}
