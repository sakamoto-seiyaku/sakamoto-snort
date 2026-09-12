/* Independent kernel TCP echo/reset/refusal endpoint; no Product code. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum { MAX_PEERS = 64, CAPACITY = 65536 };
typedef struct {
  int fd, eof;
  unsigned id, family, read_bytes, written_bytes;
  size_t begin, end;
  unsigned char bytes[CAPACITY];
} peer_t;
static volatile sig_atomic_t stopping;
static void stop(int signal) { (void)signal; stopping = 1; }
static void fail(const char *name) { perror(name); exit(1); }
static void describe(const struct sockaddr_storage *a, char *text, size_t size, unsigned *port)
{
  if (a->ss_family == AF_INET) {
    const struct sockaddr_in *v = (const void *)a;
    if (!inet_ntop(AF_INET, &v->sin_addr, text, size)) fail("inet_ntop");
    *port = ntohs(v->sin_port);
  } else {
    const struct sockaddr_in6 *v = (const void *)a;
    if (!inet_ntop(AF_INET6, &v->sin6_addr, text, size)) fail("inet_ntop6");
    *port = ntohs(v->sin6_port);
  }
}
static int bind_socket(const char *address, unsigned port, int listening)
{
  int family = strchr(address, ':') ? AF_INET6 : AF_INET;
  int fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0), one = 1;
  if (fd < 0) fail("socket");
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) fail("reuse");
  struct sockaddr_storage storage = {0}; socklen_t size;
  if (family == AF_INET) {
    struct sockaddr_in *a = (void *)&storage;
    a->sin_family = AF_INET; a->sin_port = htons(port); size = sizeof(*a);
    if (inet_pton(AF_INET, address, &a->sin_addr) != 1) exit(2);
  } else {
    struct sockaddr_in6 *a = (void *)&storage;
    a->sin6_family = AF_INET6; a->sin6_port = htons(port); size = sizeof(*a);
    if (inet_pton(AF_INET6, address, &a->sin6_addr) != 1) exit(2);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) fail("v6only");
  }
  if (bind(fd, (void *)&storage, size)) fail("bind");
  if (listening && listen(fd, 16)) fail("listen");
  printf("event=%s family=%u address=%s port=%u fd=%d\n",
         listening ? "listen" : "bound_not_listening", family == AF_INET ? 4 : 6, address, port, fd);
  return fd;
}
static void close_peer(peer_t *p, const char *reason)
{
  printf("event=close connection=%u family=%u fd=%d received=%u sent=%u reason=%s\n",
         p->id, p->family, p->fd, p->read_bytes, p->written_bytes, reason);
  close(p->fd); p->fd = -1;
}
int main(int argc, char **argv)
{
  if (argc != 4 || atoi(argv[1]) < 1024 || atoi(argv[1]) > 65533) return 2;
  unsigned base = (unsigned)atoi(argv[1]), serial = 0;
  setvbuf(stdout, NULL, _IOLBF, 0);
  signal(SIGTERM, stop); signal(SIGINT, stop);
  int listeners[4], guards[2];
  for (unsigned i = 0; i < 2; ++i) {
    listeners[i * 2] = bind_socket(argv[i + 2], base, 1);
    listeners[i * 2 + 1] = bind_socket(argv[i + 2], base + 1, 1);
    guards[i] = bind_socket(argv[i + 2], base + 2, 0);
  }
  peer_t *peers = calloc(MAX_PEERS, sizeof(*peers));
  if (!peers) fail("calloc");
  for (unsigned i = 0; i < MAX_PEERS; ++i) peers[i].fd = -1;
  puts("event=ready");
  while (!stopping) {
    struct pollfd fds[4 + MAX_PEERS];
    for (unsigned i = 0; i < 4; ++i) fds[i] = (struct pollfd){listeners[i], POLLIN, 0};
    for (unsigned i = 0; i < MAX_PEERS; ++i) {
      peer_t *p = &peers[i];
      short events = (!p->eof && p->end < CAPACITY ? POLLIN : 0)
                     | (p->begin < p->end ? POLLOUT : 0);
      fds[4 + i] = (struct pollfd){p->fd, events, 0};
    }
    if (poll(fds, 4 + MAX_PEERS, 1000) < 0) {
      if (errno == EINTR) continue;
      fail("poll");
    }
    for (unsigned i = 0; i < 4; ++i) if (fds[i].revents & POLLIN) {
      struct sockaddr_storage remote, local; socklen_t size = sizeof(remote);
      int fd = accept4(listeners[i], (void *)&remote, &size, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) { if (errno == EAGAIN || errno == EINTR) continue; fail("accept"); }
      size = sizeof(local); if (getsockname(fd, (void *)&local, &size)) fail("getsockname");
      char source[INET6_ADDRSTRLEN], destination[INET6_ADDRSTRLEN]; unsigned sport, dport;
      describe(&remote, source, sizeof(source), &sport); describe(&local, destination, sizeof(destination), &dport);
      unsigned id = ++serial;
      printf("event=accept connection=%u family=%u fd=%d source=%s source_port=%u destination=%s destination_port=%u\n",
             id, i < 2 ? 4 : 6, fd, source, sport, destination, dport);
      if (i & 1) {
        struct linger linger = {1, 0};
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) fail("linger");
        close(fd); printf("event=server_reset connection=%u\n", id); continue;
      }
      unsigned index;
      for (index = 0; index < MAX_PEERS && peers[index].fd >= 0; ++index) {}
      if (index == MAX_PEERS) { close(fd); fail("peer capacity"); }
      memset(&peers[index], 0, sizeof(peers[index]));
      peers[index].fd = fd; peers[index].id = id; peers[index].family = i < 2 ? 4 : 6;
    }
    for (unsigned i = 0; i < MAX_PEERS; ++i) {
      peer_t *p = &peers[i];
      if (p->fd < 0) continue;
      short events = fds[4 + i].revents;
      if ((events & (POLLIN | POLLHUP | POLLERR)) && !p->eof && p->end < CAPACITY) {
        ssize_t n = recv(p->fd, p->bytes + p->end, CAPACITY - p->end, 0);
        if (n > 0) {
          printf("event=read connection=%u offset=%u bytes=%zd raw=", p->id, p->read_bytes, n);
          for (ssize_t k = 0; k < n; ++k) printf("%02x", p->bytes[p->end + (size_t)k]);
          putchar('\n'); p->read_bytes += (unsigned)n; p->end += (size_t)n;
        } else if (!n) { p->eof = 1; printf("event=eof connection=%u\n", p->id); }
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          close_peer(p, errno == ECONNRESET ? "peer_reset" : "read_error"); continue;
        }
      }
      if (p->begin < p->end) {
        ssize_t n = send(p->fd, p->bytes + p->begin, p->end - p->begin, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
          printf("event=write connection=%u offset=%u bytes=%zd\n", p->id, p->written_bytes, n);
          p->begin += (size_t)n; p->written_bytes += (unsigned)n;
          if (p->begin == p->end) p->begin = p->end = 0;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          close_peer(p, "write_error"); continue;
        }
      }
      if (p->eof && p->begin == p->end) close_peer(p, "fin");
    }
  }
  for (unsigned i = 0; i < MAX_PEERS; ++i) if (peers[i].fd >= 0) close_peer(&peers[i], "stop");
  for (unsigned i = 0; i < 4; ++i) close(listeners[i]);
  for (unsigned i = 0; i < 2; ++i) close(guards[i]);
  free(peers); puts("event=stopped live_sockets=0"); return 0;
}
