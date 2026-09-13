/* Independent real kernel TCP endpoints for default-deadline evidence.
 * No Product code or fake clock. Keepalive is explicitly disabled and a
 * quiescent connection emits no periodic application data. Commands are
 * append-only lines in a test-owned control file, never Product CLI input. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *name) { perror(name); exit(1); }
static uint64_t now_ms(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) fail("clock");
  return t.tv_sec * 1000ULL + t.tv_nsec / 1000000;
}
static socklen_t address(struct sockaddr_storage *out, unsigned family,
                        const char *text, unsigned port) {
  memset(out, 0, sizeof *out);
  if (family == 4) {
    struct sockaddr_in *a = (void *)out;
    a->sin_family = AF_INET; a->sin_port = htons(port);
    if (inet_pton(AF_INET, text, &a->sin_addr) != 1) exit(2);
    return sizeof *a;
  }
  struct sockaddr_in6 *a = (void *)out;
  a->sin6_family = AF_INET6; a->sin6_port = htons(port);
  if (inet_pton(AF_INET6, text, &a->sin6_addr) != 1) exit(2);
  return sizeof *a;
}
static void options(int fd) {
  int one = 1, zero = 0, value = -1;
  socklen_t n = sizeof value;
  struct timeval timeout = {10, 0};
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) ||
      setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &zero, sizeof zero) ||
      setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ||
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ||
      getsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &value, &n)) fail("options");
  if (value) exit(1);
}
static void send_all(int fd, const unsigned char *bytes, size_t length) {
  for (size_t sent = 0; sent < length;) {
    ssize_t n = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) fail("send");
    sent += n;
  }
}
static void server(char **argv) {
  unsigned family = atoi(argv[3]), port = atoi(argv[5]);
  int fd = socket(family == 4 ? AF_INET : AF_INET6, SOCK_STREAM, 0), one = 1;
  if (fd < 0) fail("socket");
  options(fd);
  if (family == 6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one)) fail("v6only");
  struct sockaddr_storage a;
  socklen_t length = address(&a, family, argv[4], port);
  if (bind(fd, (void *)&a, length) || listen(fd, 64)) fail("listen");
  struct pollfd fds[128] = {{fd, POLLIN, 0}};
  unsigned count = 1;
  printf("listen family=%u port=%u uid=%u keepalive=0 mode=%s\n", family, port, getuid(), argv[6]);
  for (;;) {
    if (poll(fds, count, -1) < 0) { if (errno == EINTR) continue; fail("poll"); }
    for (unsigned i = 0; i < count; i++) if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
      if (!i) {
        int accepted = accept(fd, NULL, NULL);
        if (accepted < 0) fail("accept");
        if (count == 128) exit(1);
        options(accepted);
        fds[count++] = (struct pollfd){accepted, POLLIN, 0};
        printf("accepted family=%u fd=%d keepalive=0 mono_ms=%llu\n", family, accepted, (unsigned long long)now_ms());
        continue;
      }
      unsigned char bytes[512];
      ssize_t n = recv(fds[i].fd, bytes, sizeof bytes, 0);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) {
        if (n < 0 && errno != ECONNRESET) fail("recv");
        printf("eof family=%u fd=%d reset=%u mode=%s mono_ms=%llu\n", family, fds[i].fd,
               n < 0, argv[6], (unsigned long long)now_ms());
        if (strcmp(argv[6], "hold") || n < 0) close(fds[i].fd);
        /* A negative poll fd is ignored. In hold mode retain the actual
         * descriptor until process teardown, without POLLHUP busy polling. */
        fds[i].fd = -1;
        continue;
      }
      send_all(fds[i].fd, bytes, n);
      printf("echo family=%u fd=%d bytes=%zd data=", family, fds[i].fd, n);
      for (ssize_t k = 0; k < n; k++) printf("%02x", bytes[k]);
      putchar('\n');
    }
  }
}
static void echo(int fd, const char *nonce, unsigned phase) {
  unsigned char request[256], reply[256];
  int length = snprintf((char *)request, sizeof request, "%s:%u", nonce, phase);
  if (length < 0 || length >= (int)sizeof request) exit(2);
  send_all(fd, request, length);
  for (int got = 0; got < length;) {
    ssize_t n = recv(fd, reply + got, length - got, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) fail("recv echo");
    got += n;
  }
  if (memcmp(request, reply, length)) exit(1);
  printf("received nonce=%s phase=%u bytes=%d mono_ms=%llu\n", nonce, phase, length, (unsigned long long)now_ms());
}
static void client(char **argv) {
  unsigned family = atoi(argv[3]);
  int fd = socket(family == 4 ? AF_INET : AF_INET6, SOCK_STREAM, 0);
  if (fd < 0) fail("socket");
  options(fd);
  struct sockaddr_storage src, dst;
  socklen_t n = address(&src, family, argv[4], atoi(argv[5]));
  address(&dst, family, argv[6], atoi(argv[7]));
  if (bind(fd, (void *)&src, n) || connect(fd, (void *)&dst, n)) fail("connect");
  printf("connected family=%u source=%s destination=%s uid=%u keepalive=0 nonce=%s mono_ms=%llu\n",
         family, argv[5], argv[7], getuid(), argv[8], (unsigned long long)now_ms());
  echo(fd, argv[8], 0);
  printf("ready nonce=%s mono_ms=%llu\n", argv[8], (unsigned long long)now_ms());
  FILE *control = NULL;
  unsigned phase = 0;
  for (;;) {
    if (!control) {
      control = fopen(argv[9], "r");
      if (!control && errno != ENOENT) fail("control");
    }
    if (control) {
      char line[32];
      clearerr(control);
      if (fgets(line, sizeof line, control)) {
        phase++;
        if (!strcmp(line, "echo\n")) echo(fd, argv[8], phase);
        else if (!strcmp(line, "fin\n")) { if (shutdown(fd, SHUT_WR)) fail("shutdown"); }
        else if (!strcmp(line, "rst\n")) {
          struct linger linger = {1, 0};
          if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger)) fail("linger");
          close(fd); fd = -1;
        } else { fprintf(stderr, "invalid control command\n"); exit(2); }
        printf("command nonce=%s phase=%u action=%.*s mono_ms=%llu\n", argv[8], phase,
               (int)strcspn(line, "\n"), line, (unsigned long long)now_ms());
      }
    }
    usleep(100000);
  }
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (argc < 4 || (atoi(argv[3]) != 4 && atoi(argv[3]) != 6)) return 2;
  if (setgid(atoi(argv[2])) || setuid(atoi(argv[2]))) fail("uid");
  if (argc == 7 && !strcmp(argv[1], "server") &&
      (!strcmp(argv[6], "hold") || !strcmp(argv[6], "close"))) { server(argv); return 0; }
  if (argc == 10 && !strcmp(argv[1], "client")) { client(argv); return 0; }
  fprintf(stderr, "server uid family address port hold|close | client uid family src port dst port nonce control\n");
  return 2;
}
