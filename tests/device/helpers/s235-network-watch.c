/* SPDX-License-Identifier: Apache-2.0 */
/* Real collector observation without VPP. Send a newline on stdin to stop. */
#include "product_linux_network.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
static void publish (void *opaque, const sakamoto_product_network_snapshot_t *value,
                     const char *reason) {
  (void) opaque;
  printf ("snapshot revision=%llu count=%u reason=%s\n", (unsigned long long) value->revision,
          value->count, reason);
  for (unsigned i = 0; i < value->count; ++i)
    printf ("interface ifindex=%u context=%u\n", value->entries[i].linux_ifindex, value->entries[i].context);
}
int main (void) {
  setvbuf (stdout, NULL, _IOLBF, 0);
  product_linux_network_t state;
  if (!product_linux_network_open (&state, publish, NULL)) return 1;
  for (;;) {
    struct pollfd fds[] = {{state.route_fd, POLLIN, 0}, {state.timer_fd, POLLIN, 0}, {0, POLLIN, 0}};
    int ready = poll (fds, 3, 10000);
    if (ready < 0 && errno == EINTR) continue;
    if (ready <= 0 || fds[2].revents) break;
    if (fds[0].revents) product_linux_network_read (&state);
    if (fds[1].revents) product_linux_network_retry (&state);
  }
  printf ("close events=%llu resyncs=%llu publications=%llu\n", (unsigned long long) state.events,
          (unsigned long long) state.resyncs, (unsigned long long) state.publications);
  product_linux_network_close (&state);
  printf ("closed route_fd=%d query_fd=%d timer_fd=%d\n", state.route_fd, state.query_fd, state.timer_fd);
  return 0;
}
