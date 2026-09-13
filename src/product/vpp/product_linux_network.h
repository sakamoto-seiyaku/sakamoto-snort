/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_LINUX_NETWORK_H
#define PRODUCT_LINUX_NETWORK_H
#include "sakamoto_product_network.h"

/* Main-thread, same-netns kernel collector. No packet path or manager RPC.
 * Only complete, loss-free dumps may publish known classifications. */
typedef void (*product_linux_network_publish_fn) (
  void *, const sakamoto_product_network_snapshot_t *, const char *);
typedef struct {
  int route_fd, query_fd, timer_fd;
  uint32_t sequence;
  uint8_t dumping, invalid, completed, overflow;
  uint64_t revision, events, resyncs, publications;
  sakamoto_product_network_snapshot_t candidate;
  product_linux_network_publish_fn publish;
  void *opaque;
} product_linux_network_t;

int product_linux_network_open (product_linux_network_t *,
  product_linux_network_publish_fn, void *);
void product_linux_network_read (product_linux_network_t *);
void product_linux_network_retry (product_linux_network_t *);
void product_linux_network_close (product_linux_network_t *);
#endif
