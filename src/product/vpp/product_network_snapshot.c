/* SPDX-License-Identifier: Apache-2.0 */
#include "product_network_snapshot.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef __ANDROID__
#include "product_linux_network.h"
#include <vlib/file.h>
static product_linux_network_t linux_network;
static u32 linux_route_file = ~0U, linux_timer_file = ~0U;
static int linux_owned;
#endif
static u64 network_generation;
static sakamoto_product_network_snapshot_t product_network_snapshot;
static int publish_snapshot (vlib_main_t *, u64,
                             const sakamoto_product_network_snapshot_t *);
void product_network_snapshot_start (u64 generation) {
  clib_memset (&product_network_snapshot, 0, sizeof (product_network_snapshot));
  network_generation = generation;
}
void product_network_snapshot_stop (void) {
#ifndef __ANDROID__
  if (linux_route_file != ~0U) {
    clib_file_del_by_index (&file_main, linux_route_file);
    linux_route_file = ~0U;
    linux_network.route_fd = -1;
  }
  if (linux_timer_file != ~0U) {
    clib_file_del_by_index (&file_main, linux_timer_file);
    linux_timer_file = ~0U;
    linux_network.timer_fd = -1;
  }
  if (linux_owned) {
    product_linux_network_close (&linux_network);
    fprintf (stderr, "s235 event=collector_closed generation=%llu route_fd=%d query_fd=%d timer_fd=%d subscriptions=0\n",
      (unsigned long long) network_generation, linux_network.route_fd,
      linux_network.query_fd, linux_network.timer_fd);
  }
  linux_owned = 0;
#endif
  network_generation = 0;
  clib_memset (&product_network_snapshot, 0, sizeof (product_network_snapshot));
}
const sakamoto_product_network_snapshot_t *product_network_snapshot_current (void) {
  return &product_network_snapshot;
}
u32 product_network_snapshot_context (u32 interface_index) {
  if (!interface_index) return 0;
  for (u32 i = 0; i < product_network_snapshot.count; ++i)
    if (product_network_snapshot.entries[i].linux_ifindex == interface_index)
      return product_network_snapshot.entries[i].context;
  return 0;
}
int
product_network_snapshot_publish (
  vlib_main_t *vm, u64 generation,
  const sakamoto_product_network_snapshot_t *snapshot)
{
#ifndef __ANDROID__
  /* One writer per platform. Controlled projection tests must explicitly
   * choose external mode at startup; they are not kernel-classifier evidence. */
  if (linux_owned) return 0;
#endif
  return publish_snapshot (vm, generation, snapshot);
}

static int
publish_snapshot (
  vlib_main_t *vm, u64 generation,
  const sakamoto_product_network_snapshot_t *snapshot)
{
  if (!vm || vm->thread_index != 0 || !snapshot
      || !network_generation
      || generation != network_generation
      || !snapshot->revision || snapshot->reserved
      || snapshot->revision <= product_network_snapshot.revision
      || snapshot->count > SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES)
    return 0;
  for (u32 i = 0; i < SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES; ++i)
    {
      u32 iface = snapshot->entries[i].linux_ifindex;
      u32 context = snapshot->entries[i].context;
      if (i >= snapshot->count)
        {
          if (iface || context) return 0;
          continue;
        }
      if (!iface || iface > INT32_MAX
          || (context != SAKAMOTO_PRODUCT_NETWORK_WIFI
              && context != SAKAMOTO_PRODUCT_NETWORK_MOBILE
              && context != SAKAMOTO_PRODUCT_NETWORK_VPN
              && context != SAKAMOTO_PRODUCT_NETWORK_WIRED))
        return 0;
      for (u32 j = 0; j < i; ++j)
        if (snapshot->entries[j].linux_ifindex == iface) return 0;
    }
  vlib_worker_thread_barrier_sync (vm);
  product_network_snapshot = *snapshot;
  vlib_worker_thread_barrier_release (vm);
  fprintf (stderr, "s232 event=snapshot_publish generation=%llu revision=%llu event_elapsed_ns=%llu count=%u\n",
    (unsigned long long) generation, (unsigned long long) snapshot->revision,
    (unsigned long long) snapshot->event_elapsed_ns, snapshot->count);
  return 1;
}

#ifndef __ANDROID__
static void
linux_publish (void *opaque, const sakamoto_product_network_snapshot_t *snapshot,
               const char *reason)
{
  if (!publish_snapshot (opaque, network_generation, snapshot))
    clib_panic ("Linux network snapshot publication rejected");
  fprintf (stderr, "s235 event=platform_snapshot generation=%llu revision=%llu source=kernel reason=%s count=%u events=%llu resyncs=%llu\n",
    (unsigned long long) network_generation, (unsigned long long) snapshot->revision,
    reason, snapshot->count, (unsigned long long) linux_network.events,
    (unsigned long long) linux_network.resyncs);
  for (u32 i = 0; i < snapshot->count; ++i)
    fprintf (stderr, "s235 event=platform_interface revision=%llu ifindex=%u context=%u\n",
      (unsigned long long) snapshot->revision, snapshot->entries[i].linux_ifindex,
      snapshot->entries[i].context);
}

static clib_error_t *
linux_ready (clib_file_t *file)
{
  if (!linux_owned || file->private_data != network_generation) return NULL;
  if ((int) file->file_descriptor == linux_network.route_fd)
    product_linux_network_read (&linux_network);
  else
    product_linux_network_retry (&linux_network);
  return NULL;
}
#endif

void
product_network_snapshot_linux_start (vlib_main_t *vm)
{
#ifdef __ANDROID__
  (void) vm; /* Android ConnectivityManager remains the sole platform writer. */
#else
  if (!vm || vm->thread_index || !network_generation || linux_owned) return;
  const char *source = getenv ("SAKAMOTO_LINUX_NETWORK_SOURCE");
  if (source && !strcmp (source, "external")) {
    fprintf (stderr, "s235 event=collector_external generation=%llu source=controlled_external subscriptions=0\n",
      (unsigned long long) network_generation);
    return;
  }
  /* Unknown options do not silently select an injection bypass. */
  linux_owned = 1;
  if (!product_linux_network_open (&linux_network, linux_publish, vm)) return;
  clib_file_t file = {0};
  file.read_function = linux_ready;
  /* Netlink ENOBUFS is delivered as EPOLLERR. Read it to clear the socket
   * error and schedule an unknown-first resync; VPP's default closes it. */
  file.error_function = linux_ready;
  file.polling_thread_index = 0;
  file.private_data = network_generation;
  file.file_descriptor = linux_network.route_fd;
  file.description = format (0, "sakamoto-linux-network-route%c", 0);
  linux_route_file = clib_file_add (&file_main, &file);
  file.file_descriptor = linux_network.timer_fd;
  file.description = format (0, "sakamoto-linux-network-retry%c", 0);
  linux_timer_file = clib_file_add (&file_main, &file);
  fprintf (stderr, "s235 event=collector_open generation=%llu route_fd=%d query_fd=%d timer_fd=%d subscriptions=2 source=kernel\n",
    (unsigned long long) network_generation, linux_network.route_fd,
    linux_network.query_fd, linux_network.timer_fd);
#endif
}
