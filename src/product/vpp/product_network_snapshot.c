/* SPDX-License-Identifier: Apache-2.0 */
#include "product_network_snapshot.h"
#include <limits.h>
#include <stdio.h>
static u64 network_generation;
static sakamoto_product_network_snapshot_t product_network_snapshot;
void product_network_snapshot_start (u64 generation) {
  clib_memset (&product_network_snapshot, 0, sizeof (product_network_snapshot));
  network_generation = generation;
}
void product_network_snapshot_stop (void) {
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
