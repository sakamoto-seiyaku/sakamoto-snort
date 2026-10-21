/* SPDX-License-Identifier: Apache-2.0 */
#include "product_runtime_topology.h"

product_runtime_topology_t
product_runtime_topology_current (product_runtime_topology_profile_t profile)
{
  if (profile != PRODUCT_TOPOLOGY_ROOT && profile != PRODUCT_TOPOLOGY_VPN)
    return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
  /* This slice preserves the existing two-owner graph and shared TUN lane.
   * Future slices supply the configured N and append the VPN I/O worker. */
  return (product_runtime_topology_t) {
    .owner_count = 2,
    .vpp_worker_count = 2,
    .tun_io_worker = profile == PRODUCT_TOPOLOGY_VPN ? 0 : UINT32_MAX,
  };
}

int
product_runtime_topology_valid (product_runtime_topology_profile_t profile,
                                product_runtime_topology_t topology,
                                uint32_t actual_vpp_workers)
{
  if (!topology.owner_count
      || topology.owner_count > topology.vpp_worker_count
      || actual_vpp_workers != topology.vpp_worker_count)
    return 0;
  if (profile == PRODUCT_TOPOLOGY_ROOT)
    return topology.vpp_worker_count == topology.owner_count
           && topology.tun_io_worker == UINT32_MAX;
  if (profile == PRODUCT_TOPOLOGY_VPN)
    return topology.tun_io_worker < topology.vpp_worker_count
           && ((topology.owner_count == 2
                && topology.vpp_worker_count == topology.owner_count
                && topology.tun_io_worker == 0)
               || (topology.owner_count < UINT32_MAX
                   && topology.vpp_worker_count == topology.owner_count + 1
                   && topology.tun_io_worker == topology.owner_count));
  return 0;
}

int
product_runtime_topology_is_owner (product_runtime_topology_t topology,
                                   uint32_t worker)
{
  return worker < topology.owner_count;
}
