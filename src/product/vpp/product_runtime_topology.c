/* SPDX-License-Identifier: Apache-2.0 */
#include "product_runtime_topology.h"
#include <stdlib.h>
#include <string.h>

product_runtime_topology_t
product_runtime_topology_current (product_runtime_topology_profile_t profile)
{
  if (profile != PRODUCT_TOPOLOGY_ROOT && profile != PRODUCT_TOPOLOGY_VPN)
    return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
  const char *selected = getenv ("SAKAMOTO_PRODUCT_OWNER_COUNT");
  uint32_t owners = 2;
  if (selected && selected[0])
    {
      if (strcmp (selected, "1") == 0) owners = 1;
      else if (strcmp (selected, "2") != 0)
        return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
    }
  /* VPN retains its qualified shared-lane topology until the dedicated-I/O
   * implementation; it must never silently accept a Root-only selection. */
  if (profile == PRODUCT_TOPOLOGY_VPN && owners != 2)
    return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
  return (product_runtime_topology_t) {
    .owner_count = owners,
    .vpp_worker_count = owners,
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
