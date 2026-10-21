/* SPDX-License-Identifier: Apache-2.0 */
#include "product_runtime_topology.h"
#include <errno.h>
#include <limits.h>
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
      /* FRAME_QUEUE_MAX_NELTS is 64 in the pinned VPP. Its >= guard reserves
       * one slot beyond main, leaving at most 62 Root workers. Keep this bound tied to the pinned
       * frame-queue thread limit, not an arbitrary Product owner maximum. */
      if (selected[0] == '0')
        return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
      for (const char *digit = selected; *digit; digit++)
        if (*digit < '0' || *digit > '9')
          return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
      char *end = NULL;
      errno = 0;
      unsigned long parsed = strtoul (selected, &end, 10);
      if (errno || !end || *end || parsed < 1
          || parsed > PRODUCT_VPP_MAX_FLOW_OWNERS)
        return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
      owners = (uint32_t) parsed;
    }
  /* SAKAMOTO-299 admits one or two VPN owners. The appended worker remains
   * exclusively the TUN origin lane, never a canonical owner. */
  if (profile == PRODUCT_TOPOLOGY_VPN && owners > 2)
    return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
  if (profile == PRODUCT_TOPOLOGY_VPN)
    {
      /* The Android/Host launcher must supply this separately from ordered
       * owner CPUs. Native startup rejects a missing or malformed setting. */
      const char *io_cpu = getenv ("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID");
      if (!io_cpu || !*io_cpu || io_cpu[0] == '0')
        return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
      for (const char *digit = io_cpu; *digit; digit++)
        if (*digit < '0' || *digit > '9')
          return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
      char *end = NULL;
      errno = 0;
      unsigned long parsed = strtoul (io_cpu, &end, 10);
      if (errno || !end || *end || parsed >= 1024)
        return (product_runtime_topology_t) { .tun_io_worker = UINT32_MAX };
    }
  return (product_runtime_topology_t) {
    .owner_count = owners,
    .vpp_worker_count = owners + (profile == PRODUCT_TOPOLOGY_VPN),
    .tun_io_worker = profile == PRODUCT_TOPOLOGY_VPN ? owners : UINT32_MAX,
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
    return topology.owner_count <= 2
           && topology.vpp_worker_count == topology.owner_count + 1
           && topology.tun_io_worker == topology.owner_count;
  return 0;
}

int
product_runtime_topology_is_owner (product_runtime_topology_t topology,
                                   uint32_t worker)
{
  return worker < topology.owner_count;
}
