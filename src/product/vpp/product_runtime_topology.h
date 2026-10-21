/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_RUNTIME_TOPOLOGY_H
#define SAKAMOTO_PRODUCT_RUNTIME_TOPOLOGY_H

#include <stdint.h>

/* A VPP worker position is not necessarily a FlowOwner position. The TUN
 * origin lane currently shares owner 0; ADR-0012 moves it to position N. */
typedef struct
{
  uint32_t owner_count;
  uint32_t vpp_worker_count;
  uint32_t tun_io_worker; /* UINT32_MAX for Root. */
} product_runtime_topology_t;

typedef enum
{
  PRODUCT_TOPOLOGY_ROOT,
  PRODUCT_TOPOLOGY_VPN,
  PRODUCT_TOPOLOGY_INVALID,
} product_runtime_topology_profile_t;

product_runtime_topology_t
product_runtime_topology_current (product_runtime_topology_profile_t profile);

/* Validate role shape and the actual worker count before any capture opens. */
int product_runtime_topology_valid (product_runtime_topology_profile_t profile,
                                    product_runtime_topology_t topology,
                                    uint32_t actual_vpp_workers);

int product_runtime_topology_is_owner (product_runtime_topology_t topology,
                                       uint32_t worker);

#endif
