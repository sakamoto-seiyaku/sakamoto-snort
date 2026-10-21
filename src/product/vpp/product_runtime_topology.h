/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_RUNTIME_TOPOLOGY_H
#define SAKAMOTO_PRODUCT_RUNTIME_TOPOLOGY_H

#include <stdint.h>
#include "../include/sakamoto_product_limits.h"

/* Pinned VPP FRAME_QUEUE_MAX_NELTS is 64. Its >= guard requires main +
 * workers < 64, so the resource limit for Root owners is 62. */
#define PRODUCT_VPP_MAX_FLOW_OWNERS SAKAMOTO_PRODUCT_MAX_FLOW_OWNERS

/* A VPP worker position is not necessarily a FlowOwner position. VPN's TUN
 * origin lane is appended after the owners at position N. */
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
