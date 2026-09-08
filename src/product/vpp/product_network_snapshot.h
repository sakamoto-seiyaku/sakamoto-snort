/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_NETWORK_SNAPSHOT_H
#define PRODUCT_NETWORK_SNAPSHOT_H
#include <vlib/vlib.h>
#include "sakamoto_product_network.h"
/* Adapter lifecycle owns this generation. Writers run on main under the VPP
 * worker barrier; readers run inside the graph or adapter callback. */
void product_network_snapshot_start (u64 generation);
void product_network_snapshot_stop (void);
int product_network_snapshot_publish (vlib_main_t *vm, u64 generation,
  const sakamoto_product_network_snapshot_t *snapshot);
const sakamoto_product_network_snapshot_t *product_network_snapshot_current (void);
u32 product_network_snapshot_context (u32 interface_index);
#endif
