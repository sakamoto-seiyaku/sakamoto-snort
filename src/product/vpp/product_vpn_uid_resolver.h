/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_UID_RESOLVER_H
#define SAKAMOTO_PRODUCT_VPN_UID_RESOLVER_H

#include "product_packet.h"
#include "product_flow_entry.h"
#include <vlib/vlib.h>

/* One metadata-only Android channel and bounded tuple cache per FlowOwner.
 * A miss never retains a packet or waits for the Android lookup. */
void product_vpn_uid_resolver_start (u64 generation);
int product_vpn_uid_resolver_attach (int fd, u32 owner_index);
int product_vpn_uid_resolver_ready (void);
void product_vpn_uid_resolver_lookup (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, product_platform_packet_facts_t *platform,
  u64 generation);
/* Only an admitted flow may initiate or refresh Android metadata. */
void product_vpn_uid_resolver_refresh (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, u64 generation, u64 incarnation);
void product_vpn_uid_resolver_stop (void);

#endif
