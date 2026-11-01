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
/* Before policy: this packet's App identity from the owner's current result, and
 * a known UID recorded on the current admitted Flow incarnation. Returns 1 when
 * the packet is one the resolver identifies (its platform facts may have changed
 * and must be written back), 0 when it is not. Never waits or starts a query. */
int product_vpn_uid_resolver_identify (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, product_platform_packet_facts_t *platform,
  u64 generation);
/* After Flow processing of a successfully processed packet: start or refresh the
 * Android UID query for its admitted Flow. observed_incarnation is
 * the Flow this packet was observed on, or 0. The resolver selects and validates the
 * incarnation; only an admitted Flow may initiate or refresh Android metadata, so a
 * packet dropped before any Flow exists creates no query state. */
void product_vpn_uid_resolver_query (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, const product_platform_packet_facts_t *platform,
  u64 generation, u64 observed_incarnation);
void product_vpn_uid_resolver_stop (void);

#endif
