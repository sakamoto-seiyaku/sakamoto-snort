/* SPDX-License-Identifier: Apache-2.0 */
#include "product_runtime_topology.h"

#include <assert.h>
#include <stdint.h>

int main (void)
{
  product_runtime_topology_t root =
    product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT);
  product_runtime_topology_t vpn =
    product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN);
  assert (root.owner_count == 2 && root.vpp_worker_count == 2);
  assert (root.tun_io_worker == UINT32_MAX);
  assert (vpn.owner_count == 2 && vpn.vpp_worker_count == 2);
  assert (vpn.tun_io_worker == 0);
  assert (product_runtime_topology_is_owner (vpn, vpn.tun_io_worker));
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 2));
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN, vpn, 2));
  assert (!product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 3));
  assert (!product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN, vpn, 1));

  product_runtime_topology_t dedicated_one = { 1, 2, 1 };
  product_runtime_topology_t dedicated_three = { 3, 4, 3 };
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN,
                                          dedicated_one, 2));
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN,
                                          dedicated_three, 4));
  assert (!product_runtime_topology_is_owner (dedicated_three,
                                               dedicated_three.tun_io_worker));
  assert (!product_runtime_topology_valid (
    PRODUCT_TOPOLOGY_VPN, (product_runtime_topology_t) { 3, 3, 0 }, 3));
  assert (!product_runtime_topology_valid (
    PRODUCT_TOPOLOGY_VPN, (product_runtime_topology_t) { 3, 4, 2 }, 4));
  assert (!product_runtime_topology_valid (
    PRODUCT_TOPOLOGY_VPN, (product_runtime_topology_t) { 3, 4, UINT32_MAX },
    4));
  assert (!product_runtime_topology_valid (
    PRODUCT_TOPOLOGY_ROOT, (product_runtime_topology_t) { 3, 4, UINT32_MAX },
    4));
  assert (!product_runtime_topology_valid (
    (product_runtime_topology_profile_t) 99,
    product_runtime_topology_current ((product_runtime_topology_profile_t) 99),
    2));
  assert (product_runtime_topology_current (PRODUCT_TOPOLOGY_INVALID)
            .tun_io_worker == UINT32_MAX);
  return 0;
}
