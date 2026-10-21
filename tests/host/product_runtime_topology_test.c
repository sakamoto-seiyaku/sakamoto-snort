/* SPDX-License-Identifier: Apache-2.0 */
#include "product_runtime_topology.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

int main (void)
{
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN).owner_count);
  assert (setenv ("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID", "3", 1) == 0);
  product_runtime_topology_t root =
    product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT);
  product_runtime_topology_t vpn =
    product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN);
  assert (root.owner_count == 2 && root.vpp_worker_count == 2);
  assert (root.tun_io_worker == UINT32_MAX);
  assert (vpn.owner_count == 2 && vpn.vpp_worker_count == 3);
  assert (vpn.tun_io_worker == 2);
  assert (!product_runtime_topology_is_owner (vpn, vpn.tun_io_worker));
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 2));
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN, vpn, 3));
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
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "1", 1) == 0);
  root = product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT);
  assert (root.owner_count == 1 && root.vpp_worker_count == 1);
  assert (root.tun_io_worker == UINT32_MAX);
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 1));
  assert (!product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 2));
  vpn = product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN);
  assert (vpn.owner_count == 1 && vpn.vpp_worker_count == 2
          && vpn.tun_io_worker == 1);
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN, vpn, 2));
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "3", 1) == 0);
  root = product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT);
  assert (root.owner_count == 3 && root.vpp_worker_count == 3);
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 3));
  vpn = product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN);
  assert (vpn.owner_count == 3 && vpn.vpp_worker_count == 4 && vpn.tun_io_worker == 3);
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN, vpn, 4));
  assert (!product_runtime_topology_valid (PRODUCT_TOPOLOGY_ROOT, root, 2));
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "61", 1) == 0);
  vpn = product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN);
  assert (vpn.owner_count == 61 && vpn.vpp_worker_count == 62);
  assert (product_runtime_topology_valid (PRODUCT_TOPOLOGY_VPN, vpn, 62));
  assert (!product_runtime_topology_valid (
    PRODUCT_TOPOLOGY_VPN, (product_runtime_topology_t) { 62, 63, 62 }, 63));
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "62", 1) == 0);
  assert (product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT).owner_count == 62);
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN).owner_count);
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "63", 1) == 0);
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT).owner_count);
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "01", 1) == 0);
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT).owner_count);
  assert (setenv ("SAKAMOTO_PRODUCT_OWNER_COUNT", "+3", 1) == 0);
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_ROOT).owner_count);
  assert (unsetenv ("SAKAMOTO_PRODUCT_OWNER_COUNT") == 0);
  assert (unsetenv ("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID") == 0);
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN).owner_count);
  assert (setenv ("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID", "03", 1) == 0);
  assert (!product_runtime_topology_current (PRODUCT_TOPOLOGY_VPN).owner_count);
  return 0;
}
