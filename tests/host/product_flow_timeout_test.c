/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_timeout.h"
#include <assert.h>
#include <stdio.h>

int main (void)
{
  const product_ct_timeout_t classes[] = {
    PRODUCT_CT_TIMEOUT_OTHER_FIRST, PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE,
    PRODUCT_CT_TIMEOUT_OTHER_BIDIR,
    PRODUCT_CT_TIMEOUT_TCP_FIRST_PACKET, PRODUCT_CT_TIMEOUT_TCP_OPENING,
    PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED, PRODUCT_CT_TIMEOUT_TCP_CLOSING,
    PRODUCT_CT_TIMEOUT_TCP_FIN_WAIT, PRODUCT_CT_TIMEOUT_TCP_CLOSED,
    PRODUCT_CT_TIMEOUT_ICMP_FIRST, PRODUCT_CT_TIMEOUT_ICMP_REPLY,
  };
  const uint64_t durations[] = {60000000, 60000000, 30000000, 30000000,
    30000000, UINT64_C (86400000000), 900000000, 45000000, 30000000,
    60000000, 30000000};
  for (unsigned i = 0; i < sizeof (classes) / sizeof (classes[0]); i++)
    {
      uint64_t deadline = 0;
      assert (product_flow_timeout_us (classes[i]) == durations[i]);
      assert (product_flow_deadline (classes[i], 123, &deadline));
      assert (deadline == 123 + durations[i]);
      assert (product_flow_deadline (classes[i], UINT64_MAX - durations[i], &deadline));
      assert (deadline == UINT64_MAX);
      assert (product_flow_deadline (classes[i], UINT64_MAX - durations[i] + 1, &deadline));
      assert (deadline == UINT64_MAX);
      assert (!product_flow_deadline (classes[i], 1, NULL));
    }
  uint64_t unchanged = 999;
  const int unsupported[] = {PRODUCT_CT_TIMEOUT_NONE, -1, 255};
  for (unsigned i = 0; i < sizeof (unsupported) / sizeof (unsupported[0]); i++)
    {
      assert (!product_flow_timeout_us ((product_ct_timeout_t) unsupported[i]));
      assert (!product_flow_deadline ((product_ct_timeout_t) unsupported[i], 1, &unchanged));
      assert (unchanged == 999);
    }
  puts ("Flow timeout: all 11 pinned TCP/UDP/ICMP defaults, unsupported classes, saturating deadline PASS");
  return 0;
}
