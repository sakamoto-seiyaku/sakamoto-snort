/* SPDX-License-Identifier: Apache-2.0 */
#include "product_root_receive_pool.h"
#include <assert.h>
#include <stdio.h>

int main (void)
{
  product_root_receive_pool_t lanes[4] = { 0 };
  uint32_t buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
  uint16_t slots[PRODUCT_ROOT_RECEIVE_TOTAL];
  for (unsigned lane = 0; lane < 4; ++lane)
    {
      for (unsigned i = 0; i < PRODUCT_ROOT_RECEIVE_TOTAL; ++i)
        buffers[i] = lane * 1024 + i;
      assert (!product_root_receive_pool_init (&lanes[lane], 0, buffers));
      assert (product_root_receive_pool_init (&lanes[lane], 233, buffers));
    }
  for (unsigned round = 0; round < 1000; ++round)
    for (unsigned lane = 0; lane < 4; ++lane)
      {
        product_root_receive_pool_t *p = &lanes[lane];
        for (unsigned i = 0; i < PRODUCT_ROOT_RECEIVE_TOTAL; ++i)
          {
            slots[i] = product_root_receive_pool_take (
              p, 233, i >= PRODUCT_ROOT_RECEIVE_NORMAL);
            assert (slots[i] != PRODUCT_ROOT_RECEIVE_NONE);
            if (i == PRODUCT_ROOT_RECEIVE_NORMAL - 1)
              {
                assert (product_root_receive_pool_take (p, 233, 0)
                        == PRODUCT_ROOT_RECEIVE_NONE);
                assert (p->reserve_free == PRODUCT_ROOT_RECEIVE_RESERVE);
              }
          }
        assert (p->outstanding == PRODUCT_ROOT_RECEIVE_TOTAL);
        assert (product_root_receive_pool_take (p, 233, 1)
                == PRODUCT_ROOT_RECEIVE_NONE);
        assert (lanes[lane ^ 1].normal_free == PRODUCT_ROOT_RECEIVE_NORMAL);
        assert (!product_root_receive_pool_init (p, 234, buffers));
        assert (!product_root_receive_pool_return (p, 232, slots[0], p->buffers[slots[0]]));
        assert (!product_root_receive_pool_return (p, 233, slots[0], UINT32_MAX));
        assert (!product_root_receive_pool_return (p, 233, PRODUCT_ROOT_RECEIVE_NONE, 0));
        for (unsigned i = 0; i < PRODUCT_ROOT_RECEIVE_TOTAL; ++i)
          {
            uint16_t slot = slots[i];
            assert (product_root_receive_pool_return (p, 233, slot, p->buffers[slot]));
            assert (!product_root_receive_pool_return (p, 233, slot, p->buffers[slot]));
          }
        assert (!p->outstanding);
        assert (p->normal_free == PRODUCT_ROOT_RECEIVE_NORMAL);
        assert (p->reserve_free == PRODUCT_ROOT_RECEIVE_RESERVE);
        assert (product_root_receive_pool_take (p, 234, 0) == PRODUCT_ROOT_RECEIVE_NONE);
      }
  puts ("PASS: fixed lane-local VPP buffer partitions, normal/reserve exhaustion, identity and return conservation");
}
