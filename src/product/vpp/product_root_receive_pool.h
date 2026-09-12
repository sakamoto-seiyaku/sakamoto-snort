/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_RECEIVE_POOL_H
#define SAKAMOTO_PRODUCT_ROOT_RECEIVE_POOL_H

#include <stdint.h>
#include <string.h>

/* Startup partition of existing VPP buffers, not a second packet allocator.
 * Only the origin worker borrows/returns slots. The main thread may inspect
 * or withhold them under the worker barrier. No runtime growth or borrowing
 * between lanes. These are current bounds, not throughput qualification. */
#define PRODUCT_ROOT_RECEIVE_NORMAL 64
#define PRODUCT_ROOT_RECEIVE_RESERVE 8
#define PRODUCT_ROOT_RECEIVE_TOTAL \
  (PRODUCT_ROOT_RECEIVE_NORMAL + PRODUCT_ROOT_RECEIVE_RESERVE)
#define PRODUCT_ROOT_RECEIVE_NONE UINT16_MAX

typedef struct
{
  uint64_t generation;
  uint32_t buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
  uint16_t normal[PRODUCT_ROOT_RECEIVE_NORMAL];
  uint16_t reserve[PRODUCT_ROOT_RECEIVE_RESERVE];
  uint16_t normal_free, reserve_free, outstanding;
  uint8_t borrowed[PRODUCT_ROOT_RECEIVE_TOTAL];
} product_root_receive_pool_t;

static inline int
product_root_receive_pool_init (product_root_receive_pool_t *pool,
                                uint64_t generation, const uint32_t *buffers)
{
  if (!pool || !generation || !buffers || pool->outstanding)
    return 0;
  memset (pool, 0, sizeof (*pool));
  pool->generation = generation;
  memcpy (pool->buffers, buffers, sizeof (pool->buffers));
  for (uint16_t i = 0; i < PRODUCT_ROOT_RECEIVE_NORMAL; ++i)
    pool->normal[pool->normal_free++] = i;
  for (uint16_t i = PRODUCT_ROOT_RECEIVE_NORMAL;
       i < PRODUCT_ROOT_RECEIVE_TOTAL; ++i)
    pool->reserve[pool->reserve_free++] = i;
  return 1;
}

static inline uint16_t
product_root_receive_pool_take (product_root_receive_pool_t *pool,
                                uint64_t generation, int reserve)
{
  if (!generation || pool->generation != generation)
    return PRODUCT_ROOT_RECEIVE_NONE;
  uint16_t *count = reserve ? &pool->reserve_free : &pool->normal_free;
  if (!*count)
    return PRODUCT_ROOT_RECEIVE_NONE;
  uint16_t slot = (reserve ? pool->reserve : pool->normal)[--*count];
  pool->borrowed[slot] = 1;
  ++pool->outstanding;
  return slot;
}

static inline int
product_root_receive_pool_return (product_root_receive_pool_t *pool,
                                  uint64_t generation, uint16_t slot,
                                  uint32_t buffer)
{
  if (!generation || pool->generation != generation
      || slot >= PRODUCT_ROOT_RECEIVE_TOTAL || !pool->borrowed[slot]
      || pool->buffers[slot] != buffer)
    return 0;
  pool->borrowed[slot] = 0;
  --pool->outstanding;
  if (slot < PRODUCT_ROOT_RECEIVE_NORMAL)
    pool->normal[pool->normal_free++] = slot;
  else
    pool->reserve[pool->reserve_free++] = slot;
  return 1;
}

#endif
