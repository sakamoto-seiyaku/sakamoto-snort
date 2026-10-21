/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_RECEIVE_POOL_H
#define SAKAMOTO_PRODUCT_ROOT_RECEIVE_POOL_H

#include <stdint.h>
#include <string.h>
#include "product_root_defaults.h"

/* Startup partition of existing VPP buffers, not a second packet allocator.
 * Only the origin worker borrows/returns slots. The main thread may inspect
 * or withhold them under the worker barrier. Startup reserves 128+8 buffers;
 * an empty diagnostic generation may switch between 64+8 and 128+8. No packet-path
 * growth or borrowing between lanes. Bounds are not throughput qualification. */
#define PRODUCT_ROOT_RECEIVE_MIN_NORMAL 64
#define PRODUCT_ROOT_RECEIVE_NORMAL PRODUCT_ROOT_DEFAULT_NORMAL_CAPACITY
#define PRODUCT_ROOT_RECEIVE_MAX_NORMAL 128
#define PRODUCT_ROOT_RECEIVE_RESERVE 8
#define PRODUCT_ROOT_RECEIVE_TOTAL \
  (PRODUCT_ROOT_RECEIVE_NORMAL + PRODUCT_ROOT_RECEIVE_RESERVE)
#define PRODUCT_ROOT_RECEIVE_MAX_TOTAL \
  (PRODUCT_ROOT_RECEIVE_MAX_NORMAL + PRODUCT_ROOT_RECEIVE_RESERVE)
#define PRODUCT_ROOT_RECEIVE_NONE UINT16_MAX

typedef struct
{
  uint64_t generation;
  uint32_t buffers[PRODUCT_ROOT_RECEIVE_MAX_TOTAL];
  uint16_t normal[PRODUCT_ROOT_RECEIVE_MAX_NORMAL];
  uint16_t reserve[PRODUCT_ROOT_RECEIVE_RESERVE];
  uint16_t normal_capacity;
  uint16_t normal_free, reserve_free, outstanding;
  uint8_t borrowed[PRODUCT_ROOT_RECEIVE_MAX_TOTAL];
} product_root_receive_pool_t;

static inline int
product_root_receive_pool_init_capacity (product_root_receive_pool_t *pool,
  uint64_t generation, const uint32_t *buffers, uint16_t normal_capacity)
{
  if (!pool || !generation || !buffers || pool->outstanding
      || (normal_capacity != PRODUCT_ROOT_RECEIVE_MIN_NORMAL
          && normal_capacity != PRODUCT_ROOT_RECEIVE_MAX_NORMAL))
    return 0;
  memset (pool, 0, sizeof (*pool));
  pool->generation = generation;
  pool->normal_capacity = normal_capacity;
  memcpy (pool->buffers, buffers,
          (normal_capacity + PRODUCT_ROOT_RECEIVE_RESERVE) * sizeof (*buffers));
  for (uint16_t i = 0; i < normal_capacity; ++i)
    pool->normal[pool->normal_free++] = i;
  for (uint16_t i = normal_capacity;
       i < normal_capacity + PRODUCT_ROOT_RECEIVE_RESERVE; ++i)
    pool->reserve[pool->reserve_free++] = i;
  return 1;
}

static inline int
product_root_receive_pool_init (product_root_receive_pool_t *pool,
                                uint64_t generation, const uint32_t *buffers)
{
  return product_root_receive_pool_init_capacity (
    pool, generation, buffers, PRODUCT_ROOT_RECEIVE_NORMAL);
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
      || slot >= pool->normal_capacity + PRODUCT_ROOT_RECEIVE_RESERVE
      || !pool->borrowed[slot]
      || pool->buffers[slot] != buffer)
    return 0;
  pool->borrowed[slot] = 0;
  --pool->outstanding;
  if (slot < pool->normal_capacity)
    pool->normal[pool->normal_free++] = slot;
  else
    pool->reserve[pool->reserve_free++] = slot;
  return 1;
}

#endif
