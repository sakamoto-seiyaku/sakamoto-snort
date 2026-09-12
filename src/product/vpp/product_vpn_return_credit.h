/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_RETURN_CREDIT_H
#define SAKAMOTO_PRODUCT_VPN_RETURN_CREDIT_H

#include <stdint.h>
#include <stdlib.h>

/* One ledger per generating worker, fixed for a drained runtime generation.
 * Only that worker takes credits. The current native buffer holder returns
 * one credit AFTER freeing its storage (including pre-accept failures).
 * This is capacity accounting, not a packet registry or shared flow state.
 * Native buffer ownership supplies exactly-once settlement; replay probes
 * must never call release. No packet pointer or completion queue lives here. */
typedef struct {
  uint64_t generation;
  uint32_t capacity;
  uint32_t in_use;
} product_vpn_return_credit_t;

_Static_assert(__atomic_always_lock_free(sizeof(uint32_t), 0),
               "VPN return credit must not introduce a worker lock");

static inline uint32_t product_vpn_return_credit_used(
  const product_vpn_return_credit_t *credit)
{ return __atomic_load_n(&credit->in_use, __ATOMIC_ACQUIRE); }

/* Called under the lifecycle barrier, never over a live generation. */
static inline int product_vpn_return_credit_init(
  product_vpn_return_credit_t *credit, uint64_t generation, uint32_t capacity)
{
  if (!generation || !capacity || product_vpn_return_credit_used(credit)) return -1;
  credit->generation = generation;
  credit->capacity = capacity;
  return 0;
}

static inline int product_vpn_return_credit_take(
  product_vpn_return_credit_t *credit, uint64_t generation)
{
  if (generation != credit->generation || !generation ||
      product_vpn_return_credit_used(credit) >= credit->capacity) return 0;
  /* Single producer: a concurrent free can only make more room. */
  __atomic_fetch_add(&credit->in_use, 1, __ATOMIC_RELAXED);
  return 1;
}

static inline int product_vpn_return_credit_release(
  product_vpn_return_credit_t *credit, uint64_t generation)
{
  if (!generation || generation != credit->generation) return -1;
  if (!__atomic_fetch_sub(&credit->in_use, 1, __ATOMIC_RELEASE)) abort();
  return 0;
}
#endif
