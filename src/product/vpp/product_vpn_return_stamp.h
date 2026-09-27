/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_RETURN_STAMP_H
#define SAKAMOTO_PRODUCT_VPN_RETURN_STAMP_H

#include <stdint.h>

/* Lineage for the bounded, already credited HEV return buffers. The low
 * seven token bits name an exact free slot; a full token and generation are
 * checked before reading or releasing it. No packet pointer or UID lives here. */
#define PRODUCT_VPN_RETURN_STAMP_SLOTS 128U
typedef struct { uint64_t token, incarnation; } product_vpn_return_stamp_slot_t;
typedef struct {
  uint64_t generation;
  product_vpn_return_stamp_slot_t slots[PRODUCT_VPN_RETURN_STAMP_SLOTS];
} product_vpn_return_stamp_t;

_Static_assert((PRODUCT_VPN_RETURN_STAMP_SLOTS & (PRODUCT_VPN_RETURN_STAMP_SLOTS - 1)) == 0,
               "return stamp slots must be a power of two");
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t), 0),
               "return token publication must be lock free");

static inline int product_vpn_return_stamp_find_free(
  const product_vpn_return_stamp_t *ledger, unsigned start)
{
  for (unsigned n = 0; n < PRODUCT_VPN_RETURN_STAMP_SLOTS; ++n) {
    unsigned index = (start + n) & (PRODUCT_VPN_RETURN_STAMP_SLOTS - 1);
    if (!__atomic_load_n(&ledger->slots[index].token, __ATOMIC_ACQUIRE))
      return (int)index;
  }
  return -1;
}

static inline int product_vpn_return_stamp_empty(
  const product_vpn_return_stamp_t *ledger)
{
  for (unsigned i = 0; i < PRODUCT_VPN_RETURN_STAMP_SLOTS; ++i)
    if (__atomic_load_n(&ledger->slots[i].token, __ATOMIC_ACQUIRE)) return 0;
  return 1;
}

static inline int product_vpn_return_stamp_publish(
  product_vpn_return_stamp_t *ledger, uint64_t generation, uint64_t token,
  uint64_t incarnation)
{
  unsigned index = (unsigned)(token & (PRODUCT_VPN_RETURN_STAMP_SLOTS - 1));
  product_vpn_return_stamp_slot_t *slot = &ledger->slots[index];
  if (!token || !generation || ledger->generation != generation ||
      __atomic_load_n(&slot->token, __ATOMIC_ACQUIRE)) return 0;
  slot->incarnation = incarnation;
  __atomic_store_n(&slot->token, token, __ATOMIC_RELEASE);
  return 1;
}

static inline int product_vpn_return_stamp_lookup(
  const product_vpn_return_stamp_t *ledger, uint64_t generation,
  uint64_t token, uint64_t *incarnation)
{
  /* Graph policy calls this while the return buffer is live. Its completion
   * and slot release occur only after policy exits; this is not a generic
   * concurrent lookup on a token whose lifetime has already ended. */
  const product_vpn_return_stamp_slot_t *slot =
    &ledger->slots[token & (PRODUCT_VPN_RETURN_STAMP_SLOTS - 1)];
  if (!incarnation || !token || ledger->generation != generation ||
      __atomic_load_n(&slot->token, __ATOMIC_ACQUIRE) != token) return 0;
  *incarnation = slot->incarnation;
  return 1;
}

static inline int product_vpn_return_stamp_release(
  product_vpn_return_stamp_t *ledger, uint64_t generation, uint64_t token)
{
  product_vpn_return_stamp_slot_t *slot =
    &ledger->slots[token & (PRODUCT_VPN_RETURN_STAMP_SLOTS - 1)];
  if (!token || ledger->generation != generation) return 0;
  return __atomic_compare_exchange_n(&slot->token, &token, 0, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}
#endif
