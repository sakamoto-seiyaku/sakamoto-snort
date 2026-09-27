/* SPDX-License-Identifier: Apache-2.0 */
#include "product_vpn_return_credit.h"
#include "product_vpn_return_stamp.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>

enum { CAPACITY = 128, GENERATION = 239, ROUNDS = 100000 };
static product_vpn_return_credit_t credits[2];

static void return_lineage(void)
{
  product_vpn_return_stamp_t ledger = {.generation = GENERATION};
  uint64_t tokens[CAPACITY], incarnation;
  /* Holding the oldest token cannot make modulo reuse corrupt its lineage. */
  for (unsigned i = 0; i < CAPACITY; ++i) {
    int slot = product_vpn_return_stamp_find_free(&ledger, i);
    assert(slot == (int)i);
    tokens[i] = (UINT64_C(1) << 63) | (uint64_t)((i + 1) << 7) | i;
    assert(product_vpn_return_stamp_publish(&ledger, GENERATION, tokens[i],
                                            UINT64_C(0x100000000) + i));
  }
  assert(product_vpn_return_stamp_find_free(&ledger, 0) == -1);
  assert(!product_vpn_return_stamp_empty(&ledger));
  assert(!product_vpn_return_stamp_publish(&ledger, GENERATION, tokens[0] + 128, 1));
  assert(!product_vpn_return_stamp_lookup(&ledger, GENERATION + 1, tokens[0], &incarnation));
  assert(!product_vpn_return_stamp_lookup(&ledger, GENERATION, tokens[0] + 128, &incarnation));
  for (unsigned i = 1; i < CAPACITY; ++i) {
    assert(product_vpn_return_stamp_lookup(&ledger, GENERATION, tokens[i], &incarnation));
    assert(incarnation == UINT64_C(0x100000000) + i);
    assert(product_vpn_return_stamp_release(&ledger, GENERATION, tokens[i]));
    assert(!product_vpn_return_stamp_release(&ledger, GENERATION, tokens[i]));
  }
  assert(product_vpn_return_stamp_lookup(&ledger, GENERATION, tokens[0], &incarnation));
  assert(incarnation == UINT64_C(0x100000000));
  assert(product_vpn_return_stamp_find_free(&ledger, 0) == 1);
  assert(!product_vpn_return_stamp_release(&ledger, GENERATION - 1, tokens[0]));
  assert(product_vpn_return_stamp_release(&ledger, GENERATION, tokens[0]));
  assert(product_vpn_return_stamp_find_free(&ledger, 0) == 0);
  assert(product_vpn_return_stamp_empty(&ledger));
}

static void isolation(unsigned exhausted)
{
  unsigned other = exhausted ^ 1;
  for (unsigned i = 0; i < CAPACITY; ++i)
    assert(product_vpn_return_credit_take(&credits[exhausted], GENERATION));
  assert(!product_vpn_return_credit_take(&credits[exhausted], GENERATION));
  assert(!product_vpn_return_credit_used(&credits[other]));
  /* Submitting a native frame does not release its live buffer allowance.
   * The other owner can independently fill its entire allowance. */
  for (unsigned i = 0; i < CAPACITY; ++i)
    assert(product_vpn_return_credit_take(&credits[other], GENERATION));
  assert(product_vpn_return_credit_init(&credits[exhausted], GENERATION + 1, 1) == -1);
  assert(product_vpn_return_credit_release(&credits[exhausted], GENERATION - 1) == -1);
  assert(product_vpn_return_credit_used(&credits[exhausted]) == CAPACITY);
  /* Policy drop, write failure, normal completion and pre-accept rejection
   * all reach the same post-free credit operation. No delivery ACK follows. */
  for (unsigned i = 0; i < CAPACITY; ++i) {
    assert(!product_vpn_return_credit_release(&credits[exhausted], GENERATION));
    assert(!product_vpn_return_credit_release(&credits[other], GENERATION));
  }
}

static void *producer(void *opaque)
{
  product_vpn_return_credit_t *credit = opaque;
  for (unsigned i = 0; i < ROUNDS; ++i) {
    while (!product_vpn_return_credit_take(credit, GENERATION)) sched_yield();
    assert(product_vpn_return_credit_used(credit) <= CAPACITY);
  }
  return NULL;
}

static void *consumer(void *opaque)
{
  (void)opaque;
  unsigned freed[2] = {0};
  while (freed[0] < ROUNDS || freed[1] < ROUNDS) {
    for (unsigned owner = 0; owner < 2; ++owner) {
      if (freed[owner] < ROUNDS && product_vpn_return_credit_used(&credits[owner])) {
        assert(!product_vpn_return_credit_release(&credits[owner], GENERATION));
        ++freed[owner];
      }
    }
    sched_yield();
  }
  return NULL;
}

int main(void)
{
  return_lineage();
  for (unsigned i = 0; i < 2; ++i) {
    assert(product_vpn_return_credit_init(&credits[i], 0, CAPACITY) == -1);
    assert(product_vpn_return_credit_init(&credits[i], GENERATION, 0) == -1);
    assert(!product_vpn_return_credit_init(&credits[i], GENERATION, CAPACITY));
    assert(!product_vpn_return_credit_take(&credits[i], GENERATION - 1));
  }
  isolation(0);
  isolation(1);
  pthread_t writers[2], reader;
  for (unsigned i = 0; i < 2; ++i)
    assert(!pthread_create(&writers[i], NULL, producer, &credits[i]));
  assert(!pthread_create(&reader, NULL, consumer, NULL));
  for (unsigned i = 0; i < 2; ++i) assert(!pthread_join(writers[i], NULL));
  assert(!pthread_join(reader, NULL));
  for (unsigned i = 0; i < 2; ++i) {
    assert(!product_vpn_return_credit_used(&credits[i]));
    assert(!product_vpn_return_credit_init(&credits[i], GENERATION + 1, CAPACITY));
    assert(!product_vpn_return_credit_take(&credits[i], GENERATION));
    assert(product_vpn_return_credit_release(&credits[i], GENERATION) == -1);
  }
  puts("PASS: per-owner return allowance, full lifetime, generation and concurrent free accounting");
}
