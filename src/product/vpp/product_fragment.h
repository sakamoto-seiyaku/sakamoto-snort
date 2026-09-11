/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FRAGMENT_H
#define SAKAMOTO_PRODUCT_FRAGMENT_H

#include "product_packet.h"

#define PRODUCT_FRAGMENT_DEFAULT_CONTEXTS 64
#define PRODUCT_FRAGMENT_DEFAULT_ORIGINALS 32
#define PRODUCT_FRAGMENT_INDEX_NONE UINT32_MAX

/* Temporary datagram identity; never used as a FlowEntry key. */
typedef struct {
  uint8_t family, protocol;
  uint8_t source[16], destination[16];
  uint32_t identification;
} product_fragment_key_t;

typedef struct {
  product_fragment_key_t key;
  uint32_t buffer_index;
  uint16_t offset, length, header_length;
  /* IPv6 next-header byte to patch when removing the Fragment Header. */
  uint16_t previous_next_header;
  uint8_t more, selected;
} product_fragment_piece_t;

typedef enum {
  PRODUCT_FRAGMENT_WAIT,
  PRODUCT_FRAGMENT_COMPLETE,
  PRODUCT_FRAGMENT_CONTEXT_FULL,
  PRODUCT_FRAGMENT_BUNDLE_FULL,
  PRODUCT_FRAGMENT_CONFLICT,
  PRODUCT_FRAGMENT_TIMEOUT,
  PRODUCT_FRAGMENT_STOP,
} product_fragment_result_t;

/* Detached descriptors remain valid until the next table mutation. The graph
 * must transfer all originals to completion/buffer metadata before that call. */
typedef struct {
  product_fragment_piece_t *pieces;
  product_owner_assignment_t assignment;
  uint32_t count, total_length, first;
} product_fragment_bundle_t;

typedef struct {
  product_fragment_bundle_t bundle;
  product_fragment_key_t key;
  uint64_t started_us;
  uint32_t next, free_next;
  uint8_t active, have_last;
} product_fragment_context_t;

typedef struct {
  product_fragment_context_t *contexts;
  product_fragment_piece_t *storage, *detached;
  uint32_t *buckets, bucket_count;
  uint32_t free_head, active, capacity, original_limit;
  uint64_t timeout_us;
} product_fragment_table_t;

/* Returns 0 for ordinary packets, 1 for supported valid fragments, -1 for
 * malformed/unsupported fragment envelopes. No policy or platform lookup. */
int product_fragment_parse(const uint8_t *data, size_t size,
                           product_fragment_piece_t *piece,
                           product_packet_facts_t *first_identity);
uint16_t product_fragment_worker(const product_worker_layout_t *layout,
                                const product_fragment_key_t *key);
int product_fragment_table_init(product_fragment_table_t *table,
                                uint32_t capacity, uint32_t original_limit,
                                uint64_t timeout_us);
/* Only after all active bundles have been flushed and their originals moved. */
void product_fragment_table_destroy(product_fragment_table_t *table);
product_fragment_result_t product_fragment_push(
    product_fragment_table_t *table, const product_fragment_piece_t *piece,
    const product_owner_assignment_t *first_assignment, uint64_t now_us,
    product_fragment_bundle_t *out);
/* One bounded scan, called only on the owning worker or after quiescence. */
int product_fragment_take_expired(product_fragment_table_t *table,
                                  uint64_t now_us, int flush,
                                  product_fragment_bundle_t *out);
#endif
