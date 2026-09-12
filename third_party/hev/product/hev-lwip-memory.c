/* SPDX-License-Identifier: MIT */
#include "hev-lwip-context.h"
#include <stdlib.h>
#include <string.h>

/* This accounts only for the real lwIP heap, not HEV task stacks or session
 * objects. Keep the payload suitably aligned for every C allocation type. */
typedef union {
  max_align_t alignment;
  struct {
    hev_lwip_context_t *owner;
    size_t bytes;
  } allocation;
} allocation_header_t;

void *hev_lwip_malloc(size_t size)
{
  hev_lwip_context_t *owner = hev_lwip_context_current();
  allocation_header_t *header;
  if (!owner)
    abort();
  if (size > SIZE_MAX - sizeof(*header) ||
      size > SIZE_MAX - owner->heap_bytes || owner->heap_live == SIZE_MAX)
    return NULL;
  header = malloc(sizeof(*header) + size);
  if (!header)
    return NULL;
  header->allocation.owner = owner;
  header->allocation.bytes = size;
  ++owner->heap_live;
  ++owner->heap_allocations;
  owner->heap_bytes += size;
  if (owner->heap_bytes > owner->heap_peak_bytes)
    owner->heap_peak_bytes = owner->heap_bytes;
  return header + 1;
}

void *hev_lwip_calloc(size_t count, size_t size)
{
  void *memory;
  if (size && count > SIZE_MAX / size)
    return NULL;
  size *= count;
  memory = hev_lwip_malloc(size);
  if (memory)
    memset(memory, 0, size);
  return memory;
}

void hev_lwip_free(void *memory)
{
  allocation_header_t *header;
  hev_lwip_context_t *owner;
  if (!memory)
    return;
  header = (allocation_header_t *)memory - 1;
  owner = hev_lwip_context_current();
  /* A wrong-owner release is a programming error even in NDEBUG builds.
   * Never charge it to the current owner or silently mutate another owner. */
  if (!owner || header->allocation.owner != owner || !owner->heap_live ||
      header->allocation.bytes > owner->heap_bytes)
    abort();
  --owner->heap_live;
  ++owner->heap_frees;
  owner->heap_bytes -= header->allocation.bytes;
  free(header);
}
