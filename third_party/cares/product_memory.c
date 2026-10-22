/* SPDX-License-Identifier: Apache-2.0 */
/* The wire subset uses c-ares' private memory seam, without library/channel
 * initialization. This is the only replaced upstream support implementation. */
#include "product_cares.h"
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

typedef union allocation allocation_t;
union allocation {
  max_align_t alignment;
  struct { size_t bytes; allocation_t *previous, *next; } value;
};
typedef struct {
  size_t limit, live, peak;
  allocation_t *first;
  int active;
} memory_scope_t;
static _Thread_local memory_scope_t scope;
/* Aggregate health only; codec objects and budgets remain owner-thread local. */
static _Atomic size_t live_bytes, active_operations;

int product_cares_memory_begin (size_t limit)
{
  if (scope.active || !limit) return -1;
  scope = (memory_scope_t) { .limit = limit, .active = 1 };
  atomic_fetch_add (&active_operations, 1);
  return 0;
}

void *ares_malloc (size_t bytes)
{
  if (!scope.active || !bytes || bytes > SIZE_MAX - sizeof (allocation_t))
    return NULL;
  size_t total = bytes + sizeof (allocation_t);
  if (total > scope.limit - scope.live) return NULL;
  allocation_t *allocation = malloc (total);
  if (!allocation) return NULL;
  allocation->value.bytes = total;
  allocation->value.previous = NULL;
  allocation->value.next = scope.first;
  if (scope.first) scope.first->value.previous = allocation;
  scope.first = allocation;
  scope.live += total;
  atomic_fetch_add (&live_bytes, total);
  if (scope.live > scope.peak) scope.peak = scope.live;
  return allocation + 1;
}

void ares_free (void *pointer)
{
  if (!pointer) return;
  allocation_t *allocation = (allocation_t *) pointer - 1;
  if (allocation->value.previous)
    allocation->value.previous->value.next = allocation->value.next;
  else scope.first = allocation->value.next;
  if (allocation->value.next)
    allocation->value.next->value.previous = allocation->value.previous;
  scope.live -= allocation->value.bytes;
  atomic_fetch_sub (&live_bytes, allocation->value.bytes);
  free (allocation);
}

void *ares_realloc (void *pointer, size_t bytes)
{
  if (!pointer) return ares_malloc (bytes);
  if (!bytes) { ares_free (pointer); return NULL; }
  allocation_t *old = (allocation_t *) pointer - 1;
  void *next = ares_malloc (bytes);
  if (!next) return NULL;
  size_t old_bytes = old->value.bytes - sizeof (*old);
  memcpy (next, pointer, bytes < old_bytes ? bytes : old_bytes);
  ares_free (pointer);
  return next;
}

void *ares_malloc_zero (size_t bytes)
{
  void *pointer = ares_malloc (bytes);
  if (pointer) memset (pointer, 0, bytes);
  return pointer;
}

void *ares_realloc_zero (void *pointer, size_t old_bytes, size_t new_bytes)
{
  void *next = ares_realloc (pointer, new_bytes);
  if (next && new_bytes > old_bytes)
    memset ((uint8_t *) next + old_bytes, 0, new_bytes - old_bytes);
  return next;
}

void *ares_malloc_zero_array (size_t count, size_t bytes)
{
  return bytes && count <= SIZE_MAX / bytes ? ares_malloc_zero (count * bytes) : NULL;
}

void *ares_realloc_zero_array (void *pointer, size_t old_count,
                              size_t new_count, size_t bytes)
{
  if (!bytes || old_count > SIZE_MAX / bytes || new_count > SIZE_MAX / bytes)
    return NULL;
  return ares_realloc_zero (pointer, old_count * bytes, new_count * bytes);
}

size_t product_cares_memory_end (size_t *unreleased)
{
  size_t peak = scope.peak;
  if (unreleased) *unreleased = scope.live;
  /* Defensive settlement on every error exit, also reported as a codec fault. */
  while (scope.first) ares_free (scope.first + 1);
  scope = (memory_scope_t) {0};
  atomic_fetch_sub (&active_operations, 1);
  return peak;
}

void product_cares_memory_status (size_t *bytes, size_t *operations)
{
  *bytes = atomic_load (&live_bytes);
  *operations = atomic_load (&active_operations);
}
