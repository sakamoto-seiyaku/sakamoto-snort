/* SPDX-License-Identifier: Apache-2.0 */
#include "product_memory.h"
#include <stdlib.h>
#include <stdalign.h>

typedef union {
  max_align_t alignment;
  struct { sakamoto_mbedtls_budget_t *owner; size_t bytes; } value;
} allocation_t;
static _Thread_local sakamoto_mbedtls_budget_t *current;

sakamoto_mbedtls_budget_t *sakamoto_mbedtls_scope(sakamoto_mbedtls_budget_t *scope)
{ sakamoto_mbedtls_budget_t *previous=current;current=scope;return previous; }

void *sakamoto_mbedtls_calloc(size_t count,size_t size)
{
  if(!current || (size && count>(SIZE_MAX-sizeof(allocation_t))/size))return NULL;
  size_t bytes=count*size+sizeof(allocation_t);
  for(sakamoto_mbedtls_budget_t *b=current;b;b=b->parent)
    if(bytes>b->limit-b->bytes){
      for(sakamoto_mbedtls_budget_t *failed=current;failed;failed=failed->parent)++failed->rejected;
      return NULL;
    }
  allocation_t *allocation=calloc(1,bytes);if(!allocation)return NULL;
  allocation->value.owner=current;allocation->value.bytes=bytes;
  for(sakamoto_mbedtls_budget_t *b=current;b;b=b->parent){
    b->bytes+=bytes;if(b->bytes>b->high_water)b->high_water=b->bytes;
  }
  return allocation+1;
}
void sakamoto_mbedtls_free(void *memory)
{
  if(!memory)return;
  allocation_t *allocation=(allocation_t *)memory-1;
  for(sakamoto_mbedtls_budget_t *b=allocation->value.owner;b;b=b->parent)
    b->bytes-=allocation->value.bytes;
  free(allocation);
}
