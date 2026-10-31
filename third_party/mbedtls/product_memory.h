/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_MBEDTLS_MEMORY_H
#define SAKAMOTO_MBEDTLS_MEMORY_H
#include <stddef.h>
#include <stdint.h>
typedef struct sakamoto_mbedtls_budget {
  size_t bytes, high_water, limit;
  uint64_t rejected;
  struct sakamoto_mbedtls_budget *parent;
} sakamoto_mbedtls_budget_t;
/* A synchronous thread-local allocation scope, never a shared TLS arena.
 * Every retained allocation remembers its own owner until its actual free. */
sakamoto_mbedtls_budget_t *sakamoto_mbedtls_scope(sakamoto_mbedtls_budget_t *);
void *sakamoto_mbedtls_calloc(size_t, size_t);
void sakamoto_mbedtls_free(void *);
#endif
