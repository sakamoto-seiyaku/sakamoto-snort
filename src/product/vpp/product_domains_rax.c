/* SPDX-License-Identifier: Apache-2.0 */
/* The upstream sources stay byte-identical. Its supported allocator include
 * and assertion integration are the only compile-time bindings. */
#include <stdio.h>
#include <stdlib.h>
/* Upstream assertions include rollback operations and remain enabled even in
 * release builds. Preserve that contract without a Valkey server dependency. */
#define _serverAssert product_domains_rax_assert
#define _serverPanic product_domains_rax_panic
#define RAX_MALLOC_INCLUDE "product_domains_rax.h"
#include "../../../third_party/rax/rax.c"

void product_domains_rax_assert(const char *expression, const char *file, int line) {
    fprintf(stderr, "Product rax assertion: %s (%s:%d)\n", expression, file, line);
    abort();
}
