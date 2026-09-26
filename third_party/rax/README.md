# Valkey rax

Unmodified `src/rax.c`, `rax.h`, `rax_malloc.h` and `serverassert.h` from
Valkey revision `05a9c29c62538519d870d6512978f80ac58a758f`. Source hashes are
in `UPSTREAM.json`; original BSD license notices remain in each file.

Product uses `src/product/vpp/product_domains_rax.c` with the upstream allocator
include hook and a local always-enabled assertion handler. Production memory
comes from explicit VPP fallible heap allocation, matching size/free operations
and checked allocate/copy/free growth. The standalone Host semantic binding
is selected at compile time and is not a Product runtime backend.

The selection is recorded in `docs/testing/2026-09-26_T17_DOMAIN_MATCHER.md`
and `2026-09-26_T17_5_RECOVERABLE_DOMAIN_BUILD.md`. Experimental adapters were
not imported into Product.
