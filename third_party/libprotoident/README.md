# Official libprotoident dependency

Upstream: https://github.com/LibtraceTeam/libprotoident
Pinned revision: `97a8efecd257ec09f652374399f27b3a65db7d0a`.
Copyright University of Waikato WAND group and contributors; LGPL-3.0-or-later.
See COPYING.LESSER, COPYING and upstream AUTHORS. The selected upstream `lib/`
tree and licenses are vendored for reproducible offline Host/Android builds.
`upstream-manifest.json` records original hashes. CMake's explicit source list
comes from upstream lib/, tcp/ and udp/ Makefile.am (not all old files compile).

The two modified upstream files add `SAKAMOTO_LPI_FEATURES_ONLY`: omit the
libtrace packet adapter and include standard integer/network headers instead.
The official protocol detector/registry implementations are unchanged. Product
C code supplies normalized scalar features through `adapter.h`; `adapter.cc`
is only the private dependency ABI and provider-name normalization. Packet
graph, Flow state, budgets, accumulation, rule matching and queries remain C.
No source comes from the reference VPP fork, a POC or the removed C++ product.

`lpi_init_library` runs on main before worker admission. Registered matchers
are immutable afterwards; queries use a stack `lpi_data_t`, iterate fixed
registry lists and retain no query pointers. The registered global tables are
released only at process exit, after worker lifetime. Matches do not allocate,
spawn threads or take a global lock. Temporary misses return NULL; unmapped
recognitions retain the original static module name for the C supplemental
resolver, separately from mapped catalog evidence (R1).
The product catalog mapping deliberately includes only supported exact facts.
HTTPS maps to TLS because its detector directly checks TLS bytes; it does not
publish HTTP merely from a category or inheritance relationship.

The upstream QUIC detector predates QUIC v1/v2. The product's small bounded
Initial long-header recognizer supplements it using RFC 9000 sections 16/17.2.2
and RFC 9369 section 3.2. It recognizes wire headers without claiming successful
authentication or SNI extraction. Those later producers have separate scope.

Build with the workspace CMake or the Product plugin build; the dependency is
statically linked, with Android libc++ static. Retain the corresponding build
objects and this source tree to rebuild/relink modified library versions.
