# c-ares wire-only codec

Source: https://github.com/c-ares/c-ares, tag `v1.34.8`, commit
`c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab` (annotated tag
`63a4c4c71b86e448bcc1c55287c35aa4aa0f4246`). Official fixed-tag archive SHA-256:
`ddf8be8b179ef6ff656e7413da93cf0f3038c627aca29ce9aae30f66e5b32bc1`.

`upstream-manifest.json` records every retained unmodified upstream file and
the compilation closure. Reproduce the export with
`rtk proxy python3 tools/product/vendor-cares.py <fixed-tag-archive>`.
The MIT license and retained license inventory are under `upstream/`.

Only the DNS record parser/encoder and their array/list/string/math support are
linked. No channel, resolver configuration, socket, retry/cache engine, event
backend, library initialization, global allocator hooks or worker thread is
compiled. The pure onion-name helper required by the convenience encoder is
extracted verbatim, with its license, from the retained `ares_getnameinfo.c`;
the resolver functions in that file are not compiled.

`product_wire.c` compiles the unmodified parser once and exposes its static
buffer seam through a private wrapper that rejects unconsumed trailing bytes.
The public c-ares `ares_dns_parse` does not expose that consumption result.
`product_memory.c` supplies only the codec's seven private allocation functions,
using a synchronous owner-thread scope. Every allocation, including its aligned
accounting header and simultaneous old/new realloc storage, counts against the
scope limit. Scope exit reports and defensively frees any unreleased allocation.
Aggregate live-byte/operation counters are health observations, not shared codec
state. The Product currently limits one synchronous operation to 512 KiB per
FlowOwner and a message to 65,535 bytes; parse capacity is reported separately
from malformed input and policy NoMatch.

`namespace.h` gives all retained c-ares function symbols private Product names.
The Product plugin also hides this static archive's symbols from its dynamic
export table. `product_cares.h` is private to DNS implementation; the public DNS
message/context Interface does not expose dependency types. The Linux and NDK
targets compile the same POSIX profile and upstream sources offline.
