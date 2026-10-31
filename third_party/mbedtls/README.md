# Pinned Mbed TLS C profile

Source: Mbed-TLS `mbedtls-3.6.7`, Apache-2.0 (see LICENSE).
The original primitive subset came from the tag archive SHA-256
`807f0a1cc7c63b571180e9efeb6236b677e550869eb0442ace33aa9c69055fcc`.
The TLS/X.509 closure uses the same version's official release archive;
[release-source.json](release-source.json) pins its URL and SHA-256 and lists
all 33 existing upstream files verified byte-identical before expansion.
Upstream C and headers remain unmodified. `upstream-files.json` records every
retained file except itself, including the explicitly local build/config/memory
wrappers. CMake compiles only the selected C closure; public and internal headers
are retained for its pinned conditional dependencies.

The Product profile keeps AES/GCM/SHA-256 for public QUIC Initial keys and adds
an authenticated TLS 1.2 client, X.509/PEM, RSA/ECDSA, ECDHE P-256/P-384 and
AES-GCM SHA-256/SHA-384 suites. The Product provides nonblocking `getrandom`
through the library RNG callback and uses the existing owner fd/timer progression.
It reads platform CA anchors, verifies the chain/time/server identity, and applies
strict DNS SAN or IP SAN identity. It does not load application-selected anchors;
a separate explicit debug-only fixture supplies offline test trust. `MBEDTLS_SSL_ALPN` is enabled
for DoH only: its client profile offers the single protocol `http/1.1`; DoT offers none. TLS 1.3,
TLS servers, a PSA runtime and external libcrypto are outside this build profile.

`product_memory.c` scopes library allocations to each synchronous operation and
retains their actual owning budget through free. A connection has a 256 KiB
sublimit; all TLS heap, including up to 256 CA certificates, shares one 1 MiB
owner cap inside the existing DNS owner budget. Trust input is at most 512 KiB,
with 16 KiB per streamed certificate. Five TLS connections share this cap.
Symbols remain private to the Product artifact on Host and NDK.
