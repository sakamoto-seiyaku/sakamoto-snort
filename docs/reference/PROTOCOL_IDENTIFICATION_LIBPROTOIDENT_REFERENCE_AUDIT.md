# Protocol Identification libprotoident Reference Audit

Date: 2026-08-12

Status: local fact audit for SAKAMOTO-61 provider-source planning. This is not
legal advice, not a vendoring decision, and not an implementation approval.

Reference source:

- `/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/libprotoident`
- wrapper boundary:
  `/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_core.h`

## Local License Facts

The vendored `libprotoident/libprotoident.h` header states:

- copyright: University of Waikato WAND research group, 2011-2016;
- license: GNU Lesser General Public License, version 3 or later;
- no warranty.

The vendored `libprotoident` directory itself does not provide an adjacent
`COPYING`, `LICENSE`, or `NOTICE` file. Any S61 source strategy that copies or
links this code must first define the license notice/source/relink posture for
Android distribution.

## Build Shape Observed

`libprotoident/CMakeLists.txt` builds a static C++ library:

- `add_library(libprotoident STATIC ...)`
- C++ standard: `11`
- position independent code: enabled
- source collection: top-level `*.cc`, `udp/*.cc`, and `tcp/*.cc`
- local observed file shape: `531` `.cc` files, `5` `.h` files,
  `1` `version.map`, and `1` `CMakeLists.txt`

The local CMake links:

- `stdc++`
- `gcc_s`

No `libtrace` library is linked by this vendored CMake. The public header still
contains a commented `#include <libtrace.h>` and keeps API comments from the
original packet-update model.

## Android / NDK Portability Risks

Observed includes and build assumptions that need explicit Android verification:

- `pthread.h`
- `netinet/in.h`
- `endian.h` / byte-order macros and the FreeBSD-specific `sys/endian.h` path
- `glob.h`
- `dlfcn.h`
- GNU C/C++ attributes
- linker/versioning assumptions: `-Wl,--version-script`
- explicit `gcc_s` linkage in the reference CMake target
- Linux/VPP-oriented compile definitions:
  `__FAVOR_BSD`, `HAVE_NET_ETHERNET_H`, `HAVE_ICMPHDR`,
  `HAVE_TCP_STATES`, `HAVE_BSD_UDPHDR`, `HAVE_BSD_TCPHDR`

The byte-order headers/macros, dynamic-loading headers, version-script linker
flag, and explicit `gcc_s` linkage are the highest-risk Android/NDK build
facts observed in the reference copy. Validate them with a separate Android
compile probe before any provider source is copied into the active tree.

## Android / NDK Build Probe

Repo-local probe:

- `tools/protocol_identification/libprotoident_android_build_probe.sh`

Observed result on 2026-08-12:

- source:
  `/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/libprotoident`
- NDK: `/home/js/.local/share/android-sdk/ndk/29.0.14206865`
- ABI/platform: `arm64-v8a` / `android-31`
- generated build root:
  `build-output/protocol-identification/libprotoident-android-probe`
- source tree SHA-256:
  `eaa5eed00c006920f12baa0273513796905c19e27b6cf68cf67b25e8701b5d80`
- compile-probed source count: `3` top-level `.cc`, `284` `tcp/*.cc`,
  and `244` `udp/*.cc` files
- result: `probe.result=PASS`
- scope: `probe.scope=compile-link-only`
- output executable:
  `libprotoident_android_probe`, reported by `file` as an Android ARM aarch64
  PIE executable
- output static archive: `liblibprotoident_probe.a`

The probe compiles the reference `libprotoident` top-level, TCP, and UDP C++
sources and links a minimal executable that calls `lpi_init_library`,
`lpi_init_data`, and `lpi_guess_protocol`. It does not include the VPP
`stellar_lpi` C wrapper, does not include `stellar_lpi_extend`, does not copy
source into this repo, and does not approve LGPL/vendoring/product integration.

Probe interpretation:

- Android NDK r29 can compile and link the current vendored base
  `libprotoident` source for arm64 with a minimal executable.
- The earlier `endian.h`, `glob.h`, `dlfcn.h`, and byte-order observations are
  not immediate compile blockers for this local NDK r29 probe.
- The reference CMake's explicit `gcc_s` link is not needed by this minimal
  probe; do not copy that link line into Sakamoto without a separate reason.
- Many compiler warnings remain, including tautological comparisons in legacy
  byte-mask macros. Treat the provider source as third-party code requiring a
  warning policy if it is later vendored.

## Minimal API Shape

The fork wrapper exposes a small C boundary through `stellar_lpi_core.h`:

- `lpi_detector_new`
- `lpi_detector_free`
- `lpi_detect_context_new`
- `lpi_detect_context_free`
- `lpi_detect_context_update`
- `lpi_detect`
- `lpi_appid2name`

The wrapper calls the lower-level libprotoident API:

- `lpi_init_library`
- `lpi_free_library`
- `lpi_init_data`
- `lpi_guess_protocol`

The vendored copy does not link `libtrace`. It keeps a commented
`#include <libtrace.h>` in `libprotoident.h` and defines a local
`libtrace_ipproto_t` enum in `libprotoident.cc` for transport-protocol numbers.

The lower-level `lpi_data_t` carries only compact per-flow facts:

- first payload word per direction;
- observed bytes per direction;
- payload length per direction;
- client/server ports;
- transport protocol;
- IP fields and TCP/SYN sequence metadata retained from the original API.

## Do Not Copy As-Is

The VPP wrapper is useful lineage but not a drop-in Sakamoto provider. It uses:

- VPP allocator macros and utility headers;
- `uthash`;
- fork-local Qosmos/qDPI-style AppIDs;
- `stellar_lpi_extend` post-processing;
- tunnel/STARTTLS continue-detection behavior;
- VPP plugin/session assumptions.

Sakamoto should keep the existing `LpiRecognitionProvider` boundary and only
reuse a pinned recognizer source after the source, license, and Android build
strategy are decided.

## Open Questions Before Real Provider Work

1. Which source is authoritative: backup VPP vendored copy, upstream
   libprotoident, or a separate provider package?
2. Is LGPL-3.0-or-later acceptable for the Android artifact distribution model?
3. If static linking is used, what relink/source/notice obligations must the
   release process satisfy?
4. Should the provider keep a Sakamoto-owned CMake wrapper and warning policy
   for this third-party source, or normalize it into a smaller pinned package?
5. Should `stellar_lpi_extend` be included, trimmed, or replaced by
   Sakamoto-owned normalization after base libprotoident output?
