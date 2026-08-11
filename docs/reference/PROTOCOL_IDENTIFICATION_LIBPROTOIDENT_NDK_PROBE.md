# Protocol Identification libprotoident NDK Probe

Date: 2026-08-12

Status: repeatable build probe for SAKAMOTO-61 provider-source planning. This
does not copy source into the repository, does not enable a real provider, and
does not decide whether backup VPP, upstream libprotoident, or a separate
provider package should be used.

Probe command:

```bash
bash tools/protocol_identification/libprotoident_android_build_probe.sh
```

Default inputs:

- source:
  `/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/libprotoident`
- NDK root: `/home/js/.local/share/android-sdk/ndk/29.0.14206865`
- ABI: `arm64-v8a`
- platform: `android-31`
- STL: `c++_static`
- output:
  `build-output/protocol-identification/libprotoident-android-probe/`
- source tree SHA-256:
  `eaa5eed00c006920f12baa0273513796905c19e27b6cf68cf67b25e8701b5d80`
- compile-probed source count: `3` top-level `.cc`, `284` `tcp/*.cc`,
  and `244` `udp/*.cc` files

The probe creates a throwaway CMake project under `build-output`, points it at
the reference source tree, builds a static C++11 library with the same broad
source shape as the modified VPP `libprotoident/CMakeLists.txt`, and links a
minimal Android executable that touches the base `libprotoident` API. It does
not build the VPP `stellar_lpi` wrapper and does not include
`stellar_lpi_extend`.

## Current Local Result

Observed on 2026-08-12:

- command: `bash tools/protocol_identification/libprotoident_android_build_probe.sh`
- result: `probe.result=PASS`
- output executable: `libprotoident_android_probe`
- output executable type: Android ARM aarch64 PIE executable
- output static archive: `liblibprotoident_probe.a`
- source tree SHA-256:
  `eaa5eed00c006920f12baa0273513796905c19e27b6cf68cf67b25e8701b5d80`
- compile-probed source count: `3 + 284 + 244 = 531` `.cc` files
- ABI/platform: `arm64-v8a` / `android-31`
- NDK: `/home/js/.local/share/android-sdk/ndk/29.0.14206865`

This proves only that the vendored base `libprotoident` source set can currently
compile and link into a minimal Android executable with NDK r29. It does not
prove that the VPP `stellar_lpi_core` wrapper, `stellar_lpi_extend`, Sakamoto
provider adapter, catalog normalization, Activity projection, Root/VPN runtime
wiring, or final Android release distribution obligations are complete.

## Expected Use

Use this probe before any source import. Its output answers only one question:
"can this local reference source compile with the current Android/NDK toolchain
under a minimal CMake wrapper?"

It does not answer:

- whether LGPL-3.0-or-later is acceptable for distribution;
- whether static linking obligations are satisfied;
- whether the VPP wrapper can be reused without VPP allocator/session
  dependencies;
- whether the fork-local app IDs or `stellar_lpi_extend` behavior should be
  retained;
- whether the provider should be vendored, externally packaged, or replaced by
  an upstream source;
- whether ProtocolRule enforcement should start.

Those remain S61/S62 design or release-process decisions.
