# TCP send-buffer default, 2026-10-22

The existing owner-local TCP send-buffer/ring profile now defaults to **65,528
bytes** (approximately 64 KiB) in standalone HEV CMake, the Host Product builder
and the Android Product builder. Explicit
`SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT=OFF` still selects 32,768 bytes.
The existing option name is retained for compatibility.

This implements the user's capacity selection after the
[ADR-0007 design update](../adr/0007-owner-local-lwip-direct-egress.md#2026-10-22-user-selected-tcp-send-buffer-capacity).
It establishes local transport/build correctness; it establishes no device or
throughput improvement. No installation, ADB, device execution, Wi-Fi change,
frequency change, CPU placement or new performance campaign occurred.

## Scope and preserved behavior

Only the three build defaults change executable selection. The APK reuse
validator continues treating absent historical buffer fields as OFF/32,768,
with a comment explaining why. A new default request therefore rejects an old
32 KiB stage instead of relabeling its payload. Current and benchmark entry
docs describe the new default and retain the limitations of historical results.

`TCP_WND=32768`, MTU 10,000/MSS 9,940, disabled window scaling and the existing
`TCP_SNDLOWAT` sanity expression remain unchanged. 65,536 cannot represent this
capacity in the current non-window-scaled 16-bit `tcpwnd_size_t`. TCP batch and
readiness/progress gating remain OFF. No new option, runtime resize, copy,
lifetime, ACK handling, ownership, retry or scheduler path is introduced.
Root defaults, owner/dedicated-I/O topology, VPN primary credits48,
capture/shared windows64 and native return frames256 are unchanged.

## Verification

Raw evidence and executable verification scripts are in
[`build-output/tcp-send64-default-20261022/`](../../build-output/tcp-send64-default-20261022/).
All builds reuse the established standalone HEV tree or Product persistent
compilation caches. Published artifacts use separate output directories.

| Gate | Result |
| --- | --- |
| Default ON, MTU10000, batch/progress OFF | 27/27 targeted real HEV tests PASS |
| Explicit OFF32, otherwise identical | 27/27 targeted real HEV tests PASS |
| Host actual builder unchanged repeat | 0 Ninja actions, 0 Rust compilations; compiled timestamps and 20 payload hashes unchanged |
| Android actual builder unchanged repeat | 0 Ninja actions, 0 Rust compilations; 824 compiled files unchanged; all 12 native payloads byte-identical |
| APK unchanged repeat | 0 javac/D8 compilations; class/DEX timestamps and DEX bytes unchanged; all native payloads preserved |
| New default vs historical32 stage | Rejected before packaging |
| Explicit OFF vs new64 stage | Rejected before packaging |
| New default vs copied legacy32 stage lacking buffer fields | Rejected before packaging |
| Explicit OFF with historical32 and missing-field legacy32 stages | Both packaged successfully with original native bytes |

Each 27-test profile comprises 24 real TCP cases (12 per family), plus the
transport, memory and Direct receive fixtures. TCP cases cover streaming with
73728-byte payloads per owner, held ACK/ring pressure and wrap, SYN/data output
loss/rejection, refusal, unreachable, client reset, remote FIN/TIME_WAIT,
underlay invalidation and bounded session/PCB/socket/packet/pbuf capacity faults.
Existing assertions check exact committed bytes, expected buffer capacity,
65,528-byte-profile ring peaks above 32 KiB under held ACK, and balanced
allocation/socket/session settlement on stop. Both profiles run with TCP batch
and progress gating OFF; the final HEV cache is restored to the new default.

Proofs: [default HEV](../../build-output/tcp-send64-default-20261022/hev-default-tests.log),
[OFF HEV](../../build-output/tcp-send64-default-20261022/hev-off-tests.log),
[Host repeat](../../build-output/tcp-send64-default-20261022/host-repeat-identity.json),
[Android native repeat](../../build-output/tcp-send64-default-20261022/android-cache/result.json),
[APK repeat](../../build-output/tcp-send64-default-20261022/apk-cache/result.json),
and [packaging/legacy gates](../../build-output/tcp-send64-default-20261022/packaging-result.json).

The initial sandboxed HEV invocation could not open sockets/netlink; its raw
failures are retained separately. The same fixtures passed after automatic
approval for isolated local network namespaces. An initially invalid Host
publication leaf and stale historical Android VPP input were rejected by the
existing path/core-patch guards before build; corrected inputs use the required
Product output name and verified `product-vpp-android-stage-s297`. These guard
rejections are retained; they are not transport failures or successful build
claims. No fresh VPP dependency stage was built.

## Frozen identities

The Product source snapshot and per-file closure are in
[Android build.json](../../build-output/tcp-send64-default-20261022/android/build.json),
with copied source and the pre-commit dirty diff alongside it. Documentation
changes are not part of the Product source hash. The build started from
`dbb472d4`; commit identity and Product source closure serve different purposes.

| Artifact | SHA-256 |
| --- | --- |
| Product source closure | `98b2c06c0666044d151d61a3954b0eeab93fb27b8bddbec4954e417b377bb0a4` |
| New Android APK | `7105cbd896052e7d3ea1c8edfe5e00ad1d75a208425e9e7d5fed7aed5f3eff57` |
| Android stripped plugin | `c3b3406d637af2cb7dddf7fa8bdebce84605688826316967fd3cfd9a792406b7` |
| Exact Android plugin symbols | `4034a674467f2eee8111fab00477a60f33f2073f1249502b287436ea52302e17` |
| Host plugin, unstripped publication | `c3aa95b06e4c855b7c3d986bb2b73aa3c8dede077f27ae6cd9c4fa5394a54dbe` |

APK: [`android/apk/sakamoto-runtime-debug.apk`](../../build-output/tcp-send64-default-20261022/android/apk/sakamoto-runtime-debug.apk).
Exact symbols: [`android/symbols/libproduct_core_plugin.so`](../../build-output/tcp-send64-default-20261022/android/symbols/libproduct_core_plugin.so).
Stripping a temporary copy reproduces the APK plugin bytes exactly; the
[symbol witness](../../build-output/tcp-send64-default-20261022/symbols.json)
records that comparison. Full native hashes are in `android/build.json` and
Host publication hashes in `host-first-identity.json`.

The old 32 KiB fbb5 artifact remains unchanged at
[`s308-final-unified64-20261022/apk-cache-proof/first/sakamoto-runtime-debug.apk`](../../build-output/s308-final-unified64-20261022/apk-cache-proof/first/sakamoto-runtime-debug.apk),
SHA-256 `fbb5cd3bf98ad2df0304572bbdcf564b485336f3f4e8cfb6b8f76a348169c1a2`.
All 15 files in its original native stage were hashed before/after packaging
checks and remained identical. Original APKs, matching symbols, raw device
observations and historical source identities are preserved. New default
artifacts cannot inherit the old artifact's Android performance qualification.

## Review

Separate Spec and Standards reviews completed with zero remaining findings.
The Spec review independently verified all 1,446 frozen-file hashes. Root
independently confirmed the new APK identity and compared it with fbb5: only
the Product plugin changed; the other 11 native libraries and DEX are
byte-identical. [Review metadata](../../build-output/tcp-send64-default-20261022/reviews.json)
records the scoped clearance. No additional device or performance claim follows.
