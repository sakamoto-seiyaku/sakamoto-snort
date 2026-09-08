# SAKAMOTO-212 — IPv4 native reassembly

PASS, 2026-09-08. Pixel proves actual native graph reassembly with explicitly
labelled test obligations. The isolated Linux namespace proves real raw
LOCAL_OUT NFQUEUE fragments, including each original verdict and physical
buffer return. These claims follow the S231 measured entry split; no Pixel
per-fragment NFQUEUE capability is claimed.

## Result

| Current-artifact evidence | Result |
| --- | --- |
| Pixel main matrix, generation 891 | 31 original graph buffers; eight order/memory-owner/final-owner combinations, six-original bundle, duplicate, timeout, capacity, malformed length and native Stop |
| Pixel error matrix, generation 890 | 17 original graph buffers; conflict, legal one-byte final fragment, oversized output and actual typed-policy DROP |
| Linux raw IPv4 OUTPUT, generation 21210 | 65 original NFQUEUE packets; success/reverse order, six-original bundle, one-byte final, duplicate, conflict, timeout, oversized output, 33-original capacity, policy DROP and capacity/Stop |
| Linux ordinary NFQUEUE regression | 476 packets across 32 processes, IPv4/IPv6 TCP/UDP, all lane/owner combinations with allow/drop |
| Pixel ordinary NFQUEUE regression | 149 packets, generations 892–895; IPv4/IPv6 INPUT/OUTPUT visibility, ordinary TCP/UDP allow/drop/recovery and full cleanup |

All original-buffer ledgers are exactly once. Each successful datagram reaches
the shared parser, complete OwnerAssignment, policy and terminal once. The
Pixel oracle independently reconstructs the reassembled payload and checks
minimum platform facts. Native runtime vectors and fragment traces prove the
custom reassembly nodes and native internal handoff. Memory-owner/final-owner
pairs cover (0,0), (0,1), (1,0), (1,1).

On Linux, every original generation, token, packet ID, buffer index and origin
lane/thread is bound to a single real verdict and physical return. The
independent peer-link PCAP contains exactly the 57 accepted fragment bytes
from the recorded pre-Stop cases; the corresponding DROP cases do not escape.
The capacity/Stop cases run after that capture and are separately checked by
the actual NFQUEUE completion, descriptor and debt ledgers. The fragment
fixture does not claim a remote application's reassembled UDP delivery.

Every accepted run ends with zero native contexts, retained references,
originals, completion frames, buffers and obligations. Normal native drain
keeps origin descriptors open; final queue rebinding and process/temporary
network cleanup pass. Pixel is stopped after generation 895 with Wi-Fi restored.

## Product change

The pinned `ip4-full-reassembly-custom` node remains the only fragment context
and range lookup. Product adds success/error continuations and a 56-byte
inline original-fragment envelope. Intrusive links in the original buffers
carry a bounded obligation bundle; there is no second fragment table,
fragment pre-steer, corrective dispatch, or separately allocated completion
buffer. Non-survivor originals are pinned before native consume/free. Native
linearization retains a single-reference offset-zero survivor; absorbed
originals retain exactly the reference needed for their eventual origin
completion. Each origin receives its original physical buffer.

The success continuation restores offset-zero platform facts, then enters the
shared parser for the first complete assignment and the existing local/unique
Primary Handoff path. The normal opaque2 layout remains 56 bytes by removing
the redundant owner-generation copy; generation still comes from the original
AdapterObligation. Completion frames remain 32 bytes. Main-thread expiry and
flush can use the same retained return path back to each original worker.

Initial implementation parameters are 32 originals per bundle, 64 native
contexts per thread, 500 ms timeout and 50 ms expiry walk interval. Diagnostic
controls change timeout/context limits only on an active empty graph. The
complete output must fit the existing contiguous parser's first buffer before
native finalization. Capacity exits remain safe; these limits are not
production sizing or throughput qualification.

The common core fourth patch closes custom malformed and handoff rejection
exits, retires the native engine reference immediately after a retained exact
duplicate, and exposes scoped custom count/flush operations under native pool
locks. Three inclusive-range checks now accept a legal one-byte final range;
that case was previously misclassified as internal error and is directly
regression-tested on Pixel and Linux.

Resource exhaustion follows the existing S229 decision: Root originals still
held by NFQUEUE receive ProcessingCapacityBypass / NF_ACCEPT on their original
lane. Injected graph obligations have no such return capability and receive
runtime NO_RETURN. Conflicts, malformed input, timeout and Stop are runtime
dispositions. An explicit policy DROP remains DROP for every original.

Basic native quiesce/flush/drain is closed here. S229/S242 retain the broader
normal supervisor Stop, abnormal process/OS reclamation and fault matrices;
this report does not claim those future acceptance scopes. IPv6 reassembly,
full metadata-conflict coverage, alternate ingress adapters and reassembly
performance qualification also remain outside S212. No ingress readiness,
C++ fallback or POC source import was added.

## Reproducible identities

- Product base commit: `9c67175713baceb46cef015f3464893fa3d69950` (working tree; no new commit made).
- Exact Product source SHA-256: `a1a61d4c231ec8820bc1cad18186b6351ce9c9f4fafcb7eb90c55fae36677fff` on both platforms.
- Pixel source diff SHA-256: `755cef57be850b786dedad3d1bcd6c57f3cab5d39b62bd69d7f01142d7d3425f`.
- Pinned VPP: `9258530f3804a152578ce11cc7c8a1e9eab88ed0`.
- Common core: four patches, `23ae97add09b2c2288046a065f7d1422dd6699c60d3abc60170dacc6cfd47b59`.
- Android profile: 18 patches, `2f2b87b011cc131cada294ae31e6ebfb618ccdf3f303b303ff4b7f00b562af74`.
- Artifact identity: `sakamoto-product-vpp-s212-v2`.
- Pixel 6a / bluejay, serial `28201JEGR0XPAJ`, Android 16, kernel `6.1.134-android14-11-g66e758f7d0c0-ab13748739`, API 31 / arm64-v8a build.
- Installed APK SHA-256: `31b02491c77c46a7bb983eb992b982272f9ac5cedcac38695ce567bfbca409d0`.
- Android `libvnet.so`: `ab92056129b6d7f63a9bd7601da060922ba09ea3d2132442140217664e95c49d`.
- Android Product plugin: `011c44577efb0987cc8991951f950a57e6dbc7d9d9db453f338a29f12ecab902`.
- Final Linux artifact: `/home/js/Git/sakamoto/sakamoto-snort/build-output/product-vpp-host-s212-b`; build mode `SAKAMOTO_PRODUCT_HOST_EVIDENCE=OFF`.
- Final evidence index SHA-256: `7b7dc7dfbbff0504510467e13b612c1d13227188a828c7a24f55b9230b241fb1`.

Full native/library/source/build identities are retained in
`build-output/s212-reassembly/pixel-build-d/build.json` and
`linux-build-b/build.json`. The final run directories are `pixel-e`,
`pixel-errors-b`, `linux-a`, `linux-baseline` and `pixel-baseline`, each with a
PASS verifier report. `records.json` hashes their raw files and the copied
verifier/collector sources under `evidence-tools/`.

## Validation and retained failures

Core patch application, Android profile composition, Host stage contract and
pure packet-kernel semantic checks pass. Six semantic evidence mutations are
rejected: missing physical-origin witness, duplicate completion, wrong origin,
lost pin, fabricated NFQUEUE identity and changed platform facts. Verifiers
also enforce debt, exact payload, first assignment, real verdict and peer-link
byte consistency.

Early candidates are retained without PASS claims: the first Pixel timeout
script used an insufficient fixed delay, one run encountered a transient WSL
ADB transport failure, and the pre-fix artifact exposed the one-byte range
bug. The explicit DROP test was corrected to publish a real typed DROP rule,
since the existing default-pass policy correctly allows an unmatched UID.

Linux's first dependency check lacked optional development packages; the
build resumed using an existing local external-dependency cache with a fresh
CMake build. An intermediate incremental candidate then exposed VPP's outer
package timestamp skipping an older copied source timestamp. That candidate
(`linux-build-a`) is explicitly INVALID/HOLD. The final build forces actual
source recompilation, records all four `ip4_full_reass.c` object builds and
has a changed libvnet runtime hash; the live one-byte test confirms the fix.
No prior accepted S193/S231 artifact was modified. All final raw traces and
binaries belong to `linux-build-b` / `pixel-build-d`.

The old external-ownership script still refers to the VPN adapter removed
before S212 and fails at that missing file; it was not treated as current
acceptance and the adapter was not recreated. The S230 regression verifier now
uses the already established S207 typed canonical-key oracle; its other
wire, completion, policy and cleanup checks are retained.
