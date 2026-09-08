# SAKAMOTO-228 — IPv6 native reassembly

PASS, 2026-09-08. Pixel exercises explicitly GRAPH_INJECTED original buffers;
Linux exercises real IPv6 NFQUEUE originals at INPUT and raw LOCAL_OUT, as
established by S231. No Pixel per-fragment NFQUEUE verdict is claimed.

## Results

| Current-source evidence | Result |
| --- | --- |
| Pixel IPv6 main, generation 904 | 32 originals: both orders, all memory/final-owner pairs, six-original bundle, duplicate, atomic fragment, timeout, capacity, malformed length and Stop |
| Pixel IPv6 errors, generation 903 | 17 originals: conflict, valid one-byte tail, oversized output and actual typed-policy DROP |
| Linux IPv6 INPUT, generation 22810 | 64 actual NFQUEUE originals, including atomic, one-byte tail, duplicate/conflict, timeout, 33-original capacity and native Stop |
| Linux IPv6 raw OUTPUT, generation 22811 | 66 actual NFQUEUE originals, including actual policy DROP and resource NF_ACCEPT |
| IPv4 reassembly regressions | Linux 65 actual NFQUEUE originals; Pixel 31 graph originals, generation 905 |
| Ordinary dual-stack Root regressions | Linux 64 packets / 48 endpoint cases; Pixel 69 packets / 50 cases, generation 906 |

Every applicable original generation, packet ID, buffer index and origin lane
is checked against exactly one completion and physical return. Successful
reassembly reaches the shared parser, complete OwnerAssignment, policy and
terminal once. The Pixel oracle independently reconstructs payloads, checks
IPv6/UDP lengths and checksum, and requires actual IPv6 native node traces.
Memory owner is witnessed at native consume/preparation, before any native
sendout handoff; final owner is independently witnessed at policy/terminal.
All (0,0), (0,1), (1,0), (1,1) pairs occur. Existing IPv4 evidence also retains
that coverage under the corrected witness selection.

Linux original netlink packet bytes match the registered fragments. INPUT
PCAP is an ingress observation and includes packets later dropped; OUTPUT
peer-link bytes contain exactly the accepted pre-Stop fragments, with DROP
cases absent. Capture direction/address filtering excludes echo responses.
The later capacity/Stop cases are checked through actual verdict, reference,
FD/queue and completion ledgers. No remote application's fragmented delivery
claim is inferred solely from NF_ACCEPT.

All native contexts, retained references, originals, frames, buffers and
obligations are zero at acceptance boundaries. Linux queues rebind after
close and processes exit. Pixel is stopped after generation 906, echo helpers
are terminated and Wi-Fi restored. No readiness or performance qualification
is added.

## Implementation

The pinned `ip6-full-reassembly-custom` node owns context/range identity and
internal handoff. Product reuses S212's 56-byte original envelope, intrusive
bounded bundle, reference pins and 32-byte Completion Frame. It adds no
fragment table, pre-steer, corrective dispatch, final-owner queue, completion
buffer allocation, C++ fallback or POC source import.

The shared continuations are now `product-reassembly-success/error`. An inline
family flag selects the existing IPv4 behavior or native IPv6 header handling.
The native bounded extension-header walker identifies the IPv6 fragment header;
first-buffer capacity is checked before pinning. Offset-zero platform facts
are restored before the shared parser and the existing local/unique Primary
Handoff path. IPv6 atomic fragments pass through the same native lifetime.

The fifth common-core patch closes IPv6 custom malformed and handoff rejection
exits, retires a retained duplicate's native engine reference immediately,
and exposes scoped count/flush under native locks. A one-byte inclusive range
is valid. Error reasons map to the shared terminal dispositions. Root resource
exits preserve original NFQUEUE capability and issue NF_ACCEPT; injected graph
origins instead get runtime NO_RETURN. Policy DROP remains DROP.

Both families use the existing 32-original bound, 64 contexts per thread,
500 ms timeout and 50 ms walk interval by default. Diagnostic timeout/context
changes require an empty active graph. Basic native quiesce/flush/drain is
included; broad S229/S242 fault/supervisor/abnormal reclamation qualification,
S219 metadata conflict coverage and production capacity sizing remain separate.

## Artifact and evidence identities

- Build base commit `23f7e65126b7a797e5df1e510f98849c2e7d6074`; completed-task Git cleanup preceded this build.
- Exact Product source SHA-256 `92de793f76defce5c6b4ee91fbb87086f6338c0f3ad96f10118681fb6991b6a2` on both platforms.
- Dirty diff SHA-256 `51369a31246d8d9344b9d2607c253b835944e3800956d58a1a3b835db9f13677`.
- Pinned VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`.
- Common core: five patches, `4e6569b35c7b58246448f5260735bf766830483f9323fbb62fde3d4151e46247`.
- Android profile: 18 patches, `2f2b87b011cc131cada294ae31e6ebfb618ccdf3f303b303ff4b7f00b562af74`.
- Artifact identity `sakamoto-product-vpp-s228-v1`.
- Installed APK SHA-256 `16a50770b76c087006f092bcb732b393f8e9ed41b0de1bdae901323e5034e133`.
- Android plugin SHA-256 `8e2107c853584c320db84bf64ed27e8d9230f9117485270ed04bbe2d2a5669ec`.
- Android libvnet SHA-256 `68861429250407943e74dc903531ae4aca3296fecddec224a025be9b5b475d69`.
- Pixel 6a / bluejay, serial `28201JEGR0XPAJ`, Android 16, kernel `6.1.134-android14-11-g66e758f7d0c0-ab13748739`.
- Evidence index SHA-256 `a71f179181aa52fef6a12d61059cc3abe4e78fcb90329a2234b83c96bba5a464`.

Full builds: `build-output/s228-reassembly/pixel-build-b/build.json` and
`linux-build-a/build.json`. Final raw runs: `p-m-b`, `p-e-b`, `l-a`, `r4-p`,
`r4-l`, `b-p2`, `b-l`, each with PASS verification. `records.json` hashes raw
files and copied collector/verifier inputs in `evidence-tools/`. Linux policy
rules use kernel UID 1000 observed in the mapped endpoint, not namespace UID 0.
Root per-packet facts remain the unchanged S217 implementation.

Core application, Android profile, Host stage and packet semantic checks pass.
Six evidence mutations are rejected: missing origin, duplicate completion,
wrong origin, lost pin, wrong IP family and fabricated NFQUEUE identity.
The collectors gained explicit policy-helper locations for current artifacts;
relative Pixel helper paths are resolved before the repo ADB wrapper.

## Retained checkpoints

The earlier 62%/60% quota checkpoints were paused without S228 acceptance;
the user subsequently removed the current quota limit. Host compilation resumed
from its owned candidate and completed an actual new five-patch build. Only
external-dependency cache was reused, not a prior VPP runtime. The first Pixel
main run before Git cleanup is retained as exploratory evidence; the accepted
runs above use the post-cleanup build. An ordinary Pixel regression failed
before runtime start because a relative helper path was passed to Windows ADB;
the absolute-path correction and final rerun pass. None of those incomplete
checkpoints is used as current acceptance.
