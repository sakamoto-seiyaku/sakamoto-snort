# SAKAMOTO-232 — Android network snapshots in Root packet facts

PASS, 2026-09-08.

Android network callbacks now publish a bounded per-interface NetworkContext
snapshot through the existing Product Core session and generated VAPI. Root
packets look up their actual normalized Linux ifindex. Missing interface or
classification facts remain unknown. S217 had already removed the former
fixed Wi-Fi value; this task supplies the real event source.

## Accepted artifacts

Both final builds have source SHA-256
`74bdf9f5a0e4858d3b47bc1a4395ee2ea7ea6e1d654356f3d812750a88d732ad`.
Their build base is `a43e64eb2725ca620fbaf1c0faa277a6b983ed52`, with dirty-diff
SHA-256 `fd27c9d5746714aae3a1b8b54940cb97e556ebb0cc75a4771f30cd8c526e5d62`.
Each build preserves the complete per-file source snapshot, including new files.
The task is committed separately after acceptance; historical build identities
are retained as recorded.

- Android: `build-output/s232-network/pixel-build-e/build.json`.
- Linux: `build-output/s232-network/linux-build-b/build.json`, artifact
  `build-output/product-vpp-host-s232-b`.
- Product identity: `sakamoto-product-vpp-s232-v1`;
  generated API identity: `product_core.api/1.0.0@2e53fed5`.
- APK SHA-256:
  `70f65ddce18b9db4b6f3f8e4cb074c546823e615ec46122c5ff77178210f2faf`.

| Android native file | SHA-256 |
| --- | --- |
| `libvpp_runtime.so` | `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08` |
| `libproduct_core_plugin.so` | `26764d934867995a18e2148ab23e4b648dc3ef8d8232897b25a73e4372a75afd` |
| `libsakamoto_product_core.so` | `51eae3f6ba2716b022d5b1833eec425ece2f062d285d7471c4d23e9878365bbd` |
| `libsakamoto_runtime_control.so` | `3c93ee6c3e6b3322f636b388a0ee93747b289cf1d91ac7fe05864512dca28d49` |

All native dependencies and Linux artifact files are hashed in the build
manifests. Pixel installation checks match the APK and extracted native bytes.
The pinned VPP revision and five accepted core patches remain the S228 baseline;
the Product plugin, control library, JNI and APK were rebuilt for this task.

## Platform and actual packet evidence

Pixel `28201JEGR0XPAJ`, app UID `12632`, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`, ran the actual Root NFQUEUE graph.
Android reported Wi-Fi on `wlan0`, Linux ifindex `47`. An independent LAN echo
endpoint used `192.168.4.5` and `fd76:d462:c4e3:0:49f3:929a:a311:d6e7`.
Every main-matrix packet was captured from the real kernel queue; no graph
injector or fabricated NFQUEUE identity was used.

| Accepted run | Generation | Real NFQUEUE packets | Endpoint cases | Result |
| --- | --- | ---: | ---: | --- |
| `pixel-b` | 910 | 40 | 40 | Wi-Fi events, unknown, restore, actual matcher |
| `pixel-regression-b` | 913 | 69 | 50 | Ordinary dual-stack TCP/UDP facts and attribute faults |
| `linux-regression-b` | 21710 | 64 | 48 | Real Linux namespace NFQUEUE regression |

The 173 packets have independently checked original attributes, verdicts and
physical returns. The main matrix covers IPv4/IPv6 INPUT and OUTPUT before and
after an actual Wi-Fi disable/enable cycle. Each row includes an open baseline,
a Wi-Fi-specific rule, a controlled missing snapshot, restoration, and an open
recovery. The kernel supplied UID `12632` on both hooks in this LAN test:
**16 policy DROPs and 24 ACCEPTs** agree with independent socket outcomes.
Thirty-two packets have Wi-Fi context and eight have explicit unknown context.
The Linux regression runs on x86-64 kernel
`6.6.114.1-microsoft-standard-WSL2` in a disposable user/network namespace,
using the actual kernel NFQUEUE API.

The 27 native snapshot publications recorded before stop bind Android callback
elapsed timestamps to their revisions. The real lost event publishes an empty
map; reconnection supplies a new map. Controlled missing tests suppress the
published map without inventing platform facts. Network capabilities and link
properties come from their callback payloads, following the
[Android NetworkCallback contract](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback).

The independent verifier decodes raw netlink TLVs, projects the actual hook's
ifindex through the corresponding Android event map, and compares both admit
and policy facts. It recomputes the canonical key/hash/owner from raw packet
bytes using the independent S207 oracle. Policy executes on `owner + 1`, with
17 local and 23 remote completions in the main run. Every verdict returns to its
original lane/thread and every buffer is freed once. Network context never
enters that key or owner computation.

## Publication lifetime and failure handling

The control snapshot is 280 bytes with at most 32 interface/category entries.
The VAPI handler rejects stale generations/revisions, invalid counts, duplicate
interfaces and invalid categories. It replaces the map on the control thread
under the VLIB worker barrier. Workers read stable values and copy facts into
the existing packet metadata; they perform no platform RPC, allocation or
snapshot-lock acquisition. Publication does not mutate FlowEntry state.

The generation owns the Android callback and its handler thread. Stop
unregisters the callback, publishes unknown while the session is available,
quits and joins the handler thread, then follows existing Product Core cleanup.
The normal main run records `subscription_stopped thread_alive=false`, a
successful empty publication, zero pending buffers/frames/obligations, zero
reassembly contexts/originals/retained references, and successful hook/process
cleanup.

`pixel-failure` additionally tests an actual publication rejection on the final
APK. A clearly identified control helper publishes revision 100000; the next
Android publication is rejected as stale. Generation **911** reaches
`platform_network_publish_failed` with `mayBeActive=false`, clean Root residue,
no VPP process, and a stopped callback thread. Its final empty publication is
also rejected by the intentionally advanced revision; process cleanup removes
the old map, rather than claiming that rejected publication succeeded.
Generation **912** then starts at revision 1 with an empty map, receives real
Wi-Fi facts, and stops cleanly. This is controlled failure evidence, not a
platform event provider.

## Verification and retained records

- Rust Product Core library tests: 18 passed.
- S192 Java/policy-bundle contract: passed with the generated API fingerprint.
- Main network verifier, Pixel ordinary verifier and Linux ordinary verifier:
  passed on the final source/artifacts.
- Seven evidence mutations are rejected: wrong platform category, missing
  publication acknowledgement, wrong generation, duplicate verdict, wrong
  packet context, missing callback stop, and wrong canonical owner.
- `git diff --check` passes.

Raw runs, artifact manifests, helper hashes and the exact evidence-tool sources
are indexed in `build-output/s232-network/records.json`, SHA-256
`71e758b05dbb076c215214783dd9be5fa2a5cbb7d2685a7096dd1750630d4d40`.
`evidence-tools/` preserves the collectors, independent verifiers, owner oracle
and helper sources. The final negative record is
`negative-verification-final.json`.

The first build stopped at the API fingerprint check after adding the typed
message; the recorded generated fingerprint was then updated. Earlier
exploratory APKs and positive runs predate the final publication-failure guard
and are excluded from the accepted totals above.

## Scope limits

Only Wi-Fi was actually available on this Pixel; mobile interfaces were down.
Mobile, Wired and VPN classifications are not claimed as real-platform
acceptance. Linux supplies a real ordinary NFQUEUE regression here; its own
platform network classification remains S235. VPN facts, fragment-first-facts
restoration and broader teardown matrices remain the separate S218/S219/S229
contracts. This task does not publish broader readiness, latency or power claims.

Pixel is stopped after generation 913 with Wi-Fi restored. The independent LAN
echo process and disposable Linux namespace resources are closed.
