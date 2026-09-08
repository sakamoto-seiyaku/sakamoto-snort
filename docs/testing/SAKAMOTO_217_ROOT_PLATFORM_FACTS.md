# SAKAMOTO-217 — Root per-packet platform facts

PASS, 2026-09-08. Real NFQUEUE netlink attributes now determine UID evidence,
hook direction and Linux interface facts. Configured subject UID, queue,
lane and profile do not manufacture packet identity or interface metadata.

## Implementation

The queue configuration explicitly requests `NFQA_CFG_F_UID_GID` with the
corresponding mask. Previously it did not request these attributes and filled
missing OUTPUT UID from the configured owner. That fallback is removed.
Present UID=0 remains known; absent UID remains unavailable. The configured
owner comparison that bypassed a captured packet is also removed: capture
scope belongs to the supervisor's kernel rules, while the shared graph
matches the actual packet facts.

`LOCAL_IN` selects only `NFQA_IFINDEX_INDEV`; `LOCAL_OUT` selects only
`NFQA_IFINDEX_OUTDEV`. An absent, zero or out-of-positive-int-range Linux
ifindex is unavailable. The opposite-hook attribute is not substituted.
Unknown hook produces unknown direction and interface. Availability remains
explicit, including the distinction between valid UID zero and missing UID.

Network Context stays unknown until S232/S235 provide the platform snapshots.
No queue/interface/default-network inference, per-packet RPC, kernel probe or
new metadata service is added. A context-specific rule does not match unknown;
other evaluable rules and normal default pass continue. Packet provenance is
`ROOT_NFQUEUE` (value 1), so VPN provenance is not applicable; no packet is
labelled `VPN_TUN` or `FLOW_STACK_RETURN`.

A bounded diagnostic trace records the original netlink bytes, decoded raw
attributes, the explicit attribute-fault mode and normalized facts. The
independent verifier decodes the raw TLVs itself. Fault modes affect only
parsed attribute evidence, preserve real bytes/completion IDs, require an
active empty graph under the CLI worker barrier and reset to off on each
Adapter generation. They cover missing/zero UID, missing/zero interface,
opposite interface and unknown hook. They are explicitly labelled controlled
evidence, not claims that the kernel emitted those modified attributes.

## Current-artifact acceptance

| Evidence | Result |
| --- | --- |
| Linux isolated real endpoint | 64 NFQUEUE packets, 48 endpoint cases, IPv4/IPv6 INPUT/OUTPUT |
| Pixel 6a | 68 NFQUEUE packets, 50 endpoint cases, generation 900, IPv4/IPv6 INPUT/OUTPUT |
| Linux reassembly regression | 65 real original fragments; success, duplicates/conflicts, one-byte tail, capacity fail-open, DROP, timeout and Stop |
| Pixel reassembly regression | 31 original graph buffers, generation 901, native cross-owner/order/bundle/error/Stop matrix |

The attribute matrices include ordinary UDP/TCP traffic, UID/interface rule
match and no-match, missing attributes, known zero UID, wrong-side interface,
unknown hook, unknown network context and recovery. Real typed Gate rules
exercise UID, interface and network predicates; typed L4 rules exercise
direction. Every packet's raw netlink attributes, normalized facts, shared
PacketFacts, actual matcher disposition, original lane/packet ID verdict and
physical buffer return agree. All 132 attribute-matrix packets complete once.

Linux demonstrates the namespace distinction directly: the process is UID 0
inside the rootless test user namespace, but the actual NFQUEUE UID is 1000.
The adapter preserves 1000, and the test policies target the observed value.
The test does not claim an actual Linux NFQUEUE UID=0 packet. Pixel's natural
root-process cases independently produce NFQUEUE UID=0 without attribute
faults, and explicit UID=0 policy rules DROP those packets. Pixel's ordinary
app packets report UID 12632. Missing attributes remain unknown on both
platforms; fault cases declare every effective-field modification.

The final native completion/frame/buffer/obligation counters and reassembly
contexts/retained references are zero. Linux queue rebinding/process exit and
Pixel Root cleanup pass. Pixel is stopped after generation 901; test echo
processes are terminated and Wi-Fi restored. No ingress readiness or network
classification readiness is added.

## Source and artifact closure

- Base commit `9c67175713baceb46cef015f3464893fa3d69950`, with the working-tree implementation retained.
- Product source SHA-256 `6be7752b305f5305fc4e6739c3a6794fb84ef1605e5d028e90078a526a81c146` on both platforms.
- Pixel dirty diff SHA-256 `8334ac74f8de248d1ec72aa2e38b0df6677aae27e6d54397874dec4b4814b63d`.
- Artifact identity `sakamoto-product-vpp-s217-v1`.
- Pinned VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`; S212's four-patch common core and 18-patch Android profile are unchanged.
- Installed APK SHA-256 `4446ee6be392da03594d997a39f59b43577964352bc0dbe2df59a6081c4ef97c`.
- Android Product plugin SHA-256 `6ae3c92708a6c6292f2ca48e6fb791bb4850f27e6ffe26cf72e34bd651a5c7c7`.
- Pixel serial `28201JEGR0XPAJ`, bluejay / Android 16 / kernel `6.1.134-android14-11-g66e758f7d0c0-ab13748739`.
- Linux artifact `/home/js/Git/sakamoto/sakamoto-snort/build-output/product-vpp-host-s217-d`, native Product graph with HostEvidence OFF.
- Evidence index SHA-256 `ee85bc1ba96354e66584bea45b973c945ab0fcd49427f01540ae836f1c032603`.

Full source snapshots, native/runtime hashes and actual build witnesses are in
`build-output/s217-facts/pixel-build-d/build.json` and `linux-build-d/build.json`.
Accepted raw runs are `pixel-d`, `linux-d`, `r-pixel-d` and `r-linux-d`, each
with PASS verification. `records.json`, `helpers-build.json` and
`evidence-tools/` preserve the raw-file hashes, policy helper and exact
collector/verifier inputs. The Linux reassembly policy wrapper uses UID 1000
observed from the real S217 netlink matrix; it changes rule configuration,
never packet identity.

Five final-source negative evidence mutations are rejected: invented UID,
queue substituted as interface, invented network context, VPN provenance on
a Root packet, and missing physical return. Packet semantic checks and diff
whitespace checks also pass. No C++/POC implementation or removed VPN adapter
was reintroduced.

## Retained failed candidates and limits

Early Linux evidence exposed the configured-UID comparison bypassing packets
whose real kernel UID differed across the user namespace. The adapter fix is
verified by raw UID 1000 reaching the actual policy matcher. Early Pixel
collection correctly rejected an invalid Gate-direction test rule; the
fixture now uses the valid typed L4 direction rule. A later collector hit a
transient busy-graph rejection after TCP teardown; it now waits boundedly and
retries the diagnostic command, without changing Product ownership. A long
Linux collector directory exceeded Unix socket path length; the final run
uses a shorter path. Those incomplete runs are retained without PASS claims.

S217 does not implement network snapshots, VPN TUN facts, reassembly metadata
conflict matrices, or general netlink-fuzz/performance qualification. Existing
S219/S232/S235/S242 tasks retain those scopes. The actual-source regressions
above preserve S212's applicable IPv4 native ownership guarantees.
