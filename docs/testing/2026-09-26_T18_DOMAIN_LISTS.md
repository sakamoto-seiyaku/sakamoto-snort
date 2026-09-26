# T18 domain-list rules: representative Product acceptance

Date: 2026-09-26. Scope: [SAKAMOTO-269](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/b0f0763a-cbb2-4e34-8668-57d9b090ad34).
Result: **PASS_WITH_EXPLICIT_LIMITS** for the implemented TLS/QUIC domain-list
rule boundary. This is not ordinary-user VPN protection or a release gate.

The Product source closure is
`277e3991d8df4ca1ac08932b0a79b1d2ead680bfcb7aead0ffbda7df409ee333`.
The Android debug APK SHA-256 is
`0089c577210de403bd5f8dc7dfcb99622c2ec06101a7e354145783a2485a3646`.
Linux and Android use generated API identity
`product_core.api/1.0.0@22e2ac3d`. The final Linux build witness is
[`build-output/t18-sol-fresh/linux-build-final/build.json`](../../build-output/t18-sol-fresh/linux-build-final/build.json);
the Pixel build witness is
[`build-output/t18-sol-fresh/pixel-build/build.json`](../../build-output/t18-sol-fresh/pixel-build/build.json).
Both witnesses retain source snapshots and installed artifact hashes.

| Boundary | Independent result | Representative checks |
| --- | --- | --- |
| Host CTest | 50/50 PASS | Domain normalization/membership, expression and complete-winner/cache comparisons, saved/active failure handling, Rust/Java/C API contracts. A later targeted Host regression confirms FTPS, STUN and DTLS labels alone cannot satisfy the whole-rule TLS/QUIC prerequisite. |
| Linux Root TLS | [PASS](../../build-output/t18-sol-fresh/linux-tls-verification-final.json), 67 packets, 8 drops | Real ClientHello, no-SNI/error availability, list-only winner change, API/source/endpoint joins. |
| Linux Root reordered TCP | [PASS](../../build-output/t18-sol-fresh/linux-tcp-verification-final.json), 137 packets | Gaps and duplicates through bounded TCP reconstruction and domain-policy compilation. |
| Linux Root QUIC | [PASS](../../build-output/t18-sol-fresh/linux-quic-runner-regression-verification.json), 781 packets, 7 drops | v1 multi-Initial assembly, exact/descendant/label-boundary names, overlapping lists, STUN coexistence, 16 publications and two list-only winner changes. |
| Linux protected snapshot | [PASS](../../build-output/t18-sol-fresh/linux-overlap-verification-final-verified.json), 500 ms held reader | A preconnected Product VAPI client published the changed list while a named QUIC packet read the old bank; the packet kept its old winner and a second publication waited until release before reusing that bank. |
| Pixel TLS Root / controlled VPN | [PASS](../../build-output/t18-sol-fresh/pixel-tls-verification-a.json), 168 / 173 packets, 14 / 12 drops | Real app TLS, names/absence, malformed/truncated unavailability, cache/query/endpoint joins and list-only winner change in each profile. |
| Pixel QUIC Root / controlled VPN | [PASS](../../build-output/t18-sol-fresh/pixel-quic-verification-a.json), 492 / 493 packets, 7 drops each | Real app QUIC v1 multi-Initial, exact/child/lookalike/A-label names, 16 publications and two list-only winner changes in each profile. |
| VPP heap Host / Pixel ARM64 | PASS | Full 256-entry domain binding, 100 build/destroy rounds, 200,000 queries, allocation failure/retry, old result and cross-heap free. Pixel test binary and library SHA-256 matched the build witness. |

The ARM64 component run is preserved in
[`run.txt`](../../build-output/t18-sol-fresh/domains-vpp-android-b/run.txt), with
[`device-hashes.txt`](../../build-output/t18-sol-fresh/domains-vpp-android-b/device-hashes.txt)
and its [build witness](../../build-output/t18-sol-fresh/domains-vpp-android-b/build.json).
It reported a 39,088-byte allocator peak for the exercised 256-entry build;
this is a component peak, not the complete VPP process peak. The Host binding
run reported the same peak. Temporary ARM64 test files were removed from the
Pixel after collection.

The first nonempty Product requests previously ended in HOLD on both Linux and
Pixel; retained raw results are under `build-output/t18-20260926/`. An empty
query/replacement had passed. Fresh reproduction showed that the VPP API
handler placed the 124,760-byte request and 126,856-byte status on its process
stack and stopped before parsing even an empty query. The handler now keeps
those objects in checked heap scratch storage. The final nonempty API and packet
runs above passed. The failed probes are retained and not counted as acceptance.

Limits: the calculated 2 MiB admission ceiling includes old/new/candidate
representations but has not been compared with full-process peak RSS. The
held-reader case uses a Product VAPI session opened before packet admission;
the changed-list publication occurred during the hold, and reuse of the old
bank completed only after its reader released it. QUIC coverage is v1 Initial SNI,
not a completed handshake. The prior T14 Pixel segmented-TLS matrix was not
rerun with domain lists; Linux reordered TCP and Pixel direct TLS cover the
representative T18 boundary. Broader cross-feature stress belongs to
[SAKAMOTO-281 / T29](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64)
and any future release gate, without changing this result into a device-wide
performance claim.

The earlier `linux-overlap-a` probe is retained as HOLD: it opened a new VAPI
connection for the changed-list request and the publication arrived after the
500 ms hold. That timing did not test concurrent publication and does not imply
a worker barrier on the rule-config handler, which is marked safe without one.
The final test preconnected the same Product transport before arming the hold;
its helper [build witness](../../build-output/t18-sol-fresh/persistent-control-build-b/build.json)
retains the helper source, native VAPI archive and exact executable hashes.
