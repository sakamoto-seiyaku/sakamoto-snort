# T29 combined Root/VPN acceptance

[SAKAMOTO-281](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64)
joins current Product configuration, Flow, CT, LPI, domain, rule, observation,
and dashboard paths. It follows the [bounded stress interface](../interfaces/T29_COMBINED_STRESS.md).
The packet target remains VPP-native C. No C++ Product
model or POC source was restored.

## Source and evidence identity

The fixed point is T28 commit `19c00f6a9438db6bd35f2f5980ffed748c9a93ed`.
The main Linux and Pixel packet runs use Product source SHA-256
`0efda6e4538b0322393b898be8dcd3c7188d582a3770a56ae55fdf40d2aebd8b`
and Pixel APK `08a5e174d69682ab55a3431c83a905c6b774e110c592d7ab3bf0be59f8dc85a4`.
A final Java-only correction made the reachable debug L4 and app-binding intents
report the service's **pre-existing early retirement** instead of claiming a
request had succeeded. It also removed unreachable later Java writer branches;
its [APK witness](../../build-output/t29-20260927/pixel-build-g/build.json)
has Product source `416331755499a6c16a75231c9089f6413ebe46155f438b4d65c79dde8be08a2e`
and APK `a004f6b2f722a3853c1b5fb43ecdbf52b5ce2708778d64126992281667619568`.
The build witness proves only `RuntimeService.java`, `DebugControlActivity.java`
and the bounded `ProtocolFactsProbe.java` diagnostic driver changed within
Product source; every native library is byte-identical to the
preceding Android build. The final-source Pixel combined run below uses this APK.
The [evidence index](../../build-output/t29-20260927/evidence-index.json) hashes
all retained T29 attempts, source snapshots, packet captures, endpoint logs,
independent verifiers, and the final readback: 16,377 files, 607,616,667 bytes,
index SHA-256 `d5abd6129dcbf9a9ce66fab97d1cc93576276a0017949e8743cddd80d46e95ac`.

## Result by boundary

| Boundary | Actual behavior and independent verdict |
| --- | --- |
| Linux VPP/NFQUEUE | [Combined verifier](../../build-output/t29-20260927/linux-combined-b-recheck.json) `VALID`: in one generation, RTP/STUN and QUIC/domain rules persisted through three publications. The endpoint completed 29 RTP exchanges and 75 QUIC echoes; one rule DROP was observed. Saved/active revisions, stable Flow identities, winners/actions, six typed rule explanations, multi-label IDs 1004/1016/1017, Rust windows and dashboard values agree with packet and endpoint records. The container used an isolated network and `NET_ADMIN`/`NET_RAW`; this is Linux Product-path evidence, not a physical Android result. |
| Physical Pixel 6a Root | [Final-source combined verifier](../../build-output/t29-20260927/pixel-combined-k-verification.json) `VALID`, generation 1752: QUIC SNI/domain and RTP/STUN Flows stayed live together through a rule update. The same QUIC Flow used the later revision while RTP was active; each retained its winner and expected action. The endpoint completed 29 RTP exchanges and 25 QUIC echoes; one rule DROP was observed. Five typed rule explanations, saved/active VPP readback, labels 1004/1016/1017, dashboard and visible UI agree. Host and device captures corroborate payloads. Device `tcpdump -i any` recorded three copies of one blocked-payload IP datagram; the independent verifier counts its IP identity once. |
| Physical Pixel 6a controlled VPN | The same final-source verifier is `VALID`, generation 1753, with overlapping Flows, 29 RTP exchanges, 25 QUIC echoes, one actual DROP and five typed rule explanations. Both profiles also rejected a third simultaneous probe with the explicit nonce-scoped capacity error and no third-source packet. Controlled HEV/TUN traffic reached the device and endpoint; `protectionRunning=false` remains correct. Ordinary VPN Start separately returned `vpn_flow_stack_not_ready`, with [UI verification](../../build-output/t29-20260927/pixel-vpn-ordinary-ui-a-verification.json) `VALID_EXPECTED_UNAVAILABLE`. |
| TLS, TCP, import, and repair | The [Pixel Root/VPN TLS/import verifier](../../build-output/t29-20260927/pixel-tls-import-a-verification.json) is `VALID`: 801/832 real packet paths, 9/7 actual drops, 48 concurrent parser attempts per profile, 92 import operations with 28 rejected inputs, save/compile failure separation and startup repair. T14 packet and T19 import oracles independently passed. [Linux current-source import verification](../../build-output/t29-20260927/linux-quic-import-current-verification.json) passed 781 packet paths, seven drops, 121 operations, 14 rejections and startup repair. These runs are separate from the RTP/QUIC combined generation; they do not prove every detector pair in one flow. |
| Observation pressure and stop | The [10k stress verifier](../../build-output/t29-20260927/pixel-stress-f-verification.json) is `VALID` for Root generation 1738 and controlled VPN generation 1739. Each sent 10,006 actual UDP requests; host captured all requests and replies, device captured all requests and 9,994/10,004 replies. Exactly 12/2 replies went missing between host egress and device ingress; kernel capture drops were zero. VPP END totals were `[10001,9989]` / `[10001,9999]`. The record channel reported 113 full events per profile without blocking packet completion, tail delivery or buffer debt. Mappings were released and ordinary history remained byte-identical. This is bounded foreground diagnostic stress, not a background-power or lossless-underlay claim. |
| Legacy writer and final cleanup | The [debug-intent run](../../build-output/t29-20260927/pixel-legacy-authoring-e/result.json) passed L4, bind and unbind retired messages while `product.properties` and ordinary history remained byte-identical. A pre-existing early service guard already rejected these actions before any Java ProductStore write; the later writer branches were dead code. The visible network toggle and complete editor use VPP rule configuration. [Final stopped readback](../../build-output/t29-20260927/device-readback-e/summary.json) passed at generation 1755: installed APK/native hashes match, no RuntimeService/VPP or owned NFQUEUE hooks, test-store selector removed, KernelSU grant intact, SQLite integrity `ok`, and all 1,575 ordinary nonmetadata rows and the predecessor JSON unchanged. |

Host CTest passed 51/51, Product Core Rust passed 73 with three ignored, and the
Android runtime contract passed. Ten semantic and cleanup evidence mutations
were rejected by the [final negative verifier](../../build-output/t29-20260927/negative-verification-final-e.json).
The debug observation driver's new loss-tolerance option is opt-in and bounded:
the prior fail-on-timeout behavior remains the default. It records payloads
unresolved at a timeout rather than treating timeout as policy DROP. The
[final-source representative run](../../build-output/t29-20260927/pixel-stress-representative-g/result.json)
also completed 100 controlled flood requests per profile, with `[101,101]`
Flow packet totals and normal stop; the 10k/full-channel claim remains bound
to the earlier source and its separate independent verifier.

## Coverage and retained failures

R1/R2/R3/R4 each had their own prior Linux and representative Android
acceptance before T29. This run adds the RTP (R4) and QUIC/domain multi-label
combination with CT, Flow, rule publication and dashboard windows in both Pixel
profiles. The TLS/import matrix supplies a separate Root/VPN parser and repair
combination. It does not exercise every R2/R3 detector simultaneously with RTP
or QUIC, every rule syntax, every possible old-reader timing, or a full release
VPN protection session. The Host 51-test gate covers semantic and lifecycle
regressions; the live runs above bound the device claims. No 180-day retention,
battery, throughput SLO or general underlay delivery rate is inferred.

Earlier attempts remain in the index: Pixel combined `a` held on a missing VPN
underlay reply; later `b` and `c` passed before the Java fix. Stress `a` held on
an underlay reply, `b` hit a 100-second harness deadline, and `c`–`e` exposed
Android's cached-process freezer when the headless Activity finished. The final
driver keeps the interactive Activity top-resumed with a temporary screen-timeout
extension, restores the prior setting and passes both profiles. Final-source
combined attempts `d`–`f` held on, respectively, the wrong Python environment,
a copied fixture without its certificate, and a reused device nonce. Fresh
fixtures and the correct interpreter passed in `g`; `h` exposed duplicate
device capture frames with one IP identity and passed after the independent
verifier accounted for them. An attempted overlap in `i` found the diagnostic
driver's one-probe gate; the new two-probe bound and real overlapping traffic
passed in `j` and the final-source capacity-checked `k`. The first final UI
probe `c` raced an
asynchronous, unrelated profile-selection persistence write; waiting for a
stable baseline passed in `d`. These are retained and are not counted as
product packet failures. The final UI/readback checks follow the last combined
run; ordinary SQLite/JSON hashes match the T28 baseline.
An earlier negative-test invocation paired the old stress run with the newer
Pixel build, so its stress rejections were only source-identity failures. The
final negative suite requires the correct stress build and first passes each
copied, unmodified baseline before applying a mutation; only that suite's ten
rejections count above.
The [independent Standards and Spec review](2026-09-27_T29_COMBINED_REVIEW.md)
records the closed cleanup, overlap and explanation findings.
