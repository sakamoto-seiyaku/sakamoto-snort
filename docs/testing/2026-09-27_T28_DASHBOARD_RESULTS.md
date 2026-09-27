# T28 live Flow and health query acceptance

[SAKAMOTO-280](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/874b8da6-ef08-4f8c-9dfc-8e96b1a6b4f2)
adds a bounded live Flow query and one diagnostic health view to the existing
VPP-native C, Rust and Android Product path. The [interface](../interfaces/T28_DASHBOARD_QUERY.md)
defines which component owns each field, the 16-entry/256-slot page bound,
generation and cursor errors, and decimal-string 64-bit identities. The
Activity's Query health and Next flows buttons render the typed response;
they do not infer state from logs.

## Source and evidence

Base commit: `37c84bd5f38ecb30b8b3bffd7ba37ac36f300b09` (T27). The final
Host and Android source witnesses are
`build-output/t28-20260927/linux-build-final4b/build.json` and
`pixel-build-final4/build.json`; both have Product source SHA-256
`9ae7b9329d98fbfc4bbcc7429dcd528fa438f5eaaec90fc398f123fbfb51045b`.
The installed APK SHA-256 is
`d41275b8c7e5b84ad8316ddb6d13fba64acd77d82f1afdf2efabc345d0093f32`.
Raw runs, screenshots, UIAutomator XML, typed replies, build inputs and
retained failed attempts are under `build-output/t28-20260927/`.
The [combined final verifier](../../build-output/t28-20260927/final-verification.json)
is `VALID`: it rehashes both frozen Product source copies and the Host/APK
artifacts, joins all seven acceptance verifiers, checks the stopped-device
readback, and confirms all 34 unrelated dirty files against the captured
entry baseline. The [evidence index](../../build-output/t28-20260927/evidence-index.json)
rehashes 22,312 retained files with zero mismatches; its SHA-256 is
`ca8f90a4f2d4cc1069a5921d61e5d22922b2d0e54b118c084d2d8714697c2064`.

## Result

| Path | Real packet oracle | Query result |
| --- | ---: | --- |
| Isolated Linux Root baseline | 12 paths, two policy drops, 11 semantic mutations rejected | A live owner Flow was returned with current directional policy attribution. With export channels full `[188,0,188,0]`, the control query stayed fresh and returned a bounded page. A deliberately failed store open reported a Rust error while VPP remained healthy. |
| R1 protocol integration | 176 paths, five drops | Four exercised protocol IDs 1002/1003/1004/1006 and a packet-budget-stopped HTTP Flow verified against the live typed page. |
| R2 protocol integration | 442 paths, 24 drops | Exercised IDs 1003/1007–1010 and a stopped SMTP Flow verified. |
| R3 protocol integration | 433 paths, 23 drops | Exercised IDs 1011–1015 and a stopped OpenVPN Flow verified. |
| R4 protocol integration | 560 paths, 24 drops | Exercised IDs 1016–1020 and a stopped STUN Flow verified, including SNI packet-budget stop. |
| Physical Pixel 6a Root | Five allowed endpoint exchanges and two actual policy drops | UI Start, Query health, Next flows and Stop taps; five generations, a live owner-1/slot-0 Flow, exact 64-bit directional winners and named LPI/SNI stop states in UI XML. |
| Physical Pixel 6a controlled VPN | Five allowed endpoint exchanges and two actual policy drops | Debug HEV Start, UI Query health, Next flows and Stop; five generations, a live owner-1/slot-0 Flow and exact directional winners. This controlled path reports `protectionRunning=false`. |

The Linux run uses real NFQUEUE packet capture and a saved Rust SQLite store.
The independent baseline verifier is
[`linux-dashboard-final4b-verification.json`](../../build-output/t28-20260927/linux-dashboard-final4b-verification.json)
(`VALID`); the R1–R4 final4 verification files in the same evidence directory
are also `VALID`. Each R-tier verifier checks the real packet oracle,
generation, labels, availability, resources, pagination limits and a specific
stopped Flow. The Pixel
[`pixel-dashboard-final4-verification.json`](../../build-output/t28-20260927/pixel-dashboard-final4-verification.json)
is `VALID` for both profiles, independently checking wire capture, endpoint
echoes, dropped payload exclusion, selected rule counts, raw typed replies,
screen XML and 64-bit winner text. Both profiles used an isolated scaled
retention store; the final evicted packet counters were `[7,5]` and each
deliberate restart left a conservative coverage gap, four total. These short
device runs are not a 180-day retention or power test.

The T28 ticket expressly requires ADB/UIAutomator Start, Query and Stop and
requires an unstarted protection path to show failure rather than successful
empty data. The normal VPN diagnostic UI Start was tapped, followed by UI
Query and Stop. The existing
[Product adapter contract](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPacketAdapterContract.java)
sets VPN product launch unavailable and explicitly refused ordinary protection
with `vpn_flow_stack_not_ready`, `adapter=unavailable` and
`protectionRunning=false`. The Activity showed `Health query error:
management_unavailable`; the same typed response retained the RuntimeService
error code and stopped state, rather than presenting an empty successful Flow
page. This is the [current product readiness boundary](../current/README.md)
and [VPN release gate](../product/ANDROID_L4_RELEASE_GATE.md), not evidence of
ordinary-user VPN protection. The controlled HEV run above supplies the
separate available VPN packet-path/query evidence. The normal UI attempt and
its raw response are retained in `pixel-vpn-ui-final4c/`; its
[independent verifier](../../build-output/t28-20260927/pixel-vpn-ui-final4c-verification.json)
reports `VALID_EXPECTED_UNAVAILABLE`. The separate Spec reviewer confirmed
that these two branches satisfy T28's diagnostic acceptance without changing
the VPN launch boundary.

The [final stopped-device readback](../../build-output/t28-20260927/device-final4c-readback/summary.json)
is `PASS` and checks no VPP or owned NFQUEUE hook, KernelSU
grant, removed debug selector, installed APK identity, SQLite integrity and
the ordinary observation history. Both ordinary file hashes match their T27
predecessor: SQLite
`e7e8723565d32ce41a41bb036fc68a5862f813c0d471602dde4df0c9c9c5bfbd`
and JSON
`75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4`;
the 1,575 pre-existing nonmetadata SQLite rows remain unchanged.

Rust Product Core tests passed 73 with three ignored probes, the Android
runtime contract passed, and the full Host CTest suite passed 51/51. An
earlier 50/51 run failed only because this report's navigation link had been
added before the report file existed. Python syntax
and `git diff --check` passed. The [independent review](2026-09-27_T28_DASHBOARD_REVIEW.md)
records both review findings and their closed fixes. The 34 unrelated dirty
files present at task entry are preserved byte-for-byte.
