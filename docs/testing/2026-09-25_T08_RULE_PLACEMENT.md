# T08: whole-rule placement and early winners

Date: 2026-09-25. Scope: [SAKAMOTO-259](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/5f174fd0-7af8-4059-91fb-ce2113d16d6d).
The [interface contract](../interfaces/T08_RULE_PLACEMENT.md) defines bounded
placement, complete early winners and snapshot ownership. This replaces T07's
conservative whole-UID placement without changing source rule semantics.

## Source and evidence

Evidence root: `build-output/t08-20260925/`. Final Linux/Android `build-d`
source closure is
`43bae86c42a14f1c6370338cd3896a5dc906f1b922b5a3de7440adbc37872133`.
Build manifests retain exact Product sources, dirty diffs, build logs and
artifact hashes. Android verification joins installed APK/native hashes to the
build. `acceptance-index.json` is the complete local evidence index, including
original Plane task/parent/comments/dependencies, Host output, runtime/configuration
identities, packet/endpoint records, query readbacks and review results.

## Original acceptance mapping

| T08 criterion | Implementation and evidence |
| --- | --- |
| Propagate every already-post-flow overlap in complete Rank, including indirectly deferred static rules | The compiler first sorts priority/order/stable identity, then compares each static rule with all earlier deferred rules in the same effective application view. The Host chain A(dynamic port 100), B(static 100–200), C(static 200–300) verifies C remains POST although disjoint from A. Equal priority/order and reversed input order exercise complete Rank. Real TCP/UDP and Pixel TCP use the corresponding adjacent destination-port chain; its actual static DROP occurs after CT observation. |
| Static envelopes prove only definite disjointness; exhausted budget defers | AND intersects rectangular envelopes; OR takes a conservative hull; NOT, CT and fields outside the proof vocabulary widen. Family, protocol, device direction, current source/destination CIDRs and port ranges have independent disjointness cases. A 4,096 pair-proof budget bounds optimization. A 92-rule propagated-chain case exhausts the proof and verifies an otherwise disjoint last rule is deferred without losing its winner. There is no CT-history equivalence or application-wide observation prerequisite. |
| One position for the complete rule and its compiled expression | Each compiled rule stores one PRE/POST position in the immutable view; one shared matcher selects complete rules. No expression stack, fragment or partial candidate crosses Flow. ALL remains the existing full ordered evaluation interface. |
| PRE NoMatch continues; actual PRE DROP bypasses Flow; actual PRE ALLOW retains the complete winner | Owner execution performs PRE under its acquired snapshot, obtains Flow facts only when needed, and performs POST only after PRE NoMatch. A complete early ALLOW/observe result is retained through one Flow observation. Linux and Android verify high static ALLOW against lower dynamic DROP, actual early DROP on an already-established TCP/UDP tuple, and successful same-session recovery. Independent flow-query comparisons require identical CT state, packet/byte totals, activity timestamps, expiry deadline, incarnation and attribution throughout early blocking. |
| Compare winner/mode/action/counts; updates, old readers and same revision/different hash remain protected | The independent logical reference compares ALL and split PRE/POST for 1,398 complete-winner cases with identical source identities, inputs and availability. Every real selected packet is joined to its acquired generation/revision/hash, full winner, actual completion and exactly zero/one Flow observation. Basic logical-hit/drop query counts join actual packet prefixes. Linux holds an early DROP reader while a preconnected real management session saves and publishes observe mode; the held packet still drops under the old snapshot, the next uses the new one. Existing Flow identity tests cover same revision/different hash, old-reader completion, stale-decision rejection and no state reset. |
| Representative verification with retained evidence and explicit limits | Final platform totals and the baseline comparison are listed below. Host is not substituted for device evidence. Runtime cleanup requires native debt/resource zero, process absence and no leftover Product hooks or queues. |

## Verification results

Result: **PASS for T08 representative acceptance**.

- Final applicable Host suite: 43/43; independent ordered versus split reference:
  1,398 full-winner comparisons. Focused final-source CT/config compiler tests
  pass ASan/UBSan/LSan in the supported non-PIE environment.
- Linux: 58 real TCP/UDP packets, 55 logical hits and 11 actual drops. The held
  old reader uses the old early DROP after publication; its successor uses the
  new observe result. Authoritative Flow/CT/timer query rows are unchanged by
  early DROP for both protocols.
- Pixel final: Root 58 TCP packets / 14 actual drops; VPN 57 / 12. The fresh T07
  baseline records Root 58 / 14 and VPN 56 / 12. Both runs independently join
  each packet to full logical results and accounting.
- Baseline versus optimized comparison: 25 common input classes across all ten
  distinct profile/scenario/mode combinations preserve full winners. Root Flow
  observations reduce from all 58 packets in its baseline to 51 of 58 in the
  optimized run; VPN observes 51 of 57 after six early drops. The corresponding
  existing Flow rows, CT state, activity and expiry deadline stay unchanged.
- Each final platform rejects 22 independently altered witness categories,
  including a forged Flow touch and a changed last-activity query during early
  DROP. Cleanup passes; the Pixel finishes stopped VPN at generation 1531 with
  saved source revision 185 and no protection-running claim.

These are bounded semantic and lifecycle counts, not performance thresholds.

The Pixel baseline uses the previously verified T07 `build-c` Product closure
`6f129ee294adae922746ebbbe5cad78b19a3cfde49dbcf48a314aae519382930`, installed and
exercised again with the same competing configurations. The final optimized run
uses T08 `build-d`. The comparison strips only per-run rule-version identity,
checks every actual condition/binding remains equal, joins common packet input
classes, and compares logical rule, full Rank, mode, declared and actual action.
Separate real TCP runs can retransmit different numbers of packets; each run's
own packet/hit/drop accounting is checked rather than asserting equal traffic
volume. Baseline observes dropped packets; optimized early DROP intentionally
leaves the existing Flow unchanged. This is not a full-trajectory CT equivalence
claim.

The ordinary application probe sends three 256-byte payloads on one real TCP
socket. The chain and early-DROP cases change observe→enforce→observe while
keeping the socket, experience an actual data timeout/drop and recover through
normal retransmission. The high static ALLOW case transfers and closes without
timeout. VPN uses the normal TUN/owner-local transport/return graph; the probe
never forwards or fabricates Product packets. Screenshots/XML are operation
support, not the packet oracle.

Two independent review axes completed. Standards found no hard violations and
one naming suggestion, resolved. Spec found an uninitialized position on the
existing public complete-evaluation seam; snapshot acquisition now initializes
ALL before owner override. A red/green snapshot audit and review follow-up cover
the repair. Final Product artifacts and acceptance runs follow all review fixes.
See `review-results.md`.

## Retained attempts and limits

The first Android build attempt failed because its historical default temporary
VPP stage path was absent; the existing verified `s220` Android stage was then
selected explicitly. The first full Host run retained two failures: an obsolete
T07 source-shape assertion and sandbox denial of a real Unix socket. The contract
now checks T08 split execution; the Rust lifecycle suite passes with socket
permission. A sanitizer attempt under sandbox ptrace failed at LeakSanitizer
startup; the final focused non-PIE checks pass outside that restriction. These do
not reclassify T05's unexplained anomaly or T06's separate PIE startup failure.

Pre-review `linux-a/b`, `pixel-a` and intermediate `build-c` runs remain as
bounded development evidence, not final-source acceptance. The baseline's old
collector used an invalid optional `show product flow` spelling; its authoritative
packet/CT traces still establish baseline state, and final collectors use the
correct `show product flows` queries. Full current-byte acceptance is `linux-d`
and `pixel-d` only.

Linux device coverage is real IPv4 TCP/UDP in the existing isolated NFQUEUE
recipe. Pixel is representative IPv4 TCP in Root and controlled VPN. IPv6,
detailed availability/Boolean combinations and proof exhaustion are Host
coverage. Broader integration remains T29; no performance, mobile-power, thermal,
long-term expiry, network-handover, LPI/SNI, cache or release-readiness claim is
made here. Controlled VPN continues to report `protectionRunning=false`.

```sh
rtk proxy python3 tests/host/product_static_reference_test.py
rtk proxy python3 tests/evidence/verify_t08_placement.py build-output/t08-20260925/linux-d
rtk proxy python3 tests/evidence/verify_t08_placement.py build-output/t08-20260925/pixel-d
rtk proxy python3 tests/evidence/compare_t08_placement.py build-output/t08-20260925/pixel-baseline build-output/t08-20260925/pixel-d
```
