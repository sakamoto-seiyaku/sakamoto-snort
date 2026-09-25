# T05: ordinary highest-priority network disabling

Date: 2026-09-25. Scope: [SAKAMOTO-256](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/8ccb0e76-58d4-4aca-b346-934d1c30965e).
Result: **PASS for T05 representative acceptance**, with the retained sanitizer
anomaly below. The [interface contract](../interfaces/T05_NETWORK_DISABLE.md)
defines the operation, errors, identity, scope and ownership under ADR-0009.

## Source and evidence

Evidence root: `build-output/t05-20260925/`; start with `acceptance-index.json`
and `raw-manifest.json`. Final Linux and Pixel builds both use Product source
closure `39c4510431d9975e60aa8435019d7f46e286774c1b2637fdc9b73893e07cd4ac`.
`linux-build-e/build.json` and `pixel-build-e/build.json` bind exact source bytes,
dirty diff from base commit `2598631f00a250976a0d064a11ba354a61979af3`, and artifacts.
All manifest source files were checked against the final working tree. Later
test and documentation changes do not change this Product source closure.

## Original acceptance mapping

| Requirement | Implementation and evidence |
| --- | --- |
| Maintain an ordinary highest-priority DROP without privileged Gate state. | `NETWORK_DISABLE=3` maintains an ordinary direct DROP with priority/order zero through VPP's existing save/compile/publish path. The packet graph's Gate table and matcher are removed. Nonempty legacy Gate input is rejected. Host checks idempotence, ordinary complete editing, ambiguous duplicates and referenced-removal rejection. |
| Preserve application, network, direction and full predicates. | Host varies UID, context, interface, direction, family, addresses, ports and missing facts; wildcard family/protocol still respects port availability. Linux uses two actual UIDs and matching Wi-Fi versus out-of-scope Mobile context. Pixel proves Root scope, VPN scope, Mobile nonmatch, and physical Wi-Fi matching on a VPN return packet. These are controlled contexts, not cellular handover qualification. |
| Use complete ordinary ordering, ALLOW exceptions and lowest-priority fallback DROP. | Host hand-decided tests make an ALLOW win a priority/order tie by logical identity, then move its order behind the disable and check the changed winner. Shared-group fallback and promoted ALLOW cases use the same matcher. No privileged identity or opening ALLOW is persisted. |
| Retain rule version and actual action; observe is not a real drop. | Independent verifiers join ordinary winner/version, source revision/hash, rank, mode, declared action, native completion, actual endpoint delivery and counter deltas. Logical hits grow for observe DROP while actual drops stay unchanged. |
| Connect existing diagnostic/control consumers. | Java, JNI and Rust adapt the online operation; the existing network switch queries the ordinary source. Pixel uses the development entry for disable and actual UIAutomator taps on visible Open buttons for restoration. Screenshots/XML prove UI operations only; packet evidence proves delivery. |
| Combine T04 shared groups/observe with network disabling. | Host and both real platforms preserve shared groups/bindings and ordinary winners while adding/removing the higher-ranked direct DROP. Linux also converts that same ordinary rule to reusable observe, checks both UIDs, and reloads it across a VPP restart. |
| Preserve representative Host/Linux/Android evidence separately. | Final Host suite, independently verified Linux-c 12 packet cases, Pixel-d nine outbound cases (four Root, five VPN) plus return completion checks, and nine falsified witness categories rejected per platform. Source/build/runtime/configuration/packet bindings are independently checked. |

## Verification and limits

- Host: `host-complete.log` and `host-complete.xml` contain the final applicable
  41-test suite. Focused red/green records include ordinary ordering, wildcard
  port availability, scope, failure preservation, graph remapping and observe.
- Linux: `linux-c/`, `linux-c-verified.json`, `linux-c-negative-witnesses.json`.
  Real NFQUEUE traffic in an isolated Linux container, two actual UIDs, two VPP
  lifetimes. Built Product artifacts only; no POC code imported. Final processes
  are absent, hooks removed and packet resource obligations zero.
- Android: `pixel-d/`, `pixel-d-verified.json`, `pixel-d-negative-witnesses.json`.
  Installed APK/native hashes match `pixel-build-e`. Both Root and controlled
  VPN demonstrate actual drop and restore, with source/query/counter readback.
  The Wi-Fi return case deliberately permits VPN outbound but drops physical
  Wi-Fi return; the Mobile case permits both directions. UI Open restores each.
- `review-results.md` records independent Standards and Spec reviews. No hard
  standards violations or specification findings remain. An optional Java wire
  literal readability suggestion is left consistent with the existing encoder;
  it does not change semantics or acceptance.

Final recorded Pixel state (`pixel-d/vpn-stopped-latest.properties`) is stopped,
VPN profile, generation 1515, no error, `mayBeActive=false` and
`protectionRunning=false`. Saved revision 80 contains two reusable rules, two
groups, four edges and two observe bindings in the app-owned mode-0600 source.
Native owners close sessions/sockets and settle packet resources. This evidence
does not claim public VPN protection, physical cellular coverage, broad protocol
or IPv6 device coverage, performance/power budgets or release readiness. Broader
combined qualification remains T29; subsequent expression semantics belong to T06.

## Retained failures and superseded attempts

Earlier Linux/Pixel builds and campaigns remain available but do not establish
the final acceptance. Initial Pixel authoring still hit the retired path; the
consumer was fixed. An initial VPN outside-case expectation ignored physical
Wi-Fi return matching; the final campaign retains that DROP case and separately
proves Mobile nonmatch, without weakening packet-context semantics.

The sanitizer run after the final ordering test emitted repeated
`AddressSanitizer:DEADLYSIGNAL` and was stopped. Its full compressed output,
uncompressed SHA-256 and sample are retained. The same final binary then exited
zero in three bounded runs with default ASan signal handling and three with
`handle_segv=0`, with no ASan/UBSan/leak diagnostic. The root cause of the first
failure is unproven; it is not reported as a successful initial run.
`sanitizer-final-summary.json` supersedes the older `sanitizer-evidence.json`,
whose binary hash/log reference is stale. The latter remains as historical evidence.

A recovery-time full Host run passed 40 tests and failed the documentation
navigation test because the testing index already linked this then-unwritten
report. The final suite runs after adding this report; the failed log is retained
as `host-resume.log`.

```sh
rtk proxy python3 tests/evidence/verify_t05_network_disable.py build-output/t05-20260925/linux-c
rtk proxy python3 tests/evidence/verify_t05_network_disable.py build-output/t05-20260925/pixel-d
```
