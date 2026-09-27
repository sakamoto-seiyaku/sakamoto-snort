# Testing and evidence

The current product is VPP-native C with Rust control and Java supervision.
The former C++ daemon/model suite was removed by ADR-0008.

## Current acceptance entry

Start with the [2026-09-13 foundation joint report](2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md):
`PASS_WITH_EXPLICIT_LIMITS`, with independent Linux Root / Pixel Root / controlled
VPN checks, source-bound artifacts, 64 Pixel generations and retained failures.
This is not a release gate or ordinary-user VPN protection claim.

The independent checker can re-evaluate retained raw evidence without operating
a device. Write the new report separately from frozen evidence:

```sh
python3 tests/evidence/verify_foundation_joint.py \
  --input build-output/foundation-joint-20260913/acceptance-input.json \
  --output build-output/host-tests/foundation-recheck.json
```

Local raw files and matching build witnesses are required. A missing file is not
a passing or skipped acceptance branch. See [test layout](../../tests/README.md)
and [build commands](../tooling/README.md) for Host checks.

## Focused evidence

| Scope | Record |
| --- | --- |
| Directional Flow effects and query freshness | [T23](2026-09-27_T23_DIRECTIONAL_ATTRIBUTION_RESULTS.md) |
| Pre-Flow Blocked observations and independent windows | [T24](2026-09-27_T24_BLOCKED_OBSERVATION_RESULTS.md) |
| L4 and multi-label L7 protocol windows, Root/VPN and R1–R4 integration | [T25](2026-09-27_T25_PROTOCOL_WINDOWS_RESULTS.md) |
| SQLite observation migration, bounded live batching and matched Host/Pixel costs | [E02](2026-09-26_E02_SQLITE_RESULTS.md) |
| TLS/QUIC exact and descendant domain lists, real packet winners and bounded matcher | [T18](2026-09-26_T18_DOMAIN_LISTS.md) |
| Ordinary network-disable rules, scoped switches and shared observe behavior | [T05](2026-09-25_T05_NETWORK_DISABLE.md) |
| Bounded static Boolean conditions and field availability | [T06](2026-09-25_T06_STATIC_EXPRESSIONS.md) |
| Published protocol sets, NOT/availability, bounded LPI and complete-cache integration | [T12](2026-09-25_T12_PUBLISHED_PROTOCOL_FACTS.md) |
| Proxy/VPN/remote-access recognition, actual rules and bounded state | [R3](2026-09-25_R3_PROXY_VPN_RECOGNITION.md) |
| CT state/direction, conservative placement and real TCP/UDP rule changes | [T07](2026-09-25_T07_CT_EXPRESSIONS.md) |
| Startup compilation failure, online management repair and policy-before-capture lifecycle | [T03](2026-09-25_T03_STARTUP_REPAIR.md) |
| Complete VPP-owned direct rules, versions, failures and Root/VPN source lifecycle | [T02](2026-09-25_T02_COMPLETE_RULE_CONFIGURATION.md) |
| Protocol expiry and deferred real 24-hour TCP test | [S236](2026-09-13_S236_PROTOCOL_EXPIRY.md) |
| Linux network classification and projection limits | [S235](2026-09-13_S235_LINUX_NETWORK_SNAPSHOT.md) |
| Canonical owner versus CPU placement | [S220](2026-09-13_S220_WORKER_CPU_PLACEMENT.md) |
| FlowRuntime and protocol trackers | [S221](2026-09-11_S221_FLOW_RUNTIME.md), [TCP](2026-09-12_S222_TCP_TRACKER.md), [UDP](2026-09-11_S223_UDP_TRACKER.md), [ICMP](2026-09-13_S224_ICMP_TRACKER.md) |
| Independent bounded reassembly | [S229](2026-09-11_S229_INDEPENDENT_REASSEMBLY.md) |
| Artifact/source/raw witness chain | [S244](SAKAMOTO_244_EVIDENCE_CHAIN.md) |

The dated foundation report records HEV 36/36 and root CTest 35/40 at that time.
Later test maintenance does not rewrite those observations; see the
[repository organization record](../maintenance/2026-09-13_REPOSITORY_ORGANIZATION.md)
for obsolete contract replacement and its separate regression result.

## Earlier baselines and history

[Product Spine acceptance](SAKAMOTO_171_172_DEVICE_ACCEPTANCE.md), installed through
the debug APK, established the first combined S171/S172 seam.
[Host-only supporting evidence](SAKAMOTO_171_HOST_EVIDENCE.md) is not equivalent
to that Product Spine acceptance or the ADR-0007 Flow Stack.
The [S195 recovery dossier](SAKAMOTO_195_RECOVERY_ACCEPTANCE_DOSSIER.md) retains the
S176–S196 baseline and its limits.

Older unnumbered DX/IP casebooks and surveys may describe the removed daemon.
Use them as dated history, not commands to run. Their isolated scripts are in
[the test archive](../../tests/archive/README.md). Do not import C++ or POC code.
Current numbered collectors and verifier dependencies keep their original paths;
not every older filename is obsolete. Open work and deferred gates live in Plane.
