# S328 — DNS combination and normal-use acceptance

Task authority is SAKAMOTO-328 under the [application DNS specification](../product/APPLICATION_DNS_SPEC.md).
Each delivered ticket keeps its own record (S310–S327); this record adds the combined matrix on one artifact. It
does not close or change the parent SAKAMOTO-309, and does not claim association enforcement, which remains
deferred.

## Artifact

One native stage (`android-native-r1`) and one APK (`android-apk-r1`, SHA-256 `aab8db29…`) built from the
committed Product sources; the unchanged repeat compiled nothing and the payload matched the previous S324 build.
Later commits changed device drivers only. Offline DoT/DoH fixture certificates were regenerated
(`offline-certificates-r1`, valid three days) because the S322/S323 ones had expired. Every run uses ordinary App
entry, normal Start with the KernelSU grant (Root) or VPN protect (VPN), normal SQLite and normal Stop.

## Combined runs

[`s328-combined.py`](../../tests/device/s328-combined.py): one installation, two Product generations.
Run 1, without restarting: original-path association with DNS replacement off (real queries to 1.1.1.1), proxied
association after enabling replacement (a DNS view change), cleartext HTTP targets, SOCKS targets, DTLS/TLS/QUIC
SNI, each group replacing the whole rule set on the running Product. A normal Stop must leave no runtime process,
NFQUEUE entry, Product hook or owned route. Run 2 starts a fresh generation and repeats original-path
association, HTTP deny/allow, SOCKS deny and DTLS deny: the previous generation's association table and refused
targets do not carry over. With N=3 every FlowOwner must carry case flows.

| Run | Run 1 | Run 2 | Owners | Result |
| --- | --- | --- | --- | --- |
| `combined-root-n1-r4` | 49 | 5 | 0 | PASS |
| `combined-vpn-n1-r1` | 50 | 5 | 0 | PASS |
| `combined-root-n3-r4` | 49 | 5 | 0,1,2 | PASS |
| `combined-vpn-n3-r4` | 50 | 5 | 0,1,2 | PASS |

Resources were zero after both Stops of every run.

## Per-capability runs on the same artifact

| Run | Scope | Result |
| --- | --- | --- |
| `cache-stoplate-root-n3`, `cache-stoplate-vpn-n3` | pending query across Stop, old-generation late result, restart | PASS |
| `coalesce-root-n3`, `coalesce-vpn-n3` | simultaneous same-question requests, independent delivery | PASS |
| `routing-smoke-root-n3`, `routing-smoke-vpn-n3` | ordered primary/backup, UDP/TCP × IPv4/IPv6, owner coverage | PASS |
| `dot-full-root-n3-r3` | DoT full matrix (19): bootstrap, identity failover, all-failed, cache, handshake Stop | PASS |
| `doh-full-vpn-n3-r3` | DoH full matrix (31): HTTP failures, Age, framing, cache, handshake Stop | PASS |
| `cache-view-root-n1-r2` | cache across a resolver view change | PASS |
| `routing-semantics-root-n1-r2` | exceptions, local transport, route semantics | PASS |
| `cache-capacity-root-n1` | cache entry/byte bound with eviction (26 cases) | PASS |

The view, semantics and capacity drivers are written for one FlowOwner and refuse N>1; they ran at N=1 on the
same artifact. A DNS view change at N=3 is part of the combined runs.

## Findings

All changes after the artifact build are in device drivers; Product code was not changed by this ticket.

- FlowOwner-local data cache and association tables: a cache-hit check must reuse the tuple of the exchange that
  filled the cache. The shared routed-exchange helper now does so for UDP; with a new source port at N=3 the
  query landed on another owner and was correctly answered by the upstream.
- Association counts are per owner; the drivers sum them for N>1. On VPN the phone's own lookups also create pairs
  (allowed answers are always recorded), so VPN counts are deltas.
- State saved by earlier runs persists on an installed App (rules, DNS replacement); each run now sets its own
  baseline.
- A public resolver occasionally loses one UDP exchange; the driver retries once and records it
  (`public_resolver_retries`).
- One VPN N3 combined run (`combined-vpn-n3-r3`) saw a single TCP connection reset before its HTTP request left the
  App, right after an allow-all rule replacement. It did not recur in a dedicated S325 VPN N3 run or in the next
  combined run. It is recorded as an unexplained, non-reproduced event.
- A probe launch was killed by a 60 s shell timeout while it had started a real run; the Product was stopped
  normally (no process, queue or hook left), the leftover witness helpers and peers were stopped, and their files
  archived under `killed-probe-leftovers` before removal.

After the runs the original APK and all 4861 private-data members were restored at the fresh maximum generation
(`original-restoration-r2`), with no NFQUEUE entry, Product hook or owned route left.

## Acceptance decision (2026-11-01)

The user accepted this scope and asked for SAKAMOTO-328 to be marked complete with observation backpressure
recorded as an explicit uncovered item, not as qualified.

## Not covered

Observation backpressure was not re-exercised (no DNS driver floods the observation channel; the earlier
`t21`/`t29` observation stress drivers were not rerun), cellular/Wi-Fi handover, the view/semantics/capacity
matrices at N>1, and every association consumer: association enforcement stays disabled and its cross-App/profile
scope stays deferred.
