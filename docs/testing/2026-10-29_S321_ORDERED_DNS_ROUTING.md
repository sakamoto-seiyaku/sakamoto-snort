# S321: ordered resolvers, resolution views and local exceptions

The VPP-owned DNS configuration supports ordered ordinary UDP/TCP endpoints,
resolution routes and explicit internal-name exceptions. Root and VPN use the
same owner-local DNS Core, current policy and existing transport/return paths.
This is qualification of the privacy application's selected DNS slice; encrypted
upstreams, resolver IPC hooks and association enforcement remain separate work.

Authority: [application DNS specification](../product/APPLICATION_DNS_SPEC.md),
[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) and
[SAKAMOTO-321](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/0c15078c-6f40-4e48-8794-e0f2d2b49a42).
ADRs 0006/0007/0008 retain the VPP-native C boundary. No DNS daemon, background
probe runtime or removed C++ implementation is introduced.

## Configuration and routing

The normal debug configuration action accepts the existing `udp <numeric IP>
[port]` and `off` forms, plus the following multiline ordinary profile:

```text
upstream 0 udp primary.test 192.0.2.53 53
upstream 1 tcp backup.test 192.0.2.54 53
route 0 0 1
route 1 1
exception descendants corp.test route 1
exception exact printer.corp.test original
```

Indices are contiguous and zero-based; endpoints precede routes, which precede
exceptions. Route 0 is the default. Endpoint identity is stored separately from
the numeric connection address; this profile performs no bootstrap lookup or
TLS identity verification. Names use case-normalized ASCII labels. The bounds
are 8 endpoints, 8 routes, 8 different candidates per route and 32 exceptions.
Duplicate candidate IDs, unavailable endpoints, malformed names, nonzero unused
fields and duplicate same-match name scopes are rejected before publication.

An exact exception wins before suffix rules. Otherwise the longest complete
label suffix wins; `corp.test` does not match `notcorp.test`. An `original`
exception uses that request's actual original resolver. Explicit private/local
resolver destinations preserve their original scope; the implementation does
not guess every internal name or treat the `.local` spelling alone as mDNS.
Multicast UDP5353 remains on the original network path.

VPP persists, compiles, publishes and independently queries the complete saved
and active setting. `SKRULE08` persists the bounded program; versions 2–7 still
decode. The public C/Rust DNS struct is 11,376 bytes. The calibrated 2,176 KiB
configuration budget covers the 2,138,420-byte composite compiler/storage-overlap
upper bound, including views, requests and caches. The separate serialized source
buffer bound is 229,276 bytes. Neither figure is measured process RSS.

## Attempts, cache and lifecycle

Each candidate's still-valid data cache is considered before health cooldown.
Only transport, timeout or invalid-response failures advance the configured
order. Valid NOERROR, NXDOMAIN, REFUSED and SERVFAIL remain actual resolver
results and do not initiate a search for a positive answer. Failure cooldowns
are 5, 10, 20 and at most 30 seconds. The first later demand may recover a cooled
candidate; there are no periodic DNS probes, and only one recovery attempt is
in flight for that candidate per owner.

One query retains a 10 second monotonic total deadline. Each candidate receives
at most 3 seconds within the remaining total; one UDP retransmission and
same-candidate TC-to-TCP continuation share that candidate lifetime. A new
candidate has a fresh upstream attempt identity and DNS ID while each waiter
retains its own independent request, caller, token and reply identity.

Cache equivalence includes the actual selected endpoint and route, current
network/configuration view, profile and available underlay context. In-flight
sharing additionally compares the original resolver destination.
Configuration/network changes invalidate old data and work;
late transport and broker cookies cannot answer or refill the changed view.
Cancellation, policy refusal and Stop do not count as resolver health failures.
Query/current-response policy and independent delivery still apply to every
waiter, including cache hits and shared data.

The existing per-owner limits remain 64 exchanges, 128 waiters, 512 cache entries
and 2 MiB cache bytes, with 8 MiB DNS work bytes. The Root transport shares at
most six upstream channels plus two raw return sockets, totaling eight sockets;
idle nonbusy channels are reclaimable after 30 seconds. There is no socket per
configured endpoint or permanently reserved probe connection.

Normal DNS records add actual `upstream_attempt`, `resolution_route` and
`resolver_id` in version 9, at most 720 bytes. Records without routing fields
remain version 8/704 bytes and keep existing serialized history unchanged.
Stage 5 reports attempts and their timeout/transport/invalid outcomes, separately
from policy refusal, response facts and final delivery. Rust uses the existing
unified commit/close/reopen and SQLite retention path; no second DNS store exists.

## Build and self-test evidence

The review base is `4be599da92076ed5b2104b9903eaaeaa8b4312a7`.
Current R5 APK SHA-256:
`c78e101b1640f2c55214c80a554c5c13e3e0d3ebe10b4d66d3d6e5f7eae5868f`.
Current plugin SHA-256:
`9726d0768d27639d10a10a01cb24896946ec7501e86cb8ecd67031e1da2bca9d`.
Generated API CRC is `6957b396`; every generated/VAPI/JNI consumer uses that API.

The [evidence root](../../build-output/s321-ordered-resolvers-20261029/) retains
the matching native/raw symbol outputs, APK, Host artifact, source ZIPs, launch
commands and original failures. Native, APK and actual Host Product builds reuse
their persistent Product caches. Unchanged second builds compile zero Rust,
Ninja or Java/DEX inputs, preserving all 777 native, 3,684 Host and 182 bytecode
metadata identities and byte-identical published payloads.

| Scope | Actual self-test qualification |
| --- | --- |
| VPP configuration | Public replace/query, close/open persistence at all 8/8/32 bounds; conflict/overflow rejection leaves saved/live state unchanged; disabled complete program round trip |
| Shared Core | Ordered fallback, each candidate's cache, demand recovery/cooldown cap, four effective RCODEs, shared total deadline, exact/longest-label exceptions, original resolver, view/late/cancel/Stop and bounded resource behavior |
| Real socket I/O | Distinct endpoint sends, late-primary response cannot answer backup, six-channel capacity, idle/cancel baseline and asynchronous authorization/cookie fencing |
| Real Root/VPN Adapter | All eight client transport/family/profile combinations produce 48 whole routing records, then normal Rust commit/close/reopen and independent complete SQLite reads |
| Full Host and HEV | Current 123/123 Host tests and 68/68 real HEV/lwIP tests pass |
| Rust workspace | Full workspace passes its designed SKPC fixture ABI; actual VAPI unit/decoder/Store checks and actual Host Product artifact qualification remain separate |

The actual-VAPI workspace attempt also reached eight unchanged fixture-only
lifecycle servers that speak SKPC, causing one protocol mismatch and seven
poisoned-lock follow-ons. Those raw failures remain preserved; the full fixture
pass is not claimed as an execution of those servers over VAPI. Earlier missing
PLY, wrong header ordering, stale FFI size assertions and driver readiness/wire
qualification errors remain classified independently of Product failures.

The original Core and device fallback failures retain the same business
assertion: a timed-out primary must advance to the configured backup's actual
answer. The initial normal App Root result saw primary retries, zero backup
queries and local SERVFAIL. The same operation passes after the Core change.
The full Host suite also exposed a real corrupted-cache recovery regression;
current ordered and legacy cases remove the unusable cache entry and retry the
same candidate without marking a health failure.

## Device scopes and preserved failures

Every ordinary entry uses normal configuration/start/stop, the actual App probe,
independent saved/active VPP readback, passive wire, normal Rust Store close and
reopen, and whole immutable SQLite/history checks. The composed matrix covers
Root/VPN, UDP/TCP clients, IPv4/IPv6, N1/N3 and every configured owner. R3/R4
entry captures retain their exact earlier artifacts; R5 fixes the expanded mDNS
receive boundary and corrupted-cache recovery. Unchanged passing input scopes
are reused with that composition stated explicitly.

Root N1 additionally qualifies candidate-owned cache before health, idle-demand
recovery, all four valid RCODEs, five overlapping/boundary exception questions
and the same name receiving a different answer after a resolver-view change.
The first Root semantic run's whole HOLD remains: its actual advertised LAN
resolver answered a cold recursive reserved name only after about 5 seconds,
after the correct 3 second candidate timeout and one local SERVFAIL. This is an
actual original-route deadline/late-response negative, not a policy refusal or
a qualified positive answer.

A bounded stopped-device availability check established that the same advertised
resolver answers nonrecursive `localhost A` within milliseconds. The missing
Root positive is separately qualified with that question: the actual App receives
the resolver's answer, both configured replacement peers see zero queries,
resolution route is original and independent physical wire matches port53.
The cold-recursion HOLD is not rewritten, and the 13 passing Root semantic
cases are not replayed to relabel their original run.

VPN N1 runs the complete 15-case semantic batch on R5, including that qualified
advertised-resolver question and legacy mDNS. All cases pass, with 68 whole
target records, a normal 715-row MAIN, exact surviving history and native-zero
Stop. The final composed case union contains 246 distinct whole records in the
final 727-row normal MAIN, SHA-256
`c2800bec037f96ee01ac342c01c8f08c8fdb2c67adf612af93cff9d4502a14d5`.
The other 481 normal rows remain intact. This union retains the original artifact
scope and separate qualifications of whole HOLDs rather than relabeling them.

mDNS callers here are explicitly bounded shell UID sockets, not Android resolver
IPC or ordinary App caller-identity evidence. IPv4 legacy unicast response and
standard5353 group responses retain their real Root/VPN scopes. The original
VPN connected-multicast socket lost real unicast responders; a real HEV owner
regression proves the fix. A later standard5353 run exposed feedback: 1,023 TUN
returns from only two physical replies, correctly failing the unchanged 1,024
packet collector bound. The third round/1,800 second rule triggered a unified
shared-module, entry, policy, lifecycle and resource inventory.

The batch fix keeps the existing authorized UDP session and bounded queues,
derives its selected local address using that same socket without sending, and
checks IP_PKTINFO/IPV6_PKTINFO receive destination. Packets injected into the
virtual interface cannot re-enter upstream receive; multiple real responders
still retain their source identities and shared ordinary App/IP policy. A real
socket/HEV/lwIP self-return regression fails before and passes after the change.
Current standard IPv4 VPN evidence is exactly one original TUN query, two
physical replies and two TUN returns, with no replacement-resolver dispatch.

The IPv6 device multicast helper deliberately selects the original Wi-Fi
interface. Its correct answer and two independently observed physical responses
qualify that scoped original-network path. TUN ingress/return are both zero;
this is not IPv6 VPN Direct/TUN qualification. The old IPv6 wire-selector HOLD
remains; only its missing link-local observation boundary was rerun.
The final Root standard5353 and explicit Wi-Fi IPv6 controls also pass on R5;
both normal Store/history and native-zero Stop complete before restoration.

## Reproduction and recovery

Use the Product persistent builders and current libraries, then the existing
Host CTest and real HEV CTest directories. Device drivers are
[`s321-dns-routing.py`](../../tests/device/s321-dns-routing.py),
[`s321-dns-routing-semantics.py`](../../tests/device/s321-dns-routing-semantics.py)
and [`s321-dns-mdns-network.py`](../../tests/device/s321-dns-mdns-network.py).
They require a complete fresh stopped-device backup and task-owned bounded
collectors; all Android operations use repo `./dev/adb`.

Before Product writes, the S321 baseline preserved the original APK
`cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and all 4,861 private graph members at generation2904. Every replaced test cohort
retains its complete graph and exact APK first. The final R5 preservation contains
all 5,019 nodes in a complete 164,811,776-byte TAR, SHA-256
`587d5c2f4ca00e5e31787fb811c71809e8674f6cb3f37b02d5914c505e18d1f3`,
with every member's metadata and content checked against the measured source.

The original APK and all original nodes are restored at fresh BOTH2922. Only
the two generation fields differ from the initial graph. A separate post-restore
read confirms the complete graph, KSU grant, permissions, SELinux, Wi-Fi,
frequency and stay-on settings, no App/native processes and no Product hooks,
queues or owned routes. Five exact task-owned remote TAR/metadata pairs totaling
484,992,000 archive bytes are retired only after verifying their complete local
copies, hashes and terminal producers. Local raw evidence and APKs remain.
There is no Product Stop replay, unowned signal or global network reset.

The [post-restore receipt](../../build-output/s321-ordered-resolvers-20261029/coordination/device-restoration/post-restore-readonly-and-clean-r5-receipt.json)
records that actual recovery. The separate
[review-ready source/evidence map](../../build-output/s321-ordered-resolvers-20261029/coordination/implement-owner-r1/review-ready-r5/manifest.json)
pins the implementation and self-tests. The actual
[Standards](../../build-output/s321-ordered-resolvers-20261029/coordination/review-standards-r5/report.md)
and [Spec](../../build-output/s321-ordered-resolvers-20261029/coordination/review-spec-r5/report-r1b.md)
reports retain their independent findings and scope. The
[final corrected source seal](../../build-output/s321-ordered-resolvers-20261029/coordination/implement-owner-r1/final-source-seal-r5/manifest.json)
records the documentation correction against that reviewed source. Final delivery
acceptance is recorded separately in the
[final delivery receipt](../../build-output/s321-ordered-resolvers-20261029/coordination/implement-owner-r1/delivery-final-receipt.json);
self-test success alone does not imply that later gate has completed.
