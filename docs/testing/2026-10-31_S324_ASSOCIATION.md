# S324 — domain-IP association facts and independent lifetime

Task authority is SAKAMOTO-324 under the [application DNS specification](../product/APPLICATION_DNS_SPEC.md)
section 10. This record states what was actually qualified. **No Pixel 6a run has been made for this
slice**: everything below is Host evidence.

## Implemented contract

[`product_dns_assoc.c`](../../src/product/vpp/product_dns_assoc.c) is an owner-local fact store held by the
shared DNS proxy, so Root and VPN use one implementation.

- **Source.** A pair is (name, address) from an `A`/`AAAA` record in the *answer section* of an allowed,
  complete answer (upstream wire or current-view cache). The owner must be the QName or a CNAME actually
  connected to it; the chain is linear, so an address owned by `names[k]` pairs with `names[0..k]`.
  Authority, additional, SVCB/HTTPS hints, other owners, non-IN data and unspecified/loopback/multicast
  addresses never become pairs. NXDOMAIN, other RCODEs, truncated, broken-chain and uncorrelated answers
  admit nothing and leave a reason.
- **Provenance per pair.** Original caller reliability, resolver id and route, transport, cache origin,
  network/route revision, underlay epoch, request token, QType, RCODE, and the *output* result
  (accepted / not accepted). Output acceptance is separate evidence; it is not App receipt.
- **Lifetime.** Two hours (provisional) per pair, independent of the answer TTL and of every other pair.
  Only an allowed answer or a current-view cache answer for the same pair refreshes it. Qualification
  lookups and business traffic never do. A new answer does not delete older addresses and does not renew
  addresses it omits.
- **Bounds.** 1024 pairs (about 0.4 MiB, counted in the proxy's owned bytes), 128 pairs per answer
  (more admits none and reports `OVER_LIMIT`). When full, expired pairs go first, then the pair that
  expires soonest. Network/route view change and `Stop` remove pairs; cache eviction does not.
- **Consumption hook.** `product_dns_assoc_qualify` reports no, one or several candidate names for an
  address in the current view, with caller, delivery and CNAME evidence. It is read-only. One candidate is
  indirect evidence, not connection identity. `PRODUCT_DNS_ASSOC_ENFORCEMENT_ENABLED` is 0: the cross-App
  and profile scope is undecided, so nothing consumes the hook and no fallback acceptance is claimed.
- **Observation.** The existing DNS record keeps its size and versions. Four named bytes at offset 652
  (`assoc_admitted`, `assoc_refreshed`, `assoc_skipped`, `assoc_reason`) describe the admission of the
  answer for stage 2 records; the Rust decoder rejects them on any other stage. Table counts, high water
  and evictions are in the proxy resources.

## Host qualification

| Check | Result |
| --- | --- |
| Pair source, CNAME chain, authority/additional/unrelated owner exclusion, 9:00/10:00 independent expiry, lookups do not renew, omission does not renew, view change, expiry, ineligible answers, AAAA, capacity 1024 with eviction (`sakamoto-product-dns-assoc-test`, ASan/UBSan/leak) | PASS |
| Through the proxy: admission on wire answer, refresh on cache answer, persistence after the 60 s TTL, 2 h expiry, view-change drop, no-address and NXDOMAIN reasons, `Stop` (`sakamoto-product-dns-routing-test`, ASan/UBSan/leak) | PASS |
| Existing DNS, Root, VPN and observation host suite (69 tests); Rust crate including the new field guard | PASS |

One run of `sakamoto-product-root-dns-tcp-pending-bounds-test` aborted once under `ctest -j4` and
passed in 31 further runs and the next full run; no cause was found.

## Pixel 6a qualification

One native stage (`android-native-r3`) and one APK (`android-apk-r3`, SHA-256 `b42df484…`) built from the
committed sources. An unchanged repeat of each had zero Rust compilations, zero Ninja actions and zero
bytecode compilations, with a byte-identical payload. Ordinary App entry, normal SQLite, clean stops, and
an independent finite UDP/TCP peer on the host as the configured upstream. The oracle is the stage-2
observation row (`assoc_*`) of each answer plus the Product's `dns.assoc` status line, which is new
(`show product dns proxy`).

| Run | Scope | Result |
| --- | --- | --- |
| `device-root-n1-r7` | Root N1, 8 cases | PASS |
| `device-vpn-n1-r3` | VPN N1, the same 8 cases | PASS |

The cases: first allowed answer (1 pair); the same query again from the cache (the pair is refreshed, none
added); CNAME chain (QName and the connected CNAME both reach the address, 2 pairs); answer with an
unrelated owner and an additional-section address (only the one owner-connected record admitted);
NXDOMAIN (reason `NOT_ELIGIBLE`); NODATA (`NO_ADDRESS`); loopback-only answer (`UNUSABLE_ONLY`, one address
skipped); AAAA over a proxied TCP session on IPv6 (1 pair). Root counters at the end: 4 entries, 4
admitted, 1 refreshed, 1 rejected, 1 skipped, no eviction, expiry or view drop, `enforcement=0`. The
return-stage rows carry no association claim, and every stage-2 row of one answer reports the same
admission. The complete durable store after Stop lists the same admissions.

On VPN the table also holds pairs from the phone's own background lookups (`mtalk.google.com`,
`time.android.com`, caller Unknown, UID unknown). The VPN counters are therefore checked as deltas from a
baseline read after configuration, with nothing lost, evicted or double counted; the extra names are
listed in `durable_foreign_admissions`.

Defects the device runs found, all fixed in Product code before the passing runs:

- The observation decoder still required the former reserved bytes at 652..655 to be zero, so every
  delivered-answer record carrying admission evidence was dropped as malformed. The Host byte-level test
  only covered the rejecting side; the positive case is established by the device runs and the durable store.
- Admission read the caller's receive buffer after the reply callback had run. For a proxied TCP session
  that buffer was already reused and the answer looked ineligible. Admission now reads the proxy's own
  copy of the answer.

Findings that changed test code only: the CNAME answer produces one stage-2 row per connected name; the
shared validator is applied to the QName row. After the runs, the original APK and all 4861 private-data
members were restored at the fresh maximum generation (`original-restoration-r3`) with no NFQUEUE entry,
Product hook or owned route left.

## Follow-up: every allowed answer (2026-10-31)

User decision recorded in the [specification](../product/APPLICATION_DNS_SPEC.md) section 10: allowed answers
create association facts whether or not DNS replacement is enabled; whether they take part in decisions is the
user's policy.

- The table moved from the proxy to each FlowOwner (`product_packet_graph_main.dns_assoc`). It lives for one
  Product generation, is cleared at Stop, and survives DNS reconfiguration; the proxy borrows it.
- Original-path UDP and TCP answers are admitted when the answer passed policy, is complete and correlates to a
  known App request. Their pairs carry route 0 and delivery 0 (unproven) and depend on the network view only;
  proxy pairs also depend on their DNS route. Refused answers keep only their observation. Uncorrelated packets
  (for example a recaptured Product reply) are not answers to an App request and admit nothing.
- Original-path stage-2 records carry the same `assoc_*` bytes; the decoder validates them for every record kind.

Pixel 6a with APK `android-apk-r5` (`8904e090…`):

| Run | Scope | Result |
| --- | --- | --- |
| `device-root-n1-r13` | Root N1: 5 original-path cases plus the 8 proxy cases | PASS |
| `device-vpn-n1-r6` | VPN N1: the same 13 cases | PASS |

Original-path cases use real queries to 1.1.1.1 with replacement turned off: A over UDP (`example.com`), A over
TCP (`example.org`), AAAA over UDP (`one.one.one.one`) each admit pairs; `example.net` AAAA is a real NODATA
answer (`NO_ADDRESS`, no pair); `www.github.com` with a rule refusing its connected CNAME `github.com` is refused
and admits nothing. The original-path pairs are still present after the proxy configuration that follows. On VPN
the refused-answer query is sent after a first query on the same socket, so the asynchronous App UID is known.
Two driver findings: a configuration saved by an earlier run kept replacement on (the cases now turn it off
first), and the first build also admitted uncorrelated duplicates, which the correlated-only rule removed. The
device was restored afterwards (`original-restoration-r5`).

The table is still not consumed: `PRODUCT_DNS_ASSOC_ENFORCEMENT_ENABLED` stays 0 and no fallback acceptance is
claimed.

## Not covered

Root N3 and VPN N3, a return failure injected at the Adapter (the delivery field is verified on the
accepted path only), and any wait across the real two-hour window or the 1024-pair capacity on the phone;
those two are Host-only evidence (`sakamoto-product-dns-assoc-test`). Cross-App/profile consumption, SNI and connection-time use of the hook, and any
enforcement remain out of scope.
