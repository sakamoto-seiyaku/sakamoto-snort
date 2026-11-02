# T28 normal health and current-flow query

The existing Product Core generation owns a read-only dashboard query. Android
`RuntimeService` calls the Rust Product Core through the existing control
session and writes one nonce-scoped JSON response for the diagnostic Activity.
It validates then appends its own JSON section without reserializing Rust's
document, preserving older observation rule versions above Java's signed
integer range as well as the new decimal-string identities.
The response keeps three authorities separate: `runtime` is the service's
current supervised snapshot, `vpp`/`policy_source`/`health`/`current_flows`
come from typed VPP VAPI requests, and `consumer` is Rust's independently
maintained observation and SQLite state. A missing section has an explicit
error or is `null`; it is not an empty successful flow/history view.

`product_core_flow_query(generation, cursor)` is read-only and returns a fixed
16-entry page after examining at most 256 Flow slots. Each API request takes
the VPP worker barrier, so the page's entries and resource counters are one
bounded live sample. The cursor is a slot position across the two fixed owner
pools, beginning at zero. `next_cursor=0` with `done=true` ends the scan.
Entries carry generation through their page and worker/slot/incarnation per
Flow, canonical endpoint addresses and ports, `origin_is_a`, UID/network,
transport kind/protocol, first/last monotonic activity, ORIG/REPLY counters,
device/flow directions, recognition mask plus availability/stop states, and
the owner-local current directional attribution. A direction without a proven
context reports `available=false`. Catalog labels derive from the current
generated active catalog; a stopped recognizer or unavailable fact does not
become a negative match. Per-worker capacity, linked-active count, high-water
mark, allocated bytes and capacity misses accompany every page.
Identity and protocol-mask fields are decimal strings in the JSON projection,
so Android cannot round a 64-bit rule version or mask while parsing it.

Pages are *not* a frozen multi-request snapshot. A Flow may end or start
between requests; callers use generation/worker/slot/incarnation to identify
entries and may restart at cursor zero for a fresh scan. A wrong generation,
invalid cursor or broken transport reports an error. The VAPI session mutex
serializes control requests; packet owners never wait for Rust, SQLite or
observation-channel capacity. The page remains callable when export channels
are full because it does not use those channels.

The dashboard's VPP status reports management and protection readiness,
policy version/count/hits/drops, Root/VPN RX/TX and infrastructure failures.
`policy_source` reports saved and active identities, save/compile results and
counts. `health` has the independent channel attempted/published/full/consumed,
basic accounting and capacity state. Rust's `query_fresh`, `store_error`,
`persistent.save_error`, coverage gaps/evictions and storage pressure qualify
the consumer view. The Android service adds its profile, lifecycle, Adapter,
protection, generation and error fields; it never infers protection from a
nonempty Flow page. The diagnostic Activity has Query health and Next flows
buttons and renders these fields without parsing logs. Its temporary query
file is removed after display; an ADB Activity intent with an explicit nonce
can retain the raw response for acceptance evidence.

## S330 saved-history query

The same Android observation action, Query history and Query health buttons now
read saved history when the RuntimeService has no Product Core session. They call
the shared Rust saved-query branch through JNI; they do not connect to VPP,
start a consumer, start capture or change the runtime generation. Host callers use
`sakamoto-product-core-host saved-history <observation/overall.json>` without a
socket or generation. The C entry is `sakamoto_product_core_observation_saved_query`.

The response retains `consumer.persistent` with the existing bounded recent
Flow/Blocked records, independent DNS stage records, application/rule/protocol
windows, minute/hour/day aggregates, coverage, storage budget and truncation
fields. `recent_query_truncated` explicitly qualifies the shared 128-record
recent page. Flow identity remains generation/owner/slot/incarnation, separately
from Blocked and DNS identities. Native first/last activity is generation-local
monotonic time; `activity_utc_us`, receipt clocks and bucket UTC seconds retain
their existing meanings. History is a retained observation view, not a current
connection sample or complete long-term access log.

Saved queries report `capture_state=stopped`, `current_flows.state=stopped` and
`visibility=saved_committed`; live-only health and policy-source lookups report
unavailable. Rule conditions without their matching live source remain unavailable.
The stored `open_session` and recovery counters are read without changing them;
an interrupted session qualifies coverage as incomplete. An existing empty store
is a successful empty result. A missing store reports `history_unavailable`, while
busy, corrupt or unreadable history reports `history_query_failed` with the
original `consumer.query_error`. Missing history never creates an empty database.
Legacy JSON may be read and validated in memory without migration, with
`storage=legacy_json` rather than `sqlite`. The store lock
excludes a concurrent writer; running queries continue to use the consumer's
`live_including_pending` view with committed totals and persistence errors separate.

`fact_availability.target_names=per_record` directs callers to each detail's
`target_names`; recognition sequence and actual recognition payload counts remain
unavailable pending S61. Neither protocol bits, packet endpoints nor total packet
counts are used to invent missing facts. Saved reads preserve existing records and the existing
retention/space budgets; normal writer maintenance still owns eviction and rollup.

STOP does not manufacture END records for active Flows. Recent Flow/Blocked
history keeps its existing actual-END meaning; received DNS facts and committed
statistics remain readable, and the existing shutdown coverage gap remains
visible. This query adds no complete last-live-Flow snapshot at shutdown.

[S330 validation](../testing/2026-11-02_S330_ACTIVITY_QUERY.md) records the shared
Host query, real Root/VPN lifecycle coverage and their separate qualifications.


## S331 target-name details

Current Flow entries, normal consumer overview records and retained recent Flow
records expose the same `target_names` object. Old retained records and early
Blocked records have `target_names=null`: this means the fact schema is unavailable,
not a confirmed absence of SNI or a fabricated endpoint/domain match.

The object separates `sni`, `request` (the latest valid direct target), `denied`
(the target whose policy evaluation refused the connection) and `denied_rule`.
Each target contains its actual name or IP address, kind (0 unavailable, 1 hostname,
2 IPv4, 3 IPv6), request ordinal, port and source. SNI's existing `sni_result` and
`sni_stop` distinguish pending/unavailable, obtained name and confirmed absence.
Request `request_available`, `request_reason` and `request_stop` describe the latest
request's current eligibility: a later unavailable head or an untrusted stream
can invalidate eligibility while the last valid target remains visible. The
request ordinal identifies that retained request; it is not a complete name timeline.

| Source | Meaning |
| --- | --- |
| 0 | No direct target source |
| 1 / 2 / 3 | Actual TLS / QUIC / DTLS SNI |
| 4 | HTTP Host field |
| 5 | HTTP absolute-form authority |
| 6 | HTTP CONNECT authority |
| 7 / 8 | SOCKS4(a) / SOCKS5 requested target |

A packet containing several HTTP heads may retain a later valid target while an
earlier target caused DROP. `denied_rule` preserves the corresponding evaluation's
policy generation, revision, snapshot identity, winner, contemporaneous name and
actions. Its four 64-bit identity fields are decimal strings, matching the live
query identity contract; unused packet-segment/App fields are not projected. It
does not infer the denial from the last request or later rules.
It records the latest actual refusing evaluation, including ordinary policy
revision re-evaluation of a sticky denied target. Unavailable rule conditions are
not reconstructed. A direct target's availability proves neither permission nor
remote delivery. SOCKS target ports/addresses remain distinct from the outer
connection endpoints; SNI, DNS stages and DNS association evidence stay separate.
DNS association enforcement and cross-App/profile association use remain deferred.

Names attach to the existing cumulative observation boundary, not to every counted
packet or every request in that interval. The producer snapshots names after
exporting a prior attribution boundary, so a later packet cannot put its name on
that earlier record. Retention, capacity pressure, statistics and actual-END
semantics are unchanged: details own these fields, and their eviction removes the
names without creating long-term domain statistics or a shutdown snapshot.

The shared native SDK ABI is 6. Current-flow VAPI carries the same 1032-byte local
little-endian name block as normal Flow observation v12. The transport handshake
is v12 and the largest record is 1512 bytes; DNS record versions 8–11 and legacy
Flow/Blocked decoding retain their existing meanings. New Flow records always
retain the 32-byte address area before the appended names. The fixed 256-entry
short and long rings remain bounded; named Flow records use the long ring, as did
large DNS records. Queue health/loss and storage budgets continue to qualify the
retained view. Historical records missing names remain readable without backfill.

[S331 validation](../testing/2026-11-02_S331_TARGET_NAMES.md) records the normal
Root/VPN, shared Host, persistence and final projection qualifications.
