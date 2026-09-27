# T23 directional attribution and maintained effects

SAKAMOTO-275 extends the existing owner export, real C transport → Rust
consumer/query, and SQLite recovery seams. It retains ADR-0009/0010 ownership,
T21's single generation claim and E02's single live aggregate. Full retention
and rollups remain T27; the recent-history interpretation API remains T26.

Each ORIG/REPLY direction retains its own segment identifier, segment-start
cumulative packet/byte counters, last real activity UTC, application UID/network,
complete snapshot generation/revision/hash, complete winning rule version,
contemporaneous name, declared/actual action and mode. A known NoMatch has winner
zero, ALLOW and no rule hit. An empty name means none was supplied; Rust never
substitutes a current name or policy. Unknown application is the existing
`UINT32_MAX` subject, independent of unavailable attribution provenance.

The Flow tracker must process a packet before POST policy facts are available.
The observation owner therefore retains the previous directional cumulative
boundary separately: on changed final attribution it exports that exact old
boundary before advancing observation counters for this packet. Flow identity,
CT state and total counters are unchanged by a rule update. The first packet of
the new segment is exported; ordinary subsequent growth can coalesce. END uses
retained segment context and activity timestamps, including unexported tail.
No packet, rule text, pointer, ACK or retransmit obligation is added.

Wire V3 retains the first 128 bytes of V2 and adds two 144-byte directional
contexts before addresses at offset 416. IPv4/IPv6 lengths are 424/448 bytes;
queue classes are 432/448 bytes with the existing 256 slots per class/channel.
The generation handshake requires the matching version/layout. Both sides reject
incompatible live streams. Old persisted V2 records deserialize with unavailable
attribution; the upgrade preserves their totals and explicitly marks that
historical attribution unavailable. It does not reread the legacy JSON after an
E02 SQLite import or recalculate history from current policy.

For each accepted record Rust stages checked deltas and all affected rows, then
advances the baseline, lifecycle, overall minutes, application windows, rule
windows and unattributed minutes together. A segment start bounds what can be
proved after a lost boundary. Only the delta after that start belongs to the
current attribution; remaining recovered growth is unattributed. Duplicate,
stale, retired or rolled-back records cannot recount. A segment cannot change
its starting counters or context while retaining the same identifier.

Application windows key minute/UID/actual action. Rule windows additionally key
network, complete snapshot identity, full rule version, declared action and mode;
each carries the contemporary name. Directional counts stay ORIG/REPLY. Rule
counts are logical winner hits; observe DROP with actual ALLOW remains distinct
from actual policy DROP. Default ALLOW contributes to the application once and
has no rule row. Runtime/basic accounting remains independent from these Flow
history views and from transport delivery.

The normal `consumer.persistent` API exposes `application_windows`,
`rule_windows`, `attribution_unknown`, `attribution_unknown_minutes` and
`legacy_unattributed`, along with counts, limits and truncation fields. Each
window query returns at most 2,880 newest maintained rows. Queries include pending
increments; persistence status still distinguishes committed totals and pending
work. Minutes use each attributable direction's last activity, with unresolvable
remainders placed at the record's last activity. Placement is approximate and
does not imply per-packet timestamps or a one-bucket error guarantee.

SQLite row kinds 4/5/6 hold application/rule/unattributed windows in the same
transaction as kinds 0–3. Metadata's attribution schema 1 distinguishes upgraded
history. There are at most 65,536 application and 65,536 rule window rows, with
the existing bounded baseline/recent/minute state. Keys are at most 192 bytes and
row payloads at most 4 KiB. The 4,096 dirty-key bound and one-second/2,048-row
commit policy remain; commits may occur between records within a drain to admit
multi-view work safely. Failed writes retain bounded dirty state, expose errors
and gaps, and never wait on a VPP owner. Existing SQLite database/WAL/workspace
limits remain; this slice does not promise the completed T27 retention policy.

Query presentation is built only when the API requests it, on the consumer
thread between complete drains. Background aggregation and idle SQLite commits
continue without queries. Concurrent requests may share a consistent projection;
requests arriving during construction retain their own sequence for a later
answer. Paused consumers still answer queries. `query_fresh: true` means the
owning consumer answered that request, including its accepted pending state;
it does not claim the producer queue is empty. The API waits up to two seconds
for the owner response. On timeout it returns the previous coherent projection
(or an empty object before the first answer), marked `query_fresh: false` and
`query_error: observation_query_timeout`. Projection runs outside the shared
control lock; copying and serializing the returned response are additional work,
so two seconds is not an end-to-end RPC latency guarantee. Shutdown publishes a
final inactive, incomplete view.
