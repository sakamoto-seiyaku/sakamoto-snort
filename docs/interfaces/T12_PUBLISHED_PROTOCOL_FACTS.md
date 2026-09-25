# T12 published application-protocol facts

The native compiler/matcher accepts postfix opcode `15` followed by a
little-endian `uint32` stable application-protocol catalog ID. Invalid/reserved
IDs reject compilation. It means membership in the complete currently published
set, with separate availability. Existing strong three-valued AND/OR/NOT and
whole-rule placement apply. Provider numbers and categories are not predicates.
The existing Rust/native management request transports these source bytes
unchanged; VPP remains validator/compiler/owner.

The packet input carries a value-only catalog bit projection plus availability.
The generated C catalog assigns bits to active rows; these bits are an internal
software-build projection, not persistent identity. The all-application
compiled dependency union includes every protocol leaf, including losing and
negated leaves. Complete-result cache guards include the entire set and its
availability as well as the packet's existing snapshot and Flow incarnation.
No dependency is inferred from only the previous winner.

`product_flow_entry_identify` is an owner-only synchronous native seam: pool,
slot, generation, incarnation, normalized PacketFacts and borrowed current L4
payload. It rejects stale identities before mutation and never stores borrowed
pointers. One bounded LPI state lives inside the existing FlowEntry; policy
publication retains it, Flow destruction/reuse clears it. A caller obtains
facts and producer status from the existing barrier-protected Flow query.
Main initializes the immutable official libprotoident registry before workers.
The C packet domain projects features through a small private C ABI to the
upstream dependency; it does not import fork/POC or removed product sources.

Recognition attempts inspect current per-direction payload prefix/length,
accumulate mapped catalog facts by union, and make new facts available before
that same packet's post-flow query. A miss or unmapped result preserves prior
facts; neither manufactures Unknown. The catalog currently has no explicit
Unknown ID. Producer stop reason and last attempt outcome are independent of
fact availability. Empty payloads do not consume attempts. Initial finite
limits are 20 payload attempts and 32 KiB examined payload per Flow, retained
across configuration changes. This bounded observation window permits multiple
results; reaching either limit stops future calls without removing facts.
There is no packet holding, second flow table, packet-side allocation or
unbounded retry. Flow end stops any remaining producer.

Acceptance and measured storage/target behavior are recorded separately in the
dated T12 verification report. Later SNI/reassembly capabilities consume these
published facts and own their integration regression; this contract does not
claim their implementation.

## Query and footprint

`show product flows` adds `flow.lpi` for each existing Flow identity:
`available`, full `protocols` projection, `attempts`, credited payload `bytes`,
`stop`, `outcome` and readable `stop_reason`. Separate `flow.protocol_fact` rows
expose stable catalog `id` and `key` without making the internal bit position a
public protocol identity. Stop values are running=0, packet_budget=1,
byte_budget=2, flow_end=3 and unsupported=4; last outcome is no_attempt=0,
temporary miss=1, unmapped=2, mapped=3. This is the existing barrier-protected
native query boundary, not a new normal-observation/history API.

The observed x86-64/ARM64 LPI state is 56 bytes in each existing FlowEntry.
Cache entries grow by 16 bytes to guard the whole value/availability projection;
128 entries consume 23,584 bytes per worker. Exact target evidence and limits:
[dated T12 acceptance](../testing/2026-09-25_T12_PUBLISHED_PROTOCOL_FACTS.md).
