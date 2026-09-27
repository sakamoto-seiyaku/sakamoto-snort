# T25 protocol-window interface

SAKAMOTO-277 extends the VPP-native C observation producer and the existing
Rust consumer/SQLite live aggregate. The stable application-protocol catalog is
the identity authority. Provider-private IDs never cross this interface.

## Producer and wire

For a tracked Flow packet, the owner reads the Flow's published LPI mask and
availability **after** recognition and final policy evaluation. It stores both
in that packet direction's observation segment. A changed mask or availability
forces the previous cumulative boundary to be exported before the packet is
counted under the new fact. Repeating the same set can coalesce; another
direction keeps its own segment. PRE Blocked observations have no Flow or LPI
producer and always carry unavailable, empty L7 facts.

Observation wire V5 extends each directional attribution from 144 to 160 bytes:
the 64-bit stable-catalog bit mask is at offset 144, availability at 152 and
seven zero padding bytes follow. Attribution starts at record offsets 128 and
288. Addresses start at 448; IPv4/IPv6 records are 456/480 bytes. The four
owner/kind channels retain 256 entries in each of the 464/480-byte rings.
Version, lengths, reserved bytes, masks, availability and Blocked shape are
checked by Rust. The generation handshake rejects a mixed live V4/V5 pair;
old committed JSON/SQLite records deserialize with unavailable protocol facts.

The C owner owns its bounded slot and performs nonblocking best-effort export.
It does not wait for Rust, SQLite, a receipt or a retry. A full channel or
missing predecessor is a coverage gap, not permission to attribute recovered
growth to the newest label.

## Rust consumption and query

One accepted record advances the baseline, overall minute, application and
rule windows, and protocol windows in the same live merge and SQLite
transaction. Each provable directional increment contributes once to its L4
protocol and once to **each distinct** published L7 catalog label. Overall,
application and rule totals receive that increment once. A later label does
not receive earlier traffic. An available empty set is `l7_none`; unavailable
recognition is `l7_unavailable`. Growth whose attribution boundary is missing
is kept in the existing unattributed view and in `l4_unknown`/`l7_unknown`.

SQLite kind 7 holds bounded protocol minute rows. Keys contain UTC minute,
application UID, actual result, layer and stable protocol ID. The existing
4,096 dirty-key and 64 MiB database bounds apply; admission, overflow and
storage errors retain explicit gaps and never block a packet owner. An old
store with no protocol schema keeps every prior total, marks it
`legacy_protocol_unavailable`, and starts new protocol windows only for new
accepted records. Committed rows and baseline advance atomically. Pending
increments appear in queries before their durability commit.
Reopening history validates persisted L7 IDs and keys against released catalog
identities, including reserved tombstones. Historical baseline masks are kept
as recorded; newly received V5 masks must use the current active bit positions.

`consumer.persistent.protocol_windows` returns at most 2,880 newest maintained
rows with the total row count and truncation flag. Each row carries minute,
UID, actual action, layer, stable protocol ID/key, directional packet/byte
counts, the matching application-window directional denominator, and four
shares derived from these counts. A zero denominator yields `null`. L7 shares
can sum above 1.0 because labels overlap. The same response exposes
`l4_unknown`, `l7_unknown`, `legacy_protocol_unavailable` and
`coverage.protocol_incomplete`. `l7_none` is an observed no-result fact and is
separate from unavailable recognition. Existing `query_fresh` describes the
owner's answer; SQLite commit status remains separate.

Full 48-hour/30-day/180-day retention and database-space policy remain T27.
The API presents maintained minutes and explicit truncation until that work.
