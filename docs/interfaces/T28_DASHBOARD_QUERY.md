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
