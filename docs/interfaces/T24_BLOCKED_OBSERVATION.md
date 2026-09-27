# T24 pre-Flow blocked observation contract

[SAKAMOTO-276](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/74a66a66-7be5-425f-8761-5ab18928d4ae)
extends the [T23 directional record](T23_DIRECTIONAL_ATTRIBUTION.md) for a
complete PRE policy winner whose **actual** action is DROP. It does not inspect
or allocate `FlowEntry`, advance CT, run LPI, or retain packet payloads. The
terminal packet path still owns the independent basic ALLOW/policy-DROP/runtime
accounting, including when no blocked slot is available.

Each execution owner has a bounded blocked table, separate from its Flow pool.
The key is the assigned canonical five-tuple (or eligible ICMP query identity)
plus the UID and network context available at that packet. Rule ID and policy
version are attribution, never table identity. The first blocked packet fixes
origin/reply orientation. Opposite packet directions maintain separate
cumulative counters and attribution segments. A later rule version on the same
key exports the old boundary before counting the new winner. Flow and Blocked
Observation slots may have the same number and overlapping lifetimes; no record
changes kind or transfers counters between them.

The per-owner blocked capacity is `min(Flow capacity, 1,024)` slots. A new key
at capacity loses its observation only; `health.channels[owner*2+1].allocation_lost`
and `health.blocked_capacity_misses[owner]` advance. The next generation starts
with empty blocked state. Thirty seconds after its **last real blocked packet**,
an idle timer emits one cumulative END with any pending tail and frees the slot;
it does not read TCP FIN/RST, advance CT or change Flow activity. Subsequent
same-tuple blocking uses a new monotonically increasing incarnation. Creation,
attribution change, 32 packets, or 65,536 bytes trigger an immediate cumulative
export; otherwise a one-second pending flush uses the existing owner deadline
driver. A full or unavailable channel loses evidence without waiting or replay.

Observation transport V4 keeps the V3 424/448-byte record layout and uses flag
bit `8` for Blocked Observation. Even channels remain Flow and basic-accounting
channels; each owner's odd channel carries blocked records. The matching
handshake version rejects an older consumer. A record's generation, owner,
slot, incarnation and sequence identify one monotone instance. `CREATE`,
`END` with idle/expired reason `2`, clock-change, directional counters, contemporaneous rule name/version,
declared/actual action, UID/network, addresses and ports retain T23 meanings.
No ACK, retry, borrowed pointer or new packet-domain Rust callback is added.

Rust consumes both channels on one owner thread. It keeps separate in-memory
`overview.records` and `overview.blocked_records`, and uses a `B:` prefix for
blocked SQLite baseline/recent keys; existing Flow keys and old rows remain
unchanged. Blocked contributions join the same overall, application and rule
minute windows once. `persistent.blocked` and overview blocked counters expose
their own packet/byte/END totals. `blocked: true` in recent records preserves
kind after END. Transport loss or blocked allocation loss makes coverage
incomplete; a missing boundary is not attributed to the latest rule. A
duplicate, stale, rolled-back or post-END update cannot recount. On-demand
queries retain T23's coherent accepted-pending versus committed distinction.

Invalid identity/shape is rejected at the consumer; VPP's basic counters
continue independently. Interface callers exercise real C→Rust transport,
SQLite restart, simultaneous B/F slots and API query shape. Real packet
validation separately establishes PRE placement, packet outcome, Flow/CT
nonmutation, idle retirement and pressure costs.
