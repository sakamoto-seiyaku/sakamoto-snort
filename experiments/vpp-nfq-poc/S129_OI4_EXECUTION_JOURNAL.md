# SAKAMOTO-129 OI-4 execution journal

Date: 2026-08-23 (host Linux, x86_64)

OI-4 asks whether the owner-inline context can be replicated into independent
worker-local shards: stable tuple routing, HEV/lwIP state and timers local to
the owner, no migration/spill/global core lock, and delay/fault/wrong-owner
isolation.

## Artifacts and deterministic model

```text
state model       28718485450d147592a65da701df6a94e22e8d53445410abe3c64458ad43d92b
HEV shard runner  d3d2f694c4ad2aebf023f66bc41587a62447698db50a91a90568db9cc8d8cd6e
runner executable b035e30cbe117944f3718c3817000cd8713b414fa01d228b4dc5523c2082b38b
model output      /tmp/s129-oi4-model-current.json
model output SHA  3eb313d0c5b6fe2374d5f7226c577b97407c4052b38a62cbdba5ef0a07c47cd6
real raw output   /tmp/s129-oi4-hev-direct.raw
real raw SHA-256  550a016162c1778bae2a50eb10e6a1bec54408d76e28431fba804811c3a8e1d9
```

The model's `two_live_shards` cell routed 10 flows to shard A and 6 to shard
B; all 8 accepted fixture flows succeeded (`5/3`) and ended with residue 0.
The `fault_isolation` cell faults/stops A while B continues for four bounded
owner ticks and succeeds; both release packet/pbuf/VPP-buffer/socket-request/
completion ledgers exactly once.  The `owner_tripwires` cell rejects submit,
output, completion, and cross-worker callback deliveries without mutation.
All model cells report:

```text
global-mutable=0 core-lock=0 migration=0 spill=0 residue=0
```

The model schema is `owner-inline-oi4-shards/v2`; every resource ledger is
reported as allocated/released and equal.

The fixture includes IPv4/IPv6 TCP/UDP tuples and uses a stable canonical tuple
hash, not a mutable global routing table.

## Real two-pthread HEV/lwIP + Direct socket runner

The C runner creates two opaque `FlowStackOwner` contexts on distinct pthreads.
Shard 0 is IPv4/port 49154 and delayed 120 ms; shard 1 is IPv6/port 49164.
Each config has an owner-local UDP connector.  The connector creates a
nonblocking socket, connects to a separate loopback underlay echo (`port +
1000`), submits the payload from the owner pthread, and the owner output emits
the returned packet.  The underlay receive counter proves the bytes traversed
the real socket rather than only the model.  The first-flow barrier makes the
delay visible: B completes while A is waiting, then A is stopped through the
owner lifecycle and B runs 32 additional bounded scheduler steps without
accessing A or migrating/spilling state.

Representative raw result:

```text
oi4 owner-identity owner=0 ... owner-pthread=125095609628352 ... mutable-state=owner-local
oi4 owner-identity owner=1 ... owner-pthread=125095601235648 ... mutable-state=owner-local
oi4 direct-socket-create owner=1 fd=7 owner-pthread=125095601235648
oi4 direct-connect owner=1 result=0 add-fd=0 owner-pthread=125095601235648
oi4 direct-send owner=1 length=14 owner-pthread=125095601235648
oi4 underlay-recv owner=1 length=14
oi4 output owner=1 pthread=125095601235648 length=62
oi4 driver-stop owner=0 mode=BOUNDED_FAULT result=0 other-owner=1 untouched=1 migration=0 spill=0
oi4 shard-stop owner=0 ... packet=1/1 pbuf=1/1 session=1/1 timer=1/1 socket=1/1 residue=0
oi4 owner-continuation owner=1 after-owner0-stop accessed-owner0=0 migrated=0 spilled=0
oi4 shard-stop owner=1 task-steps=34 submitted=1 outputs=1 direct-send=1 direct-recv=0 underlay-recv=2 fault=0 driver-stopped=1 packet=1/1 pbuf=1/1 session=1/1 timer=1/1 socket=1/1 residue=0
oi4 tripwire kind=submit target-owner=1 expected-owner=0 rejected=1 callback-mutated=0
oi4 tripwire kind=output target-owner=1 expected-owner=0 rejected=1 callback-mutated=0
oi4 tripwire kind=completion target-owner=1 expected-owner=0 rejected=1 callback-mutated=0
oi4 tripwire kind=callback target-owner=0 expected-owner=1 rejected=1 callback-mutated=0
oi4 tripwire wrong-owner-submit=1 wrong-owner-output=1 wrong-owner-completion=1 cross-worker-callback=1 migration=0 spill=0 global-mutable=0 core-lock=0
schema=owner-inline-oi4-hev-shards/v3 owners=2 owner0-output=1 owner1-output=1 owner0-direct-send=1 owner1-direct-send=1 owner0-underlay-recv=2 owner1-underlay-recv=2 owner1-post-stop-steps=32 ... residue=0
```

The UDP connector's returned packet is reported through the owner output
callback; its optional connector-output callback remains zero in this bounded
HEV ABI path.  The direct-send plus underlay-recv and owner-thread output are
the transport evidence, while the model covers the explicit timer/session and
wrong-owner ledgers.  The `packet=1/1` etc. fields in the real runner are
bounded fixture-owned allocation/settlement counters; the model is the exact
owner-resource ledger.  This is not a capacity/soak result and does not claim
four-worker Android coverage.  The second owner continuation is deliberately
reported as scheduler isolation, not as a fabricated second flow: this
one-shot ABI stops its task after the first output.

## OI-4 conclusion

**SCOPED_SHARD_ISOLATION_GO.** The original two-owner design survives a real
two-pthread HEV/lwIP run with independent IPv4/IPv6 UDP Direct sockets, owner0
stop/owner1 continuation, bounded runner closure counters, and the model's
IPv4/IPv6 TCP/UDP tuple, fault, and tripwire matrix.  The real runner does not
claim four-worker Android coverage or capacity.  The separate TCP addendum
below closes the bounded real two-owner TCP transport seam.  Continue to
bounded OI-5 generation/epoch teardown; no production conclusion is implied.

## Real two-pthread TCP shard addendum

To close the real-transport gap without changing the original UDP runner, the
bounded TCP runner was added as a separate executable:

```text
source  oi4_hev_tcp_shard_probe.c
        SHA-256 3c881a9a2dd005d06e71fc7043e56c1103040119dea4019ef502f6980a9663f1
binary  /tmp/oi4-hev-tcp-shard-probe
        SHA-256 1edb2f0fe41fc5c8a277785e0aafea8e4eb7f26dff70e39b98f4f821174090ed
raw     /tmp/s129-oi4-hev-tcp.raw
        SHA-256 4fb780b8d52acbca2e48236e6b07ef3c17fe11e056ae3ef380bf79ea508eb58a
```

The raw run is `rc=0` and reports, for both owner 0 (IPv4) and owner 1
(IPv6), `tcp-handshake`, `direct-socket-create`, `tcp-connect`,
`tcp-direct-send`, two underlay receives, `tcp-direct-recv`, and owner output.
Each owner submitted four packets (SYN/ACK/payload/FIN), settled
`packet=4/4 pbuf=4/4 session=1/1 timer=1/1 socket=1/1 residue=0`, and drained
one post-stop task step before destroy.  Owner 0 stopped with
`other-owner=1 untouched=1 migration=0 spill=0`; owner 1 then continued for
32 bounded owner steps.  The three wrong-owner events and cross-worker callback
were each rejected with `callback-mutated=0`.

This closes the previously stated real-TCP boundary for the bounded two-owner
host seam.  It still does not claim four-worker Android coverage, capacity,
pressure, soak, or release readiness.
