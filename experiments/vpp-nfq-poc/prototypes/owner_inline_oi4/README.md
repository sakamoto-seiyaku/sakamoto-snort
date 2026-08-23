# Owner-inline OI-4 shard-isolation prototype

This deterministic model answers one bounded question: can two canonical
FlowOwner shards keep all HEV/lwIP mutable state, timers, PCBs, and sockets
worker-local while one shard is delayed or faulted?  The companion C runner
also creates two real HEV/lwIP contexts on two pthreads, sends each shard's
UDP payload through a worker-owned nonblocking Direct socket to a loopback
underlay echo, and records the returned owner output.

It deliberately does not claim production capacity or Android transport
coverage.  It proves the ownership seam and its rejection tripwires:

- canonical tuples map to A or B and never migrate/spill;
- a stalled/faulted A does not stop B;
- a completion delivered to the wrong owner is rejected;
- every accepted flow drains its owner-local buffer/session/socket ledger;
- each real shard records `direct-send=1`, at least one underlay receive, and
  an owner-thread output before teardown.

Run it with:

```text
rtk python3 experiments/vpp-nfq-poc/prototypes/owner_inline_oi4/state_machine.py

gcc -O2 -Wall -Wextra -pthread -o /tmp/oi4-hev-shard-probe \
  experiments/vpp-nfq-poc/prototypes/owner_inline_oi4/oi4_hev_shard_probe.c -ldl

gcc -O2 -Wall -Wextra -pthread -o /tmp/oi4-hev-tcp-shard-probe \
  experiments/vpp-nfq-poc/prototypes/owner_inline_oi4/oi4_hev_tcp_shard_probe.c -ldl
```

The TCP variant is a separate bounded runner: both owner pthreads use real
IPv4/IPv6 TCP FlowStackOwner sessions, nonblocking owner-local Direct sockets,
and loopback stream echoes.  It drives SYN/ACK, payload, and FIN before a
post-stop task drain, so the real HEV owner-session set is settled before
destroy (no assertion-based cleanup shortcut).  It is still a two-pthread
host cell, not a capacity or Android result.
