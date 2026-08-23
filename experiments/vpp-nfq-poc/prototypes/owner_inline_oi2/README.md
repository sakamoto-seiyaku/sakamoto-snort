# Owner-inline OI-2 broker contract prototype

This is a throwaway logic prototype for one bounded question:

> Can a VPP FlowOwner submit an opaque socket-preparation request without
> waiting, let a separate Android broker perform bind/protect, and consume a
> completion exactly once without reviving a stopped or foreign flow?

The model deliberately keeps the socket identity, `SCM_RIGHTS` duplicate,
generation, owner, shard, and underlay epoch visible. It does not claim that a
Python model is the Android implementation; the next gate must exercise the
same contract through real Unix sockets and the Pixel `VpnService.protect()`
boundary.

Run all deterministic cells with:

```text
rtk python3 experiments/vpp-nfq-poc/prototypes/owner_inline_oi2/state_machine.py
```

The command exits non-zero if an invariant is violated and prints a compact
JSON evidence ledger otherwise.
