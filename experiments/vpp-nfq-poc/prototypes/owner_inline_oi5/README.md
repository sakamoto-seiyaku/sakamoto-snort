# Owner-inline OI-5 generation/epoch teardown prototype

This bounded model checks teardown and restart identity, not soak or release
capacity.  It exercises runnable/waiting owners, established TCP/FIN state,
UDP timer state, socket/broker tokens, output/TUN wakeups, fd/stale/duplicate
late events, underlay epoch invalidation, one forced Flow Stack restart, and
exact quiesce/drain/close/settle resource ledgers.

The required result is that `generation=N` events cannot touch
`generation=N+1`, old TCP does not reconnect, old UDP is not reused, and every
owner-local resource/buffer ledger reaches zero.  Two shards are stopped and
restarted independently in the multi-shard cell.  The fresh underlay snapshot
must use the new epoch, and a forced fault permits one bounded restart before a
fresh flow succeeds.

```text
rtk python3 experiments/vpp-nfq-poc/prototypes/owner_inline_oi5/state_machine.py
```
