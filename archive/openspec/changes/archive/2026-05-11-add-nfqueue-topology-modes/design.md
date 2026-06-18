## Context

`PacketListener` currently computes an even queue count per IP family, splits that range into `_inputQueues` and `_outputQueues`, installs INPUT and OUTPUT NFQUEUE rules on disjoint ranges, and derives packet direction from the listener thread partition through `_inputTLS`. This is the `split-in-out` topology and remains the default.

The next topology experiment is `shared-flow-pool`: for the same IP family, INPUT and OUTPUT should both target the same queue range so NFQUEUE connection stickiness can keep both directions of a flow on the same listener more often. Correctness still cannot depend on that affinity, and the packet hot path must stay free of broad locks, per-packet allocation, or extra control-plane lookups.

## Goals / Non-Goals

**Goals:**

- Add a persisted string enum device config `nfqueue.topology` with values `split-in-out` and `shared-flow-pool`.
- Keep `split-in-out` as the default and preserve existing behavior unless the configured mode is changed before daemon startup.
- Implement startup queue planning for both IPv4 and IPv6 without changing the one-queue-one-listener model.
- Derive packet direction from the NFQUEUE packet hook whenever topology can no longer imply direction.
- Preserve downstream semantics for remote IP selection, IPRULES direction matching, traffic counters, Flow Telemetry direction fields, and Debug Stream direction fields.
- Keep the Chinese interface contract in `docs/INTERFACE_SPECIFICATION.md` aligned with the new config key and restart requirement.

**Non-Goals:**

- No hot switch while the daemon is running.
- No change to conntrack correctness assumptions or internal concurrency protection.
- No per-flow owner table, worker migration, CPU affinity, or private per-worker conntrack table.
- No telemetry ABI or IPRULES rule schema change.

## Decisions

1. **Persist a string enum in `Settings`**

- Choice: add a small typed enum internally, serialize it through the existing `/data/snort/settings` save file, and expose it through vNext as `nfqueue.topology`.
- Rationale: a string enum avoids a bool-shaped API and leaves room for future topology profiles.
- Alternative rejected: use a boolean such as `nfqueue.shared`. That would make later topology variants awkward and ambiguous.

2. **Make topology next-start only**

- Choice: `CONFIG.SET(scope=device,set={"nfqueue.topology":...})` persists the configured value, but the active listeners and iptables rules are not rebuilt until the daemon is restarted.
- Rationale: current PacketListener startup owns NFQUEUE rule installation and detached listener creation. Rebuilding that live would require a separate lifecycle/quiesce design and would add risk unrelated to the topology experiment.
- Alternative rejected: live reconfigure iptables and listeners. That would need listener shutdown ownership, queue unbind ordering, packet drain semantics, and stream/telemetry diagnostics.

3. **Split queue planning from listener direction**

- Choice: add a small queue-plan helper used by `PacketListener::start()` to compute INPUT and OUTPUT rule ranges from the active topology.
  - `split-in-out`: INPUT uses the first half and OUTPUT uses the second half of the IP-family range.
  - `shared-flow-pool`: INPUT and OUTPUT both use the full IP-family range.
- Rationale: queue planning is startup-only; isolating it keeps the hot path unchanged except for direction derivation.
- Alternative rejected: duplicate branch logic at iptables command construction and listener startup sites. That would increase the risk of IPv4/IPv6 drift.

4. **Derive direction from NFQUEUE hook**

- Choice: map `NF_INET_LOCAL_IN` to input and `NF_INET_LOCAL_OUT` to output using `nfqnl_msg_packet_hdr::hook`, then pass that per-packet boolean through existing downstream calls.
- Rationale: `shared-flow-pool` makes queue/thread partition unable to represent direction. The hook is already in the packet header parsed by the callback.
- Alternative rejected: infer direction from `NFQA_IFINDEX_INDEV` / `NFQA_IFINDEX_OUTDEV`. Those attributes are useful interface metadata, but the netfilter hook is the direct source for INPUT/OUTPUT chain direction.

5. **Keep `_inputTLS` only as compatibility state during migration**

- Choice: implementation may keep `_inputTLS` for listener setup or split-mode assertions, but packet decisions must use a per-packet direction variable derived from hook.
- Rationale: this avoids a large mechanical refactor while removing the semantic dependency that shared mode breaks.
- Alternative rejected: preserve `_inputTLS` as the decision input in split mode and use hook only in shared mode. That would create two direction sources and make tests less meaningful.

## Risks / Trade-offs

- [Risk] Some NFQUEUE packets arrive with an unexpected hook -> Mitigation: accept the packet without policy blocking or treat direction as unavailable in a fail-open path, and cover this with a focused unit test.
- [Risk] Settings file version migration is easy to get wrong -> Mitigation: bump the settings version, default older saves to `split-in-out`, and test restore of older settings.
- [Risk] Shared queue range reduces direction isolation and can change performance distribution -> Mitigation: keep `split-in-out` as default and validate `shared-flow-pool` through device perf/stability runs before considering a default change.
- [Risk] Direction source changes can regress observability -> Mitigation: add host coverage for hook mapping and device smoke checks that compare packet direction surfaces in both modes.

## Migration Plan

- Existing installs restore without the new setting and default to `split-in-out`.
- New `CONFIG.SET` persists the next-start value immediately using the existing settings save path.
- The Chinese interface document must state that RuntimeService/frontends own the stop/start sequence needed to activate a changed topology.
- Rollback is `CONFIG.SET nfqueue.topology=split-in-out` followed by daemon restart.

## Open Questions

None for this change. Exposing a separate active-mode key such as `nfqueue.topology.active` remains a future diagnostic option and is not part of this contract.
