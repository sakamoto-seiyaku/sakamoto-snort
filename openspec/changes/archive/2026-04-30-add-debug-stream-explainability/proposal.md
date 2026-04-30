## Why

Flow Telemetry now owns normal high-cardinality records, while vNext `STREAM.START(type=dns|pkt)` remains the only short-lived diagnostic channel for per-event evidence. Debugging policy issues still requires joining scattered fields, metrics, and manual rule inspection; the stream should carry enough structured, self-contained explanation to reconstruct why a DNS or packet verdict happened from the event alone.

## What Changes

- Reposition vNext `dns` and `pkt` streams as Debug Stream outputs: tracked-gated, short-lived, high-detail, and explicitly separate from Flow Telemetry records, history/timeline views, and low-cardinality metrics.
- Extend `dns` stream events with a structured `explain` object containing the ordered DomainPolicy stages, matched/winning rule and list-entry snapshots, shadowed stages, fallback mask inputs, and truncation markers for bounded candidate lists.
- Extend `pkt` stream events with a structured `explain` object containing the ordered packet verdict stages, including self-contained IPRULES rule definition snapshots, `IFACE_BLOCK` mask evidence, legacy domain/IP leak fallback, and IPRULES would-match overlay.
- Keep `tracked=1` as the gate for per-event Debug Stream output; `tracked=0` continues to suppress event construction and report only aggregate suppressed notices.
- Keep command compatibility for `STREAM.START(type="dns"|"pkt"|"activity")`, but define only `dns` and `pkt` as Debug Stream surfaces. `activity` remains a compatibility stream and does not gain new debug semantics.
- Re-scope legacy stream duties in this change: replay parameters are a bounded debug prebuffer, notices are debug delivery diagnostics, and the stream must not be treated as the normal record/history/timeline API.
- Update `docs/INTERFACE_SPECIFICATION.md` so clients treat `explain` as the authoritative debug evidence chain for `dns` and `pkt` events; existing top-level fields are compatibility summaries only.
- Do not add Flow Telemetry records, Metrics names, DEV query surfaces, Top-K/timeline/history aggregation, or long-term storage.

## Capabilities

### New Capabilities

- `debug-stream-explainability`: Defines the structured evidence chains carried by tracked Debug Stream DNS and packet events, including bounded candidate output and non-overlap with Flow Telemetry/Metrics.

### Modified Capabilities

- `control-vnext-stream-surface`: Changes the `dns` and `pkt` event contracts to include structured `explain` objects while preserving the existing `STREAM.START/STOP` state machine.
- `dx-smoke-domain-casebook`: Adds device coverage proving DNS Debug Stream events can explain app/device/fallback DomainPolicy decisions.
- `dx-smoke-ip-casebook`: Adds device coverage proving packet Debug Stream events can explain IPRULES allow/block, would-match, and `IFACE_BLOCK` decisions.

## Impact

- Affected APIs: vNext `STREAM.START(type=dns|pkt)` event JSON shape, debug-prebuffer semantics for stream replay, and `docs/INTERFACE_SPECIFICATION.md`.
- Affected code: `ControlVNextStreamManager` event snapshots, stream JSON builders, DNS verdict attribution helpers, packet verdict attribution helpers, and IPRULES debug evaluation helpers.
- Affected tests: host stream JSON/helper tests, domain/IP device smoke cases, and sanitizer runs for changed C++ paths.
- Dependencies: no new external libraries, no persistent data migration, and no Flow Telemetry ABI change.
