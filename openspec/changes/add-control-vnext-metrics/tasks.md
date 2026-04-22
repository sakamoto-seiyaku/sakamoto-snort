## 1. vNext Metrics Handler Plumbing

- [x] 1.1 Add vNext metrics command handler module (`src/ControlVNextSessionCommandsMetrics.*`)
- [x] 1.2 Wire metrics handler into `src/ControlVNextSession.cpp` dispatch order (after iprules handler)
- [x] 1.3 Ensure `METRICS.RESET` runs under exclusive `mutexListeners` lock; `METRICS.GET` under shared lock

## 2. `METRICS.GET` Surface (v1 names)

- [x] 2.1 Implement strict args parsing + unknown-key reject for `METRICS.GET` (`SYNTAX_ERROR`)
- [x] 2.2 Validate `args.name` is one of `perf|reasons|domainSources|traffic|conntrack` (`INVALID_ARGUMENT` on unknown)
- [x] 2.3 Enforce selector constraints: allow `args.app` only for `traffic` and `domainSources`; others reject (`INVALID_ARGUMENT`)
- [x] 2.4 Resolve `args.app` via `ControlVNextSessionSelectors::resolveAppSelector` with structured errors (`SELECTOR_NOT_FOUND/AMBIGUOUS + candidates[]`)
- [x] 2.5 Implement `name=perf` response shape (`result.perf{...}`) and reuse existing perf snapshot semantics
- [x] 2.6 Implement `name=reasons` response shape (`result.reasons{...}`) and reuse existing reason counters snapshot
- [x] 2.7 Implement `name=domainSources` response shape (device-wide `result.sources{...}`; per-app adds `uid/userId/app`)
- [x] 2.8 Implement `name=traffic` response shape (device-wide + per-app) per `traffic-observability` spec
- [x] 2.9 Implement `name=conntrack` response shape per `conntrack-observability` spec

## 3. `METRICS.RESET` Surface (reset boundaries)

- [x] 3.1 Implement strict args parsing + unknown-key reject for `METRICS.RESET` (`SYNTAX_ERROR`)
- [x] 3.2 Implement reset for `perf|reasons|domainSources|traffic` (device-wide + per-app where applicable)
- [x] 3.3 Reject `METRICS.RESET(name=conntrack)` with `INVALID_ARGUMENT` (hint: use `RESETALL`)
- [x] 3.4 Verify `RESETALL` clears `perf/reasons/domainSources/traffic/conntrack` counters

## 4. Traffic Counters (hot path, fixed-dimension atomics)

- [x] 4.1 Add fixed-dimension traffic counters type (DNS + packet: `dns/rxp/rxb/txp/txb` × `{allow,block}`)
- [x] 4.2 Add per-app traffic counters to `src/App.hpp` with `observe/snapshot/reset` APIs (no gating by `tracked`)
- [x] 4.3 Update `src/DnsListener.cpp` to observe `dns.allow|dns.block` per DNS verdict when `settings.blockEnabled()==true`
- [x] 4.4 Update `src/PacketManager.hpp` to observe `rxp/rxb/txp/txb` per final verdict for all verdict paths (bytes use NFQUEUE payload length)
- [x] 4.5 Implement device-wide traffic aggregation for `METRICS.GET(name=traffic)` (full: include tracked + untracked apps)

## 5. Conntrack Metrics Exposure

- [x] 5.1 Expose `Conntrack::metricsSnapshot()` via a read-only `PacketManager` accessor for the vNext metrics handler
- [x] 5.2 Confirm conntrack counters are reset by `PacketManager::reset()` and therefore by `RESETALL`

## 6. Host P0 Unit Tests

- [x] 6.1 Add host test target `control_vnext_metrics_surface_tests` and wire into `tests/host/CMakeLists.txt`
- [x] 6.2 Add tests for strict reject (unknown args key) + invalid `name` (`INVALID_ARGUMENT`)
- [x] 6.3 Add tests for selector constraints (unsupported `app` field rejection; selector not-found/ambiguous errors)
- [x] 6.4 Add tests for `traffic` shapes (device-wide + per-app) and reset semantics (device-wide + per-app)
- [x] 6.5 Add tests for `conntrack` shape + `METRICS.RESET(name=conntrack)` rejection (`INVALID_ARGUMENT`)
- [x] 6.6 Run host tests under ASAN/UBSAN preset (fix any memory/UB issues before proceeding)

## 7. Integration (P1)

- [x] 7.1 Extend `tests/integration/vnext-baseline.sh` to cover `METRICS.GET` shape checks for `perf|reasons|domainSources|traffic|conntrack`
- [x] 7.2 Add a minimal, best-effort traffic generation step and validate `traffic` counters increase + reset clears (skip with explicit message if traffic cannot be produced deterministically)
- [x] 7.3 Add integration checks for reset boundary: `METRICS.RESET(name=conntrack)` must fail; `RESETALL` clears conntrack counters

## 8. Docs / Spec Sync

- [x] 8.1 Update `docs/INTERFACE_SPECIFICATION.md` with vNext `METRICS.GET/RESET` (names, args, shapes, reset boundaries)
- [x] 8.2 After implementation, sync delta specs to main specs (`openspec sync-specs`) and archive the change (`openspec archive`)
