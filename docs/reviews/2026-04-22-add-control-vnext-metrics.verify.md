# Verification & Code Review Report — `add-control-vnext-metrics`

Date: **2026-04-22**  
Scope: **review-only** (no fixes or remediation steps listed)

## Context

- OpenSpec change was unarchived and is currently active at:
  - `openspec/changes/add-control-vnext-metrics/`
- Prior review observed a stale-device-binary failure where `METRICS.GET/RESET` returned `UNSUPPORTED_COMMAND`.
- This rerun verifies the current manually rebuilt/default device binary at:
  - `build-output/sucre-snort`

## Environment

- Base git commit: `040b4e0`
- Workspace state at rerun: working tree contains staged change files (see `git status`).
- Explicit constraint for this rerun: do **not** invoke `snort-build-regen-graph`.

## Scorecard

| Dimension | Status | Notes |
|---|---:|---|
| Completeness | PASS | OpenSpec tasks show **34/34** done. |
| Correctness (host) | PASS | `snort-host-tests` passed (Debug + ASAN). |
| Correctness (device) | PASS | `p1-vnext-baseline` passed against the current deployed `build-output/sucre-snort`. |
| Coherence | PASS | Handler layering, strict-reject, selector errors, lock lanes, and hot-path constraints match stated design intent. |

## Findings

### CRITICAL

None found in the rerun.

### WARNING

1) **Delegated direct-ninja build path remains a known stale-graph risk**

- Evidence:
  - Previous review observed `cmake --build --preset dev-debug --target snort-build` failing to link `handleMetricsCommand`.
  - This rerun intentionally did not invoke `snort-build` or `snort-build-regen-graph`; it verified the already manually rebuilt default device binary instead.
- Impact:
  - The feature is verified on-device with the current binary, but the delegated direct-ninja shortcut path still needs separate workflow review before relying on it after `Android.bp` source-list changes.

### SUGGESTION

None remaining after rerun cleanup.

### Resolved Suggestions

1) **SPDX header year range inconsistency in new header**

- Status:
  - Resolved by aligning `src/TrafficCounters.hpp:2` with the existing `2024-2028 sucré Technologies` project convention.

## Prior Finding Status

| Prior Finding | Current Status | Evidence |
|---|---:|---|
| `METRICS.GET/RESET` returned `UNSUPPORTED_COMMAND` on-device | RESOLVED IN RERUN | `p1-vnext-baseline` passed after deploying the current `build-output/sucre-snort`. |
| `snort-build` direct ninja reuse failed to link `handleMetricsCommand` | NOT RERUN | Excluded by explicit rerun constraint; remains a build-workflow risk, not a feature-surface failure in this rerun. |
| `snort-build-regen-graph` had no completion result | NOT RERUN | Excluded by explicit rerun constraint. |

## Evidence: Implementation Mapping (selected)

- vNext command dispatch + lock lanes:
  - `src/ControlVNextSession.cpp:224` (exclusive lane includes `METRICS.RESET`)
  - `src/ControlVNextSession.cpp:182` (dispatch calls `handleMetricsCommand`)
- Strict args reject + selector constraints:
  - `src/ControlVNextSessionCommandsMetrics.cpp:94` (unknown args key -> `SYNTAX_ERROR`)
  - `src/ControlVNextSessionCommandsMetrics.cpp:122` (app selector allowed only for `traffic|domainSources`)
  - `src/ControlVNextSessionCommandsMetrics.cpp:133` (selector resolution via `resolveAppSelector`)
- Traffic counters hot-path updates (always-on, relaxed atomics):
  - `src/TrafficCounters.hpp:19` (fixed keys `dns/rxp/rxb/txp/txb`)
  - `src/DnsListener.cpp:211` (gated by `settings.blockEnabled()`)
  - `src/PacketManager.hpp:114` (updates on final verdict paths)
- Conntrack metrics surface:
  - `src/PacketManager.hpp:77` (snapshot accessor)
  - `src/ControlVNextSessionCommandsMetrics.cpp:252` (`METRICS.RESET(name=conntrack)` rejected)

## Evidence: Tests Executed

- OpenSpec:
  - `openspec status --change add-control-vnext-metrics --json` (PASS; schema `spec-driven`, artifacts done)
  - `openspec instructions apply --change add-control-vnext-metrics --json` (PASS; progress **34/34**)
  - `openspec validate --type change add-control-vnext-metrics --json` (PASS)
  - `openspec validate --specs --json` (PASS; 16/16 specs valid)
- Binary sanity:
  - `strings build-output/sucre-snort | rg 'METRICS|unsupported cmd|conntrack does not support'` (PASS; current binary contains metrics-related strings including `conntrack does not support METRICS.RESET; use RESETALL`)
- Host P0 lane:
  - `cmake --build --preset dev-debug --target snort-host-tests` (PASS; 141/141)
  - `cmake --build --preset host-asan-clang --target snort-host-tests` (PASS; 141/141)
- Shell syntax check:
  - `bash -n tests/integration/vnext-baseline.sh` (PASS)
- Device lane:
  - `ctest --preset dev-debug -R '^p1-vnext-baseline$' --output-on-failure` (PASS; 1/1)
- Not executed:
  - `cmake --build --preset dev-debug --target snort-build-regen-graph`
  - `cmake --build --preset dev-debug --target snort-build`
