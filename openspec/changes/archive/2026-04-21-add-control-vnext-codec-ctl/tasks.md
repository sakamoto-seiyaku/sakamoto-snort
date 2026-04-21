## 1. Dependencies & Build Wiring

- [x] 1.1 Confirm `third_party/rapidjson/include` is present and treated as the only vNext JSON library
- [x] 1.2 Wire RapidJSON into Android.bp as a SYSTEM include (avoid `-Werror` fallout from vendor headers)
- [x] 1.3 Wire RapidJSON into host CMake targets as a SYSTEM include (avoid `-Werror` fallout from vendor headers)

## 2. Netstring Codec

- [x] 2.1 Implement netstring encoder helper (payload → `<len>:<payload>,`)
- [x] 2.2 Implement incremental netstring decoder with `maxFrameBytes` guard and deterministic errors
- [x] 2.3 Add P0 unit tests: roundtrip, partial read, multi-frame, non-digit header reject, leading-zero reject, missing-terminator reject, oversize reject

## 3. Strict JSON + Envelope Helpers

- [x] 3.1 Implement strict JSON parse from `(char*, len)` with trailing-garbage rejection and top-level object enforcement
- [x] 3.2 Implement strict JSON encode (compact + pretty) using RapidJSON writers (no stringstream JSON)
- [x] 3.3 Implement strict-reject helper for unknown keys on JSON objects
- [x] 3.4 Implement request/response/event envelope helpers and validation (including mutual exclusion rules)
- [x] 3.5 Add P0 unit tests: trailing-garbage reject, string escape roundtrip, non-object reject, unknown-key strict reject, response invariants

## 4. `sucre-snort-ctl` Host CLI

- [x] 4.1 Create `sucre-snort-ctl` host target and minimal argument parser (tcp vs unix socket)
- [x] 4.2 Implement `--help` and `help` output (vNext command directory + examples)
- [x] 4.3 Implement request send + response decode + event decode using shared codec (pretty/compact output modes)
- [x] 4.4 Add a host-only mock server harness to validate end-to-end framing with the CLI (single request/response + event frame)

## 5. Acceptance / Regression Hooks

- [x] 5.1 Ensure `openspec apply` prerequisites are satisfied (tasks reflect the specs and design)
- [x] 5.2 Provide a short developer runbook snippet (how to build/run `sucre-snort-ctl` and codec tests on host)
