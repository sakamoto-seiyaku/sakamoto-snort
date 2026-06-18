## Context

The current host-side test lane is already GTest/CTest based and runs successfully under both normal Clang debug and the existing `host-asan-clang` preset. The gap is not basic executability; the gap is workflow clarity and coverage completeness:

- normal host tests and ASAN are currently separate manual invocations
- coverage artifacts are not wired into the repo
- the host-testable module backlog is documented but not yet converted into implementation work
- device/DX tests must stay separate from this change
- current CMake/script code that registers or runs real-device tests is explicitly out of scope

The change should treat `docs/testing/HOST_TEST_SURVEY.md` as the current inventory source and avoid expanding product behavior while improving test/tooling behavior.

## Goals / Non-Goals

**Goals:**

- Provide an explicit Clang/LLVM coverage artifact workflow for host unit tests.
- Keep normal host tests and ASAN host tests visible as two clear test entries.
- Provide a single high-frequency host gate that runs both normal host tests and ASAN.
- Close practical host-side unit-test gaps for low-coupling C/C++ modules.
- Keep `Host` and `Device / DX` boundaries explicit.

**Non-Goals:**

- No frontend work.
- No Android real-device test expansion.
- No edits to existing CMake or script paths that register/run real-device tests.
- No product API, daemon protocol, rule semantics, or runtime behavior changes unless a minimal test seam is required.
- No coverage threshold gate in the first version.
- No attempt to make ASAN and coverage run in the same binary configuration.

## Decisions

### 1. Keep one source of truth for host cases

Host test cases remain registered from `tests/host/CMakeLists.txt` through GTest/CTest. New module tests should be added as additional host gtest targets or cases in that lane, not as one-off shell tests.

Alternatives considered:

- Add standalone scripts per module. Rejected because discovery, labels, IDE test integration, and ASAN reuse would diverge.
- Move host tests into device/integration scripts. Rejected because these tests do not require a device and should stay cheap.

### 2. Use two visible test entries plus one aggregate host gate

The workflow should expose two developer-visible entries:

- normal host unit tests
- ASAN host unit tests

The high-frequency host gate should run both entries in sequence so that "run host unit tests" also covers ASAN. The exact command shape can be implemented through CMake presets, build targets, or a thin repo script, but the visible model must remain two entries rather than a hidden ASAN side effect.

This decision only applies to host-side entries. It must not modify existing real-device CMake targets, `tests/integration/` scripts, or `tests/device-modules/` scripts.

Rationale:

- Developers can run the faster normal lane when iterating.
- The combined gate prevents ASAN from being forgotten.
- Test UI / command output stays understandable: normal and ASAN failures are separated.

### 3. Make `host` the primary label and keep historical labels as compatibility only

New workflow documentation and commands should prefer the `host` label. Existing historical labels such as `p0` may remain temporarily for compatibility, but should not be the primary conceptual name.

This label cleanup is host-only. Device/DX labels and registrations are not part of this change.

Rationale:

- The project is moving away from `P0/P1/P2` as roadmap terminology.
- The actual runtime boundary is `Host` vs `Device / DX`.

### 4. Add a dedicated Clang coverage preset/workflow

Coverage should use a dedicated Clang/LLVM configuration, separate from normal and ASAN builds. The expected implementation shape is:

- compile with LLVM source-based coverage flags
- run the same host gtest/CTest suite
- merge profiles with `llvm-profdata`
- generate human-readable and machine-readable artifacts with `llvm-cov`
- write artifacts under the coverage build directory, not into source-controlled paths

The coverage workflow is an artifact-producing workflow, not initially a pass/fail threshold.

Alternatives considered:

- GCC/gcov/lcov. Rejected because the requested path is explicitly Clang based and the repo already centers host presets around Clang.
- ASAN + coverage in one build. Rejected for the first version because it complicates compiler/runtime flags and makes failures harder to classify.
- Enforce a numeric threshold immediately. Rejected because the first goal is to establish trustworthy artifacts and complete obvious host gaps.

### 5. Close host-testable module gaps in waves

Test additions should follow dependency and seam risk:

1. Low-coupling modules:
   - `DnsRequest`
   - `Saver`
   - `Timer`
   - `SocketIO`
2. Manager/model modules:
   - `AppManager`
   - `HostManager`
   - `Packet`
   - `PacketManager`
   - `Streamable`
3. Semantics/seam-first modules:
   - `Activity`
   - `ActivityManager`
   - `CmdLine`

Modules identified as runtime/device-oriented should remain outside this host-unit change unless a narrow pure helper is extracted:

- `Control`
- `ControlVNext`
- `ControlVNextSessionCommandsDaemon`
- `DnsListener`
- `PackageListener`
- `PacketListener`
- `sucre-snort`

### 6. Allow minimal test seams, but only when they reduce coupling

If a module cannot be tested without binding to sockets, clocks, files, or process state, the implementation may introduce a small host-test seam. The seam must not change product behavior and must stay local to the module under test.

Examples of acceptable seams:

- injectable clock for deterministic timer behavior
- local `socketpair`-based tests for socket I/O
- temp-directory paths for save/restore behavior

Examples of unacceptable seams:

- broad manager rewrites only to make tests easier
- product-facing protocol or rule semantic changes
- Android/device mocking that belongs in DX tests

## Risks / Trade-offs

- Coverage artifacts can look authoritative before the module gap is closed → Document that early coverage is a baseline artifact, not a quality threshold.
- ASAN doubles host gate runtime → Keep the normal and ASAN entries separately runnable while making the aggregate gate explicit.
- Stale build directories can confuse test discovery → Use dedicated build directories per preset and document clean reconfigure behavior when test lists look inconsistent.
- Minimal seams can grow into refactors → Require each seam to be justified by a specific host test and keep it module-local.
- Manager tests can become brittle if they assert incidental ordering/state → Prefer externally observable snapshot/reset/find behavior over private implementation details.

## Migration Plan

1. Add or normalize host-only workflow entries so normal host tests and ASAN are both visible.
2. Add a combined host gate that runs normal host tests and ASAN in sequence.
3. Add the Clang coverage workflow and artifact documentation.
4. Add host tests for low-coupling module gaps first.
5. Add manager/model tests after the low-coupling wave is stable.
6. Re-run normal host, ASAN, and coverage artifact generation before considering the change complete.

Rollback is straightforward because this change is host test/tooling-only: remove the new host presets/targets/scripts and host test files. Product binaries and device/DX lanes should not require rollback.

## Open Questions

- Should the aggregate host gate be a CMake custom target, a CMake workflow preset, or a repo script?
- Should coverage artifacts include only summary/report output, or also checked-in baseline records?
- Should the historical `p0` CTest label be kept indefinitely as an alias, or removed after documentation migrates to `host`?
