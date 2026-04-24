# host-test-workflow Specification

## Purpose
TBD - created by archiving change host-test. Update Purpose after archive.
## Requirements
### Requirement: Host unit tests expose normal and ASAN entries
The project MUST expose host-side unit tests as two clear developer-visible entries: a normal host `gtest/CTest` entry and an ASAN host `gtest/CTest` entry. The ASAN entry MUST run the same host test suite under AddressSanitizer rather than a different set of tests.

#### Scenario: Run normal host unit tests
- **WHEN** a developer invokes the normal host unit-test entry
- **THEN** the project SHALL build and run the host `gtest/CTest` suite without requiring an Android device

#### Scenario: Run ASAN host unit tests
- **WHEN** a developer invokes the ASAN host unit-test entry
- **THEN** the project SHALL build and run the same host `gtest/CTest` suite with AddressSanitizer enabled

#### Scenario: Host unit-test gate includes ASAN
- **WHEN** a developer invokes the combined host unit-test gate
- **THEN** the project SHALL run both the normal host entry and the ASAN host entry in a clearly separated sequence

### Requirement: Host coverage artifacts are generated with Clang/LLVM tooling
The project MUST provide a Clang/LLVM coverage workflow for host-side unit tests. The workflow MUST compile the host tests with LLVM source-based coverage instrumentation, run the host test suite, merge profile data, and generate coverage artifacts under the coverage build/output directory.

#### Scenario: Generate host coverage artifacts
- **WHEN** a developer invokes the host coverage workflow
- **THEN** the project SHALL produce reproducible coverage artifacts using Clang/LLVM coverage tooling

#### Scenario: Coverage output stays out of source-controlled paths
- **WHEN** the host coverage workflow completes
- **THEN** generated coverage reports and profile outputs SHALL be written under build/output directories rather than committed documentation or source directories

#### Scenario: Coverage is not a threshold gate
- **WHEN** the host coverage workflow reports line/function/region coverage
- **THEN** the project SHALL treat the output as an artifact baseline and SHALL NOT fail solely because of a numeric coverage threshold

### Requirement: Host unit tests cover practical host-testable module gaps
The project MUST add host-side unit-test coverage for modules that can be validated without Android device, daemon lifecycle, NFQUEUE, iptables, or rooted-device prerequisites. The implementation MUST prioritize low-coupling modules first and MAY use minimal module-local test seams when direct testing would otherwise require external process, clock, socket, or filesystem coupling.

#### Scenario: Low-coupling host modules receive tests
- **WHEN** this change is implemented
- **THEN** host-side tests SHALL cover practical low-coupling gaps identified for modules such as `DnsRequest`, `Saver`, `Timer`, and `SocketIO`

#### Scenario: Manager and model modules receive behavior tests
- **WHEN** low-coupling host coverage is stable
- **THEN** host-side tests SHALL cover practical observable behavior for manager/model modules such as `AppManager`, `HostManager`, `Packet`, `PacketManager`, and `Streamable`

#### Scenario: Test seams remain module-local
- **WHEN** a host test requires a seam for deterministic time, socket, file, or process behavior
- **THEN** the seam SHALL be limited to the module under test and SHALL NOT change product-facing behavior

### Requirement: Host workflow changes do not modify real-device test paths
The project MUST keep this change limited to host-side testing and tooling. It MUST NOT modify current CMake or script code that registers, selects, or runs real-device tests.

#### Scenario: Device test registration remains unchanged
- **WHEN** this change modifies host CMake or preset entries
- **THEN** existing real-device test registration and execution paths SHALL remain unchanged

#### Scenario: Device scripts remain unchanged
- **WHEN** this change adds host unit tests, host ASAN entry, or host coverage workflow
- **THEN** files under real-device test paths such as `tests/integration/` and `tests/device/` SHALL NOT be modified as part of this change

#### Scenario: Host and Device/DX boundaries are documented
- **WHEN** a developer reads the updated testing documentation
- **THEN** the documentation SHALL distinguish host unit-test/ASAN/coverage workflows from Device/DX workflows
