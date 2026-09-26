# T22 persistent minute acceptance — 2026-09-26

SAKAMOTO-273 implements the minimal Flow → VPP `svm_msg_q` → Rust → persistent
overall-minute chain required before E01. Linux and Android Root/controlled VPN
acceptance passed for the scenarios below. This is not a storage-engine selection,
release performance/retention claim, or implementation of the remaining views.

The [interface contract](../interfaces/T22_MINUTE_WINDOWS.md) defines transaction,
identity, clock, error and coverage behavior. Rust owns the observation file;
VPP remains the only configuration writer. No ACK/retransmission, second packet
engine, removed C++ source or POC implementation was introduced.

## Source and evidence

Final Product source closure:
`38906618008deda0298637323b6c67a8d7e042f8fe72281b9e54b88ea00fbdc4`.
The two final builds bind identical Product source snapshots. Typed VAPI identity
remains `product_core.api/1.0.0@c9a3f640`; observation wire V2 is a distinct contract.
IPv4/IPv6 records are 136/160 bytes. The 144/160-byte queue classes retain 512
descriptors per channel and use 332544 mapped bytes. These are development values.

All paths below are under `build-output/t22-20260926/`.

| Evidence | Retained location |
| --- | --- |
| Host build and artifact closure | `linux-build-d/build.json`; `build-output/product-vpp-host-t22-d` |
| Android build and installed native closure | `pixel-build-d/build.json`; `pixel-b/installed-native.txt` |
| Final APK SHA-256 | `4b635774337dac2b8b921f3fcf36a4bb1e211de55422d3b3cc41ac27c63a10e4` |
| Linux actual pipeline and interruption | `linux-e/` |
| Android actual Root/VPN pipeline | `pixel-b/` |
| Independent verification and semantic mutations | `linux-verification-final.json`, `pixel-verification-final.json` |
| Native C/Rust and sanitizer checks | `final-native/` |
| ARM64 runtime checks | `final-arm64-root/`; shell-only attempt retained in `final-arm64/` |
| Directory-fsync retry regression | `directory-retry-red/`, `directory-retry-green/`, `directory-retry-final/` |
| Unseen queued lifecycle shutdown regression | `shutdown-red/`, `native-c/` and `final-native/` |
| Complete regression | `ctest-final.log`, `cargo-final.log`, `host-regression-final.json` |

`tests/evidence/verify_t22.py` checks source/build order, retained source and
binary hashes, runtime identities, actual admitted/policy/terminal packet
identities, endpoint payloads, cumulative totals, maintained buckets, lifecycle,
write interruption, restart and cleanup. Android also joins host/device packet
captures and proves that foreground queries did not drive the background arm.
Eight rehashed semantic mutations per platform are rejected, including an
overcount that preserves minute/total conservation, changed packet identities,
lost baselines and hidden gaps. The final verifier SHA-256 is
`c0b44f4131a5fd2e05c0b62d03b4b7be9b5dcd61c9920887b124e26001446745`.

## Linux result

Actual UID-separated IPv4 UDP sockets crossed NFQUEUE and the current VPP
producer. Generation 27301 persisted the first echo as 1/1 packets, 60/60 IP
bytes. A combined END added three unseen tail packets per direction and reached
4/4 packets, 264/264 bytes. Tuple reuse created another incarnation.

A real filesystem obstruction rejected snapshot writes while two more echo pairs
completed. The API retained the committed baseline and reported the save error.
Later cumulative growth recovered those known contributions exactly once, reaching
8/8 packets and 524/524 bytes. END was then delayed into another UTC minute;
its retained activity timestamp and maintained minute totals did not move.

The test-only libc injector wrote half a new snapshot, stopped its writer, and
the collector killed the consumer. The retained pending file is genuinely
incomplete (960 bytes), while the committed file remains at 8/8 and 524/524.
Packets continued through VPP. A fresh runtime generation, 27302, reopened that
committed baseline, reported an unclean recovery/gap and added three new echo
pairs, reaching 11/11 packets and 752/752 bytes. Generation-qualified baselines
prevented slot/incarnation reuse from mixing the cumulative values.

The independent packet oracle contains 13 echo pairs: 26 IP packets / 1744 bytes.
The persisted contribution is 22 packets / 1504 bytes. The four packets / 240
bytes lost around the interrupted consumer are explicitly incomplete coverage;
no invented replay or proportional adjustment forces the two totals to agree.
The final store retains mode 0600. Fsync witnesses establish the observation
directory entry before the first snapshot and file/directory synchronization.

## Android result

The same source was installed and verified by APK and individual native hashes.
Root generation 1597 and controlled VPN generation 1598 each completed 106 real
echo transactions, matching 212 native IP packets and 12768 IP bytes per profile.
Root traces prove `NFQ_CAPTURED`; VPN traces prove `TUN_CAPTURED` and
`FLOW_STACK_RETURN`. Payload identities agree with both-end captures; both
capture processes report zero kernel drops.

Each profile returned to the launcher before releasing the
100-echo background arm. No Activity query ran during that interval. The separate
Rust service committed the expected increments before the frontend was reopened;
the normal API then returned those same maintained windows.

After Root stopped normally, its service process was force-stopped and verified
gone. VPN started a different service process and runtime generation and restored
the exact persisted counters/baseline count before new traffic. The store began
this accepted run with an earlier retained 106/106-packet observation baseline;
Root advanced it to 212/212 and VPN to 318/318, rather than resetting or recounting
old cumulative values. Each consumer termination records a coverage boundary.
VPP processes and observation mappings were released at both normal stops.
Final checks retain stopped generation 1598, `mayBeActive=false`, and no Product
process, NFQUEUE socket/hook, TUN or T22 scratch. Network-link inspection used
the existing Root context after Android denied the shell-only dump.

## Focused regressions and limits

The public store tests cover END tail and duplicate END across reopen, immutable
first-END time, failed writes and leftover pending bytes, sequence gaps,
incarnation/generation changes, backwards wall-clock movement, corrupt files and
counter overflow without partial advancement. Two real native C→Rust process
tests cover current wire/capacity, persistent totals, duplicates, producer exit,
and stopping an empty paused consumer with an unseen queued lifecycle.

The full Host suite passed 50/50; all 28 ordinary Rust workspace tests passed.
The two native process tests passed separately. Product C transport and its
boundary test passed ASan/UBSan with leak detection; pinned shared libraries were
not rebuilt with sanitizers. ARM64 capacity/fd-rejection/accounting and bounded
handshake timeout passed under the existing authorized KernelSU Root context
(handshake 2.024 seconds), without changing SELinux. The initial shell-only
listener was denied by Android policy and is retained as a restricted-context
attempt, not a Product failure or an app-domain permission claim.

Retained failures distinguish Product fixes from test/environment problems:

- `linux-a` stopped before traffic because the old VAPI callback rejected wire
  version 2; the callback now checks the current version and its contract passes.
- Review found that a clean stop could hide an entirely unseen queued flow.
  `shutdown-red` reproduced false complete coverage; the conservative shutdown
  boundary is GREEN through the real queue.
- Review found directory creation was not durable, then found a retry edge after
  failed parent fsync. The filesystem-boundary RED omitted the successful retry
  sync; GREEN records the injected failure followed by a real successful sync.
- `pixel-a` completed Root traffic/background persistence but its collector checked
  process disappearance immediately after `am force-stop`. A bounded exit wait
  fixed the collector; final Root/VPN evidence uses `pixel-b`.
- `linux-d` interrupted before commit, but its injector allowed the writer to
  finish JSON while process group-stop propagated. The independent verifier
  rejected the asserted half-write claim. The corrected injector holds the writer;
  `linux-e` passes without changing Product source or weakening the assertion.
- The first full Host run encountered the sandbox's Unix-socket restriction;
  the complete unsandboxed rerun passed. It was not treated as a product regression.

Physical power removal was not tested. This ticket does not establish the full
48-hour/hour/day retention chain, a 256 MiB total budget, other traffic views,
attribution segments, Blocked Observation, mobile energy/thermal costs, Doze,
or release pressure capacity. The atomic JSON snapshot intentionally exposes
whole-snapshot write amplification and memory-copy costs for E01. Clock sampling
now occurs on real activity and is another cost E01 must measure.

T21's longer Android UDP pressure remains HOLD and is not upgraded by these
bounded 100-echo background arms. E01 / SAKAMOTO-274 remains a mandatory experiment
and user-result decision gate; completing T22 does not approve its storage values
or authorize advancing beyond that gate.

## Reproduction

Use the retained build manifests and fresh evidence directories. The Host
collector needs its isolated Docker network namespace and NET_ADMIN/NET_RAW;
the verifier needs read access to the fixture's protected configuration file.
Android collectors use only `./dev/adb` and an existing selector witness.

```sh
rtk proxy python3 tests/evidence/verify_t22.py build-output/t22-20260926/pixel-b --mutations
rtk proxy docker run --rm --network none -v "$PWD:$PWD:ro" -w "$PWD" \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory \
  -e GIT_CONFIG_VALUE_0="$PWD" sakamoto-vpp-nfq-poc:dev \
  python3 tests/evidence/verify_t22.py build-output/t22-20260926/linux-e --mutations
rtk proxy python3 tests/evidence/t22_store_faults.py --output /tmp/t22-directory-retry-fresh
rtk proxy ctest --test-dir build-output/t22-20260926/host-tests --output-on-failure
rtk proxy cargo test --workspace
```

The [two-axis review](../reviews/2026-09-26_T22_MINUTE_WINDOWS_REVIEW.md) records the
independent findings and their fixes. Original user-owned dirty files remain
byte-for-byte preserved by `preserved-baseline.json`; they are not part of T22.
