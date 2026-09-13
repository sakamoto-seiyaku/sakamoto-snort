# SAKAMOTO-220 — startup-ordered worker CPU placement

## Preregistered scope

Worker Layout remains fixed W2 with equal canonical-owner participation. Only
startup Worker Placement changes. Linux CPU IDs never enter packet keys, hashes,
handoff metadata or policy. No live affinity manager, automatic CPU selection,
core-type inference or flow migration is introduced.

The shared pinned VPP startup syntax is:

```text
cpu { main-core 0 workers 2 ordered-workers 1,3 }
```

`ordered-workers` is a decimal sequence, not a bitmap; the bitmap still reserves
the exact set, while native thread launch consumes the sequence in worker order.
The sequence count must equal the explicitly configured worker count. Duplicate,
missing/malformed/out-of-range, main conflict, absent/offline and inherited-affinity
conflict reject before workers and Product packet admission. Relative numbering,
automatic skip, pthread-only placement, competing corelist/coremask and unconsumed
CPU tokens are rejected. Inherited affinity is the native snapshot taken before
VPP narrows its main thread, not the already-singleton main-thread affinity.

Android START optionally carries `runtimeWorkerCpuIds="1,3"`; omission reuses the
last successfully started selection (initially `1,2`). Main remains CPU 0. Java
checks the W2 shape and forwards the ordered list; the actual native child checks
its own online/allowed CPUs. A different selection while active reports
`worker_placement_requires_restart` without rebinding workers. Successful startup
checks native worker IDs before persisting the choice. The same startup generator
serves Root and VPN; no UI redesign or readiness expansion is claimed here.

## Real-device collection plan

Both Pixel Root and Linux rootless NFQUEUE use this task's source-built artifact.
The test supplies a noncontiguous mapping and its exact reverse. It records the
CPU online/present set, startup config, VPP `show threads`, real per-thread
`Cpus_allowed_list` and `/proc/.../stat` last-executed CPU. Main/worker OS TIDs are
bound to VPP thread IDs. All affinity sets must be singleton and match the selected
mapping before and during actual TCP/UDP IPv4/IPv6 nonce traffic on both owners.
No per-packet sched_getcpu or steering algorithm is added to Product.

Reusable S242 independent kernel endpoints and native completion checks supply
all four origin lanes and both local/remote paths. Raw packets are independently
mapped by the S207 canonical oracle, and owner-sensitive graph traces must execute
on that owner thread. Reusing UDP tuples after clean restart proves the owner/hash
does not change when the CPU order changes. Stop occurs under an eight-second
bounded traffic cohort; unique native verdict/free, queue/flow/buffer/credit/timer
residue and old-generation exclusion remain required. There is no long idle case.

Native invalid-start cases use actual pinned binaries, including real taskset
restrictions for forbidden worker/main CPUs. A CPU absent from the actual online
set exercises its rejection; if the machine has no physically present offline
CPU, that particular hardware condition is reported unavailable, not fabricated
by offlining a user CPU or altering sysfs. Host parser checks complement, not
replace, real affinity and packet evidence. Android supervisor START/STOP/saved
selection/live-change refusal is a separate check from the standalone native run.

## Implementation checks before device collection

Java default/reverse/noncontiguous/round-trip checks and 27 invalid inputs pass;
the updated S187 startup/status contract also passes. No native status ABI changed.

The first native candidate revealed that upstream cpu_config silently ignores
unconsumed input: an empty `ordered-workers` started instead of rejecting (bounded
three-second run exited via timeout 124). The corrected parser recognizes the
keyword first, requires its list and rejects unknown CPU tokens. Candidate A's
APK/core patch is not accepted as completion evidence.

The Host build uses the existing S233 compiler/dependency environment. Its generic
apt preflight lists optional formatting/demangling packages; actual CMake compile,
dependency and link checks still execute. Installed external-dependency package
24.06-10 is the existing local build input; VPP's 26.02-1 warning is retained.
No system packages are installed, and original S236 artifacts are preserved.

## Verified result — source B

Product source closure:
`6ead7ea5fea3cbf6584c1c9179d57596fb0c30c19a6af225d7fb6e7315204a5b`.
Both platform stages use common-core series SHA-256
`26cd4db436b5eb79d65db6d834464f6437cb21464bea4adc25f9f5cbb33f72c3`.
The installed Pixel APK is
`bd96bb4e4be85f253fc77357cdabfb7c25131e2f7a18eb2060e9da0be429bf3b`.
Build manifests, complete frozen source, dirty diff, helpers and raw files are
under `build-output/s220-20260913/`.

| Evidence | Result | Actual captured packets / native verdicts |
| --- | --- | --- |
| `linux-native-b` | Both mappings, 18 actual invalid starts, all eight TCP/UDP × family × owner cells | 167/167 forward; 147/147 reverse |
| `pixel-native-d` | Same matrix and 18 actual invalid starts | 1125/1125 forward; 1164/1164 reverse |
| `pixel-supervisor-b` | Four clean generations: explicit `1,3`, saved `1,3`, explicit `3,1`, restore `1,2`; live-change and duplicate refusals | 61, 43, 32, 32 captures; every native completion/free reconciled |

Native and service runs prove real VPP/OS TID and affinity agreement, fixed
CPU-independent owner/hash behavior, clean generation replacement, and zero
native queue/flow/buffer/credit/timer residue. Both machines had no physically
present offline CPU; that particular hardware condition is `not-available`.
The actual absent/online-set rejection and real taskset-forbidden worker/main
cases passed on both platforms. No CPU was offlined or reclassified for a test.

One Pixel TCP echo overlapped native stop and completed about 5.1 seconds later;
all endpoint echoes still completed and native drain itself remained bounded.
This is functional placement/lifecycle evidence, not a latency/performance PASS.

Android's S187 properties include historical descriptive owner/capacity
placeholders. They are explicitly excluded from S220 acceptance. The verifier
uses the actual `product_graph_hash_seed`, worker count/core IDs, OS evidence and
the independent packet oracle; it does not reinterpret a legacy `generation`
seed label as the current fixed seed.

The first two Pixel collections remain rejected: one encountered Toybox env
treating `=` in the randomized APK path as an assignment; the other encountered
Toybox taskset lacking `-c`. The corrected test wrapper executes the quoted
native path via a plain shell name and uses the platform-shared hexadecimal CPU
mask syntax. Product source B was unchanged by these test-wrapper corrections.

Rehashed semantic-negative tests reject 20 corruptions (six per native platform,
eight service checks), including swapped startup order, wrong OS affinity or owner
thread, altered saved selection/seed, missing rejection, false stopped state, and
native resource debt. Original raw evidence is never modified by those tests.

The corrected full Host CTest result is 34/39. The three S175 patch-count/identity
fixtures now require the exact new six-patch closure and pass. The five remaining
failures are the pre-S220 VPP/S176/S189/S190/S191 static assertions documented in
S236; their failing scripts and first failing inputs remain byte-identical to
pre-S220 commit `d6fbf81f70123d14e6197a3f16ba9ba5c50a3c3f`. No whole-repo green claim
is made. The current Java contract and its 27 invalid-placement cases pass.

Report SHA-256 values:

- Linux verified: `c590e66179e3129ccc1eaf23f263e6664411ff35df2cc05eadd5beb0e1e8ec95`.
- Pixel native verified: `039e9b226705ba6f8e416050ab499caae937feacd871c449756ee75c8f1bce44`.
- Pixel service verified: `d75d4c0e904621ff72a2a2e99306fed13db5c03425311efc425f5130d02b4213`.
- Full Host JUnit: `570f018bfa1659ffa06d9d46dae75efa6316c185175970a92559ebf144b937cc`.

## Reproduce

After stopping the current runtime, an experimental ordered start can be requested
through the existing Android control entry:

```sh
rtk proxy ./dev/adb shell am start \
  -n com.sakamoto.snort.androidruntime/.DebugControlActivity \
  --ez runtimeStart true --es runtimeProfile root --es runtimeWorkerCpuIds 3,1
```

Verification entry points (each replays the independent evidence):

```sh
rtk proxy python tests/device/verify-s220-worker-placement.py build-output/s220-20260913/linux-native-b
rtk proxy python tests/device/verify-s220-worker-placement.py build-output/s220-20260913/pixel-native-d
rtk proxy python tests/device/verify-s220-supervisor.py build-output/s220-20260913/pixel-supervisor-b
```

The corresponding collectors are `s220-worker-placement.py` (Linux/Pixel native)
and `s220-pixel-supervisor.py`; both require source-bound build/helper manifests.
`test_s220_placement_negatives.py` checks each native run, or the service run with
`--supervisor`. No Root-to-VPN readiness expansion, live migration or performance
qualification follows from these checks. Completion status remains in Plane.
