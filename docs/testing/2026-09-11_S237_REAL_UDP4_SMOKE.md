# S237 real owner-inline UDP4 smoke evidence

## Latest verified artifact (build m)

Product source `489b5cab7ffd50b36751695b6f727b0b540e86fa414db3a10bf11a7ede3e327b`
produced APK `7e111952821f07aa2e344ed0ccad1072a9669df2955f77b73c71a32ded3eee39`.
`pixel-m-*` records generations 1052–1062: all 11 echo, input rejection, output
allocation, pre-accept, TUN write, stale output, return policy drop/recovery,
overlapping stop, and three unknown-availability cases passed both the device
runner and the independent verifier. No diagnostic BPF mutation was used.
All runs reached clean stop; the startup barrier failure did not recur.

An additional fixed 20-run campaign, `pixel-m-startup-01` through `-20`, passed
every real echo and independent verification in generations 1063–1082 without
retry. Every run installed the same APK, started, exchanged three datagrams,
and stopped with zero recorded resource residue. Together with the matrix,
this is 31 successful fresh starts on build m, not a claim of infinite-run
reliability. Fresh `host-final-tests` also passes all eight dependency/Product
seam tests, including pending and connected UID-conflict closure and rebuild.

The Android profile now wakes workers at the initial barrier as well as the
regular barrier. The extracted real initial-barrier function fails the
sleeping-worker regression before this change and passes after it, including
20 repeated runs. The Android idle timeout and barrier deadline were not
increased. Final patch-series SHA256 is
`d8291c8041b5a812f08ad4bede453431bacca16805529531870acd8a55d9ac05`.

The final APK's 12 ELF payloads pass the hardening audit. The final stage passes
the mempolicy and native Product stage contracts. The verifier accepts the
new `pixel-m-echo` recording and rejects 28 mutations, including per-stage
identity, availability, provenance and generation corruption.

Same-source Linux build d and `linux-root-regression-d/verification.json` pass:
106 OUTPUT + 104 INPUT endpoint cases, 178 + 176 captured packets, both IP
families and owner lanes, no verification errors. Earlier sections below
preserve historical failures and narrower intermediate evidence; they are not
claims about the final artifact. These results remain scoped to S237 and do
not establish W2 VPN transport, IPv6 VPN forwarding, or TCP readiness.

Evidence scope: one active logical owner, IPv4 UDP, Pixel 6a, same-session three-datagram
echo. This is not complete S237 acceptance or a full VPN readiness claim. Plane SAKAMOTO-237
remains the work record; the failure/stop matrix in the implementation specification still
defines its completion gate.

## Later Pixel acceptance hold: stale platform ingress rule

The final dependency audit also maps `0005-direct-only-build.patch` to the
real-session Direct receive test, Product flow-stack test, successful NDK
build and packaged ELF audit. This build-selection patch has no standalone
runtime test executable; the other patch-specific regression mappings are
listed in `third_party/hev/patches/series.json`. The offline source inventory
and full applied patch inventory were verified during the fresh builds.

Build-k runs `pixel-rx-counter-a` and `pixel-rx-policy-a` time out on all three
nonce echoes. Kernel UDP `InErrors` increased 39811 → 39814, while
`RcvbufErrors=39649`, `InCsumErrors=0`, `MemErrors=0`, and `NoPorts=21728`
did not change. This does not support buffer overflow or checksum failure.

During the policy run, UID 12632 had `HAPPY_BOX_MATCH IIF_MATCH BACKGROUND_MATCH
952`; the current tun0 ingress-discard entry referenced interface 956. After
normal Product stop, `IIF_MATCH BACKGROUND_MATCH 952` remained, although no tun
interface remained and Permission Monitor listed no interface filtering rules.
The underlay wlan0 interface index is 47. The scoped snapshot is retained in
`build-output/s237-20260911/pixel-rx-policy-a/failure-uid-policy.txt`.

[AOSP netd BPF source](https://android.googlesource.com/platform/packages/modules/Connectivity/+/a60572f8441e5799da6d09f5ced03fa6ad42ed18/bpf/progs/netd.c)
rejects non-loopback ingress when a nonzero UID IIF rule names another interface;
that check does not exempt a protected or Network-bound socket. This strongly
implicates stale platform filtering, but is not yet controlled causal proof:
no platform rule was changed and no post-cleanup comparison has run. The rule's
origin and earlier startup failure remain unproven. These runs do not pass
acceptance. Product and local endpoint processes stopped normally.

### Authorized causal comparison (not acceptance)

After explicit user authorization, the scoped helper changed only UID 12632's
stale IIF rule. Clearing before install/start was not durable: the platform
restored interface 952. In `pixel-iif-after-start-a`, clearing after startup
changed the raw map value from `(iif=952, rule=4225)` to `(iif=0, rule=4097)`,
preserving all non-IIF bits. The same build-k pre-accept test then produced
`echo, timeout, echo`, as expected for the injected second-packet failure.
The raw value stayed `(0,4097)` through the probe; after stop it returned to
`(952,128)`. This establishes the stale IIF restriction as the cause of the
three-packet receive failure, but not the origin of that stale restriction.

The restoration is consistent with Android's
[SingleWriterBpfMap userspace cache](https://android.googlesource.com/platform/packages/modules/Connectivity/+/9eca02a8fa20aa14920f0dd3bf88c06ce04a2575/staticlibs/device/com/android/net/module/util/SingleWriterBpfMap.java),
which does not observe out-of-band writes. This is an inference from AOSP and
observed restoration, not direct inspection of the device's Java heap.
The diagnostic runner flag is explicit and `verify-s237.py` rejects such runs
as acceptance. Do not add this platform mutation as a Product workaround.

## Offline verifier and final ELF checks

`tests/host/s237_verifier_negative_test.py --build
build-output/s237-20260911/pixel-build-j/build.json --run
build-output/s237-20260911/pixel-audit-echo` accepts the historical positive
recording and rejects all 13 mutations: missing/duplicate copy, missing
completion/buffer-free/pbuf-free, three lifecycle order inversions, wrong
thread/TLS/generation, and forged copy count/bytes. The initial test exposed
five false accepts; the verifier now requires unique matching copy/admission
tokens and policy → terminal → completion → free ordering. This tests
`verify_run`, not current-source closure; old build j is not fresh acceptance.

`tests/host/s237_apk_elf_audit.py --build
build-output/s237-20260911/pixel-build-k/build.json` passes for all 12 packaged
arm64 libraries. The audit hashes the APK and each extracted ELF against the
build manifest, then checks actual GNU_RELRO, immediate binding, non-executable
GNU_STACK and absence of TEXTREL. It does not infer hardening from compiler
flags or claim that ELF hardening proves runtime ownership correctness.

## Fresh Linux Root regression

`linux-build-b` was rebuilt from Product source
`1521d75dc67604da4ef4489620ec11033be3c12dfb77227492aa011edfa5a7d2`, matching
Pixel build k. `linux-root-regression-b` completed 106 OUTPUT and 104 INPUT
endpoint cases under `unshare --user --map-root-user --net`. The recorded netns
was `4026532425`, distinct from host netns `4026531840`.

The independent `verify-s223-udp.py` result is PASS with no errors: 178 OUTPUT
and 176 INPUT captured packets, both IPv4/IPv6 and both owner lanes, zero
capacity bypasses, and the expected UDP state transitions. Evidence is in
`build-output/s237-20260911/linux-root-regression-b/verification.json`.
This closes the stale-source limitation of Linux build a; it does not replace
the still-failing Pixel VPN acceptance or broaden S237's UDP4 scope.

## Build and source closure

The Product statically links the pinned HEV session, task system and owner-local lwIP fork
into `libproduct_core_plugin.so`. It does not launch the retired external HEV transport or
load an experiment DSO. Original source licenses and file-specific copyright notices are
included in APK `assets/hev-notices.txt`.

Fresh successful build: `build-output/s237-20260911/pixel-build-e/build.json`.

- Source closure: `c0bd9a4d396492d31cd00a8ee863ddd7502fb6bdf9eb197b96e6e48ee9508819`.
- APK: `13f49d642c6ed6dbc75dfc1c30953babaaee136874a1417afff0d61bf425a19a`.
- Product plugin: `80c14996038dac848bc79c4268f3d33a4d3b7b14874f2d9cba8a980d783f12a5`.
- Unchanged VPP runtime: `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08`.

The runner verifies the installed APK/native hashes against that build and records the
independent endpoint source and executable hashes separately. The evidence binds this
exact snapshot, not subsequent source edits.

## Preserved failures and fix

Android builds `pixel-build-a`, `-b`, and `-c` preserve, respectively, an obsolete lwIP
`fd_set` typedef collision, a hardcoded `-lpthread` link failure on bionic, and a packaging
guard incorrectly scanning temporary HEV compiler inputs as distributed artifacts.
The narrow fixes use bionic's system `fd_set`, `Threads::Threads`, and audit the stage after
removing its existing temporary build directory. The distributed-library allowlist remains.

Build `pixel-build-d` produced two reproducible failures in `pixel-smoke-a` and `-b`:
the first packet timed out at 1500 ms and the next probes received the previous datagram.
All three datagrams eventually reached the endpoint and were written back to TUN; these
were retained as failures, not reclassified as successful delivery.

Diagnosis found an integration mismatch with the accepted Android idle profile: that profile
allows a worker to sleep despite polling nodes, with an idle wait up to one second. Merely
registering the new transport as a polling input node left broker replies, Direct socket
readiness and HEV deadlines outside VPP's wakeup set.

The Product adapter now subscribes the real HEV reactor and broker descriptors to the
owning VPP worker, projects the nearest HEV deadline through a timerfd, and dispatches a
bounded interrupt-driven step. Input admission and quiesce also schedule that node. VPP
owns subscription descriptor duplicates; each original remains with its proper owner.
The existing VPP core, global idle policy and packet wakeup implementation were not changed.

## Device observations

`pixel-smoke-c` (generation 1005) and `pixel-smoke-d` (generation 1006) both recorded:

- Pixel `28201JEGR0XPAJ`, Wi-Fi address `192.168.4.151`, real LAN endpoint `192.168.4.5`.
- Three matching app replies on the same UDP socket; three independent endpoint receipts.
- One HEV session and one socket/broker request, with Android protect and bind both successful.
- Three actual HEV sends, three receives, three independent return submissions and three
  successful TUN write attempts.
- Actual callback/graph execution on worker thread/TLS 1, logical owner 0.
- Return UID 12632 known, Wi-Fi context known, Linux ifindex unknown. The capture UID is the
  explicitly controlled app-only validation provider, not a general multi-app attribution claim.
- Normal RuntimeService stop completed, and the runner verified no residual VPP process.

Natural return pbufs consisted of two spans (protocol header and referenced payload); the
Product copied both into independent VPP storage. No probe timeout was increased for the fix.
The existing eight Host regressions also passed after the NDK portability changes.

The `pixel-build-e` shared graph trace helper still labels return packets `NFQ_CAPTURED` by
its old default branch, although their typed metadata, return completion flags and TUN
write path are correct. The source now explicitly labels `FLOW_STACK_RETURN`; subsequent
matrix evidence must use a newly built artifact containing that correction.

This smoke does not prove allocation-failure recovery on-device, return policy DROP, TUN
write failure, overlapping stop, full descriptor/pbuf allocation-interval closure, IPv6,
multiple active transport owners or TCP. Those claims cannot be inferred from the echo.

## Pixel failure/recovery continuation

`pixel-build-f/build.json` binds source
`d2b1902510b3d593762e77f559031e907bb1da49a8864fcf5c1d8e3a5db7288b` to APK
`0248d29b6e39e89e554c6878dc9f77bc468b177638e3c4f6faa32b2007553cca`.
It includes the corrected return trace label and explicit, validation-only one-shot faults.

| Evidence directory under `build-output/s237-20260911/` | Generation | Observed sequence |
| --- | --- | --- |
| `pixel-input-reject-a` | 1007 | echo → injected input-capacity rejection → same-session echo |
| `pixel-output-alloc-a` | 1008 | echo → injected output-allocation failure → same-session echo |
| `pixel-pre-accept-a` | 1009 | echo → rejection after copy but before graph submission → same-session echo |
| `pixel-write-a` | 1010 | echo → real TUN syscall with deliberately invalid zero length → same-session echo |
| `pixel-return-drop-a` | 1011 | three echoes → three real shared INPUT L4 policy drops → three echoes after policy removal |

Each sequence retained exactly one HEV session, one socket and one broker request. Input
rejection did not reach the endpoint. Output failures and return DROP did reach the endpoint;
their differing admission, output and TUN-write counters were verified separately. The write
case did not convert an already accepted graph submission into an output callback failure.
Allocation failure is explicitly injected; it is not evidence of natural system OOM.

The return DROP case used the normal Product Core/generated-VAPI policy path, with an INPUT
UDP rule, and kept outbound traffic allowed. All nine endpoint requests and HEV outputs
were observed, but only the six allowed returns attempted TUN writes. Policy removal did
not create a replacement transport session.

These runs also preserved `native-stop.log` before RuntimeService removed the generation's
profile. The runner checked pbuf allocation intervals (allowing address reuse), a final
owner-destroy witness after zero lwIP heap/PCB/pbuf checks, matching socket create/close
counts, closed timer/broker originals, and zero graph buffers/obligations/completion frames.
It then checked normal stopped state and absence of the VPP process. Controlled overlapping
stop and the remaining full acceptance audit are not proved by these normal-stop cases.

## Same-artifact matrix and overlapping stop

Build `pixel-build-g` binds source
`b92997015505dbf9c3a83094064399b6a302fef5f996b562c856fe5e988fca76` to APK
`559ef5567f37472351c135b48885bb85202a1dc087cad9b9e2b602beae1d7a39`.
All seven scenarios were rerun with this same APK in `pixel-final-echo`,
`pixel-final-input-reject`, `pixel-final-output-alloc`, `pixel-final-pre-accept`,
`pixel-final-write`, `pixel-final-return-drop`, and `pixel-final-overlap-stop`.
Their generations are 1013–1019 respectively. Every result completed without a cleanup
error. Each run stores the runner, oracle and helper source snapshots and hashes.

The overlap test establishes a working session first, then uses an explicitly diagnostic,
bounded transport-step hold (at most 5000 ms). It does not sleep the VPP worker or replace
the HEV queue: a real input copy remains in the real session queue. Normal RuntimeService
stop bypasses this hold and gates forwarding before advancing the teardown tasks.

Generation 1019 recorded `quiesce_begin` with one session, one queued input and one live
pbuf, after three successful sends and returns. The held nonce never reached the endpoint.
After this gate there were no new output callbacks, return copies, pbuf allocations or
socket creations. Final session/input/pbuf and graph debts were zero, with socket counts
1 created / 1 closed. The owner also requires the HEV all-task list to be empty before
reporting stopped, so a retained task reference cannot be hidden by the runnable counters.

This is a controlled overlap regression, not a claim about a natural stress distribution.
The task's complete requirement-by-requirement and evidence-verifier audits remain separate
from these runtime observations.

## Availability and stale-generation audit additions

Re-reading SAKAMOTO-237's original acceptance criteria identified explicit device
known/unknown fact projection and old-generation output rejection requirements. Build
`pixel-build-h` supplies those controlled cases with source
`b2bf851804bd9b281968f9efb23535b11983501bdbc3e1db9bc3a191a3dc2aa2` and APK
`c59a5a6cf8f73c1c4d618419b9827af9ff1260acb63bc7ef58712011bd0e453c`.

`pixel-unknown-identity-a` (1020), `pixel-unknown-context-a` (1021), and
`pixel-unknown-both-a` (1022) all completed three real echoes. These are explicitly
controlled missing-fact providers, not claims about general UID discovery or natural
platform classification failures. Identity absence uses a distinct attachment operation,
not a numeric UID sentinel. Network-classification absence is independent of successful
Android bind/protect. The real return packets preserve each availability combination;
unknown identity does not acquire the app/Direct socket UID.

`pixel-stale-output-a` (1023) injects an older generation into the real output submission
call on the second datagram. Submission rejects before allocating a VPP buffer, while
the real HEV caller releases its pbufs. The first and third datagrams echo on the same
session, with two accepted return submissions. This is a controlled generation-mismatch
case, not a claim that an obsolete owner is permitted to run after destruction.

A separate Release-mode Android arm64 dependency build passed the writable-section
audit. Its Clang `-fdata-sections` output names the TLS section `.tbss.current` and includes
zero-sized mapping markers; the verifier handles those encodings while still requiring
the permitted object to cover every byte of the section. This object audit does not
substitute for final Product RELRO, installed-symbol or runtime ownership verification.
