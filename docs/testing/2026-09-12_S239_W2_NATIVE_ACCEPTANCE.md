# S239 W2 native UDP ownership and credit evidence

This record closes SAKAMOTO-239's W2 ownership/credit/lifecycle and notification
correctness scope. On 2026-09-12 the user explicitly moved formal CPU/p99
comparison into SAKAMOTO-248. This is not TCP, wake-performance, energy or
release acceptance. Plane owns task status; earlier progress comment
`242729d2-3b6c-46f3-a4c0-90d5fa9b6b5b` remains historical.

## Current artifact

- Manifest: `build-output/s239-20260912/pixel-build-g/build.json`.
- Product source: `c568caca61a252c7c34f38c091c53ff9d08491262bc2c5f21bea8850d7338e84`.
- APK: `c1ac9d752fa521b2eddbfe8652889675f3e5da3dc8729b5d05cf8d370487f483`.
- VPP stage: `/tmp/s239-wake-vpp-stage`, same pinned 26.02 revision and 19
  Android patches as the [worker notification fix](2026-09-12_S239_WORKER_WAKE_FIX.md).
- Pixel `28201JEGR0XPAJ`, all device operations through `./dev/adb`.

The manifest includes dirty source, native/APK hashes, source snapshots and
separately attributed test helpers. Installed APK/native files were hashed for
every run. Build-g adds only the bounded concurrent debug traffic generator and
validation hold/trace seams to the earlier wake-fix Product artifact; the VPP
core remains the same. Earlier d/f artifacts are historical for those source
closures, not current-source acceptance.

## Executed real-device matrix

Run directories below are under `build-output/s239-20260912/`.

| Run | Generation | Controlled original/return packets | Outcome |
| --- | --- | --- | --- |
| `g-concurrent` | 1124 | 1000 / 1000 | Four simultaneous real UDP flows: IPv4/IPv6 on each owner; all exact echoes |
| `g-quota0` | 1125 | 204 / 172 | Owner 0 quota full at 128; 32 further return admissions rejected; other owner progresses; recovery |
| `g-quota1` | 1126 | 204 / 172 | Same test with owners swapped |
| `g-stop0` | 1127 | 192 / 160 | Stop while owner 0 still holds 128 native returns; actual quiesce/drain releases all |
| `g-stop1` | 1128 | 192 / 160 | Same stop test with owner 1 holding returns |

All five passed `verify-s239-w2.py`. These counts exclude kernel-generated ICMP
control packets, which are also checked for exactly-once native completion.
There were no primary-handoff drops in these final runs.

The concurrent plan closes one owner-0 IPv4 application socket after ten
requests. The other three flows each continue for 330 requests at a nominal
200 ms send interval. Acceptance requires their last echoes to occur more than
60 seconds after the early socket closes, and requires actual HEV socket/session
closure on owner 0 while owner 0 retains its IPv6 session and owner 1 retains
both sessions. Application socket closure alone is not treated as transport
session termination.

The quota plan first establishes four sockets, then sends 160 requests on one
owner using a 2 ms inter-send interval without waiting for replies. Its 128
native return buffers stay charged while 20 requests on the other owner echo
before release. All 160 selected requests reach the real endpoint; 32 outputs
are explicitly rejected by the exhausted native allowance. Both owners then
recover using the same four transport sessions, without re-brokering sockets.
The stop variants preserve the full 128-credit snapshot immediately before
stop and require all 128 releases after that owner's actual quiesce event.

Each final stop reports both shards with zero sessions, inputs, pbufs, buffers,
obligations and completion frames; exactly two created/closed sockets per
owner; timer/broker descriptors `-1`; destroyed heaps empty; and no surviving
native process. Separate runs use new generations.

## Validation seam and independent checks

`product tun return-hold <owner> <0..10000 ms>` is restricted to active HEV
validation. It delays actual return completion in the existing native retained
completion storage. It does not create another packet queue, map or copy.
The retry node scans at most 64 entries per invocation, rotating only
validation-held returns so original TUN capture completions can still release
the shared capture allowance. Ordinary native destination congestion retains
its existing retry behavior. Stop clears holds before draining.

The trace-limit CLI permits a bounded monotonic increase after attachment:
Android can emit ICMP control packets before CLI access is ready. It does not
reset packet ordinals or retroactively produce missing trace events.

The independent verifier joins exact application payloads and real endpoint
receives to actual graph packets, computes canonical ownership with the
separate oracle, and checks buffer identity through policy, terminal,
completion and native free. It checks return-credit ownership through the
post-native-free release witness. The shared bookkeeping `buffer_free` log is
emitted after the release log; source ordering confirms the actual native free
precedes both. Log-line ordering is not substituted for the native call order.

HEV pbuf allocation intervals are checked across both owners; reused addresses
are allowed after free. Mutable callback thread/TLS must match each owner.
Session IDs are owner-local, so `(owner, session ID)`, not a global session ID,
is the verifier key. Both owners must have actual callback activity.

Six negative controls reject missing credit release, wrong return worker, wrong
pbuf owner, duplicate native free, falsely early credit release and a changed
generation. The extracted actual native retry loop also passes bounded-scan,
wraparound, held-return/original-progress, normal-congestion and drain tests.
The existing ten real HEV host tests and native notification primitive tests
passed again; host evidence does not replace these Pixel rows.

## Retained diagnostic failures

- `e-quota1`: trace-limit setup correctly refused changing the old cap after
  attachment-generated control traffic; the bounded monotonic-increase seam
  addresses that test setup requirement.
- `f-concurrent`: Android froze the cached UI process hosting the traffic
  generator. ActivityManager logged freeze/unfreeze; the separate native
  runtime continued transport expiry. The runner now keeps the ordinary debug
  Activity visible during sustained traffic without disabling the platform
  freezer or adding a wakelock.
- `f-concurrent-b`: all sent packets echoed, but the initial 650-packet plan
  exceeded the generator's 90-second total bound with tracing enabled. The
  final lower-rate plan preserves the real 60-second expiry check. No Product
  packet timeout was increased, and this is not a throughput gate.
- Unpaced f quota/stop runs sometimes lost packets in the existing primary
  handoff path before reaching native return admission. Their outcomes remain
  separate from return-quota rejection. The final 2 ms burst pacing reliably
  reaches the full return allowance and accounts for all 160 endpoint receives.

These failed or narrower runs are not relabeled as the final acceptance rows.

## Installed notification and same-artifact regressions

`g-native-notify-d`, generation 1134, passed both `verify-s239-w2.py` and
`verify-s239-notify.py`. A bounded simpleperf instruction probe observes the
actual compiled notifier's exchange result; raw syscall and scheduler events
are recorded from the same native process. The instruction/register mapping
is pinned to libvlib SHA-256
`06b64e815c1322600798a63ab93b0a7acd89d7d24244bbd47707c4a4f9fa4318`,
ELF VA `0x321c8`, file offset `0x2e1c8`. This is not an alternate notifier or
an injected wake source. The verifier re-reads the raw perf file and checks it
against the derived event record.

- Target thread 1: 62 observed latch operations, four coalesced, 58 actual
  successful eventfd writes and 58 successful reads.
- Target thread 2: 37 latch operations, 37 successful writes and reads.
- Empty nonblocking reads are separately counted, not interpreted as lost
  notifications. Recorded lost samples: zero.
- Actual interruptible scheduling and positive-timeout epoll intervals are
  retained for both workers. After the initial four-flow burst, both were
  observed in epoll; one isolated remote-owner request then arrived during an
  actual recorded epoll sleep and completed policy after an elected notifier
  and wake. All 49 registered requests echoed and settled.

The probe adds overhead and changes scheduling opportunities. These counts
establish real integration and observed coalescing, not an energy saving,
representative coalescing ratio or latency-percentile result. A prior complete
short trace (`g-native-notify-c`, generation 1131) independently passed with
90 latch operations / five coalesced / 85 writes. Earlier trace-run export
failures remain failed runner records, not acceptance substitutes. No uprobe
event remained registered after the final audit.

The same build-g also passed these regressions:

| Run suffix under `g-` | Generation | Independent verifier |
| --- | --- | --- |
| `root-reassembly-basic` | 1132 | S229 basic matrix, 32 original native buffers |
| `root-completion-pressure` | 1133 | S229 policy-return pressure, 24 original buffers |
| `owner0-udp4-input-reject` | 1135 | Sleeping worker, input rejection and recovery |
| `owner1-udp4-output-alloc` | 1136 | Sleeping worker, output allocation failure |
| `owner0-udp6-write` | 1137 | Sleeping worker, real TUN write failure and settlement |
| `owner1-udp6-pre-accept` | 1138 | Sleeping worker, pre-graph return rejection/free |
| `owner0-udp4-stale-output` | 1139 | Stale output generation rejected |
| `owner1-udp6-stale-output` | 1140 | Same stale-generation check on remote owner/IPv6 |
| `owner0-udp6-return-drop` | 1141 | Shared return Policy DROP and recovery |
| `owner1-udp4-return-drop` | 1142 | Same return-policy check on remote owner/IPv4 |

Root rows retain their GRAPH_INJECTED fragment-witness scope; they are not
claims that all fragments were captured from real network traffic. VPN rows
use real application/underlay UDP. Each selected worker was observed sleeping
before the probe without a VPP CLI barrier during that observation window.
The maximum measured graph leg across these small diagnostic runs was
6.487 ms; this is not p99 qualification. Both shard shutdowns and resource
settlement were checked in each VPN row. The wake verifier's negative controls
again rejected missing release, wrong return worker and a two-second delay.

## Reproduction

```sh
rtk proxy python3 tests/device/s239-pixel-w2.py \
  --build build-output/s239-20260912/pixel-build-g/build.json \
  --ipv4 192.168.4.5 --ipv6 fd76:d462:c4e3:0:683a:da9a:d9e1:abdd \
  --case quota1 --output <new-run-directory>
rtk proxy python3 tests/device/verify-s239-w2.py \
  --build build-output/s239-20260912/pixel-build-g/build.json \
  --run build-output/s239-20260912/g-quota1
```

Endpoint addresses are the controlled lab environment, not product defaults.

## Controlled Doze procedure registered before execution

Build-g, same four canonical flows, 50 requests per flow at nominal 500 ms
spacing, existing 1500 ms receive timeout. After five seconds of traffic,
request screen-off and `cmd deviceidle force-idle deep`; require observed
`IDLE`, retain power-policy state, wait ten seconds, and require `IDLE` again.
Unforce and wake the screen, restoring the initially unforced/awake state.
Require all 200 exact echoes and normal native ownership/free/stop checks for
a traffic PASS. A failure remains a failure pending classification against
actual power/network policy; missing evidence is not silently waived.

This controlled forced-policy test does not simulate battery state, modify
whitelists or persistent settings, or prove physical CPU suspend/energy use.
Cleanup restores power policy even if the traffic test fails. It is separate
from the still-unqualified CPU/p99 performance gates in SAKAMOTO-248.

Executed result: `g-doze`, generation 1143, passed the independent W2 verifier:
200 originals, 200 exact returns, 200 endpoint receives and no primary drops.
Power state was observed as `Dozing` with `mDeviceIdleMode=true`, and the
controller remained `IDLE` across the ten-second interval. It was restored to
`Awake`, `mDeviceIdleMode=false`, `mForceIdle=false`, and `ACTIVE` afterward.
Final runtime state: stopped, `mayBeActive=false`, `pid=-1`, no error; both
shards and native resources drained.

## Accepted task split — 2026-09-12

These results close the recorded correctness scenarios, not the formal
performance gate. Existing ADR/P6 thresholds have not been changed or waived.
The old requirement of at least 20% p99 improvement needs an explicit
comparison definition for this new complete protocol: comparison with the
known seconds-long failing Product demonstrates defect removal; comparison
with a reliable uncoalesced notifier tests the incremental optimization.
Those are different questions. No favorable short trace is used as a proxy
for either campaign. The user explicitly requested a separate formal CPU/p99
performance task. SAKAMOTO-248 now owns that comparison definition,
pre-registration and campaign; it depends on S239's correctness artifact,
not the reverse. S239 is complete under the agreed functional scope. Existing
thresholds and historical non-GO results are neither changed nor waived.
