# SAKAMOTO-127 OI-2 execution journal

Date: 2026-08-22 (host Linux, x86_64)

This record started as the first bounded contract probe after the OI-1
Host/Pixel scoped GO and now includes the same seam attached to a VPP owner
worker on host Linux and the selected Pixel 6a runtime.  The earlier Android
standalone-VPP run was only the native integration baseline; the gate below
continues through the real Android Java/native broker before assigning the
OI-2 conclusion.

## Hypothesis under test

An owner can create a nonblocking IPv4/IPv6 TCP/UDP socket and submit an
opaque request plus one `SCM_RIGHTS` duplicate through a bounded request
channel without waiting.  A separate broker can perform bind then protect,
close its duplicate exactly once, and publish a completion.  The original
owner can continue graph work while completion is delayed, and generation /
owner / epoch checks prevent a late or foreign completion from reviving a flow.

The wire contract is in
`prototypes/owner_inline_oi2/oi2_broker_contract.h`; the Python model is a
state-shape check, while `oi2_socket_probe.c` exercises real Unix socket,
IPv4/IPv6 socket creation, `bind(2)`, `SCM_RIGHTS`, nonblocking submission,
and a separate broker thread.

## Artifacts

```text
state model       d3f077b325df574ce09a0ff9803947c7dab43184b3a2904777f7bf1d024d406b
wire contract     71a6c46c59f0db6fd963ada589c60e4d013ef57e88fee2da9f36d441042edc3a
socket probe      fe68b5cb5a569e6854afeb52c25a4b20eebc75a223c2c37137382e0ee123c533
host executable   167c7c9869053d533eaf2648ca3d1d5864252e01181e373b7ae1e99439c8fa91
VPP OI2 source    003d024302d742aede1202aaad19937aced84d82f558b48ba1639c9db6cb5abb
OI2 overlay ABI   2b50efe955805f193482a88af0f4fffa222286b14d89f93434e5cbb3a9dd3d3b
host OI2 plugin   e57132658a1b6ffb11e8e4739a44e0ab729a12f993e8d83036e74fc19d8ff423
host VPP binary   5c4d1f707d2e7072a2da5974b76e3f7c43b13ecd823f2d76fbb91d5aa644908d
Android JNI       5fd98113246162cb73064eb4b95139d19722cbacb6bcbb68ba73abb69291b8ff
Android JNI .so   24073c25679c39df91f1437c30f4a0c353dff62d847469ca8711307467eae7a9
Android Java      613923801c05d7de232d4a7a8aa4ce9d32004718f6ba0a50f79aab1a8ef5c5fc
Android manifest  daa7e739faed7f34585d72c2f51ec96f48d2c33968423ed7d9a0178ae6339443
Android OI2 plugin 435d872a570c1fadfe4e7a6cf00dddd615c87e3707716262e1b4364b408f693d
Android APK       a6debcf91d17c9a4048f6c8e89b3cadacd54e81693cb02f9304039af0d642ffb
Android VPP       8f4714d4bde4e1e86b35ef8941e1e490a07e47285445b844f5b9176b928691f7
Android vppctl    002434f6a652f35fd87c4c141ff47a22886de44e0dec78e2c456ec34f33551e3
```

Commands:

```text
rtk make -C experiments/vpp-nfq-poc owner-inline-oi2-model
rtk make -C experiments/vpp-nfq-poc owner-inline-oi2-socket-probe
```

The real socket command required the approved host capability because the
default sandbox returned `EPERM` for IPv4/IPv6 socket creation.  The model ran
without escalation and passed first.

## Real host cells

The clean probe output was:

| Cell | Evidence |
| --- | --- |
| IPv4/IPv6 TCP/UDP success | 4 accepted; bind=4, protect=4; order `BPCBPCBPCBPC` (bind/protect/close-duplicate); owner/sentinel ticks 120/120; original close=1 and connect/first-send=1 for all four. |
| Forced bind/protect failure | 2 accepted; bind=2, protect=1; both original sockets closed once; connect/first-send stayed 0; outcomes were bind-failure and protect-failure. |
| Delayed broker + stop | owner/sentinel ticks 43/43 while completion was delayed; late completion rejected with stale=1/late=1; original close=1. |
| Broker unavailable | accepted=0, unavailable=1, bind/protect=0, original close=1. |
| Bounded queue full | accepted=2, queue-rejects=2; accepted sockets completed, rejected sockets had no connect/send and were closed once. |
| Completion tripwires | duplicate=1, stale=1, wrong-owner=1, wrong-epoch=1; no second connect/send. |

The Python model covered the same cells and additionally checks that policy
DROP/fallback is never substituted for an infrastructure/transport failure.

## VPP owner-worker integration gate

The contract was attached to `owner_inline_oi2.c` in the existing
`hev_external_driver_poc` plugin.  The owner worker creates nonblocking
IPv4/IPv6 TCP/UDP sockets, submits one `SCM_RIGHTS` duplicate through a
directional request channel, and never calls `poll`, `recv`, `connect`, or
`send` while waiting.  The host build keeps the deterministic broker for the
contract gate; the Android build switches the same owner/client code to an
inherited-FD external broker.  In both cases the completion is consumed by a
main-thread `clib_file` callback that only enqueues a buffer back to the
original worker.  A 64-buffer VPP sentinel is scheduled to the same worker to
make delayed completion fairness observable.

The host plugin was built with warnings-as-errors:

```text
rtk env INSIDE_VPP_NFQ_CONTAINER=1 SKIP_CORE_PATCHES=1 \
  VPP_DIR=experiments/vpp-nfq-poc/work/vpp \
  ./experiments/vpp-nfq-poc/scripts/apply-vpp-overlay.sh
rtk env PYTHONPATH=/home/js/android/lineage/external/ply/ply \
  CCACHE_DIR=/tmp/oi2-ccache \
  cmake --build /tmp/s119-vpp-build \
  --target hev_external_driver_poc_plugin -j4
```

Post-fix host CLI results (two VPP workers, target worker `1`):

| Cell | Worker / completion evidence |
| --- | --- |
| families | `submitted=4 completed=4 inflight=0`, bind/protect `4/4`, connect/first-send `4/4`, duplicate-fd-closes `4`, sentinel `64`, buffers `70/70`, residue `0`. |
| failures | `submitted=2 completed=2`, bind/protect `2/1`, connect/first-send `0/0`, infrastructure/transport failures `2/2`, sentinel `64`, buffers `68/68`. |
| unavailable | `submitted=1 completed=1`, bind/protect `1/0`, connect/first-send `0/0`, infrastructure/transport failures `1/1`, sentinel `64`, buffers `67/67`. |
| queue-full | `submitted=2 completed=2 inflight=0`, queue rejects `2`, bind/protect `2/2`, connect/first-send `2/2`, sentinel `64`, buffers `68/68`. |
| tripwires | `submitted=1 completed=1`, duplicate/stale/wrong-owner/wrong-epoch `1/1/1/1`, connect/first-send `1/1`, buffers `67/67`. |
| delayed-stop | after owner stop: `submitted=1 completed=0 inflight=0`, stale `1`, bind/protect `1/1`, connect/first-send `0/0`, sentinel `64`, buffers `68/68`. |

The first VPP queue-full run exposed a lifecycle bug: `completed + rejected`
could satisfy the finish condition while another accepted request was still
inflight, turning its completion into a false stale.  Finish now additionally
requires `inflight == 0`; the clean post-fix run above has no stale completion.

## Android arm64 / Pixel 6a Java-native broker gate

The same plugin was cross-built for arm64-v8a with Android NDK r29, staged with
one worker (`main-core 0`, `corelist-workers 1`), packaged into the test APK,
and installed through the repo-local `./dev/adb` wrapper.  The live device was
serial `28201JEGR0XPAJ`, Pixel 6a, Android 16,
`google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`.

The Android mode is `vpp-oi2` (`vppMode=15`).  The native parent creates two
bounded `SOCK_SEQPACKET` socketpairs, passes fixed child descriptors through
`SAKAMOTO_OI2_REQUEST_FD`/`SAKAMOTO_OI2_COMPLETION_FD`, and starts a broker
thread in the `VpnService` process.  The VPP child sees
`external-broker=1`; its owner path remains nonblocking and its completion
callback remains the original-worker handoff seam.  The broker thread receives
exactly one `SCM_RIGHTS` duplicate, calls Java
`Network.bindSocket(FileDescriptor)` and then `VpnService.protect(fd)`, closes
the duplicate once, and sends the opaque completion.

```text
Android APK       a6debcf91d17c9a4048f6c8e89b3cadacd54e81693cb02f9304039af0d642ffb
Android JNI       24073c25679c39df91f1437c30f4a0c353dff62d847469ca8711307467eae7a9
Android Java      613923801c05d7de232d4a7a8aa4ce9d32004718f6ba0a50f79aab1a8ef5c5fc
Android manifest  daa7e739faed7f34585d72c2f51ec96f48d2c33968423ed7d9a0178ae6339443
Android VPP       8f4714d4bde4e1e86b35ef8941e1e490a07e47285445b844f5b9176b928691f7
Android vppctl    002434f6a652f35fd87c4c141ff47a22886de44e0dec78e2c456ec34f33551e3
Android OI2 plugin 435d872a570c1fadfe4e7a6cf00dddd615c87e3707716262e1b4364b408f693d
startup.conf      07a5ce727c7ee6dd6e83c6c566b76991b6a4e2695c8c725f5ed7a46049b371b8
```

The first APK run exposed only a missing manifest declaration:
`ConnectivityManager.getActiveNetwork()` raised `SecurityException` because
`ACCESS_NETWORK_STATE` was absent.  The permission was added, the APK rebuilt,
and the gate was rerun.  This was an environment/packaging correction, not a
change to the owner/broker design.

The successful Java ledger logged one active network handle per run (the final
single-artifact rerun used `3641242996749` for both IPv4 and IPv6 requests;
the earlier post-permission run used `3632653062157`).  Each success logged, in order,
`Network.bindSocket ... result=true`, `VpnService.protect ... result=true`,
and native `java-result=1`; each request then logged `duplicate close`.
Failure flags were exercised through the same Java call and overridden only at
the broker completion boundary: `flags=1 -> result=2` (bind failure) and
`flags=2 -> result=3` (protect failure).  The unavailable request used
`flags=4 -> result=4` and did not enter Java.  Thus no failure path connected,
sent, or fell back to policy drop.

| Cell | Pixel VPP owner ledger | Android broker ledger |
| --- | --- | --- |
| families | `submitted=4 completed=4 inflight=0`, `connect=4 first-send=4`, sentinel `64`, buffers `69/69`, residue `0`. | Four Java bind→protect successes; four duplicate closes. |
| failures | `submitted=2 completed=2`, `connect=0 first-send=0`, infrastructure/transport `2/2`, buffers `67/67`. | Java returned success for both deterministic requests; completion results were bind-failure/protect-failure (`2/3`), with two duplicate closes. |
| unavailable | `submitted=1 completed=1`, `connect=0 first-send=0`, infrastructure/transport `1/1`, buffers `66/66`. | `flags=4`, result `4`; no Java call; duplicate closed. |
| queue-full | `submitted=2 completed=2`, queue rejects `2`, `connect=2 first-send=2`, buffers `67/67`, residue `0`. | Two accepted Java bind→protect requests and two owner-side rejected sockets closed without transport. |
| tripwires | `submitted=1 completed=1`, duplicate/stale/wrong-owner/wrong-epoch `1/1/1/1`, `connect=1 first-send=1`, buffers `66/66`. | One Java bind→protect success and one duplicate close; synthetic foreign completions were rejected by the owner. |
| delayed-stop | after an in-shell `delay-ms 1000` then owner stop: generation advanced, `submitted=1 completed=0 inflight=0`, stale `1`, `connect=0 first-send=0`, buffers `67/67`. | Broker completed Java bind→protect after the stop boundary and closed the duplicate; owner rejected the late completion. |

All device cells reached `STOPPED`, had sentinel progress `64`, and left VPP
buffer residue at zero.  A clean service stop through `./dev/adb` left no VPP
process on the Pixel.

The final APK/JNI rebuild was smoke-tested again after the broker receive
lifecycle guard was added: the exact artifact reported `external-broker=1`,
four family requests completed with `connect=4` and `first-send=4`,
`sentinel=64`, `buffers=69/69`, and `residue=0`.  Its broker log recorded four
Java bind→protect successes and four duplicate closes.  Service stop left no
VPP process; a child-socket `ENOENT` is logged once at teardown and exits the
broker loop rather than spinning.

## Bugs exposed and fixed by the probe

1. The first implementation used one bidirectional `SOCK_SEQPACKET` endpoint
   for both directions.  The broker read its own completion as a request,
   broke the receive loop, and left the last family/type request pending.
   Separate bounded request and completion channels fixed this.
2. `stop_broker()` could run before the new thread stored
   `broker_running=true`; the thread then overwrote the stop state and polled
   forever.  An independent C11 atomic stop flag fixed the lifecycle race.
3. The first real APK run was rejected by Android permission enforcement before
   any network operation.  Declaring `ACCESS_NETWORK_STATE` restored the
   intended `getActiveNetwork()` -> `Network.bindSocket()` -> `protect()` path;
   no owner-path redesign was needed.
4. Normal child teardown could return a non-`EAGAIN` receive error after the
   stop boundary.  The broker now logs that disconnect once and exits the
   receive loop, preventing a repeated-error spin while preserving the
   generation-safe late-completion rejection.

These are evidence that the contract needs explicit directional channels and a
generation-safe broker lifecycle; they are not grounds to silently reuse the
old synchronous `send_fd_and_wait_result()` path.

## OI-2 conclusion

**ASYNC_BROKER_GO (POC seam).** The original hypothesis survived every gate and
was completed rather than replaced: the host contract probe, VPP owner-worker
integration, and real Pixel Java/native broker all passed the same bounded
cells.  The Android evidence specifically establishes:

- owner-side request submission is nonblocking and uses no synchronous JNI,
  `poll`, `recv`, `connect`, or `send` while waiting;
- the Java-only Android operations occur on the separate broker thread, in the
  observed order `Network.bindSocket` -> `VpnService.protect`;
- request/completion directions are separate, inherited FD handoff is live,
  SCM_RIGHTS duplicate ownership is closed exactly once, and late/foreign
  completions are rejected;
- bind/protect/unavailable failures become infrastructure plus transport
  failures without policy-drop/fallback, and sentinel fairness plus VPP buffer
  residue remain clean.

This is an OI-2 seam decision, not a claim about the out-of-scope full TUN
remote datapath, throughput/capacity, network migration, or production
lifecycle hardening.
