# S199 / S201 / S202 — foundation integration evidence

This record covers the final foundation integration matrix, not a Product Release
gate. The original implementation sequence is complete through S235. The user's
2026-09-13 decision still defers the real 86400-second TCP idle/reuse test in S236;
neither shorter deadlines nor this integration run convert that test into PASS.

The combined gate passed as **PASS_WITH_EXPLICIT_LIMITS**, covering 64 distinct
Pixel generations plus the separate Linux lifecycle matrix. It found no blocking
connectivity failure within the declared test scope; it does not guarantee every
protocol, network, hardware or long-duration workload.

## Current Product identity

Product commit: `50d71316aedbc25237c13535116af9fdb0d900e9`.
Both Linux and Pixel use the S235 source-B artifacts, built from the frozen source
and dirty diff before that commit, with identical current Product source closure:

```text
ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96
```

The installed Pixel APK SHA-256 is
`e964f9d9a83ece13bbc5ac02465931ee97091c2681f39168d487b0f8eb71994f`.
Build manifests are `build-output/s235-20260913/linux-build-b/build.json` and
`pixel-build-b/build.json`; they retain native hashes, source files and build
witnesses. VPP remains pinned at `9258530f3804a152578ce11cc7c8a1e9eab88ed0`,
with the six-patch core series from S220. No Product C, Rust, Java, VPP or HEV code
changed during this joint regression; only test collection/verification changed.

Pixel is the dedicated `28201JEGR0XPAJ`, operated through `./dev/adb`. Independent
LAN peers use `192.168.4.5` and `fd76:d462:c4e3:0:8846:7e07:294a:ac41`, checked
before collection. Linux Root operates in a disposable rootless user/network
namespace; it does not install hooks or routes in the host namespace.
Observed kernels are `6.6.114.1-microsoft-standard-WSL2` (x86_64) and
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` (Pixel aarch64).

## New integration observations

Paths below are relative to `build-output/foundation-joint-20260913/`.

| Evidence | Observed scope |
| --- | --- |
| `linux-root` | Real NFQUEUE, W2/Q2 per family, independent TCP/UDP4/6 clients; partial-start rollback, native verdict failure, duplicate/stale completion rejection, stop, restart, crash and recovery |
| `pixel-root-b` | RuntimeService/JNI and production Root hooks; generations 1435–1438, 24 observed continuous TCP/UDP clients per generation; normal and abnormal closure checked separately |
| `vpn-active-a` | Generations 1384–1391; 64 app flows across normal stop/restart, native crash/recovery and both owners' broker-loss/recovery |
| `vpn-underlay-a` | Generation 1392; 16 app flows, real Wi-Fi loss/new Android Network, same UDP socket echo/timeout/DROP/echo and fresh dual-stack TCP/UDP afterward |
| `vpn-capacity-a` | Generations 1393–1434; all 42 TCP/UDP × IPv4/IPv6 processing/transport capacity and failure cases, with the other owner as a live witness |
| `vpn-tcp-a` | Generations 1441–1442; full dual-stack W2 FIN/RST, connect refusal, server reset, SYN retransmission, return-policy DROP, active stop and restart matrix |
| `vpn-recovery-a` | Generations 1443–1447; one automatic retry, exhausted retry budget, cancellation, two rejected preparation attempts and eight ordinary app echoes after VPN withdrawal |
| `vpn-credit-b` | Generations 1448–1449; actual two-slot completion queue, 32 DROP datagrams per family, 15/29 retained completions followed by native retry and exactly-once settlement |

Linux's four traffic generations captured 233/42/41/190 packets and performed
233/42/40/190 native verdict operations. Four deliberately failed operations belong
to the first generation. The one unfinished captured packet in the crash case is
an OS-reclaim observation, not a successful drain. Each generation has 24 kernel
clients; the immediate gated stop/crash does not claim all clients were captured
before termination. Ordinary stop/recovery observes all 24 in the native path.

Pixel Root captured 1248/1171/1647/1097 packets. Normal generations have exactly
matching native verdict/completion/free counts. The crashed generation has 1625
observed verdict calls and 22 unfinished captures; its supervisor explicitly
records OS reclamation, without a false native-zero claim. Restart uses a new
durable generation owner, and the production hooks/queues are absent after stop.

The capacity run independently reconciles 1265 TUN captures and 630 real HEV/lwIP
returns. Its 61 processing-bypass observations, six policy drops, 164 rejected
transport inputs and 186 transport-failure events are distinct counters, not
interchangeable outcomes. Existing flows and the other owner remain usable;
new tuples recover after real resource release. UDP limiting resources use their
actual 60-second transport idle expiry, never a shortened clock or forced close.

Normal VPN return bytes originate from HEV/lwIP, re-enter shared parsing and
policy as `FLOW_STACK_RETURN`/INPUT, then complete at the original TUN lane.
Independent app/peer bytes, packet checksums, canonical owner calculation,
generation, pbuf lifetimes, input/output copies, completion credits, FD closure
and buffer/obligation settlement are checked together. `protectionRunning=false`
on the controlled VPN validation entry remains explicit; this is not a normal-user
release protection claim.

## Boundaries and earlier leaf evidence

- S236's real 24-hour ESTABLISHED expiry/reuse remains **USER-DEFERRED / UNVERIFIED**.
  Its accepted short/mixed scope and cancelled-run cleanup are recorded in
  [the S236 report](2026-09-13_S236_PROTOCOL_EXPIRY.md).
- S235 proves actual Linux WireGuard classification, event loss/resync, interface
  reuse and separately labelled controlled projections. This machine has no
  qualified physical Wi-Fi, Wired or Mobile endpoint for those Linux checks;
  see [the S235 report](2026-09-13_S235_LINUX_NETWORK_SNAPSHOT.md).
- Pixel has no SIM. Real Wi-Fi loss/restoration is proved; cellular handover is
  not. No arbitrary VPN-provider discovery or all-hardware compatibility follows.
- Detailed fragment/reassembly cases retain their separately scoped
  [S229 leaf evidence](2026-09-11_S229_INDEPENDENT_REASSEMBLY.md); this TCP/UDP joint
  matrix does not replay or expand those claims. Graph injection is never renamed
  real NFQUEUE/TUN input. The superseded native-reassembly exception proposal is
  not used to waive an acceptance branch.
- Canonical packet ownership, ordered CPU placement and per-packet network facts
  remain separate. Production artifacts exclude the historical Host-only owner
  guard/corrective path; neither CPU order nor network ifindex enters the packet
  owner hash. The runtime as a whole is not claimed to be lock-free.

## Verification and excluded attempts

`tests/evidence/verify_foundation_joint.py` freshly invokes the independent
component verifiers. It requires matching current Product builds, all declared
matrix cells, distinct lifetimes, raw device/endpoint identities and resource
closure. Its result is scoped `PASS_WITH_EXPLICIT_LIMITS`, not a release result.
The recipe and reports retain hashes for all raw files and verifier dependencies.

The original `pixel-root` attempt is excluded. Its host-side download of a large
active log outlasted the existing 500-ms policy hold before SIGSTOP, leaving no
unfinished capture for the required crash test. The verifier correctly rejected
it. `pixel-root-b` observes the hold and freezes the owned process on-device in
one bounded shell operation. Product timing, hold limits and acceptance assertions
are unchanged. Network subscription observations also bracket each app lifetime.

`vpn-credit-a` is excluded from the combined acceptance: its IPv6 run reached
retained completion pressure, but the IPv4 16-datagram burst did not fill the
two-slot return ring. Correct DROP alone is not pressure coverage. The repeated
pair uses a declared 32-datagram app burst, still within the existing 32 primary
credits; neither Product capacity nor the strict retained/retry assertion changes.

The TCP collector now accepts the existing separate current-build helper manifest;
it does not edit a frozen build witness to invent a legacy helper entry. The
checker verifies build/source/helper identities for either declared manifest form.

HEV host regression is **36/36**. Full current repository CTest is **35/40**, not
green: the five pre-existing VPP/S176/S189/S190/S191 static-contract failures remain.
Their scripts are unchanged from `82547e84a4d36eefe46b855d213bf9f4eb418dd8`.
Current XML is retained as `hev-host.xml` and `host-tests.xml` in the joint evidence.
The pinned OVS differential test also passed 131072 vectors under ASan/UBSan:
73080 valid, 53884 invalid and 4108 replacement results. Only its throwaway host
executable uses non-PIE to avoid the environment's previously recorded sanitizer
startup failure; Product hardening and the independent shared replay oracle are
unchanged. The failed sanitizer attempts are not counted as passing tests.

Twenty-nine current-witness corruption cases are rejected: eight Linux Root,
eleven Pixel Root and ten VPN. They cover rehashed stale-source/build declarations,
wrong installed identity, graph injection, POC readiness/return claims, duplicate
or redirected verdicts, wrong generation and nonzero resource debt. Mutations
overlay reads in memory, with updated raw hashes where applicable; original
device evidence is never overwritten.

Final gate report SHA-256:
`c30e50b88da0dfa53f4b6eb5cb42ce595c27eade52765700da6b8bb76db94862`.
Recipe SHA-256:
`80bc17c9e8fc1eb434c91fe12aaa616e0a82c6242a3342b01e3ec663e628a09e`.
The Pixel finished at generation 1449 with `state=stopped`, `mayBeActive=false`,
`pid=-1` and no error. Wi-Fi is restored to on; worker CPU preference remains `1,2`.
Independent host peers and the Linux namespace are closed.

```sh
rtk proxy python3 tests/evidence/verify_foundation_joint.py \
  --input build-output/foundation-joint-20260913/acceptance-input.json \
  --output build-output/foundation-joint-20260913/acceptance.json
```

## Release requirements check

[SAKAMOTO-59](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/32a7eb03-f251-4070-a43e-1c3ddb5c0699)
remains a separate release gate. This foundation evidence supports scoped
connectivity, ownership, lifecycle and failure behavior. It does not establish
a signed release/support-device matrix, the complete user-facing Root/VPN scenario,
profile-switch/policy-persistence conformance, performance/power/thermal budgets,
bilingual product content/privacy/diagnostics or user feedback entry points.
Those requirements are not implemented or marked complete by this work. Linux is
an engineering test endpoint, not an added desktop product release target.

Task status and any deferred acceptance live in Plane; this is a dated evidence
record, not another backlog.
