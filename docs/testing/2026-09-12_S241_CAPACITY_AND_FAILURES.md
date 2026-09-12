# S241: VPN policy bypass and transport failure boundaries

Executed on 2026-09-12 for SAKAMOTO-241, using the current VPP-native C
Product and real owner-local HEV/lwIP TCP/UDP. This is fault/recovery evidence,
not release readiness, underlay migration, or a throughput/p99 qualification.

## Product increment

Inspection capacity and transport capacity remain different domains. A full
FlowEntry pool produces `FLOW_CAPACITY` processing bypass, retaining already
evaluated policy results and entering the same canonical owner's Flow Stack.
Its completion says `NOT_EVALUATED`, not a fabricated Policy Verdict ALLOW.
Root's pre-policy NF_ACCEPT capacity path is not a VPN transport fallback.

The dependency-private owner interface now records typed execution failures:
session, PCB, socket, packet-credit and pbuf capacity; allocation/socket errors;
broker submission/timeout/authorization; protect/bind; refusal/unreachable;
connect/socket I/O; output capacity/rejection. These are not policy decisions
or end-to-end delivery acknowledgements. Each owner exposes counts, first/last
failure times and the last error/session. Diagnostics retain failure history
for the generation even after traffic recovers; they do not publish protection
readiness or turn a single packet failure into a global runtime stop.

`0012-owner-pcb-budget.patch` accounts actual lwIP PCB allocations and frees,
including the two listeners. The existing owner TCP patch already excludes
lwIP's PCB-eviction fallback. Session and socket limits reject new creation;
packet credit counts live input-pool pbufs, and the existing total-pbuf budget
rejects the current allocation. Existing transports are not evicted, moved to
another owner or directly forwarded by the kernel. Quiesce/destroy verifies
all PCBs, pbufs and lwIP heap storage are reclaimed.

Default per-owner limits are 256 sessions, 258 PCBs, 256 sockets, 1,024 input
packets and 8,192 pbufs. The debug validation profile can only reduce these
startup limits, not resize a live owner. A separate one-shot broker diagnostic
exercises actual Android protect/bind failure on an invalid descriptor. Native
error codes survive the broker reply; no failed request connects or retries
without protection. Packet and completion metadata sizes remain unchanged.

## Artifact and independent witnesses

Build: `build-output/s241-20260912/pixel-build-a/build.json`, with source
snapshots, dirty diff and all twelve native library hashes. Git base is
`0f5957290fded7884f7b5a795a97f9145c58f182`; the dirty source closure, not that
commit alone, identifies the executed implementation.

| Identity | SHA-256 |
| --- | --- |
| Product source closure | `91de5e8bb3a792ec7b994ec3b99a6ddce2195b177804949b9e2a1f99df360982` |
| Installed APK | `6038edd53a34f0818760bd21e06edd3e99bfcd3331a48a3a2ecdcd2e58c9c401` |
| Product plugin | `197b1b0319d5b77c4736073c5112c112bcc27350c2b34e54148a6296b2da164b` |
| VPP runtime | `62d2c7339c9d17089f7198d4d74cc3d79f44321cd841e734e38004c607dff5bb` |
| S241 verifier | `fb2b9d2bf77eaf07c501358f2bd371306683a898075b69e4c7f4273fee7d7aad` |
| S241 negative suite | `cf506452daa6415e65b4b0b9308ea7fa1e95155f4a3b29fb86d168bcded1f15c` |

The VPP stage was rebuilt from pinned VPP 26.02 commit
`9258530f3804a152578ce11cc7c8a1e9eab88ed0` and all nineteen current Android
patches. Their aggregate hash is
`884aa3aac9457d8b34482f0d0c0faeb933831653f37e0f856fd8a6756a4ea400`.
HEV's upstream export remains unchanged; Product patches are separately
tracked. No retired C++ or POC implementation was imported.

Pixel `28201JEGR0XPAJ` ran kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`, AArch64. The controlled test
UID is 12632, not proof of production UID resolution. Actual LAN peers are
`192.168.4.5` and `fd76:d462:c4e3:0:49f3:929a:a311:d6e7`; IPv6 is ULA, not
public Internet IPv6. Every run checks installed APK/native/helper hashes and
preserves runner, helper, endpoint and independent owner-oracle sources.

The independent verifier joins raw capture and copied return packets through
real admission, policy, terminal, origin completion and exactly one native
free. It decodes checksums and tuples, recomputes canonical ownership, checks
callback TLS, pbuf allocation intervals, immutable transport identity, broker
ordering, return-credit release, health counters, app nonces and independent
kernel endpoint bytes. A stateless TCP RST is accepted only for a failed,
closed candidate, with matching synchronous input identity and no fabricated
session, network context or epoch. Runner status strings are not acceptance.

## Real-device matrix

All paths below are under `build-output/s241-20260912/`.

| Run | Generations | Cases | Result |
| --- | --- | --- | --- |
| `pixel-udp-matrix-b` | 1177–1196 | 10 cases × IPv4/IPv6 | 20 independently verified |
| `pixel-tcp-matrix-b` | 1197–1218 | 11 cases × IPv4/IPv6 | 22 independently verified |
| `pixel-drop-completion-a` | 1219–1220 | actual two-slot completion ring, owner 1, both families | 2 independently verified |

Both owners carry real app traffic in each generation. The primary matrices
limit owner 0 while owner 1 supplies the independent live-flow witness. They
cover FlowEntry, session, PCB, socket, input-packet and pbuf capacity;
protect/bind failure; network unreachable; and policy DROP under full session
capacity. TCP additionally covers real connect refusal. Across the 44 cases,
1,324 captures and 642 copied returns settle; 61 processing bypasses, 159
rejected inputs, 181 typed transport failures and 38 policy drops are checked.
TCP app/kernel/wire witnesses agree on 52,224 unique echoed bytes.

For new-flow limits, a warmed flow retains its original HEV transport while
the candidate fails; the other owner keeps communicating. After actual
transport cleanup, a fresh tuple succeeds without increasing the configured
limit. UDP uses the real 60-second idle timeout and verifies released sessions,
sockets and pbufs before creating the new flow. Packet/pbuf pressure instead
holds the existing owner task, fills actual retained input capacity, and
rejects only excess packets. Releasing the hold resumes the same transport;
TCP completes its existing stream and UDP resumes the same mapping.

Protect/bind cases verify Android's failed operation, the precise native error,
closed descriptor duplicates, no outer connect and successful later creation.
Unreachable cases temporarily install only a checked-absent host route to
`198.18.241.1/32` or `2001:db8:241::1/128` in the test device's `wlan0` table.
The kernel returns an actual unreachable error. Each route is removed and an
empty read-back is preserved; unrelated routes and devices are unchanged.

The completion-pressure pair uses an actual two-slot native return queue.
Each family drops sixteen app packets before Flow Stack admission, despite
the full transport limit. Thirteen IPv4 and twelve IPv6 completion carriers
actually enter the bounded retained backlog, retry on the native completion
path, reach Origin and free exactly once, all retaining DROP. Restoring the
128-slot default and releasing old sessions permits fresh normal traffic.

All normal stops show two owner shards with zero sessions, inputs, pbufs,
PCBs, VPP buffers, obligations and completion frames. Socket creation/close
counts agree, broker/timer FDs are -1, TUN is closed and supervised native
processes are absent. Every debug run keeps `protectionRunning=false`.

## Regression and robustness

- Current-source HEV suite: 32/32 passed; UBSan 31/31 and non-PIE ASan with
  leak detection 31/31 passed. The separate lwIP state audit passes on host and
  the Android build. HEV custom-stack switching retains the previously
  documented ASan coverage limitation; sanitizer success alone is not the
  lifetime proof.
- Real host TCP4/6 `sendmsg` each reports 66 EAGAIN observations with bounded
  socket buffers and a paused kernel peer, then transfers 73,728 bytes per
  owner and finishes. A real bounded AF_UNIX datagram pair separately proves
  retained-frame recovery from EAGAIN; that test is not claimed as Android/IP
  datagram backpressure evidence. No outer infinite retry loop was added.
- Eight shared TCP/UDP/FlowEntry, policy snapshot, capacity and typed Origin
  completion contract tests pass. The S192 static check now verifies one call
  site per typed adapter endpoint at Origin, rather than an obsolete mutable
  global callback. This source contract does not claim host VPP execution.
- All twelve installed APK native libraries pass RELRO, immediate binding,
  non-executable stack and no-text-relocation checks.
- Same-APK S240 TCP matrix and restart pass at generations 1221/1222: 32
  sessions, 1,128 TCP packets, 1,077 OVS-checked tracker updates, 510 returns,
  51 policy drops and 262,144 echoed bytes. FIN, both reset directions, refusal,
  SYN/data retries, return-DROP recovery and active stop are included. The
  immutable OVS v3.1.0 reference is the same pin as the S240 report.
- Same-APK S239 simultaneous TCP-independent UDP4/6 regression passes at
  generation 1223: 1,000 app packets, 1,000 kernel receipts and 1,000 returns,
  no primary-handoff drops and both owners fully stopped. Not a performance
  qualification.
- S241 corrupted-evidence checks reject 31 TCP, 29 UDP and seven completion
  mutations, including forged ALLOW, hidden failure, wrong owner/session/epoch,
  missing recovery, lost/duplicate free, fake pressure and redirected completion.
  The updated S240 regression verifier also rejects all 22 corrupted copies,
  including a fabricated reset on an echo connection and a missing peer reset.

## Retained observations and limits

The initial two-pbuf host stress vector left no ingress ACK headroom while
TCP output retained both buffers; it is not a recovery PASS. The executed
recovery vector uses eight actual pbufs, fills them with small inputs, proves
excess rejection and drains before checking the unchanged stream.

Initial device collectors queried `show product flow`, an invalid CLI spelling.
Their evidence remains retained but is excluded from final acceptance. The
final matrices use `show product flows` and reject unknown diagnostic commands.

The default-capacity TCP reset peer can close after kernel accept but before
the owner's first SO_ERROR query. The initial verifier incorrectly required
zero there. The updated check allows ECONNRESET only for the independently
witnessed reset endpoint, verifies its actual reset event and still requires
zero for all echo connections; refusal remains ECONNREFUSED. This changed
test expectation, not Product behavior.

Underlay invalidation, stale broker replies, crash recovery and the broader
lifecycle matrix belong to S243. The present evidence does not claim those
paths, Android lockdown recovery, production identity resolution or release
protection readiness.

## Reproduce

```sh
rtk proxy python3 tests/device/verify-s241-capacity.py \
  --build build-output/s241-20260912/pixel-build-a/build.json \
  --run build-output/s241-20260912/pixel-tcp-matrix-b
rtk proxy python3 tests/host/s241_capacity_verifier_negative_test.py \
  --build build-output/s241-20260912/pixel-build-a/build.json \
  --run build-output/s241-20260912/pixel-drop-completion-a
rtk proxy ctest --test-dir build-output/s241-20260912/hev-host \
  --output-on-failure -j2
```

Use `pixel-udp-matrix-b` for the UDP verifier/negative suite, and the matching
`verified.json` and `*-negatives.json` for exact verifier identities. Device
re-execution uses `tests/device/s241-pixel-capacity.py` with current real LAN
addresses and the repo-local `./dev/adb` wrapper, never a prebuilt old APK.
