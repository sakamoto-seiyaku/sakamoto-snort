# S243 lifecycle checkpoint — underlay semantics still pending

Status: **partial, not S243 acceptance**. Stop, broker failure and native-crash
recovery have current-Product Pixel evidence. Underlay change/invalidation and
the same-tuple UDP follow-up behavior remain unimplemented pending discussion.
No release protection readiness is claimed.

## Current artifact

- Commit: `0f5957290fded7884f7b5a795a97f9145c58f182`, with the build's saved dirty
  diff and complete hashed source snapshot.
- Build: `build-output/s243-20260912/pixel-build-g/build.json`.
- Product source SHA-256:
  `bbea98ab2ae343534cf31ac3215d709fe6d95e74b02a3f1e2368e56ea5dbe385`.
- APK SHA-256:
  `736b1f57ea697f59b3573fd3c6c0dab92a1998d938bffe525b7cd118191b4223`.
- Product VAPI library SHA-256:
  `a42526bd795e73c513ce59be1f534a8dec5a6de340a36468ae8b1659d5190414`.
- Product plugin SHA-256:
  `566b34e483cffb4334020d1a0258941b8bc8f3016d4f191cc558487b0070d654`.
- Pinned VPP: `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, existing 19-patch Android
  stage; no new VPP-core patch in this checkpoint.
- Dedicated Pixel `28201JEGR0XPAJ`, Android 16, arm64; exact kernel/package,
  installed APK and all installed native hashes are captured in each run.
- LAN peers: IPv4 `192.168.4.5`, IPv6
  `fd76:d462:c4e3:0:49f3:929a:a311:d6e7`; these are real kernel TCP/UDP sockets,
  not mocked transport or public-service availability oracles.

## Implemented lifecycle changes

`RuntimeService` retains lifecycle ownership. After a recoverable VPN Flow Stack
failure and successful old-resource cleanup, it permits one delayed
fresh-generation restart. A successful restart does not replenish that budget.
Explicit Start/Resume begins a new request budget; Stop, Pause, service
destruction and authorization revocation invalidate pending recovery. Delayed
work checks the original request and failed generation before starting.

The existing generic recovery policy is not changed into a VPN-wide three-retry
loop. Cleanup, authorization, persistence and protocol-identity failures do not
authorize a retry. Native connect/query/disconnected/retired-handle failures use
their typed modern Product Core codes. An exhausted retry reports protection
stopped and withdraws the unusable VPN. Lockdown is not disabled or bypassed.

An explicit Stop on an already empty runtime now clears the prior terminal
error. Destruction still preserves failure diagnostics. Broker and platform
subscription references participate in the stop barrier even if no VPP process
or VAPI connection remains. An unjoined broker thread or still-registered
network callback cannot be reported as cleaned.
Native ingress quiescence and return/completion drain precede platform snapshot
closure; the ordinary stop evidence checks this order explicitly.

## Reproduced failures fixed here

1. **VAPI request reuse after failed blocking dispatch.** In generation 1225,
   killing the VPP sidecar caused Android supervisor PID 15474 to abort at
   `vapi_store_request: !vapi_requests_full(ctx)`. The saved crash stack goes
   through network publication during cleanup. A failed generated blocking call
   could retain its stack callback in the one-entry VAPI request table, yet the
   Product bridge allowed another request. Network publication, status, scalar
   policy and bundle policy calls now fence the session after failed dispatch or
   an absent real callback. Explicit disconnect still reclaims its context even
   after the usable-session flag is cleared. The pinned UDS disconnect path
   drains without invoking those obsolete callbacks.
2. **Local broker close did not wake blocking receive.** Active generation 1233
   did not recover after the debug broker-channel close. Plain Android
   `LocalSocket.close()` closes the descriptor but does not cancel another
   thread's already-blocking socket read. The common close path now shuts down
   both directions before closing, then retains the bounded thread-exit check.
   Both owner-specific real channel-failure cases subsequently completed.
3. **Unsubmitted VAPI message ownership.** A generated call that fails before
   sending leaves the allocated request with its caller. Correcting the API
   stub to model that contract produced a deterministic five-message leak.
   All four Product request paths now free an unconsumed message on definite
   send failure, while a dispatched request with an outstanding callback is
   not freed again. The host regression requires zero remaining messages and
   contexts; removing any of the four release calls makes it fail.

These are current-artifact reproductions, not an asserted explanation for the
historical S198 generation-924 `product_core_not_ready` event. Its initiating
cause remains unconfirmed. The independently reproducible empty-runtime Stop
projection is covered here.

## Current Pixel evidence

Active matrix: `build-output/s243-20260912/pixel-active-g/`.
Every old generation has eight held real app sockets: TCP and UDP, IPv4 and
IPv6, on each of W2 owner 0/thread 1 and owner 1/thread 2. Each replacement is
checked with eight fresh app connections and independent kernel echo peers.

| Case | Old generation | Replacement | Old-resource evidence |
| --- | --- | --- | --- |
| Explicit Stop/restart | 1274 | 1275 | Orderly native drain |
| Actual sidecar SIGKILL | 1276 | 1277 | OS process reclaim, **not** orderly native drain |
| Owner 0 broker channel loss | 1278 | 1279 | Orderly native drain |
| Owner 1 broker channel loss | 1280 | 1281 | Orderly native drain |

Independent verification covers raw inner TCP/UDP checksums and payloads,
canonical owner, callback TLS, app UID, fixed socket binding facts,
`TUN_CAPTURED`/`FLOW_STACK_RETURN` provenance, TUN-origin completion, buffer and
pbuf lifetime intervals, and return-credit release. Orderly paths close four
sockets per owner, reclaim shard state, close timer/broker fds, and finish with
zero sessions, pbufs, input packets, buffers, obligations and completion frames.
Abrupt crashes are deliberately not required or allowed to manufacture those
orderly destruction records. New-generation packet data comes from new app
connections, not replayed old queues.

Supervisor matrix: `build-output/s243-20260912/pixel-recovery-g/`.

- 1282 → 1283: exactly one automatic restart after an actual sidecar kill.
- Another kill of 1283 exhausts recovery; no third automatic generation starts.
  The same Android supervisor survives both native failures.
- Explicit Stop clears the retained error. A fresh explicit Start creates
  1284; Stop cancels its armed recovery without starting a replacement.
- A controlled invalid startup-capacity request exercises preparation cleanup
  in 1285 and its sole retry 1286. This is a preparation rejection, **not** proof
  of a native HEV allocator-failure branch.
- After both retry exhaustion and preparation failure, four ordinary app
  TCP/UDP4/6 probes echo successfully with no VPN binding and no active runtime.
  The Pixel lockdown setting is captured as disabled; no lockdown guarantee is
  inferred from these eight echoes.

Final device state: generation 1286 stopped, `mayBeActive=false`,
`protectionRunning=false`, empty error, no Product VPP process.

## Auxiliary checks and invalid evidence

- Android runtime contract and Product Core Rust tests passed.
- Existing HEV host regression suite: 32/32 passed with its required local
  socket/network-namespace permissions; sandbox socket denials are not Product
  failures.
- Production VAPI bridge API-shaped-stub test passed. Removing any one of its
  four post-dispatch fences or four unsent-message releases makes the regression
  test fail. This auxiliary test is not a mock substitute for the real Pixel
  VAPI-crash reproduction and recovery evidence.
- Host VAPI ASan/UBSan test passed, including 20 repeat executions. Clang 14 PIE
  sanitizer startup separately faulted in `AsanInitInternal`/`internal_mmap`
  before `main`; only the throwaway host checker uses non-PIE to avoid that
  environment issue. Product hardening and system ASLR remain unchanged.
- Recovery evidence tamper tests reject incorrect installed identity,
  reused generation, stale retry, active VPN residue, remaining native process,
  uncleared terminal error and a missing ordinary echo.
- Active-flow evidence tamper tests reject incorrect APK identity, missing
  buffer release, wrong callback TLS, an unclosed socket, stale generation and
  changed kernel-peer echo bytes, plus platform facts being cleared before
  the same generation's native drain.
- Earlier `pixel-active-final/` captured the real traffic but lost early
  recovery log lines to service-log rotation. It is not the complete accepted
  matrix. Subsequent collectors, including current `pixel-active-g`, store
  per-case recovery checkpoints.
- Earlier `pixel-active-a/` is HOLD: its broker-close case exposed the blocking
  receive problem. Its held probes also exceeded deadlines; those results are
  not delivery acceptance.

Commands recorded for artifact G (require its corresponding source;
current-source acceptance is in the later underlay report):

```sh
rtk proxy python3 tests/device/verify-s243-active.py \
  --build build-output/s243-20260912/pixel-build-g/build.json \
  --run build-output/s243-20260912/pixel-active-g
rtk proxy python3 tests/device/verify-s243-recovery.py \
  --build build-output/s243-20260912/pixel-build-g/build.json \
  --run build-output/s243-20260912/pixel-recovery-g
rtk proxy bash tests/host/product_vapi_callback_contract.sh
rtk proxy python3 tests/host/product_vapi_retirement_negative_test.py
```

## Boundary of this historical checkpoint

At artifact G the Java broker used the runtime-start underlay. This checkpoint does not
implement or claim latest-underlay admission, old-epoch invalidation, same-tuple
UDP recreation rules, active-network switch/loss acceptance, or the complete
DROP/underlay/recovery combination. The later user decision explicitly permits
a fresh protected/bound transport for subsequent same-tuple UDP datagrams
after old-session cleanup, without queue replay or VPP FlowEntry teardown.
See [`2026-09-12_S243_UNDERLAY.md`](2026-09-12_S243_UNDERLAY.md) for that
implementation and its own source-matched device/host evidence. Artifact G
must not be used to claim this later behavior.
