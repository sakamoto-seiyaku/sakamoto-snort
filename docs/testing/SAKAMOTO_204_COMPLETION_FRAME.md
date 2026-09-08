# SAKAMOTO-204 — owner-local Completion Frame

Acceptance: **PASS**, 2026-09-08, final generations 650/651. This task proves a single
Root NFQUEUE lane and owner-local real IPv4 UDP completion. Cross-worker
completion remains S205 work. No VPN readiness is added.

## Contract and native ownership

`product_packet_completion_frame_t` is a 32-byte value containing the opaque
AdapterObligation (token, original queue generation, packet ID, origin lane and
kind), producer thread, terminal intent, runtime drop reason and bounded trace/
replay flags. It contains no PacketFacts, Platform Packet Facts, packet pointer,
flow pointer, UID, ifindex or NetworkContext.

The ordinary graph terminates at `product-packet-terminal`. After recording its
terminal intent, this node ends the packet-facts lifetime and writes only the
Completion Frame into the existing buffer's opaque2. It publishes the original
buffer index through a native VLIB next frame to
`product-packet-origin-completion`. It does not call the adapter, send a verdict,
free the buffer or decrement the live obligation debt. Packet bytes are unchanged.
This explicit overlay transition follows S216's ordinary metadata interval.

The origin-completion node loads only the Completion Frame, invokes the native
origin-lane consumer, and returns the retained buffer once. Only then does the
runtime decrement buffer/frame/obligation debt and count settlement. The callback
interface no longer accepts a PacketLease or a borrowed facts object. Even the
same-worker path runs both distinct VPP nodes; there is no synchronous fast path
from terminal into the adapter.

The current adapter has one lane on logical worker 0 / VPP thread 1. The consumer
checks actual execution thread, origin lane, socket readiness, full 64-bit queue
generation, opaque token, packet ID and native carrier identity before consuming
the obligation. A bounded 64-slot-per-lane identity ledger is reserved before
admission. Each slot stores only a 32-byte completion descriptor, buffer index
and active state (40 bytes including alignment); it contains no packet/domain
facts. Tokens increase independently of packet IDs within a generation.
Completed slots remain bounded replay history until reused. An inactive identity
is not a live obligation or retained buffer.

The consumer marks the identity consumed before its single native verdict
attempt. Duplicate and stale descriptors do not send verdicts or consume a live
packet's reservation. An observed native failure is not retried. Existing
pre-admission fail-open exceptions remain origin-lane confined; they are not
successful graph admission or a second admitted-packet completion path. Slot
capacity and queue-pressure qualification belong to S210, not a release capacity
claim from this test.

The frame carrier reuses the original VPP allocation. No new normal-path packet
allocation, payload copy, heap object, exdata or general metadata side table was
introduced. Reassembly, policy, routing or other VNET overlays must not run after
this completion transition.

## Pixel matrix

- Real owner-local UDP allow, then a second real packet; both visit parser,
  canonical selector, policy, terminal, completion publish, origin completion,
  verdict and native return exactly once.
- Replay the first completed descriptor after the second packet has completed.
  This specifically rejects a non-last duplicate rather than relying on the
  old `last_verdict_packet_id` check.
- Replay the second descriptor with a generation differing above bit 32.
  The native origin consumer rejects it as stale. Both negative descriptors use
  fresh, explicitly labeled `COMPLETION_REPLAY` carriers; neither represents a
  second NFQUEUE packet or a second ownership of the original buffer.
- Send another real owner-local packet to prove recovery after both rejections.
- Send one real packet whose selected owner is remote, which the current scope
  deliberately closes on arrival with runtime DROP. Its DROP intent crosses the
  same Completion Frame. It does not visit remote policy and is not counted as
  remote-owner acceptance.
- Stop with pending/frame/buffer/obligation zero, verify hooks/process cleanup,
  restart with a new generation, complete a new owner-local packet, then stop
  cleanly again.

The native runtime must show four admit / four terminal / three policy vectors
and six origin-completion vectors in the first generation (four real packets
plus two descriptor replays), all on VPP thread 1. After restart it shows one
vector in all four nodes. Runtime's narrow text table truncates the completion
node name; the final collector also captures `show node` with its full name.

The independent checker binds actual event order, original buffer identity,
original generation/packet ID/lane, intent, NFQUEUE verdict, packet facts against
raw bytes, native node vectors and final ledgers. Endpoint delivery is verified
only for the real allow cases. A successful NFQUEUE operation alone is not used
to claim endpoint delivery.

## Harness findings and limits

The first harness attempt incorrectly required exactly one installed L4 rule;
the device retained prior rules, which were preserved. A second attempt found
`product_core_owner_live` when trying to mutate L4 rules through the debug
control entry point while running. This control-plane limitation is recorded in
`pixel-a` / `pixel-a2`; its cause and baseline were not established by this task,
and it is not presented as a Completion Frame failure or as a resolved bug.
The accepted S204 matrix does not depend on that mutation path. Its negative
DROP case is explicitly the currently unsupported remote-owner path, not a
claim of new policy authoring behavior. Both failed runs cleaned up.

`pixel-a3` passed the first complete matrix on generations 648/649. Final
acceptance uses the final source and a fresh post-build request/run below.

## Final identity and verification

- Source/build witness: `build-output/s204-completion/build-b/build.json`, with
  retained source snapshot and dirty diff.
- Request: `build-output/s204-completion/request-b.json`, created after the build
  and before the accepted packet nonces.
- Run: `build-output/s204-completion/pixel-b`, generations 650/651.
- Commit: `9c67175713baceb46cef015f3464893fa3d69950` plus recorded dirty source.
- Source SHA-256: `dcadc70834187af1b2715100c0f26087f68fcd25db7786d2e69c3482f9ed1e4d`.
- APK SHA-256: `4b8efd71d770b5ffe5a78de68bd28ca336fc6fff4bbef07de21c83e5d529101d`.
- Plugin SHA-256: `266ed75d242b4efaa2132f931836b92eee17aaacd9cc99d2fc0ae476204260cf`.
- `tests/device/verify-s204-completion.py` with the request returns PASS/no errors.
  Installed base.apk and all twelve native libraries match the build witness.
- Full node query identifies origin-completion as native node 1, with terminal
  node 2 as its predecessor; consume traces use that actual node index.
- First generation: four real verdicts, four packet returns, two separately
  returned replay carriers, duplicate=1, stale=1, all live ledgers zero.
  Restart: one real completion, no duplicate/stale counts, all ledgers zero.
- Evidence clones in `build-output/s204-completion/negative-b` reject a missing
  consume event and a completion carrying the wrong generation.
- Android/APK build, Host-evidence plugin compilation, S192 source contract,
  Python syntax and diff checks passed. Native C compilation adds no warnings.

The complete acceptance report is also recorded in the private Plane instance.
