# T29 combined acceptance and diagnostic stress contract

The current Product configuration, packet, observation and dashboard interfaces
remain those exercised by T19/T23–T28. T29 adds one bounded option to
the **debuggable** `t12ProbePlan` observation workload. The diagnostic Activity
owns its socket and writes nonce-scoped `files/product-state/t12-<nonce>.json`;
it does not own rules, VPP packets, or the observation store.

`observationFlood` remains 1–10,000 and `observationBatch` remains 1–16.
`observationTolerateLoss` defaults to false, retaining the prior fail-on-timeout
behavior. When true, `observationMaxTimeouts` must be 1–256, and the receive
timeout is 750 ms. A timed-out batch records its unresolved payloads and sends
the next batch. A later exact echo removes its unresolved payload and increments
`lateReplies`; an unexpected payload remains an error. The response reports
`sent`, `received`, `transportTimeouts`, `lateReplies`, and
`unresolvedReplies` at each phase. More than the declared timeout budget is an
error. This is a bounded traffic-driver option, not an ALLOW, delivery or
Product recovery semantic.
`transportTimeouts` counts payloads unresolved when a socket receive times out;
a batch with several pending payloads contributes several, not one timeout
event.

The caller supplies a fresh nonce, endpoint, profile-specific local binding and
source port, then owns phase release files and cleanup. Probe and observation
query intents are headless and finish the Activity. The runner reopens the
interactive Activity after the final pause query, verifies it is top-resumed,
and temporarily extends screen timeout during the long flood. Android may
freeze the diagnostic thread when the Activity is cached; the old screen
timeout is restored on exit. RuntimeService and VPP have separate process
lifetimes. The runner uses the existing isolated
`t27-test.enabled` observation store selector and removes it after each run;
ordinary SQLite/JSON hashes must remain unchanged.

The debug probe driver permits at most two concurrent nonce-scoped socket
plans. T29 uses one gated QUIC/domain plan and one RTP/STUN plan to keep both
Flows live through a VPP rule publication; each retains its own socket, source
port and release files. A third plan writes a nonce-scoped `finished` result
with `error=protocol_probe_capacity` before opening a socket. The concurrency
bound does not change Product packet
ownership or provide a general background traffic service.

Verification joins the same Product source and installed APK, runtime
generation, VPP Flow identity and cumulative counts, Rust windows/channel
health, endpoint payloads, host and device packet captures, and the diagnostic
UI's typed response. Actual device ingress is the denominator for packet-path
claims. A timeout alone does not locate a missing reply. Host-only replies,
device-underlay replies and TUN/Root replies are reported separately. A full
record channel must not block packet completion; evidence loss is explicit.
Controlled VPN HEV traffic retains `protectionRunning=false`; ordinary VPN
Start still returns `vpn_flow_stack_not_ready`.
