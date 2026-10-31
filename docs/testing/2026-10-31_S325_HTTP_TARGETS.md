# S325 — cleartext HTTP request-target filtering (interim record)

Task authority is SAKAMOTO-325 under the [application DNS specification](../product/APPLICATION_DNS_SPEC.md)
section 11. **Status: Host and Pixel 6a Root N1 qualified; VPN is not working yet and is not claimed.**

## Implemented contract

- [`product_http_target.c`](../../src/product/vpp/product_http_target.c): incremental HTTP/1.x request-head
  parser for one direction of one TCP stream. It reports the effective target of every request:
  absolute-form authority, CONNECT authority, or the single Host of an origin-form request. Content-Length and
  chunked bodies are skipped, never stored, to find the next head. Heads are bounded (4096 bytes, 64 fields).
  A request with no usable target is reported with its reason (no/duplicate Host, bad authority, userinfo,
  non-http scheme, wrong form) and parsing continues. Framing it cannot trust, an HTTP version other than 1.x,
  CONNECT or an Upgrade ends parsing for the connection (encrypted HTTP keeps using SNI/association).
- [`product_flow_http.c`](../../src/product/vpp/product_flow_http.c): per-Flow state in the TCP-owned reserved
  storage (no Flow growth). A flow whose first payload byte is an upper-case letter is an HTTP candidate;
  SNI recognition is stopped for it (TLS cannot start that way). In-order bytes only: a retransmission is
  ignored, a gap ends parsing. Per packet it keeps up to four finished heads, the last head, and the latest
  refused target.
- Policy: HTTP target is a third domain source next to SNI and DNS QName. It has its own availability, is
  evaluated per request against the current policy, and never satisfies an explicit SNI condition. A refusal
  uses the existing DROP and marks the flow; every later packet of the connection (either direction) is
  evaluated against the refused target, so the connection stays blocked while the policy still refuses it
  and is released when it no longer does.
- IP-literal targets keep the requested address and port in the flow (`flow.http current_kind/current_address`)
  as the pending-qualification point; no domain decision is made and the proxy/peer address is never used.
- `show product flows` prints a `flow.http` line per HTTP flow.

## Host qualification

| Check | Result |
| --- | --- |
| Parser: forms, every split, pipelining, chunked, IP targets, unusable targets, connection-level stops, bounds, 1 MB body without memory (`sakamoto-product-http-target-test`, ASan/UBSan) | PASS |
| Flow state: split heads, pipelining, overflow, retransmission/overlap/loss, reply direction, non-HTTP, CONNECT, sticky denial, SNI deadline never touches it (`sakamoto-product-flow-http-test`) | PASS |
| Policy source: refused/unavailable/SNI-inapplicable (`sakamoto-product-policy-http-target-test`) | PASS |
| Graph integration compiled inside the extracted-policy harness and the real NDK build | PASS |

## Pixel 6a qualification

Native stage `android-native-r1` and APK `android-apk-r2` built from the committed sources, unchanged repeat with
zero compilations. Ordinary App entry, an independent finite HTTP peer on the host, the Product's own `flow.http`
status of the very flow, normal stop.

| Run | Scope | Result |
| --- | --- | --- |
| `device-root-n1-r4` | Root N1, 12 cases | PASS |
| `device-vpn-n1-r1` | VPN N1 | HOLD, see below |

Root cases: allow, head split across packets, successive requests to different names on one connection, refused
Host, refused descendant, refusal blocks the rest of the connection (an allowed request before it is answered,
the refused and a later allowed one never reach the peer), absolute-form target wins over Host in both
directions, IP target kept without a decision, duplicate Host unavailable, CONNECT ends HTTP parsing, allow-all
after the rule is removed.

Findings:

- The shared physical-wire witness only captures DNS ports. Its output for these cases is recorded but is not
  evidence. The peer's own receipt is the oracle, which is stronger.
- While the App keeps its socket open no refused byte reaches the peer. After the App closes the socket, the
  kernel's retransmissions of the refused segment arrived at the peer (`late_arrivals`). The Root capture rule
  matches on socket owner (`-m owner --uid-owner`), and a closed (orphaned) socket has none. This is a property
  of the Root capture rule, not of the HTTP code, and it applies to every Root rule once the owner socket is gone.
- **VPN**: the App's request is answered through the VPN (client address is the TUN address, the peer sees the
  Product's egress socket) but `show product flows` holds no FlowEntry for the App's connection, so no HTTP
  state exists and nothing is filtered. VPN Direct TCP appears to terminate the App's TCP stream in the flow
  stack, so the packet graph's Flow observer never sees the request bytes. This needs a decision, see the
  ticket.

## Not covered

VPN, N3, handover, packets that arrive out of order (parsing ends), more than four heads in one packet
(the surplus is counted, the last head is kept), HTTP/2 and encrypted HTTP.
