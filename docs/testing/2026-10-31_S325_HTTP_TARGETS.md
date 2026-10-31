# S325 — cleartext HTTP request-target filtering

Task authority is SAKAMOTO-325 under the [application DNS specification](../product/APPLICATION_DNS_SPEC.md)
section 11. Host evidence and Pixel 6a Root/VPN N1 evidence are kept apart.

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

Native stage `android-native-r1` and APK `android-apk-r3` (SHA-256 `2cc0e330…`) built from the committed
sources; unchanged repeats compiled nothing. Ordinary App entry, an independent finite HTTP peer on the host,
the Product's own `flow.http` status of the very flow, normal stop. The peer's own receipt is the oracle: a
refused request is one that never reaches it while the App owns its socket.

| Run | Scope | Result |
| --- | --- | --- |
| `device-root-n1-r5` | Root N1, 12 cases | PASS |
| `device-vpn-n1-r4` | VPN N1, the same 12 cases plus the cold-UID case | PASS |

Cases: allow; head split across packets; successive requests to different names on one connection; refused Host;
refused descendant; refusal blocks the rest of the connection (an allowed request before it is answered, the
refused and a later allowed one never reach the peer); absolute-form target wins over Host in both directions;
IP target kept with address and port and no decision; duplicate Host unavailable; CONNECT ends HTTP parsing;
allow-all after the rule is removed.

Findings:

- **VPN App identity is asynchronous.** The VPN resolves a new connection's App UID through the Android lookup
  after its first packets, and App-bound rules apply only from then on (existing resolver contract; a miss never
  holds a packet). The 12 shared cases therefore wait 1.5 s after connect before the first request on VPN. The
  extra `http-vpn-cold-uid` case sends at once: the refusal is still recorded and the second request never
  reaches the peer; in this run the first one did not reach it either (`first_request_reached_peer=false`), but
  that is timing, not a guarantee, and is not claimed.
- **Root retransmission after close.** While the App owns its socket no refused byte reaches the peer. After
  the App closes it, the kernel's retransmissions of the refused segment reached the peer (`late_arrivals`).
  The Root capture rule matches the socket owner (`-m owner --uid-owner`); an orphaned socket has none. This is a
  property of the existing Root capture rule for every policy, not of the HTTP code. VPN has no such case.
- The shared physical-wire witness only captures DNS ports, so it is recorded but is not evidence here.
- Driver findings that changed test code only: a closed VPN flow leaves the table at once, so the Flow is read
  before wire output is collected; Android's cached-app freezer can stop the probe thread while it sleeps, so the
  App is brought to the foreground before waiting for it to close (as in S322).

After the runs the original APK and all 4861 private-data members were restored at the fresh maximum
generation (`original-restoration-r4`), with no NFQUEUE entry, Product hook or owned route left.

## Review correction (2026-10-31, after the Opus review)

A review of the first implementation found two ways around per-request filtering, both fixed in Product code:

- **More than four heads in one packet.** Only four heads per packet were judged; the rest were counted and
  skipped. Root output packets can be large, so this was reachable. Now the Flow stops at a full batch without
  consuming the remaining bytes and the policy stage resumes the same packet batch by batch until every head is
  judged or one is refused (64 batches; beyond that the rest of the connection is unavailable). A refused packet's
  retransmission resumes where parsing stopped.
- **Stale target after a parse stop.** After a malformed, framing, head-limit, version or loss stop the rest of
  the connection was judged as its last target. Now its later packets, responses included, have no known target;
  a refused target stays refused, and a tunnel (CONNECT, Upgrade, SOCKS) keeps its target. This matters for
  allow-style policies (an ALLOW for one name no longer keeps matching other requests). With deny-style rules an
  unknown target still makes no domain decision, which is the unified rule semantics, so traffic after such a stop
  is not refused by domain rules.

Device re-qualification with APK `android-apk-r4` (`150f0370…`): Root N1 `device-root-n1-r7` 14 cases and VPN N1
`device-vpn-n1-r5` 15 cases PASS, adding `http-pipelined-six` (six heads in one packet, the sixth refused: the
whole packet never reaches the peer) and `http-allowlist-after-framing-stop` (the malformed first head itself is
judged and delivered; the rest of the connection is refused). S326 SOCKS was re-run with the same APK: Root
`device-root-n1-r2` and VPN `device-vpn-n1-r2`, 10 cases each, PASS. The device was restored afterwards
(`original-restoration-r5`).

## Not covered

Root/VPN N3, handover, packets that arrive out of order (parsing ends and the rest is unavailable), more than 256
heads in one packet (the rest is unavailable), HTTP/2 and encrypted HTTP. IP-literal targets stop at the
pending-qualification point; no association consumer exists and none is enabled.
