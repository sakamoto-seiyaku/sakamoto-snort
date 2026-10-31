# S326 — SOCKS request-target filtering

Task authority is SAKAMOTO-326 under the [application DNS specification](../product/APPLICATION_DNS_SPEC.md)
section 11. Builds on [S325](2026-10-31_S325_HTTP_TARGETS.md): the same Flow direct-target storage,
per-request evaluation and sticky connection-level DROP. Host and Pixel 6a Root/VPN N1 evidence are kept apart.

## Implemented contract

- [`product_socks_target.c`](../../src/product/vpp/product_socks_target.c): SOCKS4, SOCKS4a and SOCKS5 request
  targets from the client stream, with the server stream proving the negotiation.
  - SOCKS5: the greeting's offered methods; the server's selection must be version 5 and an offered method
    (no-auth or RFC 1929 username/password) before a request is accepted. Credentials are skipped and the buffer
    bytes they occupied are cleared. GSSAPI, "no acceptable method" or a non-SOCKS server end parsing. A client
    that sends greeting and request together is judged when the selection arrives.
  - SOCKS4/4a: the request is the first message and is judged on its own packet; the server reply 0x00 0x5a–0x5d
    is recorded as confirmation. 0.0.0.x (x != 0) selects 4a and its host name.
  - Only CONNECT names a remote target. BIND and UDP ASSOCIATE are reported with reason `COMMAND` and no target.
    Domain names use the HTTP authority validator; a name that is an IP literal becomes an IP target. Port 0,
    0.0.0.0, a port inside the name and bad names are reported without a target. Fields are bounded (255 bytes,
    600-byte message buffer). After the request the connection is a tunnel and is not parsed further.
- The Flow decides its direct-target protocol from the connection's first client byte only: an upper-case letter
  is HTTP, 0x04/0x05 is SOCKS (TLS starts with 0x16). Server-first bytes never decide. Both directions are kept
  in order separately for SOCKS.
- Policy: `PRODUCT_POLICY_DOMAIN_SOCKS_TARGET` is a fourth domain source next to SNI, QName and HTTP target, with
  its own availability; it never satisfies an explicit SNI condition. The outer proxy endpoint (the connection's
  own address) is never the target. IP targets keep the requested address and port at the pending-qualification
  point; no association consumer is enabled.
- `show product flows` prints `flow.socks` (version, 4a, confirmed, method, command, reply) and the shared
  `flow.http` target line (`mode=3`).

## Host qualification

| Check | Result |
| --- | --- |
| Parser: SOCKS4/4a every split, BIND, 0.0.0.0, port 0, bad and host:port 4a names, SOCKS5 no-auth every split, password with credentials cleared, IPv6, optimistic client, early selection, UDP ASSOCIATE, refused/unsupported methods, non-SOCKS server, malformed requests, field bounds, loss, bytes after the request (`sakamoto-product-socks-target-test`, ASan/UBSan) | PASS |
| Flow: SOCKS5 negotiation and tunnel bytes not parsed, SOCKS4 retransmission, 4a split, sticky denial, server-first bytes (`sakamoto-product-flow-http-test`) | PASS |
| Policy source (`sakamoto-product-policy-http-target-test`) | PASS |
| Host suite: all except `unified-rule-runtime-contract`, which needs an external `PRODUCT_ARTIFACT_DIR` and stops before any assertion | PASS |

## Pixel 6a qualification

Native stage `android-native-r1` and APK `android-apk-r1` (SHA-256 `04740b2c…`) from the committed sources;
unchanged repeats compiled nothing. Ordinary App entry, an independent finite SOCKS peer on the host that never
connects outward, the Product's own `flow.socks`/`flow.http` status of the very flow, normal stop. The peer's own
receipt is the oracle; each case uses its own target port so the peer can tell cases apart.

| Run | Scope | Result |
| --- | --- | --- |
| `device-root-n1-r1` | Root N1, 10 cases | PASS |
| `device-vpn-n1-r1` | VPN N1, the same 10 cases | PASS |

Cases: SOCKS5 allowed domain with tunnel data; SOCKS5 refused name (negotiation answered, the request never
reaches the peer); SOCKS5 username/password and refused descendant; SOCKS5 IPv6 target kept without a decision;
SOCKS4 IPv4 target and confirmation; SOCKS4a allowed name with tunnel data; SOCKS4a refused name; SOCKS5 UDP
ASSOCIATE reported without a target; the outer proxy endpoint is not the target; allow-all after the rule is
removed. On VPN the shared cases wait 1.5 s after connect for the asynchronous App UID, as in S325. No refused
request reached the peer after the App closed its socket in either run.

After the runs the original APK and all 4861 private-data members were restored at the fresh maximum generation
(`original-restoration-r1`), with no NFQUEUE entry, Product hook or owned route left.

## Not covered

Root/VPN N3, handover, SOCKS5 GSSAPI, BIND's second reply, UDP ASSOCIATE datagram targets, out-of-order packets
(parsing ends) and nested proxies inside the tunnel. The target name is in the Product's flow status and its DROP
decision and winner are in the normal flow record; the target name itself is not yet a normal SQLite field.
