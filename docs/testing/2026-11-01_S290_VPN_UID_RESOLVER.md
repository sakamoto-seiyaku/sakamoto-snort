# S290 — the VPN UID resolver owns identity and incarnation decisions

Task authority is SAKAMOTO-290. This is a refactor with no intended change in behaviour; the accepted
asynchronous identity contract is in [VPN_ASYNC_UID_AND_RETURN_LINEAGE](../decisions/VPN_ASYNC_UID_AND_RETURN_LINEAGE.md)
and the [S289 record](2026-09-28_S289_VPN_NORMAL_START.md).

## Change

[`product_vpn_uid_resolver.c`](../../src/product/vpp/product_vpn_uid_resolver.c) now has two entry points:

- `product_vpn_uid_resolver_identify` (before policy): decides whether the packet is one it identifies
  (VPN TUN; device-origin only in product mode), reads the owner's current result into the packet's
  platform facts, and records a known UID on the Flow incarnation that is current for the tuple. It returns
  whether the facts must be written back. It never waits and never starts a query.
- `product_vpn_uid_resolver_query` (after Flow processing of a successfully processed packet):
  receives the packet's observed Flow incarnation or 0, selects the observed or the current admitted
  incarnation itself, and decides whether to query.

The former `lookup` and `refresh` are private to the resolver (`read_identity`, `query_identity`). The packet graph keeps both call points and its
own processing-order conditions (terminal intent, processing result) and writes the platform facts back to the
lease; it no longer enriches the Flow UID or selects an incarnation for a UID query. No second cache, layer or
owner was added.

Preserved: cold packets stay Unknown; a packet dropped before any Flow exists creates no query state; a dropped
packet of an admitted Flow can still refresh it; generation, request and incarnation validation; capacity, rate
and timeout behaviour; a timeout or Unknown never clears a known UID or destroys a Flow; the TCP new-SYN rule;
the accepted live-UDP tuple reuse ambiguity. The window in which a new connection's first packets pass before its
App UID is known is unchanged; this refactor does not address it.

## Verification

| Check | Result |
| --- | --- |
| Line-by-line comparison of the old and new call paths: same gating conditions, same incarnation selection, same order of side effects | done in the main thread |
| Independent review in two subagents (standards, spec) of `1922ba7f` | no behaviour defect found; fixed in `29754d66`: entry point renamed to `product_vpn_uid_resolver_query`, private helper names, one clock helper instead of four copies, a duplicate provenance check removed, test cases added for observed versus retired incarnation and live-UDP reuse |
| `product_vpn_uid_dns_test` on the actual resolver with real SEQPACKET messages: return packets untouched, no request without a Flow, known UID recorded on the current Flow, observed versus current incarnation, cold/known/system/timeout/late generation, identity conflict retires the cached identity, TCP new SYN, controlled-provider UID without a broker | PASS |
| Host suite: all except `unified-rule-runtime-contract`, which needs an external `PRODUCT_ARTIFACT_DIR` and stops before any assertion | PASS, 132/132 at `e9d87143`. The first record of this row was wrong: 20 host tests had failed since `c8cd7a8a` (S324 owner association tables) and S327 (DTLS SNI applicability) because their stubs and the reference model were not updated; `e9d87143` updates them. None of the 20 covered the resolver |
| NDK native and APK build (`android-native-r1`, `android-apk-r1` `d6b0a3b2…`); unchanged repeats compiled nothing | PASS |
| NDK stage build after the review fixes (`android-native-r2-compile`) | PASS (compile only; the review fixes change no behaviour and were not re-run on the device) |
| Pixel 6a ordinary VPN N1, `combined-vpn-n1-r1` with the S328 driver: asynchronous UID update and App-bound ALLOW/DROP across DNS, HTTP, SOCKS and DTLS/TLS/QUIC, return traffic, two generations, resources zero after both Stops | PASS (50 + 5 cases) |

The device was restored afterwards (`original-restoration-r1`): original APK and all 4861 private-data members,
no NFQUEUE entry, Product hook or owned route.

## Not covered

VPN N3 and the full performance matrix (out of scope by the ticket). The host test stubs the Flow runtime; the
real graph call path is covered only by the Pixel VPN N1 run, which used `1922ba7f` before the review fixes.
