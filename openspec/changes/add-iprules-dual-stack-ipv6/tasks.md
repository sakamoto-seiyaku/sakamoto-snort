## 1. Control vNext Dual-Stack IPRULES Surface

- [x] 1.1 Extend IPRULES rule model to include required `family=ipv4|ipv6`, IPv6 CIDR parsing/canonicalization (`/0..128`), and `proto=other` validation (ICMP/other MUST keep ports=any).
- [x] 1.2 Update `IPRULES.APPLY` handling to compute mk2 `matchKey` including `family`, reject duplicates/conflicts, and return `{clientRuleId,ruleId,matchKey}` mapping for all committed rules.
- [x] 1.3 Update `IPRULES.PRINT` output to include `family` and canonical CIDR strings for both families; keep ordering by `ruleId` and existing numeric/toggle field types.
- [x] 1.4 Update `IPRULES.PREFLIGHT` to return `byFamily.{ipv4,ipv6}` summary objects (mirroring `summary` field set) and to include per-family violations/warnings attribution.

## 2. IpRulesEngine Dual-Stack Snapshot (Preserve IPv4 Hot Path)

- [x] 2.1 Add `PacketKeyV6` and dual-stack evaluation entrypoints (keep `PacketKeyV4`/IPv4 evaluate semantics unchanged; add `evaluate(PacketKeyV6)` + HotSnapshot overload).
- [x] 2.2 Compile active rules into per-family compiled views (v4/v6) while preserving a single external ruleset model (no `family` defaulting, no cross-family matching).
- [x] 2.3 Implement `uidUsesCt(uid,family)` (and any cached fast path state) so conntrack work can be skipped per `uid+family` when no `ct.*` consumers exist.
- [x] 2.4 Extend preflight complexity accounting to produce both `summary` and `byFamily` counts and to enforce limits without penalizing IPv4 fast path.

## 3. Datapath Parsing: IPv6 Header Walker + `l4Status` + Fail-Open

- [x] 3.1 Introduce a small stack-only parse result (`L4Status` + terminal/declared proto + ports availability) shared by IPv4/IPv6 listener paths.
- [x] 3.2 Implement IPv6 extension header walker (budget: max 8 headers / 256 bytes) with required classifications: `known-l4|other-terminal|fragment|invalid-or-unavailable-l4`.
- [x] 3.3 Update `PacketListener` to stop `NF_DROP` on malformed TCP/UDP; instead classify as `invalid-or-unavailable-l4`, force ports unavailable (0), and continue into policy evaluation.
- [x] 3.4 Ensure fragments (IPv4 + IPv6) are classified as `fragment`, never parse ports, and never create/update conntrack (ct treated as invalid for policy matching).

## 4. PacketManager: IPv6 Enters IPRULES (Per-Family Fast Path)

- [x] 4.1 Extend IPRULES fast path to IPv6 (build `PacketKeyV6`, evaluate correct family snapshot, attribute `reasonId` + `ruleId/wouldRuleId` consistently).
- [x] 4.2 Preserve existing IPv4 fast path performance profile (no forced 128-bit key on IPv4; no new locks/allocations on the hot path).
- [x] 4.3 Wire `uid+family` conntrack gating into PacketManager so IPv6 traffic does not pay conntrack cost unless rules require `ct.*`.

## 5. vNext pkt stream: `l4Status` Always-Present

- [x] 5.1 Extend `ControlVNextStreamManager::PktEvent` to carry `l4Status` (internal enum/u8) and plumb from datapath through PacketManager stream event fill.
- [x] 5.2 Update `ControlVNextStreamJson::makePktEvent()` to always emit `l4Status` (string) and to enforce `srcPort/dstPort=0` when `l4Status!=known-l4`.

## 6. Conntrack Dual-Stack + byFamily Metrics

- [x] 6.1 Add IPv6 packet input model and tracking (TCP/UDP/ICMPv6/other terminal); treat IPv6 fragments as invalid; keep concurrency guarantees.
- [x] 6.2 Implement split tables by family (two tables under one Conntrack instance) sharing global capacity budget; ensure `uid+family` is part of key space.
- [x] 6.3 Update conntrack metrics snapshot and `METRICS.GET(name=conntrack)` output to include `byFamily.ipv4/ipv6` with stable fields.

## 7. IPRULES Persistence: Save Format v4 (Explicit Family)

- [x] 7.1 Bump IPRULES save format to `formatVersion=4` and include `family` + IPv6 CIDR + `proto=other` in persisted rules.
- [x] 7.2 Implement restore policy: only accept v4; v1/v2/v3/unknown are restore failures (daemon continues with empty ruleset; log warning/error; no crash).

## 8. Host Tests (Unit + KTV)

- [x] 8.1 Update `tests/host/control_vnext_iprules_surface_tests.cpp` to include required `family` fields in APPLY rules and to assert PRINT/matchKey mk2 behavior for both IPv4 and IPv6 CIDR canonicalization.
- [x] 8.2 Add host unit tests for pkt events `l4Status` always-present and ports=0 semantics by directly exercising `ControlVNextStreamJson::makePktEvent()` with crafted `PktEvent`.
- [x] 8.3 Add KTV (Known Test Vectors) host tests for IPv6 header walker covering: skip ext headers, fragment classification, `other-terminal` (ESP/No Next Header), budget exceeded, and malformed L4 mapping to `invalid-or-unavailable-l4`.
- [x] 8.4 Extend host conntrack tests for IPv6 flows (state/direction), IPv6 fragment invalid behavior, and `uid+family` gating (no ct work when no consumers).

## 9. Device Tests (Smoke/Matrix) Update to Dual-Stack Tier‑1

- [x] 9.1 Update Tier‑1 netns/veth setup (`tests/device/ip/lib.sh`) to assign IPv6 addresses and routes alongside IPv4, with tool detection/fallback (`ping -6` vs `ping6`, nc IPv6 flags) and clear SKIP behavior when missing.
- [x] 9.2 Extend vNext IPRULES smoke (`tests/device/ip/cases/14_iprules_vnext_smoke.sh`) to apply/print IPv6 rules (`family=ipv6`) and validate mk2/mapping/canonicalization on device.
- [x] 9.3 Extend datapath smoke (`tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`) to generate IPv6 TCP/UDP traffic and assert verdict + pktstream `l4Status`/ports behavior.
- [x] 9.4 Extend Tier‑1 matrix (`tests/device/ip/cases/20_matrix_l3l4.sh`) to include IPv6 rows (CIDR match/no-match; ICMPv6 + port constraint no-match; fragment/invalid cases where feasible).

## 10. Verification

- [x] 10.1 Run host presets (at least `dev-debug` + `host-asan-clang`) and ensure all host tests pass.
- [x] 10.2 Run device IP module profiles (`--profile smoke` and `--profile matrix`) and record results; ensure no crashes and stable verdict semantics.
  - Pixel 6a (`bluejay`) kernel panic in `sock_ioctl` can be triggered by `ip -6 addr show`; to keep Tier‑1 usable we removed that prereq probe from `iptest_require_tier1_prereqs()` (repro + evidence remains in `tests/device/ip/records/20260427T071418Z_28201JEGR0XPAJ_*` and `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`).
  - Device run (serial `28201JEGR0XPAJ`, 2026-04-27): `tests/device/ip/run.sh --profile smoke` PASS (3/3), `--profile matrix` PASS (4/4).
- [x] 10.3 Run perf sanity compare (IPv4 baseline must not regress meaningfully) using existing perf scripts; record results in the existing perf record workflow.
  - Device run (serial `28201JEGR0XPAJ`, 2026-04-27): `IPTEST_PERF_COMPARE=1 tests/device/ip/run.sh --profile perf` PASS; `rulesTotal=2000` (no bg); `nfq_total_us` avg: iprules_on=168us vs iprules_off=135us (p95: 575us vs 351us).
- [x] 10.4 Run `openspec validate add-iprules-dual-stack-ipv6 --strict` and ensure change artifacts/spec deltas validate cleanly.
