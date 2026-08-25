# S141 B2 final closure audit

Date: 2026-08-26
Plane: `SAKAMOTO-141`
Status: `CLOSABLE_FOR_BOUNDED_B2_POC`

## Decision

S141 can be closed for the bounded B2 POC claim: on the selected Pixel 6a
full-device AppA -> VpnService/TUN -> OI3 multi-owner path, the current
evidence separates policy decisions, transport outcomes, and Android
bind/protect/broker infrastructure failures without unprotected retry, SOCKS
fallback, or second datapath.

This audit does not upgrade EG-07 to global `SUPPORTED`. EG-07 remains
`PARTIAL` for pre-connect `ECONNREFUSED`, arbitrary public-Internet behavior,
arbitrary teardown mapping, production timeout/capacity constants, complete
distinct-App matrices, Doze, soak, and OEM variation.

Machine-readable audit bundle:

```text
experiments/vpp-nfq-poc/evidence/s141-b2-final-closure-audit-20260826/b2-closure-audit.json
```

## Acceptance audit

| S141 acceptance item | Evidence | Audit verdict |
| --- | --- | --- |
| Real-App allow/success control on the B1 full-device route | S178 carried current-artifact IPv4/IPv6 UDP/TCP DNS through the full-device owner-inline path with `appValidCount=6`, `nativeValidCount=6`, `failureCount=0`, and zero post-run `vpp`/`tun0` residue. S181-S185 each also include a positive AppA UDP DNS control on the same WSL2/LAN fixture path. | `PASS_FOR_BOUNDED_B2` |
| Real-App UID drop | S183 run `20260825-192207-202830` dropped AppA UID `12630` at the native TUN gate before OI3 broker/socket admission. The UID ledger recorded `MISS_SUBMITTED -> COMPLETION_ACCEPTED uid=12630 -> CACHE_HIT uid=12630`; the fixture observed no packet; `gateDrop=2`, `gateForward=0`; zero residue. | `PASS_FOR_BOUNDED_B2` |
| Real-App UID allow/drop context | A2/S190 is the current UID attribution and known-UID allow/drop aggregate, including A2-5 `PASS_KNOWN_UID_ALLOW_DROP`. B2 uses that attribution context only to support the bounded S183 drop and AppA success controls; it does not claim the full EG-08 distinct-App matrix. | `PASS_AS_SUPPORTING_CONTEXT` |
| Representative IP/policy drop | S182 run `20260825-190147-303631` dropped a target IPv4 packet in OI3 multi pre-owner dispatch: `stage=pre-owner`, `no-transport=1`, `broker=0`, `socket=0`, fixture observer received no packet, zero residue. | `PASS_FOR_BOUNDED_B2` |
| Bounded transport refusal/reset and no-reply remain transport outcomes | S179 run `20260825-172718-237536` reran the controlled full-TUN refused/no-reply/policy-drop negative contract on the final artifact with native `PASS_EXPECTED_FAILURE`, `verifierRc=0`, `failureCount=0`, and zero residue. S181 run `20260825-183033-563849` proved real UDP no-reply and classified the unbound TCP fixture as timeout rather than false refusal. S184 run `20260825-210129-290257` proved bounded post-SYN LAN reset with one owner-local `ECONNRESET`, one downstream `RST|ACK`, AppA `dns_response_reset`, one transport failure, zero infrastructure failure, and exact buffer settlement. | `PASS_FOR_BOUNDED_B2` |
| Forced bind failure, forced protect failure, broker unavailable | S185 run `20260825-213903-524622` passed bind failure, protect failure, and broker unavailable with exact broker result and phase accounting: `BIND_FAILURE` `1/0`, `PROTECT_FAILURE` `1/1`, `BROKER_UNAVAILABLE` `0/0`; all failure cells stopped before fixture query, TUN output, Direct send, policy drop, or transport failure. | `PASS_FOR_BOUNDED_B2` |
| Policy drop stops before broker/socket creation | S179 controlled policy-drop and S182 real target-IP policy-drop both record broker/socket/transport zero. S183 UID-drop records gate drop before OI3 broker/socket admission. | `PASS_FOR_BOUNDED_B2` |
| Accepted transport failure never rewrites policy | S179 refusal and S184 reset both record transport-failure outcomes after broker/protected admission; S181 no-reply/timeout remains timeout/no-reply. None are relabelled as policy drop. | `PASS_FOR_BOUNDED_B2` |
| Infrastructure failure never retries unprotected, through SOCKS, or through another dataplane | S185 failure cells record no fixture query, no TUN output, no Direct send, and no transport failure. S127/OI2 also proves the broker seam closes SCM_RIGHTS duplicates exactly once and rejects foreign/late completions. | `PASS_FOR_BOUNDED_B2` |
| Refusal, timeout, bind/protect, and broker outcomes are unambiguous | S146/S147 fixed the cell-aware negative contract. S181 records the invalid `real-refused` assumption and reclassifies the unbound TCP cell as timeout. S184 introduces distinct `EXPECTED_REAL_TRANSPORT_RESET`; S185 splits bind/protect/broker phases into exact enums. | `PASS_FOR_BOUNDED_B2` |
| Descriptor, packet buffer, and transport resource settlement is exactly once | S179, S181, S182, S183, S184 raw cleanup, and S185 all record zero post-run `vpp`/`tun0` residue. S127 covers descriptor duplicate close, stale/duplicate/wrong-owner/wrong-epoch rejection; S128 covers controlled OI3 buffer residue; S130 covers generation/epoch late-event settlement. | `PASS_FOR_BOUNDED_B2` |
| Host/model support covers duplicate, stale, wrong-owner, wrong-epoch, and outcome-class matrix using the B1/B2 schema | S127 OI2 covers duplicate/stale/wrong-owner/wrong-epoch completion tripwires and bind/protect/broker infrastructure phases. S128 OI3 covers IPv4/IPv6 TCP/UDP success plus refused/no-reply/policy-drop outcome classes with zero buffer residue. S130 OI5 covers generation/epoch stale late-event rejection. | `PASS_FOR_BOUNDED_B2_SUPPORT_ONLY` |
| Artifact/device/network provenance, cell results, raw outcome, cleanup facts, supported claim, non-claims, Finding Ledger entries, and POC corrections are recorded | S179-S185 execution docs include artifact hashes, device/fixture/run IDs, cell results, cleanup/outcome facts, boundaries, and invalid-run notes. `POC_FINDING_LEDGER.md` records VPN-F055 through VPN-F059. This audit records the final supported claim and non-claims. | `PASS_FOR_BOUNDED_B2` |

## S184 derived-manifest caveat

The S184 downstream-reset evidence directory intentionally preserves its raw
device files. The historical CSV/manifest in that directory still show the old
derived `FAIL` caused by a verifier-only double count: the summarizer read
`native-combined.log`, which already embeds `vpp-stdout.log`, and then read
`vpp-stdout.log` again.

For S141 closure, S184 is accepted on the authoritative raw evidence and the
corrected verifier/source tests:

- one fixture connection and one `tcp_rst_sent`;
- one owner-local `READ_ERROR errno=104`;
- one downstream owner-output `RST|ACK`;
- AppA `tcp_payload_sent/dns_response_reset`;
- `PASS_EXPECTED_REAL_RESET`;
- one transport failure, zero infrastructure failure;
- exact `buffers=7/7 residue=0`;
- no post-run VPP process or `tun0`.

The old derived S184 CSV/manifest must not be used as the final S184 oracle
without the caveat above.

## Supported claim

The bounded B2 POC supports this claim:

> On the selected Pixel 6a, current AppA/VpnLite/OI3 multi-owner path, and
> WSL2/LAN fixtures, policy drop, UID drop, transport no-reply/timeout/reset,
> and Android bind/protect/broker infrastructure failures remain separately
> attributable, do not use fallback datapaths, and settle with zero process/TUN
> residue.

## Non-claims retained

- Pre-connect `ECONNREFUSED` on a public or arbitrary endpoint.
- Public-Internet failure behavior beyond the registered DNS and WSL2/LAN
  fixture cells.
- Arbitrary TCP teardown mapping; S184 only proves exact owner-observed
  `ECONNRESET` -> one downstream `RST|ACK`.
- Production timeout constants, production policy authoring, production UID
  gate capacity, throughput, CPU/thermal/power, Doze, or long soak.
- Complete EG-08 distinct-App UID matrix; A2/S190 is the current UID
  attribution aggregate and remains separately bounded.
- OEM/device/network combinations beyond the selected Pixel 6a environment.
