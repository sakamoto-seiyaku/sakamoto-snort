# Protocol Identification VPP LPI Corpus Manifest

Date: 2026-08-12

Status: reference-only manifest for SAKAMOTO-61 and later Protocol
Identification work. This does not import packet captures, does not decide the
recognizer source strategy, and does not move Protocol Identification into the
Android L4 Product Release gate.

Source corpus:

- `/home/js/backup/backup/Git/vpp/test/decoders/stellar_lpi/test_pcap`
- repeatable local inventory command:
  `bash tools/protocol_identification/vpp_lpi_corpus_inventory.sh`
- repeatable APP_NAME/provider-alias coverage command:
  `tools/protocol_identification/vpp_lpi_expected_alias_inventory.py`
- policy: do not copy PCAPs into this repository without an explicit license
  and privacy review.
- policy: do not copy expected-result JSON into this repository for the alias
  inventory; read the backup corpus in place.

## Current Inventory

The observed corpus contains:

- `85` `.pcap` files.
- `7` expected-result `.json` files.
- `7` corpus groups.
- `267` expected-result rows.
- `23` unique normalized `APP_NAME` values.

| Group | PCAPs | Expected JSON | Expected sessions | Expected app names | S61/S63 use |
| --- | ---: | --- | ---: | --- | --- |
| `app_pcap` | 7 | `app_pcap.json` | 7 | QQ, WeChat, WIREGUARD | long-tail mapped applications; none are in the current Sakamoto catalog |
| `dns_pcap` | 2 | `dns_pcap.json` | 53 | DNS | first DNS-over-TCP provider proof candidate |
| `mixed_pcap` | 41 | `mixed_pcap.json` | 41 | DNS, DTLS, FTP, HTTP, IMAP, POP3, QUIC, RTCP, RTP, SMTP, STUN | HTTP, QUIC, mail, STUN/DTLS, mixed long-tail cases |
| `openvpn_pcap` | 12 | `openvpn_pcap.json` | 13 | OPENVPN, QUIC | unmapped or later VPN-protocol catalog candidates |
| `ppp_pcap` | 6 | `ppp_pcap.json` | 115 | DNS, HTTP, ISAKMP, NETBIOS, PPTP | PPP/L2TP/PPTP and unknown-result behavior |
| `smtps_pcap` | 1 | `smtps_pcap.json` | 1 | SMTPS | SMTPS catalog candidate after first S61 proof |
| `socks_pcap` | 16 | `socks_pcap.json` | 37 | DHCP, DNS, FTP, HTTP, NETBIOS, POP3, RDP, SMTP, SOCKS, SSL | SOCKS plus nested application results |

## Current Catalog Alias Coverage

Observed by
`tools/protocol_identification/vpp_lpi_expected_alias_inventory.py` on
2026-08-12 against
`resources/application-protocol-catalog/catalog.tsv`.

The current Sakamoto provider aliases are the authority for mapping; VPP
fork-local numeric `APP_ID` values are not imported or asserted as Sakamoto
catalog identity.

- mapped unique `APP_NAME` values: `4`.
- mapped `APP_NAME` occurrences: `206`.
- unmapped unique `APP_NAME` values: `19`.
- unmapped `APP_NAME` occurrences: `81`.
- rows without `APP_NAME` / expected `UNKNOWN`: `6`.
- multi-result rows: `25`.

Mapped evidence:

| Expected APP_NAME | Occurrences | Expected alias evidence | Current catalog key | Canonical catalog provider alias |
| --- | ---: | --- | --- | --- |
| DNS | 145 | `lpi:dns` | `dns` | `lpi:dns` |
| HTTP | 36 | `lpi:http` | `http` | `lpi:http` |
| QUIC | 21 | `lpi:quic` | `quic` | `lpi:quic` |
| SSL | 4 | `lpi:ssl` | `tls` | `lpi:tls` |

Unmapped expected `APP_NAME` values:

`DHCP`, `DTLS`, `FTP`, `IMAP`, `ISAKMP`, `NETBIOS`, `OPENVPN`, `POP3`,
`PPTP`, `QQ`, `RDP`, `RTCP`, `RTP`, `SMTP`, `SMTPS`, `SOCKS`, `STUN`,
`WECHAT`, `WIREGUARD`.

The repo-local host target `lpi_expected_alias_replay_tests` uses this
coverage as a scripted provider fixture against the real
`LpiRecognitionPipeline` and `BoundedFlowTable`. It has two evidence modes:

- a committed aggregate baseline for environments without the backup VPP
  checkout;
- an optional in-place expected JSON reader, enabled when
  `VPP_LPI_CORPUS_ROOT` or the default backup path exists, that parses the
  `7` reference JSON files, validates `267` rows / `287` APP_NAME occurrences /
  `6` UNKNOWN rows / `25` multi-result rows, normalizes provider aliases, and
  replays the derived events through the same pipeline.

It verifies mapped, unmapped, no-result, and compound unmapped-then-mapped
replay behavior without copying corpus files or enabling a real provider.

## Expected JSON Shape

The expected-result files use VPP fork output fields:

- `SESSION_ADDRESS`
- `SESSION_TYPE`
- `APP_ID`
- `APP_NAME`
- `FLOW_DIRECTION`
- `LABEL`

Sakamoto must treat this as reference evidence, not a product schema. In
particular:

- `APP_ID` values are fork-local qDPI/Qosmos-style numbers and must not be imported as Sakamoto catalog IDs.
- `APP_NAME` strings are useful as provider aliases only after normalization to
  the project-owned `lpi:<name>` namespace.
- `FLOW_DIRECTION` is useful lineage for ORIG/REPLY handling, but not a direct
  Android device direction schema.

## Recommended First Import Candidates

After license and privacy review, the smallest useful S61 corpus subset should
prefer:

1. one DNS-over-TCP capture from `dns_pcap`;
2. one HTTP capture from `mixed_pcap`;
3. one QUIC capture from `mixed_pcap`;
4. one no-result case from `mixed_pcap/39-pop3-mistake-redis.pcap`,
   `SESSION_ADDRESS=192.168.40.82:41450-192.168.44.230:7002-6-0`,
   where `mixed_pcap.json` row 18 records `FLOW_DIRECTION=SYMMETRIC`,
   `SESSION_TYPE=TCP`, `LABEL=LPI_RESULT_18`, `APP_ID="UNKNOWN"`, and no
   `APP_NAME`;
5. one nested/compound result such as
   `socks_pcap/1-socks45-http-example.pcap`,
   `SESSION_ADDRESS=10.180.156.185:53535-10.180.156.249:1080-6-0`,
   where `socks_pcap.json` records `LABEL=LPI_RESULT_6`,
   `APP_NAME=["SOCKS","HTTP"]`, and `APP_ID=[8005,67]`.

Do not use the corpus to expand S61 into ProtocolRule enforcement. The first
runner should prove provider aliases, bounded payload submission, mapped vs.
unmapped/no-result results, and Activity projection readiness. A selected
UNKNOWN smoke may prove no-result handling for one flow; a selected SOCKS+HTTP
smoke may prove ordered unmapped-then-mapped behavior for that one flow. These
are not a full corpus accuracy result, a provider runtime wiring decision, a
provider-source decision, or a ProtocolRule/source-acceptance decision.
