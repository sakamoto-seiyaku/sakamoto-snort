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
- policy: do not copy PCAPs into this repository without an explicit license
  and privacy review.

## Current Inventory

The observed corpus contains:

- `85` `.pcap` files.
- `7` expected-result `.json` files.
- `7` corpus groups.

| Group | PCAPs | Expected JSON | Expected sessions | Expected app names | S61/S63 use |
| --- | ---: | --- | ---: | --- | --- |
| `app_pcap` | 7 | `app_pcap.json` | 7 | QQ, WeChat, WIREGUARD | long-tail mapped applications; none are in the current Sakamoto catalog |
| `dns_pcap` | 2 | `dns_pcap.json` | 53 | DNS | first DNS-over-TCP provider proof candidate |
| `mixed_pcap` | 41 | `mixed_pcap.json` | 41 | DNS, DTLS, FTP, HTTP, IMAP, POP3, QUIC, RTCP, RTP, SMTP, STUN | HTTP, QUIC, mail, STUN/DTLS, mixed long-tail cases |
| `openvpn_pcap` | 12 | `openvpn_pcap.json` | 13 | OPENVPN, QUIC | unmapped or later VPN-protocol catalog candidates |
| `ppp_pcap` | 6 | `ppp_pcap.json` | 115 | DNS, HTTP, ISAKMP, NETBIOS, PPTP | PPP/L2TP/PPTP and unknown-result behavior |
| `smtps_pcap` | 1 | `smtps_pcap.json` | 1 | SMTPS | SMTPS catalog candidate after first S61 proof |
| `socks_pcap` | 16 | `socks_pcap.json` | 37 | DHCP, DNS, FTP, HTTP, NETBIOS, POP3, RDP, SMTP, SOCKS, SSL | SOCKS plus nested application results |

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
4. one unknown or unmapped case from `ppp_pcap` or `openvpn_pcap`;
5. one nested/compound result only after single-result mapping is green.

Do not use the corpus to expand S61 into ProtocolRule enforcement. The first
runner should prove provider aliases, bounded payload submission, mapped vs.
unmapped results, and Activity projection readiness.
