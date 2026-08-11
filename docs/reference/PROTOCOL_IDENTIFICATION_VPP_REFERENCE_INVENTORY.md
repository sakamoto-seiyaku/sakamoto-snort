# Protocol Identification VPP Reference Inventory

Date: 2026-08-12

Status: reference inventory for SAKAMOTO-61 and later Protocol Identification
work. This is not an implementation decision and does not move Protocol
Identification into the Android L4 Product Release gate.

## Source

Reference repository:

- `/home/js/backup/backup/Git/vpp`
- branch observed: `dev-26.03...origin/dev-26.03`
- local state observed: dirty reference checkout with many deleted upstream
  external packaging files and an untracked `test/` copy; treat paths as
  evidence inputs, not as a clean upstream baseline.

This repository is a deeply modified VPP gateway codebase, not plain upstream
VPP. It contains prior gateway, protocol identification, decoder, policy,
statistics, and PCAP-test work that is useful as design lineage for Sakamoto.

## Relevant Components

Primary LPI plugin:

- `src/plugins/stellar_lpi/`
- VPP plugin name: `stellar_lpi`
- VPP feature node used by tests: `stellar-lpi`
- Binary API: `src/plugins/stellar_lpi/stellar_lpi.api`
- C wrapper boundary:
  `src/plugins/stellar_lpi/stellar_lpi_core.h`
- vendored recognizer:
  `src/plugins/stellar_lpi/libprotoident/`
- build shape: `stellar_lpi` links against local `libprotoident`

Adjacent protocol and policy components worth using as reference, not copying
as first implementation scope:

- `stellar_flow_dissector`
- `stellar_session_manager`
- `stellar_qdpi_detector`
- protocol decoders including HTTP, TLS, QUIC, SSH, DNS, FTP, mail, SIP, STUN,
  DTLS, RTP, RDP, SOCKS, GTP, GBT32960, and others
- policy/enforcer components including ACL, security enforcer, statistics
  enforcer, threshold enforcer, traffic sketch, policy sketch, AppSketch,
  scanner, exporter, and flow sync tests

## LPI Shape Observed

The fork's LPI wrapper exposes a small C boundary:

- `lpi_detector_new/free`
- `lpi_detect_context_new/free`
- `lpi_detect_context_update`
- `lpi_detect`
- `lpi_appid2name`

The detector context is initialized with:

- current packet direction as server-to-client or client-to-server
- host client/server ports
- transport protocol

The context updates only small derived payload facts per direction:

- observed bytes per direction
- first up-to-four payload bytes per direction
- payload length per direction
- packet counters per direction

The fork caps recognition by `max-detect-pkts`; tests use `20` as the baseline.
That matches Sakamoto's current product-plan stance: use a bounded
payload-bearing packet budget, but do not treat `20` as a final product
constant without Android Root/VPN measurements.

The fork's LPI mapping converts libprotoident names into a private Qosmos-style
application catalog. Sakamoto must not inherit those numeric IDs. Current
Sakamoto catalog IDs remain project-owned and provider aliases stay in
`lpi:<name>` form.

## Test Corpus

The reference repo has real packet-capture material that this repository
currently lacks:

- all reference packet captures under `/home/js/backup/backup/Git/vpp/test`:
  `756` files total, split as `751` `.pcap`, `5` `.pcapng`, and `0` `.cap`
- LPI batch corpus under
  `/home/js/backup/backup/Git/vpp/test/decoders/stellar_lpi/test_pcap`: `85`
- LPI batch expected JSON files under the same tree: `7`

LPI corpus groups observed:

- `app_pcap`: QQ, WeChat, WireGuard
- `dns_pcap`: DNS over TCP
- `mixed_pcap`: HTTP/FTP/mail/QUIC/STUN-DTLS and mixed cases
- `openvpn_pcap`: UDP/TCP/OpenVPN and QUIC/OpenVPN cases
- `ppp_pcap`: L2TP/PPTP cases
- `smtps_pcap`: SMTPS
- `socks_pcap`: SOCKS4/SOCKS5 with HTTP/HTTPS/FTP/mail/RDP cases

Group-level shape observed on 2026-08-12:

| Group | PCAPs | Expected JSON | Expected sessions | Observed expected app names | Notes |
| --- | ---: | ---: | ---: | --- | --- |
| `app_pcap` | 7 | 1 | 7 | QQ, WeChat, WIREGUARD | app-style protocol names only; none are in the current Sakamoto catalog |
| `dns_pcap` | 2 | 1 | 53 | DNS | useful for current `lpi:dns` catalog evidence |
| `mixed_pcap` | 41 | 1 | 41 | DNS, DTLS, FTP, HTTP, IMAP, POP3, QUIC, RTCP, RTP, SMTP, STUN | useful for `lpi:http`, `lpi:quic`, mapped/unmapped, and multi-protocol behavior |
| `openvpn_pcap` | 12 | 1 | 13 | OPENVPN, QUIC | useful as long-tail/tunnel evidence; OpenVPN is not in the current catalog |
| `ppp_pcap` | 6 | 1 | 115 | DNS, HTTP, ISAKMP, NETBIOS, PPTP | includes expected `UNKNOWN` rows; useful for no-result and unmapped handling |
| `smtps_pcap` | 1 | 1 | 1 | SMTPS | not currently in the Sakamoto catalog |
| `socks_pcap` | 16 | 1 | 37 | DHCP, DNS, FTP, HTTP, NETBIOS, POP3, RDP, SMTP, SOCKS, SSL | useful for ordered multi-result behavior such as SOCKS plus inner protocol |

The fork runner for this corpus is
`/home/js/backup/backup/Git/vpp/test/test_stellar_lpi.py::test_lpi_batch`.
It discovers the `test_pcap` subdirectories, replays every `.pcap` through
`stellar-flow-dissector` and `stellar-lpi`, extracts event-logger
`LPI TRACE SESSION` JSON, and compares the ordered actual results with each
group's expected JSON. This is a runner shape reference only; Sakamoto should
build a repo-local host runner that feeds packet bytes through the pinned
provider boundary and verifies `lpi:<name>` provider aliases before any Android
or ProtocolRule gate.

Repo-local expected-result alias inventory:

- command:
  `tools/protocol_identification/vpp_lpi_expected_alias_inventory.py`
- source:
  `/home/js/backup/backup/Git/vpp/test/decoders/stellar_lpi/test_pcap`
- policy: `policy.copiesExpectedJsonIntoRepo=false`
- current baseline: `7` expected JSON files, `267` expected sessions, `23`
  unique normalized `APP_NAME` values.
- current mapped evidence against the Sakamoto Application Protocol Catalog:
  DNS `145` -> `lpi:dns`, HTTP `36` -> `lpi:http`, QUIC `21` -> `lpi:quic`,
  SSL `4` -> catalog key `tls` / canonical alias `lpi:tls`.
- current unmapped expected `APP_NAME` values:
  DHCP, DTLS, FTP, IMAP, ISAKMP, NETBIOS, OPENVPN, POP3, PPTP, QQ, RDP, RTCP,
  RTP, SMTP, SMTPS, SOCKS, STUN, WECHAT, WIREGUARD.

This inventory is a contract over reference evidence and current catalog alias
coverage. It does not connect a real libprotoident provider and does not start
ProtocolRule enforcement work.

Repo-local host replay evidence:

- test target: `lpi_expected_alias_replay_tests`
- source: `tests/host/lpi_expected_alias_replay_tests.cpp`
- scope: replays the current expected-alias coverage baseline through the real
  `LpiRecognitionPipeline`, `LpiRecognitionAdapter`, and worker-owned
  `BoundedFlowTable` using a scripted provider.
- mapped baseline: DNS `145`, HTTP `36`, QUIC `21`, SSL `4`.
- unmapped baseline: the `19` long-tail `APP_NAME` values above, `81`
  occurrences total.
- no-result baseline: `6` expected `UNKNOWN` / no-`APP_NAME` rows.
- compound readiness: `SOCKS` followed by `HTTP` on the same synthetic flow
  keeps `SOCKS` unmapped, maps `HTTP`, and leaves latest exact result as HTTP.

This host replay test still does not read PCAP bytes and does not prove a real
recognizer. It proves that the current Sakamoto seam can consume the reference
result shape once a provider and licensed corpus subset exist.

License/privacy status:

- The reference repo root and copied `test/` tree contain Apache-2.0 `LICENSE`
  files, but there is no corpus-local README, NOTICE, source-attribution, or
  privacy file under `test/decoders/stellar_lpi/test_pcap`.
- Several capture names and expected JSON rows include real-looking public and
  private IP addresses, service names, and application names. Treat the corpus
  as sensitive test evidence until license, provenance, and privacy suitability
  are explicitly reviewed.
- Do not copy the full corpus, publish it, or claim redistributed fixture
  rights from this inventory. A later implementation may import only a small
  pinned subset after license/privacy review, preferably reduced or synthetic
  enough to prove the current Sakamoto catalog entries plus unmapped/unknown
  behavior.

These are the strongest immediate source for S61/S63 fixture planning. Before
copying any corpus into this repo, confirm licensing and privacy suitability,
then import only a small pinned subset that proves the first Sakamoto catalog
entries and known unknown/long-tail behavior.

## Sakamoto Fit

Useful to reuse as design evidence:

- in-graph recognition before adapter completion
- bounded payload-bearing packet submission
- ORIG/REPLY style direction state
- provider-name-to-project-catalog normalization
- keeping protocol recognition attached to the existing flow entry rather than
  creating a second product flow table
- PCAP replay plus expected-result JSON as corpus format

Do not copy into the first Sakamoto implementation:

- Qosmos/qDPI numeric AppIDs
- MAAT object/rule model
- qDPI vendor dependency
- downstream decoder chain as a prerequisite for Protocol Identification
- `continue_scanning_flag` as product semantics
- full CT, TCP stream reassembly, HTTP/TLS/QUIC metadata, NAT/gateway, or
  traffic-sketch enforcement as part of S61

## Current Sakamoto Boundary

Current Sakamoto S61 work has already implemented the local product boundary:

- `src/core/protocol/LpiRecognitionProvider.hpp` defines a disabled/provider
  submission interface.
- `src/core/protocol/LpiRecognitionAdapter.hpp` maps provider aliases to the
  project-owned Application Protocol Catalog.
- `resources/application-protocol-catalog/catalog.tsv` currently contains DNS,
  HTTP, TLS, QUIC, and SSH with `lpi:*` provider aliases.
- Root/VPN adapters count provider availability and payload submission, but no
  real libprotoident provider is wired by default.

Therefore the next S61 implementation step should not start from protocol rule
enforcement. It should first add a real, pinned recognizer provider behind the
existing `LpiRecognitionProvider` boundary and prove it against a small licensed
PCAP subset derived from the reference repo.

## Recommended Next Slice

1. Pin a source strategy for the recognizer:
   vendored fork subset, upstream libprotoident, or a separate local provider
   package.
2. Import a minimal corpus subset for the current catalog:
   DNS, HTTP, TLS/SSL, QUIC, SSH, plus at least one unmapped result and one
   no-result flow.
3. Add a host corpus runner that feeds packet bytes through the provider and
   verifies provider aliases before touching ProtocolRule enforcement.
4. Wire the provider into Root and VPN only after host corpus evidence is green.
5. Add Android device evidence for provider availability, payload budget,
   mapped/unmapped counters, Activity projection, and Root/VPN parity.
