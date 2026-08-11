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
