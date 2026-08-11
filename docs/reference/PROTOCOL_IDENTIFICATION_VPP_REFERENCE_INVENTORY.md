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

Repo-local wrapper inventory evidence:

- command:
  `tools/protocol_identification/vpp_stellar_lpi_wrapper_inventory.sh`
- policy:
  `policy.copiesSourceIntoRepo=false`,
  `policy.providerSourceDecision=false`, and
  `policy.protocolRuleDecision=false`.
- observed wrapper files:
  `stellar_lpi_core.{c,h}`, `stellar_lpi_extend.{c,h}`,
  `stellar_lpi_plugin.c`, `stellar_lpi.api`, `CMakeLists.txt`, and
  `libprotoident/CMakeLists.txt`.
- exported C boundary:
  `lpi_detector_new`, `lpi_detector_free`,
  `lpi_detect_context_new`, `lpi_detect_context_free`,
  `lpi_detect_context_update`, `lpi_detect`, and `lpi_appid2name`.
- lifecycle call order observed in the wrapper:
  `lpi_detector_new` at plugin init, `lpi_detect_context_new` on first
  payload-bearing packet for a session, `lpi_detect_context_update` then
  `lpi_detect` per submitted payload packet, `lpi_appid2name` only for
  trace/status name projection, `lpi_detect_context_free` when session exdata
  is released, and `lpi_detector_free` at plugin exit.
- per-packet provider call order:
  `lpi_detect_context_update` then `lpi_detect`; the provider reports a
  `stop_detect` signal, which the fork uses to stop further bounded scanning
  for that session.
- wrapper dependency shape:
  The VPP plugin source includes VPP/VNET/VLIB/session/buffer feature headers,
  uses session exdata, buffer exdata, buffer tags, feature arcs, and optional
  TCP reassembly continuation. It is not a pure library as-is.
- extractable pure-provider candidate shape:
  `stellar_lpi_core` plus `stellar_lpi_extend` and vendored `libprotoident`
  form the smallest observed recognizer wrapper candidate, but even this
  wrapper still uses fork-local `vlib/uthash/uthash.h`, `vlib/utils/utils.h`,
  `ALLOC/FREE` macros, OpenVPN helper state, and payload heuristics.
- source counts:
  wrapper `4` `.c` files and `8` `.h` files; vendored libprotoident
  `3` top-level `.cc`, `284` `tcp/*.cc`, and `244` `udp/*.cc` files.
- build/link evidence:
  the VPP plugin uses `add_vpp_plugin(stellar_lpi ...)` and links
  `libprotoident`; vendored libprotoident builds as a static C++11 PIC library
  with definitions `__FAVOR_BSD`, `HAVE_NET_ETHERNET_H`, `HAVE_ICMPHDR=1`,
  `HAVE_TCP_STATES=1`, `HAVE_BSD_UDPHDR=1`, and `HAVE_BSD_TCPHDR=1`, and the
  fork CMake lists `stdc++` and `gcc_s`.
- provenance risk evidence:
  the plugin headers contain placeholder Apache-2.0 text with
  `<current-year> <your-organization>`, while vendored libprotoident headers
  state GNU LGPL v3-or-later. The local libprotoident directory does not provide an adjacent `COPYING` or `LICENSE` file.
- Sakamoto seam risk:
  the current `LpiRecognitionProvider` seam already matches the high-level
  lifecycle shape, but a real adapter must translate Sakamoto
  `ORIG`/`REPLY`, host-order ports, payload budgets, stop-detect behavior,
  provider aliases, memory ownership, and unavailable VPP session/tag concepts
  without introducing a parallel FlowEntry table.

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
- expected JSON readiness: when `VPP_LPI_CORPUS_ROOT` or the default backup
  path exists, the same target parses the `7` reference expected JSON files in
  place, validates row shape and APP_NAME normalization, derives replay events,
  and runs them through the same pipeline. It skips this optional evidence path
  when the backup corpus is absent.
- mapped baseline: DNS `145`, HTTP `36`, QUIC `21`, SSL `4`.
- unmapped baseline: the `19` long-tail `APP_NAME` values above, `81`
  occurrences total.
- no-result baseline: `6` expected `UNKNOWN` / no-`APP_NAME` rows.
- compound readiness: `SOCKS` followed by `HTTP` on the same synthetic flow
  keeps `SOCKS` unmapped, maps `HTTP`, and leaves latest exact result as HTTP.

This host replay test still does not read PCAP bytes and does not prove a real
recognizer. It proves that the current Sakamoto seam can consume the reference
result shape once a provider and licensed corpus subset exist.

Repo-local Recognize-to-Activity projection evidence:

- `nfqueue_flow_adapter_tests` proves a fake `LpiRecognitionProvider` fact
  produced before adapter completion updates Root/NFQUEUE `allowedFlowActivity`
  through the shared graph ingress and worker-owned `FlowEntry`.
- `vpn_tun_flow_adapter_tests` proves the same fake-provider path updates
  VPN/TUN `allowedFlowActivity`; VPN does not need a parallel recognition
  path.
- `control_server_contract_tests` proves both `NFQUEUE.STATUS` and
  `VPN_TUN.STATUS` expose non-empty `allowedFlowActivity` protocol recognition
  fields, including `lastProtocolRecognitionState`,
  `lastApplicationProtocolKey`, `lastApplicationProtocolCategory`,
  `lastProtocolRecognitionSequence`, and `lastProtocolPayloadPackets`.
- `AndroidRuntimeContractTest` proves product-side native activity ingestion
  turns a recognized allowed-flow record into an `ActivityItem` with
  `flow_entry_lpi_recognition` evidence and round-trips the protocol state,
  latest exact result, category, full sequence, and payload packet count through
  `ProductActivityProjectionStore`.

This projection evidence uses fake/scripted recognition facts only. It proves
that a future real provider can reach Activity without changing the current
Root/VPN adapter, ControlServer JSON, RuntimeService ingestion, or product
Activity model. It does not prove libprotoident detection accuracy.

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
- Root/VPN adapters count provider availability and payload submission, and
  fake/scripted provider facts have host evidence through Activity projection.
- No real libprotoident provider is wired by default.
- No repo-local PCAP corpus has been imported.
- No Android device evidence proves a real provider on Root or VPN.
- No ProtocolRule enforcement has started.

Repo-local Android wrapper build probe evidence:

- command:
  `tools/protocol_identification/stellar_lpi_wrapper_android_build_probe.sh`
- current result:
  `probe.result=PASS`
- scope:
  compiles and links `stellar_lpi_core.c + stellar_lpi_extend.c` with the
  vendored base libprotoident Android source set into the throwaway
  `stellar_lpi_wrapper_android_probe` executable.
- generated compatibility:
  `probe.generatedUtilsShim=true` for `ALLOC` / `FREE`; the probe uses
  `probe.referenceUthashInPlace=true` for the backup tree's
  `vlib/uthash/uthash.h`.
- policy:
  `policy.copiesSourceIntoRepo=false`,
  `policy.providerVendoringDecision=false`,
  `policy.providerRuntimeWiring=false`, and
  `policy.protocolRuleDecision=false`.

This closes the immediate compile/link unknown for the extractable wrapper
candidate. It still does not create a real Sakamoto provider, prove packet
detection accuracy, import corpus fixtures, or answer source/license strategy.

Repo-local host synthetic payload probe evidence:

- command:
  `tools/protocol_identification/stellar_lpi_wrapper_host_payload_probe.sh`
- current result:
  `probe.result=PASS`
- scope:
  compiles, links, and runs `stellar_lpi_core.c + stellar_lpi_extend.c` with
  the vendored base libprotoident host source set, then submits synthetic
  application payload bytes through the wrapper lifecycle.
- observed cases:
  HTTP -> fork-local `appid=67` / `HTTP` / `lpi:http` / `stopDetect=1`;
  DNS -> fork-local `appid=32` / `DNS` / `lpi:dns` / `stopDetect=1`;
  SOCKS5 -> fork-local `appid=8005` / `SOCKS` / `lpi:socks` /
  `stopDetect=0`.
- policy:
  `policy.copiesSourceIntoRepo=false`,
  `policy.copiesPcapIntoRepo=false`,
  `policy.usesSyntheticPayloads=true`,
  `policy.providerVendoringDecision=false`,
  `policy.providerRuntimeWiring=false`, and
  `policy.protocolRuleDecision=false`.

This closes a runtime-smoke unknown for the extractable wrapper candidate on
synthetic payload bytes. It still does not prove PCAP corpus replay accuracy,
Android Root/VPN provider behavior, provider-source acceptability, or
ProtocolRule enforcement readiness.

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
