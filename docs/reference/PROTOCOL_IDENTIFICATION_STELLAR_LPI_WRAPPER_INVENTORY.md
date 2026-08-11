# Protocol Identification stellar_lpi Wrapper Inventory

Date: 2026-08-12

Status: repeatable local inventory for SAKAMOTO-61 provider-source planning.
This is not a vendoring decision, not a source-strategy decision, and not
ProtocolRule implementation approval.

Inventory command:

```bash
bash tools/protocol_identification/vpp_stellar_lpi_wrapper_inventory.sh
```

Default input:

- source: `/home/js/backup/backup/Git/vpp`
- wrapper root: `/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi`
- libprotoident root:
  `/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/libprotoident`
- policy: `policy.copiesSourceIntoRepo=false`
- policy: `policy.providerSourceDecision=false`
- policy: `policy.protocolRuleDecision=false`

## Wrapper API Shape

`stellar_lpi_core.h` exposes a small C boundary:

- `lpi_detector_new`
- `lpi_detector_free`
- `lpi_detect_context_new`
- `lpi_detect_context_free`
- `lpi_detect_context_update`
- `lpi_detect`
- `lpi_appid2name`

Current observed signatures:

- `struct lpi_detector *lpi_detector_new()`
- `void lpi_detector_free(struct lpi_detector *lpip)`
- `struct lpi_detect_context *lpi_detect_context_new(bool current_is_s2c_flow, uint16_t host_client_port, uint16_t host_server_port, uint8_t trans_proto)`
- `void lpi_detect_context_free(struct lpi_detect_context *ctx)`
- `void lpi_detect_context_update(struct lpi_detect_context *ctx, const char *scan_data, unsigned int scan_data_len, bool current_is_s2c_flow)`
- `int lpi_detect(struct lpi_detector *lpip, struct lpi_detect_context *ctx, const char *payload, size_t payload_len, unsigned int *stop_detect)`
- `const char *lpi_appid2name(struct lpi_detector *lpip, int appid)`

The call shape is:

1. create one detector with `lpi_detector_new`;
2. create one per-flow context with `lpi_detect_context_new`;
3. call `lpi_detect_context_update` for each payload-bearing packet;
4. call `lpi_detect`;
5. map the returned fork-local appid to a name with `lpi_appid2name`;
6. free per-flow context and detector with the matching `free` functions.

This is close to Sakamoto's existing `LpiRecognitionProvider` seam, but the
returned integer appid is not a Sakamoto catalog ID.

Machine-readable call fields currently emitted by the inventory script:

- `call.lifecycle=lpi_detector_new,lpi_detect_context_new,lpi_detect_context_update,lpi_detect,lpi_appid2name,lpi_detect_context_free,lpi_detector_free`
- `call.perPacket=lpi_detect_context_update,lpi_detect`
- `call.providerStopSignal=stop_detect`

## Source and Build Shape

Current local inventory:

- wrapper C files: `4`
- wrapper header files: `8`
- base libprotoident source shape: `3` top-level `.cc`, `284` `tcp/*.cc`,
  `244` `udp/*.cc`
- `CMakeLists.txt` uses `add_vpp_plugin(stellar_lpi ...)`
- plugin target links `libprotoident`
- plugin target includes `stellar_lpi_extend.c`
- vendored libprotoident target is static, C++11, and PIC
- vendored libprotoident compile definitions:
  `-D__FAVOR_BSD`, `-DHAVE_NET_ETHERNET_H`, `-DHAVE_ICMPHDR=1`,
  `-DHAVE_TCP_STATES=1`, `-DHAVE_BSD_UDPHDR=1`, `-DHAVE_BSD_TCPHDR=1`
- vendored libprotoident link list in the fork CMake: `stdc++`, `gcc_s`

`stellar_lpi_core.c` includes:

- standard C headers: `stdio.h`, `stdlib.h`, `string.h`, `time.h`
- local wrapper headers: `stellar_lpi_core.h`, `stellar_lpi_extend.h`
- VPP-tree headers: `vlib/uthash/uthash.h`, `vlib/utils/utils.h`

The plugin source includes VPP/VNET/VPPInfra/VAT headers and additional
Stellar gateway headers. The plugin source is not a standalone provider
adapter for Sakamoto.

## Dependency Facts

Observed wrapper facts:

- `stellar_lpi_core.c` uses `ALLOC` / `FREE` macros from the modified VPP tree.
- `stellar_lpi_core.c` uses `uthash` and `HASH_*` macros for appid/name maps.
- `stellar_lpi_core.c` includes `stellar_lpi_extend.h`.
- `stellar_lpi_extend.h` includes `libprotoident/libprotoident.h`.
- `stellar_lpi_extend.h` adds OpenVPN state in `struct ovpn_ctx`.
- `stellar_lpi_extend.c` adds payload heuristics through
  `lpi_plus_extended_guess`.

This means the wrapper is not just a thin base-libprotoident adapter. It carries
fork-local normalization, extended heuristics, and VPP-tree allocation/hash
dependencies.

## Mapping Facts

Current local `lpi_protocol_mappings[]` inventory:

- entries: `80`
- unique app names: `58`
- contains fork-local IDs: `true`
- sample mappings:
  `UNCATEGORIZED:8000:UNCATEGORIZED`,
  `DNS:32:DNS`,
  `DNS_TCP:32:DNS`,
  `FTP:45:FTP`,
  `FTP_Control:45:FTP`,
  `FTP_Data:45:FTP`,
  `FTPS:751:FTPS`,
  `HTTP:67:HTTP`

The integer IDs are fork-local Qosmos/qDPI-style IDs. Sakamoto must continue to map provider names or aliases into the project-owned Application Protocol Catalog instead of importing these IDs.

## License / Provenance Facts

The wrapper inventory reports:

- `license.pluginHeaderApachePlaceholder=true`
- `license.libprotoidentLgpl3OrLater=true`
- `license.libprotoidentAdjacentCopying=false`

This means the plugin files carry placeholder Apache-2.0 text, while vendored
libprotoident declares LGPL v3-or-later and the local libprotoident directory
does not provide an adjacent `COPYING` or `LICENSE` file. This is evidence for
provider-source planning only, not legal advice and not a vendoring decision.

## Sakamoto Fit

Useful evidence:

- the detector/context split matches a per-provider plus per-flow shape;
- packet update before detect matches the existing packet-submission seam;
- `stop_detect` can inform terminal `Done` semantics later;
- name output can be normalized to `lpi:<name>` provider aliases.

Not ready to copy as-is:

- VPP allocation/hash dependencies must be removed or wrapped;
- `stellar_lpi_extend` inclusion must be a source-strategy decision;
- fork-local app IDs must not cross the Sakamoto provider seam;
- license/source/relink obligations are not solved by this inventory;
- the Android wrapper build probe below proves compile/link shape only; it does
  not make the wrapper product-owned source or a runtime provider.

## Android Wrapper Build Probe

Probe command:

```bash
bash tools/protocol_identification/stellar_lpi_wrapper_android_build_probe.sh
```

Current local result observed on 2026-08-12:

- result: `probe.result=PASS`
- output executable: `stellar_lpi_wrapper_android_probe`
- output root:
  `build-output/protocol-identification/stellar-lpi-wrapper-android-probe/`
- source scope:
  `stellar_lpi_core.c + stellar_lpi_extend.c` plus the same vendored
  libprotoident source shape as the base NDK probe.
- compatibility scope:
  generated `vlib/utils/utils.h` compatibility shim for `ALLOC` / `FREE`, and
  reference `vlib/uthash/uthash.h` in place from the backup VPP tree.
- policy:
  `policy.copiesSourceIntoRepo=false`,
  `policy.providerVendoringDecision=false`,
  `policy.providerRuntimeWiring=false`, and
  `policy.protocolRuleDecision=false`.
- probe shape:
  `probe.wrapper=stellar_lpi_core-plus-extend-with-generated-compat-shim`,
  `probe.generatedUtilsShim=true`, and
  `probe.referenceUthashInPlace=true`.

This proves the current NDK can compile and link the extractable wrapper
candidate without the full VPP plugin. It still does not prove detection accuracy,
provider-source acceptability, Android runtime wiring, Root/VPN device behavior,
corpus rights, or ProtocolRule enforcement readiness.

## Host Synthetic Payload Probe

Probe command:

```bash
bash tools/protocol_identification/stellar_lpi_wrapper_host_payload_probe.sh
```

Current local result observed on 2026-08-12:

- result: `probe.result=PASS`
- output executable: `stellar_lpi_wrapper_host_payload_probe`
- output root:
  `build-output/protocol-identification/stellar-lpi-wrapper-host-payload-probe/`
- source scope:
  `stellar_lpi_core.c + stellar_lpi_extend.c` plus the same vendored
  libprotoident source shape as the base probe.
- payload scope:
  synthetic application payload bytes only, not PCAP replay and not packet
  parsing.
- cases:
  - HTTP request payload -> fork-local `appid=67`, app name `HTTP`,
    provider alias `lpi:http`, `stopDetect=1`
  - DNS query payload -> fork-local `appid=32`, app name `DNS`, provider alias
    `lpi:dns`, `stopDetect=1`
  - SOCKS5 greeting payload -> fork-local `appid=8005`, app name `SOCKS`,
    provider alias `lpi:socks`, `stopDetect=0`
- policy:
  `policy.copiesSourceIntoRepo=false`,
  `policy.copiesPcapIntoRepo=false`,
  `policy.usesSyntheticPayloads=true`,
  `policy.providerVendoringDecision=false`,
  `policy.providerRuntimeWiring=false`, and
  `policy.protocolRuleDecision=false`.
- probe shape:
  `probe.scope=host-compile-link-run-synthetic-payload-recognition`,
  `probe.sakamotoPipeline=LpiRecognitionPipeline,LpiRecognitionAdapter,BoundedFlowTable`,
  `probe.payloadBoundary=application-payload-bytes-only`,
  `probe.generatedUtilsShim=true`, and
  `probe.referenceUthashInPlace=true`.
- Sakamoto seam path:
  the generated executable adapts the real wrapper behind a generated
  `LpiRecognitionProvider` and drives
  `LpiRecognitionPipeline -> LpiRecognitionAdapter -> BoundedFlowTable`.
  It verifies that `lpi:http` maps to the project-owned HTTP catalog ID,
  `lpi:dns` maps to DNS, and `lpi:socks` remains an unmapped provider result.

This proves the extractable wrapper candidate can execute its lifecycle and
return expected fork-local names for a minimal synthetic payload set on the
host, then pass those names through the current Sakamoto recognition seam. It
still does not prove PCAP corpus accuracy, Android Root/VPN runtime behavior,
provider-source acceptability, default provider wiring, corpus rights, or
ProtocolRule enforcement readiness.

## Host Reference PCAP Probe

Probe command:

```bash
bash tools/protocol_identification/stellar_lpi_wrapper_host_pcap_probe.sh
```

Current local result observed on 2026-08-12:

- result: `probe.result=PASS`
- output executable: `stellar_lpi_wrapper_host_pcap_probe`
- output root:
  `build-output/protocol-identification/stellar-lpi-wrapper-host-pcap-probe/`
- executable stderr isolation:
  the generated probe executable redirects reference wrapper warnings to
  `probe.executableStderrLog` under the build-output probe root and reports
  `probe.executableStderrLineCount` on stdout, keeping the stdout
  `key=value` evidence stable while preserving stderr diagnostics.
- selected reference fixtures, read in place:
  - `mixed_pcap/01-http-not-ftp.pcap`
  - `mixed_pcap/37-dns-response-4029-53-115.24.235.11-8.210.152.150.pcap`
  - `mixed_pcap/21-iquic-29-192.168.50.29.61891-31.13.77.35.443.pcap`
  - `mixed_pcap/39-pop3-mistake-redis.pcap`
  - `socks_pcap/1-socks45-http-example.pcap`
  - expected rows checked from `mixed_pcap/mixed_pcap.json` and
    `socks_pcap/socks_pcap.json`
- expected JSON validation:
  `selectedExpectedJsonValidation=PASS` confirms row-level matches for the
  selected HTTP/DNS/QUIC session address, UNKNOWN/no-result flow
  `192.168.40.82:41450-192.168.44.230:7002-6-0`,
  `FLOW_DIRECTION=SYMMETRIC`, `SESSION_TYPE=TCP`, `LABEL=LPI_RESULT_18`,
  `APP_ID="UNKNOWN"`, no `APP_NAME`, plus SOCKS flow
  `10.180.156.185:53535-10.180.156.249:1080-6-0`,
  `FLOW_DIRECTION=SYMMETRIC`, `SESSION_TYPE=TCP`, `LABEL=LPI_RESULT_6`,
  `APP_NAME=["SOCKS","HTTP"]`, `APP_ID=[8005,67]`, and PCAP filename.
- parser scope:
  classic PCAP, Ethernet link type `DLT_EN10MB`, IPv4, TCP/UDP payload bytes.
- observed cases:
  - HTTP PCAP -> fork-local `appid=67`, app name `HTTP`, provider alias
    `lpi:http`, Sakamoto catalog key `http`
  - DNS PCAP -> fork-local `appid=32`, app name `DNS`, provider alias
    `lpi:dns`, Sakamoto catalog key `dns`
  - QUIC PCAP -> fork-local `appid=2521`, app name `QUIC`, provider alias
    `lpi:quic`, Sakamoto catalog key `quic`
  - UNKNOWN PCAP -> four payload-bearing target TCP packets submitted to the
    wrapper/provider seam; the wrapper emits no positive app id/name and no
    provider alias, the pipeline records `payloadEligible=true`,
    `submittedToProvider=true`, `providerProducedFact=false`, `mapped=false`,
    `unmapped=false`, `latestProtocol=none`, and increments
    `providerNoResultPackets`.
  - SOCKS PCAP -> ordered wrapper emissions `appid=8005` / `SOCKS` /
    `lpi:socks` before `appid=67` / `HTTP` / `lpi:http`; the Sakamoto seam
    first records `lpi:socks` as an unmapped provider result, then maps the
    later `lpi:http` fact to catalog key `http` as the latest exact result.
- policy:
  `policy.copiesSourceIntoRepo=false`,
  `policy.copiesPcapIntoRepo=false`,
  `policy.copiesExpectedJsonIntoRepo=false`,
  `policy.usesReferencePcapInPlace=true`,
  `policy.providerVendoringDecision=false`,
  `policy.providerRuntimeWiring=false`, and
  `policy.protocolRuleDecision=false`.
- probe shape:
  `probe.scope=host-compile-link-run-selected-reference-pcap-recognition`,
  `probe.packetParser=classic-pcap-ethernet-ipv4-tcp-udp`,
  `probe.corpusAccuracyClaim=false`, and
  `probe.sakamotoPipeline=LpiRecognitionPipeline,LpiRecognitionAdapter,BoundedFlowTable`.

This proves selected mapped, no-result, and unmapped/compound real-PCAP smoke
can pass through the extractable wrapper candidate and the current recognition
seam: HTTP/DNS/QUIC map to current Sakamoto catalog entries; the selected
UNKNOWN flow reaches the provider no-result path without inventing
`lpi:unknown`; and the selected SOCKS flow reaches the current unmapped
provider-alias path before a later HTTP mapping. It still does not prove full
corpus replay accuracy, non-Ethernet link parsing, TCP stream reassembly,
Android Root/VPN runtime behavior, provider-source acceptability, corpus
redistribution rights, default provider wiring, or ProtocolRule enforcement
readiness.

## Decision / Use as Input

Evidence implication: the wrapper and selected-PCAP probes are source, corpus,
and runtime decision inputs, not an implementation queue. A real provider
implementation depends on a pinned provider source/license strategy and the
smallest licensed corpus subset. ProtocolRule remains outside this evidence
boundary until packet bytes replay through a real provider behind
`LpiRecognitionProvider`, with provider/corpus/runtime evidence available before
any ProtocolRule readiness claim.
