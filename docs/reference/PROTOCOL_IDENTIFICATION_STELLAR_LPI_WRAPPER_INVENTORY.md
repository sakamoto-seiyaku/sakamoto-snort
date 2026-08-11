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
- no Android wrapper build probe has compiled the wrapper yet;
  `stellar_lpi_core.c` and `stellar_lpi_extend.c` still need a separate probe.

## Next Evidence Step

Before a real provider implementation, add a separate wrapper build probe that
compiles `stellar_lpi_core.c` and `stellar_lpi_extend.c` against the existing
base-libprotoident Android probe source set using compatibility shims for
`ALLOC`, `FREE`, and `uthash` as needed. That probe should still read the
backup source in place and must not copy provider source into this repository.
