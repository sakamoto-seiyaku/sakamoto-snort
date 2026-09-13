# Protocol Identification VPP LPI Control and Runner Contract

> 参考命名说明（2026-09-13）：本机参考仓库绝对路径已抽象；外部插件、API、CLI、环境变量和证据标识保留原名，仅用于溯源，不是 Sakamoto 领域术语。下文是标注日期的历史观察；命令能否重跑须核对现行入口，旧结果不证明当前 Product 实现。

Date: 2026-08-12

Status: `reference_only` contract for SAKAMOTO-61. This document records the
control-plane, feature-arc, event, and runner shape observed in the modified
VPP reference tree. It is not a provider-source decision, an implementation
plan, or an Android L4 Product Release approval.

## Evidence boundary

The facts below are read from the following files in the local reference tree:

- `<reference-root>/src/plugins/stellar_lpi/stellar_lpi.api`
- `<reference-root>/src/plugins/stellar_lpi/stellar_lpi_test.c`
- `<reference-root>/src/plugins/stellar_lpi/stellar_lpi_plugin.c`
- `<reference-root>/test/test_stellar_lpi.py`

The runner also reads its adjacent reference corpus at
`test/decoders/stellar_lpi/test_pcap` when that checkout is exercised. No
source, PCAP, expected JSON, or generated event fixture is copied into this
repository by this contract.

The contract markers are:

```text
reference_only=true
sourceImported=not_claimed
corpusImported=not_claimed
realProviderEnabled=not_claimed
protocolRule=out_of_scope
```

These markers describe evidence posture only. They do not claim that a real
provider is wired, that the corpus is redistributable, or that ProtocolRule
work has started.

## Reference path and default overrides

`<reference-root>` below abstracts the machine-specific checkout path recorded
at the time. For an explicitly requested inventory, supply the real checkout
through `VPP_REFERENCE_ROOT`; the exact wrapper and corpus suffixes remain:

```text
referenceRoot=${VPP_REFERENCE_ROOT:?set the external reference checkout path}
wrapperRoot=${VPP_STELLAR_LPI_ROOT:-${referenceRoot}/src/plugins/stellar_lpi}
corpusRoot=${VPP_LPI_CORPUS_ROOT:-${referenceRoot}/test/decoders/stellar_lpi/test_pcap}
```

`VPP_REFERENCE_ROOT` is the default-root override used by
`vpp_stellar_lpi_wrapper_inventory.sh`, `vpp_lpi_corpus_inventory.sh`, the
source-shape inventory, and the S61 reference-probe runner. The wrapper and
host probes additionally accept `VPP_STELLAR_LPI_ROOT` and
`LIBPROTOIDENT_SOURCE_ROOT`; corpus readers additionally accept
`VPP_LPI_CORPUS_ROOT`.

The source-shape inventory also exposes an explicit `--vpp-root PATH` override
and writes only to an explicit `--output-root PATH` (or its build-output
default). Missing reference paths are reported as unavailable reference-only
evidence by default; strict inventory mode may make an unavailable root fail.

The VPP Python runner is different: `<reference-root>/test/test_stellar_lpi.py`
derives its corpus from the directory containing that file, so its
`test_base_dir` is the runner checkout's
`test/decoders/stellar_lpi/test_pcap`. The repo-local inventories/probes must
be used when a caller needs a portable root override; neither mode imports the
reference tree into Sakamoto.

## Binary API: `stellar_lpi.api`

The reference API file declares version `0.1.0`, imports
`vnet/interface_types.api`, and contains the declaration
`autoreply define stellar_lpi_enable_disable`.

Its control fields are:

| Field | Reference type | Meaning in the file |
| --- | --- | --- |
| `client_index` | `u32` | API client identifier |
| `context` | `u32` | caller context matched by the reply |
| `enable_disable` | `bool` | `1` enables the feature and `0` disables it |
| `sw_if_index` | `vl_api_interface_index_t` | target interface handle |

The message is interface-scoped. It is not a protocol-rule API and does not
carry a provider source, catalog ID, payload, or corpus selector.

## VAT test client: `stellar_lpi_test.c` and disable behavior

The reference VAT client includes the VAT helper macros and generated API enum,
types, and test sources. Its `api_stellar_lpi_enable_disable(vat_main_t *vam)`
function has the following observed behavior:

- `enable_disable` starts at `1`; the command therefore defaults to enable.
- The parser accepts an interface name through `unformat_sw_if_index` or an
  explicit `sw_if_index <number>` form.
- The token `disable` changes the outgoing field to `0`.
- A missing interface reports `missing interface name / explicit sw_if_index
  number` and returns `-99`.
- The request is built with `M(STELLAR_LPI_ENABLE_DISABLE, mp)`, writes the
  interface index and boolean field, sends with `S(mp)`, and waits with `W(ret)`.

Thus VAT disable is an explicit control-plane path, not an inferred teardown
side effect. The generated `stellar_lpi.api_test.c` is included by the actual
file; this contract does not copy or regenerate that generated source.

## Plugin control and dataplane shape: `stellar_lpi_plugin.c`

### Interface enable/disable

`stellar_lpi_enable_disable(u32 sw_if_index, u8 enable_disable)` first rejects
an invalid interface index. It checks the TCP-session feature state and then
enables or disables the same `stellar-lpi` node on both session feature arcs:

- enable: `stellar-tcp-session` and `stellar-udp-session`, both with `1`;
- disable: `stellar-tcp-session` and `stellar-udp-session`, both with `0`.

Already-enabled and already-disabled states return the corresponding VPP
feature errors. The CLI command is:

```text
set stellar-lpi interface <interface> [enable|disable]
```

The API handler converts `sw_if_index` from network order before calling the
same action function. The interface action therefore remains the shared seam
for CLI and binary API callers.

### Debug and max-detect-pkts controls

The plugin main state contains `debug_enabled` and a bounded
`max_detect_pkts`. The reference constant is `MAX_DETECT_PKTS 20`, and init
sets the runtime value to `20`.

The debug CLI is:

```text
stellar-lpi debug [on|off]
```

`on` enables session event emission, `off` disables it, and an empty query
reports the current state. The debug flag controls the `LPI TRACE SESSION`
event emitted while session extra data is freed; it does not enable a Sakamoto
provider or ProtocolRule.

The packet-budget controls are:

```text
set stellar-lpi max-detect-pkts <max>
show stellar-lpi max-detect-pkts
```

The setter clamps values above `20` to `20` and rejects input that cannot be
parsed as an unsigned integer. The dataplane submits only non-empty
payload-bearing, non-pseudo packets while `stop_detect != 1` and the detected
packet count is below the configured maximum. The observed provider call order
per submitted packet is context update followed by detect; the provider can
set `stop_detect` to stop further bounded scanning.

### TCP and UDP feature arcs

The plugin registers the same `stellar-lpi` node on two distinct VPP feature
arcs:

| Feature registration | Arc | Node | Ordering |
| --- | --- | --- | --- |
| `stellar_lpi_tcp_session` | `stellar-tcp-session` | `stellar-lpi` | before `stellar-tcp-session-feat-arc-end` |
| `stellar_lpi_udp_session` | `stellar-udp-session` | `stellar-lpi` | before `stellar-udp-session-feat-arc-end` |

Initialization also registers the interface enable/disable callback with the
traffic-inspection feature set. This is reference VPP graph wiring; it is not a
request to create a second Sakamoto flow table.

## Event JSON and `test_stellar_lpi.py` runner

### Event JSON produced by the plugin

`stellar_lpi_trace_json_export` constructs the event object with:

- `SESSION_ADDRESS`;
- `SESSION_TYPE` (`TCP` or `UDP`);
- `APP_ID` and, when a result exists, `APP_NAME` arrays;
- `APP_ID: "UNKNOWN"` when no app ID was detected; and
- `FLOW_DIRECTION` (`SYMMETRIC`, `C2S`, or `S2C`).

The exported event JSON does **not** contain `LABEL`. The event logger wraps the
JSON with the `LPI TRACE SESSION: ` prefix. The debug-enabled session cleanup
path emits that event; it is not an expected-result schema declaration.

### Runner prerequisites

The reference `TestStellarLpi` class is skipped when `stellar_lpi` is in the
excluded plugin list. A runnable VPP test environment requires:

- `stellar_lpi_plugin.so` and `session_manager_plugin.so` enabled in
  `extra_vpp_plugin_config`;
- a `60,000` ms session timeout, one VPP worker, and the ordered nodes
  `stellar-flow-dissector` then `stellar-lpi`;
- two packet-generator interfaces (`pg0` and `pg1`) configured for IPv4,
  resolved with ARP, and administratively up;
- a polling virtual wire, enabled session manager, and enabled IP reassembly
  for each test; and
- cleanup that disables the session manager, deletes the virtual wire, resets
  packet information, and tears down the packet-generator interfaces.

The batch test discovers subdirectories below its `test_base_dir`. Each group
must contain at least one `*.pcap` and a same-named `<group>.json` expected file.
It enables both `stellar-flow-dissector` and `stellar-lpi`, turns on
`stellar-lpi debug`, replays each PCAP's packet stream, forces session cleanup,
and reads `show event-logger all`. The event extraction pattern selects
`LPI TRACE SESSION` JSON objects in emitted order.

### Runner-generated labels

The reference expected JSON files include `LABEL`, but the plugin event object
does not. After extraction, `_test_lpi_directory` enumerates `actual_results`
starting at one and mutates each actual result:

```text
result["LABEL"] = "LPI_RESULT_<i>"
```

Only then does it compare the ordered actual results with the expected JSON.
Therefore `LPI_RESULT_i` is runner-generated ordering metadata, not a field
produced by the plugin event JSON and not a Sakamoto product schema.

## Reference-only decision boundary

This slice deliberately remains evidence-only:

- `reference_only=true` and `realProviderEnabled=not_claimed` remain explicit;
- no source or corpus import is performed (`sourceImported=not_claimed`,
  `corpusImported=not_claimed`);
- no source files, PCAPs, expected JSON, or generated fixtures are copied,
  linked, or committed;
- fork-local VPP numeric `APP_ID` values are not Sakamoto catalog IDs; and
- `protocolRule=out_of_scope`; interface controls, debug events, and the batch
  runner do not authorize ProtocolRule enforcement.

The contract can guide a later provider-neutral adapter or a separately
approved fixture subset, but it does not select provider source, establish
license/privacy rights, enable runtime recognition, or claim full corpus
accuracy.
