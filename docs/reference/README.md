# Reference docs

These are focused comparisons and dated evidence, not default Product context.
Use [current mainline](../current/README.md) for implementation and readiness.

[Reference naming rules](NAMING_AND_PROVENANCE.md): mainline prose uses Sakamoto
terms; external filenames/API/CLI/output identities stay exact for provenance.
Machine-specific roots may be abstracted, not the technical identifiers below them.

## Pinned current semantic reference

- [OVS Conntrack Semantic Baseline](OVS_CONNTRACK_BASELINE.md): S221's pinned
  TCP/UDP/ICMP userspace baseline, commit/file hashes, timeout mapping and license
  attribution. This is not one of the historical provider probes below.

## Historical engineering evidence

- [Android VPP POC retrospective](ANDROID_VPP_POC_TECHNICAL_RETROSPECTIVE.md).
- [Fork AppID number origin](FORK_VPP_APPID_NUMBER_ORIGIN.md).
- [VPP reference inventory](PROTOCOL_IDENTIFICATION_VPP_REFERENCE_INVENTORY.md).
- [LPI control and runner record](PROTOCOL_IDENTIFICATION_VPP_LPI_CONTROL_AND_RUNNER_CONTRACT.md).
- [LPI corpus manifest](PROTOCOL_IDENTIFICATION_VPP_LPI_CORPUS_MANIFEST.md).
- [libprotoident audit](PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_REFERENCE_AUDIT.md).
- [libprotoident NDK probe](PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_NDK_PROBE.md).
- [Reference wrapper inventory](PROTOCOL_IDENTIFICATION_REFERENCE_LPI_WRAPPER_INVENTORY.md).
- [Provider source decision inputs](PROTOCOL_IDENTIFICATION_PROVIDER_SOURCE_DECISION_INPUT.md).
- [Provider source package requirements](PROTOCOL_IDENTIFICATION_PROVIDER_SOURCE_PACKAGE_CHECKLIST.md).

S61/S63 observations retain their original scope. They do not approve source
import, provider runtime enablement, ProtocolRule enforcement or release readiness.
The Host payload/PCAP probes describe the removed C++ recognition seam; do not
restore it to replay them. Tool names in the dated records identify historical
commands, not current runnable Product gates. Check source prerequisites before
any explicitly requested reference-only inventory or standalone third-party probe.
The [reference tool map](../../tools/protocol_identification/README.md) separates
retained inventories from the now fail-closed C++-dependent entrypoints.
