# Protocol Identification Provider Source Package Evidence Requirements

Date: 2026-08-12

Status: S61 pre-decision source-package evidence and decision requirements
catalog. This document is not legal advice, does not choose a provider source
strategy, does not approve vendoring or distribution, does not enable a real
provider, and does not start ProtocolRule enforcement.

This document is not a tracker/checklist or open-work ledger. Plane remains the
source of truth for open work. The bullets below preserve evidence requirements
for future source, license, privacy, build, runtime, and release decisions. Real
provider work must wait until the required decisions and evidence are completed
and recorded in decision records.

Reference inputs only:

- `docs/reference/PROTOCOL_IDENTIFICATION_PROVIDER_SOURCE_DECISION_INPUT.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_VPP_REFERENCE_INVENTORY.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_REFERENCE_AUDIT.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_STELLAR_LPI_WRAPPER_INVENTORY.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_NDK_PROBE.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_VPP_LPI_CORPUS_MANIFEST.md`
- backup VPP reference path: `/home/js/backup/backup/Git/vpp` reference only;
  do not copy, link, vendor, or import backup source, vendored
  `libprotoident`, PCAP files, or expected JSON from that tree by using this
  checklist.

Contract guardrails:

- this document is an evidence catalog, not a completed source decision;
- no work-item completion is implied by this document;
- Plane remains the source of truth for open work;
- `DisabledLpiRecognitionProvider` remains the default runtime provider;
- `SAKAMOTO_ENABLE_LPI_PROVIDER` stays explicit and off by default until a
  source decision says otherwise;
- fork-local numeric AppIDs remain provider-local evidence and must not cross
  the Sakamoto provider seam;
- provider aliases remain the boundary currency, for example `lpi:http`;
- Root and VPN must share the same provider-neutral recognition seam;
- ProtocolRule work must wait for a real pinned provider, licensing/provenance
  approval, minimized/approved corpus evidence, and explicit enforcement
  evidence requirements.

## Source Identity, Pin, Checksum, and File Manifest

- Authoritative source option selected in a decision record: backup VPP
      wrapper plus vendored `libprotoident`, reference-only lineage with a new
      provider source, or an external/curated provider package.
- Source repository URL, archive URL, or source package origin recorded.
- Exact revision, tag, commit, release version, or immutable archive pin
      recorded.
- Source archive checksum recorded with algorithm and command used.
- Local file manifest recorded for every source file intended to enter the
      build.
- Manifest explicitly excludes VPP plugin/runtime-only files that are not
      part of the chosen provider package.
- Manifest explicitly excludes PCAP files and expected JSON unless a
      separate corpus/fixture decision approves their import.
- Reproducible fetch/unpack procedure documented without depending on a
      mutable local backup path.

## License, NOTICE, and Provenance

- License files required for the chosen source are present in the planned
      source package.
- NOTICE, attribution, copyright, and provenance files required for the
      chosen source are present or explicitly documented as not provided by the
      upstream package.
- Placeholder wrapper headers, including any placeholder Apache-2.0 text,
      are resolved by replacement, upstream clarification, or legal review.
- `libprotoident` LGPL-3.0-or-later facts are reviewed for the Android
      distribution model.
- Any fork-local changes, including `stellar_lpi_core` and
      `stellar_lpi_extend`, have recorded authorship/provenance and license
      posture.
- Release notes identify third-party components and source-package
      obligations without implying legal approval from this catalog.

## LGPL Source and Relink Posture Placeholders

- Static, dynamic, or separately packaged provider linking choice recorded.
- Source-offer, source-bundle, or relinkable-object posture recorded for the
      chosen packaging model.
- Android APK/AAB release artifact obligations recorded.
- Build scripts identify where provider source, generated objects,
      libraries, license files, NOTICE files, and relink materials are produced.
- Verification step confirms release artifacts can be matched back to the
      pinned source manifest.
- Legal owner signs off separately; this catalog remains non-legal
      engineering evidence.

## Wrapper Provenance Including `stellar_lpi_core` / `stellar_lpi_extend`

- Decision records whether `stellar_lpi_core` is reused, trimmed, rewritten,
      or replaced.
- Decision records whether `stellar_lpi_extend` is included as-is, trimmed,
      rewritten, or replaced by Sakamoto-owned normalization.
- VPP allocation/hash/session dependencies are removed, wrapped, or
      justified before source import.
- Wrapper C boundary is documented against Sakamoto's
      `LpiRecognitionProvider` seam.
- Provider-native numeric IDs are mapped only to provider aliases and never
      persisted as Sakamoto catalog IDs.
- Wrapper behavior is covered by synthetic host evidence before Android
      runtime evidence is claimed.

## Corpus, Fixture Privacy, and Import Policy

- Fixture policy decides whether reference PCAP files, expected JSON,
      reduced captures, synthetic payloads, or anonymized samples may be used.
- Privacy review covers public/private IPs, service names, application
      names, and any user/network-identifying metadata.
- Corpus license/provenance files are present or absence is explicitly
      recorded before any fixture import.
- No PCAP or expected JSON is copied from the backup VPP tree until corpus
      import is explicitly approved.
- Minimum acceptance baseline is recorded for DNS, HTTP, TLS/SSL, QUIC,
      SSH, unmapped, no-result, and compound behavior.
- Selected reference PCAP smoke remains reference evidence only and is not
      described as full corpus accuracy.

## Android ABI, API, and NDK Build Matrix

- Supported Android ABIs recorded, including whether `arm64-v8a` is the
      minimum or whether additional ABIs are required.
- Minimum Android API level recorded for the provider build.
- NDK version and C/C++ toolchain identity recorded.
- Host build matrix recorded separately from Android/NDK build matrix.
- C++ standard, PIC, STL, exception, RTTI, sanitizer, and hardening settings
      recorded.
- Root/NFQUEUE and VPN/TUN profiles identify whether they share identical
      provider binaries and ABI settings.
- Build output path policy confirms probes write only under
      `build-output`.

## Static/Dynamic Packaging Choice Placeholder

- Static package shape recorded, if selected.
- Dynamic shared-library package shape recorded, if selected.
- Separately packaged component shape recorded, if selected.
- APK/AAB native library placement and split behavior recorded.
- Release process records how checksums, source manifests, license files,
      NOTICE files, and relink materials are attached to artifacts.
- Packaging choice is locked by tests before provider runtime enablement.

## Warning Policy

- Host compiler warning policy recorded for third-party provider source.
- Android/NDK compiler warning policy recorded for third-party provider
      source.
- Allowed warnings are categorized and justified instead of hidden by broad
      suppression.
- New warnings in Sakamoto-owned wrapper/adaptation code fail the build.
- Warning logs are attached to source-package evidence for review.

## Runtime Enablement Gate

- Build flag name and default-off behavior recorded.
- Configure/build fails when real-provider enablement is requested without
      the selected source package evidence.
- Host tests prove disabled/unavailable/no-result/mapped/unmapped behavior
      through the provider-neutral seam.
- Runtime status exposes provider name, availability, and counters for Root
      and VPN profiles.
- Real provider is not enabled by default in host, Android, Root, or VPN
      runtime.
- Rollback path to `DisabledLpiRecognitionProvider` is documented.

## Root/VPN Evidence Requirements

- Root/NFQUEUE device evidence records device model, Android version, API
      level, root state, SELinux state, ABI, build fingerprint, and exact APK or
      native artifact.
- VPN/TUN device evidence records device model, Android version, API level,
      root state, SELinux state, ABI, build fingerprint, and exact APK or
      native artifact.
- Evidence proves both Root and VPN paths submit eligible payload-bearing
      packets through the same `LpiRecognitionProvider` seam.
- Evidence proves provider available, provider unavailable, no-result,
      mapped, unmapped, detector-done, and budget-exhausted counters where
      applicable.
- Evidence proves no parallel flow/session table was introduced.
- Evidence distinguishes already-rooted test devices from never-rooted device claims.

## Release Artifact Evidence

- Release candidate artifact checksum recorded.
- Native library/binary manifest recorded for APK/AAB artifacts.
- License and NOTICE payload location recorded.
- Source package, source offer, or relink materials location recorded.
- Build logs and warning logs archived for host and Android provider builds.
- Runtime evidence artifact versions match the release candidate checksum.
- Release notes state that provider recognition does not by itself start
      ProtocolRule enforcement.

## Decision Record Requirements

- Provider source decision record exists and names the authoritative source
      strategy.
- License/provenance decision record exists and names the owner approving
      distribution posture.
- Corpus/fixture decision record exists and names the owner approving
      privacy/import posture.
- Android ABI/API/NDK build matrix decision record exists.
- Static/dynamic/separate packaging decision record exists.
- Runtime enablement decision record exists for Root and VPN.
- ProtocolRule remains out of scope until a later explicit decision record
      names the enforcement evidence required to begin it.
