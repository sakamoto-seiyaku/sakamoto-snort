# Protocol identification reference tools

These tools inspect an **external** reference tree or a proposed source package.
They are not part of Product build/launch and do not enable a runtime provider,
approve source import or establish protocol-policy enforcement.

External `stellar_*` filenames and `VPP_STELLAR_LPI_ROOT` remain exact technical
identifiers, not Sakamoto domain terms. Set `VPP_REFERENCE_ROOT` explicitly for
portable reference use; see [naming/provenance rules](../../docs/reference/NAMING_AND_PROVENANCE.md).

## Retained, explicitly requested reference operations

| Files | Boundary |
| --- | --- |
| `vpp_lpi_source_shape_inventory.sh`, `vpp_stellar_lpi_wrapper_inventory.sh` | Read external source shape, API and provenance; no source import |
| `vpp_lpi_corpus_inventory.sh`, `vpp_lpi_expected_alias_inventory.py` | Read external corpus metadata/expected aliases; no sample import or accuracy/release claim |
| `libprotoident_android_build_probe.sh`, `stellar_lpi_wrapper_android_build_probe.sh` | Standalone external-library compile/link probes; require explicit source/NDK prerequisites and write only generated output |
| `lpi_provider_source_intake_gate.sh` | Inspect supplied source-package evidence; not a legal/vendor approval |
| `probe_build_root.sh`, `probe_generation.sh` | Shared bounded output/provenance helpers, not standalone Product runners |

No probe was rerun as part of repository organization. Historical PASS observations
remain in [reference documents](../../docs/reference/README.md) with their original dates.

## Retired C++-dependent entrypoints

`stellar_lpi_wrapper_host_payload_probe.sh` and
`stellar_lpi_wrapper_host_pcap_probe.sh` compiled the removed C++ recognition model.
The old `run_s61_reference_probes.sh` aggregate and
`tests/android/s61-vpp-reference-inventory-contract-test.sh` depended on that same
removed seam. All four names now fail immediately with `RETIRED` and exit code 2,
before builds, writes, external source reads or device operations.

The generated C++ test bodies are removed, not copied into another source archive.
Their preceding Git revision and dated probe records retain historical provenance;
do not restore the removed model to replay them. Read-only inventories above remain
separate, and current Product acceptance stays in [the testing map](../../docs/testing/README.md).
