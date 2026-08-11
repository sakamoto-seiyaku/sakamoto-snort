#!/usr/bin/env bash
set -euo pipefail

# Non-default S61 reference-probe aggregator.
#
# This runner is intentionally explicit-only: it is not part of the default
# build/test gate. It orchestrates the existing reference-only inventories and
# throwaway probes, writes per-probe stdout/stderr under the requested output
# root, and emits one top-level machine-readable properties file. It never
# copies backup VPP source, PCAP, expected JSON, or license files into this repo.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/protocol_identification/probe_build_root.sh"

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
repo_build_output_root="${repo_root}/build-output"
output_root_input="${S61_REFERENCE_PROBES_OUTPUT_ROOT:-${repo_build_output_root}/protocol-identification/s61-reference-probes}"
output_root="$output_root_input"
continue_on_fail=0

properties_file=""

show_help() {
  cat <<EOF
Usage: $0 [--vpp-root PATH] [--output-root PATH] [--continue-on-fail]

Runs the non-default S61 reference probe suite against a backup VPP tree:
  $reference_root

Writes per-probe evidence and a top-level summary:
  $output_root/s61-reference-probes.properties

Options:
  --vpp-root PATH       backup VPP checkout root
  --output-root PATH    output directory for probe logs and generated probes
  --continue-on-fail    run all available probes and report aggregate FAIL
  -h, --help            show this help

Environment overrides:
  VPP_REFERENCE_ROOT
  S61_REFERENCE_PROBES_OUTPUT_ROOT

Safety boundaries:
  sourceImported=not_claimed
  corpusImported=not_claimed
  realProviderEnabled=not_claimed
  protocolRule=out_of_scope

This runner is explicit-only and is not wired into the default build/test gate.
EOF
}

require_arg() {
  local option="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || {
    echo "missing value for $option" >&2
    exit 1
  }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vpp-root)
      require_arg "$1" "${2:-}"
      reference_root="$2"
      shift 2
      ;;
    --output-root)
      require_arg "$1" "${2:-}"
      output_root_input="$2"
      shift 2
      ;;
    --continue-on-fail)
      continue_on_fail=1
      shift
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

output_root="$(protocol_identification_probe_canonical_build_root "$repo_root" "$output_root_input")"

mkdir -p "$output_root"
properties_file="${output_root}/s61-reference-probes.properties"

declare -a probe_keys=(
  vppLpiSourceShapeInventory
  vppLpiCorpusInventory
  vppLpiExpectedAliasInventory
  vppStellarLpiWrapperInventory
  libprotoidentAndroidBuildProbe
  stellarLpiWrapperAndroidBuildProbe
  stellarLpiWrapperHostPayloadProbe
  stellarLpiWrapperHostPcapProbe
)

declare -A probe_script=(
  [vppLpiSourceShapeInventory]="tools/protocol_identification/vpp_lpi_source_shape_inventory.sh"
  [vppLpiCorpusInventory]="tools/protocol_identification/vpp_lpi_corpus_inventory.sh"
  [vppLpiExpectedAliasInventory]="tools/protocol_identification/vpp_lpi_expected_alias_inventory.py"
  [vppStellarLpiWrapperInventory]="tools/protocol_identification/vpp_stellar_lpi_wrapper_inventory.sh"
  [libprotoidentAndroidBuildProbe]="tools/protocol_identification/libprotoident_android_build_probe.sh"
  [stellarLpiWrapperAndroidBuildProbe]="tools/protocol_identification/stellar_lpi_wrapper_android_build_probe.sh"
  [stellarLpiWrapperHostPayloadProbe]="tools/protocol_identification/stellar_lpi_wrapper_host_payload_probe.sh"
  [stellarLpiWrapperHostPcapProbe]="tools/protocol_identification/stellar_lpi_wrapper_host_pcap_probe.sh"
)

declare -A probe_dir_name=(
  [vppLpiSourceShapeInventory]="vpp-lpi-source-shape-inventory"
  [vppLpiCorpusInventory]="vpp-lpi-corpus-inventory"
  [vppLpiExpectedAliasInventory]="vpp-lpi-expected-alias-inventory"
  [vppStellarLpiWrapperInventory]="vpp-stellar-lpi-wrapper-inventory"
  [libprotoidentAndroidBuildProbe]="libprotoident-android-build-probe"
  [stellarLpiWrapperAndroidBuildProbe]="stellar-lpi-wrapper-android-build-probe"
  [stellarLpiWrapperHostPayloadProbe]="stellar-lpi-wrapper-host-payload-probe"
  [stellarLpiWrapperHostPcapProbe]="stellar-lpi-wrapper-host-pcap-probe"
)

declare -A probe_status=()
declare -A probe_reason=()
declare -A probe_exit_code=()
declare -A probe_output_path=()
declare -A probe_stdout_path=()
declare -A probe_stderr_path=()

for probe_key in "${probe_keys[@]}"; do
  probe_status["$probe_key"]="NOT_RUN"
  probe_reason["$probe_key"]="not_run"
  probe_exit_code["$probe_key"]="-"
  probe_output_path["$probe_key"]="${output_root}/${probe_dir_name[$probe_key]}"
  probe_stdout_path["$probe_key"]="${probe_output_path[$probe_key]}/${probe_dir_name[$probe_key]}.stdout.properties"
  probe_stderr_path["$probe_key"]="${probe_output_path[$probe_key]}/${probe_dir_name[$probe_key]}.stderr.log"
done

wrapper_root="${reference_root}/src/plugins/stellar_lpi"
libprotoident_root="${wrapper_root}/libprotoident"
corpus_root="${reference_root}/test/decoders/stellar_lpi/test_pcap"

bool_dir() {
  local path="$1"
  [[ -d "$path" ]] && printf 'true' || printf 'false'
}

write_properties() {
  local aggregate="PASS"
  local probe_key=""

  for probe_key in "${probe_keys[@]}"; do
    if [[ "${probe_status[$probe_key]}" != "PASS" ]]; then
      aggregate="FAIL"
      break
    fi
  done

  {
    printf 'suite=s61-reference-probes\n'
    printf 'suiteEvidence=reference_only\n'
    printf 'defaultBuildTestGate=false\n'
    printf 'continueOnFail=%s\n' "$([[ "$continue_on_fail" -eq 1 ]] && printf 'true' || printf 'false')"
    printf 'sourceImported=not_claimed\n'
    printf 'corpusImported=not_claimed\n'
    printf 'realProviderEnabled=not_claimed\n'
    printf 'protocolRule=out_of_scope\n'
    printf 'policy.copiesSourceIntoRepo=false\n'
    printf 'policy.copiesPcapIntoRepo=false\n'
    printf 'policy.copiesExpectedJsonIntoRepo=false\n'
    printf 'policy.copiesLicenseFilesIntoRepo=false\n'
    printf 'referenceRoot=%s\n' "$reference_root"
    printf 'referenceRoot.available=%s\n' "$(bool_dir "$reference_root")"
    printf 'wrapperRoot=%s\n' "$wrapper_root"
    printf 'wrapperRoot.available=%s\n' "$(bool_dir "$wrapper_root")"
    printf 'libprotoidentRoot=%s\n' "$libprotoident_root"
    printf 'libprotoidentRoot.available=%s\n' "$(bool_dir "$libprotoident_root")"
    printf 'corpusRoot=%s\n' "$corpus_root"
    printf 'corpusRoot.available=%s\n' "$(bool_dir "$corpus_root")"
    printf 'outputRoot=%s\n' "$output_root"
    for probe_key in "${probe_keys[@]}"; do
      printf 'probe.%s.script=%s\n' "$probe_key" "${probe_script[$probe_key]}"
      printf 'probe.%s.status=%s\n' "$probe_key" "${probe_status[$probe_key]}"
      printf 'probe.%s.reason=%s\n' "$probe_key" "${probe_reason[$probe_key]}"
      printf 'probe.%s.exitCode=%s\n' "$probe_key" "${probe_exit_code[$probe_key]}"
      printf 'probe.%s.outputPath=%s\n' "$probe_key" "${probe_output_path[$probe_key]}"
      printf 'probe.%s.stdoutPath=%s\n' "$probe_key" "${probe_stdout_path[$probe_key]}"
      printf 'probe.%s.stderrPath=%s\n' "$probe_key" "${probe_stderr_path[$probe_key]}"
    done
    printf 's61ReferenceProbes=%s\n' "$aggregate"
    printf 'propertiesFile=%s\n' "$properties_file"
  } >"$properties_file"
}

mark_unavailable() {
  local probe_key="$1"
  local reason="$2"
  mkdir -p "${probe_output_path[$probe_key]}"
  probe_status["$probe_key"]="UNAVAILABLE"
  probe_reason["$probe_key"]="$reason"
  probe_exit_code["$probe_key"]="-"
  {
    printf 'probe=%s\n' "$probe_key"
    printf 'probe.status=UNAVAILABLE\n'
    printf 'probe.reason=%s\n' "$reason"
    printf 'sourceImported=not_claimed\n'
    printf 'corpusImported=not_claimed\n'
    printf 'realProviderEnabled=not_claimed\n'
    printf 'protocolRule=out_of_scope\n'
  } >"${probe_stdout_path[$probe_key]}"
  : >"${probe_stderr_path[$probe_key]}"
  write_properties
}

required_reference_reason() {
  local probe_key="$1"

  case "$probe_key" in
    vppLpiSourceShapeInventory)
      return 0
      ;;
    vppLpiCorpusInventory|vppLpiExpectedAliasInventory|stellarLpiWrapperHostPcapProbe)
      [[ -d "$reference_root" ]] || {
        printf 'reference_root_unavailable'
        return 1
      }
      [[ -d "$corpus_root" ]] || {
        printf 'corpus_root_unavailable'
        return 1
      }
      ;;
    vppStellarLpiWrapperInventory|stellarLpiWrapperAndroidBuildProbe|stellarLpiWrapperHostPayloadProbe)
      [[ -d "$reference_root" ]] || {
        printf 'reference_root_unavailable'
        return 1
      }
      [[ -d "$wrapper_root" ]] || {
        printf 'wrapper_root_unavailable'
        return 1
      }
      [[ -d "$libprotoident_root" ]] || {
        printf 'libprotoident_root_unavailable'
        return 1
      }
      ;;
    libprotoidentAndroidBuildProbe)
      [[ -d "$reference_root" ]] || {
        printf 'reference_root_unavailable'
        return 1
      }
      [[ -d "$libprotoident_root" ]] || {
        printf 'libprotoident_root_unavailable'
        return 1
      }
      ;;
  esac

  case "$probe_key" in
    stellarLpiWrapperAndroidBuildProbe|stellarLpiWrapperHostPayloadProbe|stellarLpiWrapperHostPcapProbe)
      [[ -f "$wrapper_root/stellar_lpi_core.c" ]] || {
        printf 'stellar_lpi_core_unavailable'
        return 1
      }
      [[ -f "$wrapper_root/stellar_lpi_extend.c" ]] || {
        printf 'stellar_lpi_extend_unavailable'
        return 1
      }
      [[ -f "$reference_root/src/vlib/uthash/uthash.h" ]] || {
        printf 'vpp_uthash_unavailable'
        return 1
      }
      ;;
  esac

  if [[ "$probe_key" == "stellarLpiWrapperHostPcapProbe" ]]; then
    local selected_fixture=""
    for selected_fixture in \
      "$corpus_root/mixed_pcap/01-http-not-ftp.pcap" \
      "$corpus_root/mixed_pcap/37-dns-response-4029-53-115.24.235.11-8.210.152.150.pcap" \
      "$corpus_root/mixed_pcap/21-iquic-29-192.168.50.29.61891-31.13.77.35.443.pcap" \
      "$corpus_root/mixed_pcap/39-pop3-mistake-redis.pcap" \
      "$corpus_root/socks_pcap/1-socks45-http-example.pcap" \
      "$corpus_root/mixed_pcap/mixed_pcap.json" \
      "$corpus_root/socks_pcap/socks_pcap.json"; do
      [[ -f "$selected_fixture" ]] || {
        printf 'selected_reference_fixture_unavailable'
        return 1
      }
    done
  fi

  return 0
}

run_probe_command() {
  local probe_key="$1"
  local probe_root="${probe_output_path[$probe_key]}"
  local stdout_path="${probe_stdout_path[$probe_key]}"
  local stderr_path="${probe_stderr_path[$probe_key]}"
  local script_path="${repo_root}/${probe_script[$probe_key]}"
  local status=0

  mkdir -p "$probe_root"
  echo "running ${probe_key} -> ${probe_root}" >&2

  set +e
  case "$probe_key" in
    vppLpiSourceShapeInventory)
      "$script_path" \
        --vpp-root "$reference_root" \
        --output-root "$probe_root" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    vppLpiCorpusInventory)
      env \
        VPP_REFERENCE_ROOT="$reference_root" \
        VPP_LPI_CORPUS_ROOT="$corpus_root" \
        "$script_path" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    vppLpiExpectedAliasInventory)
      "$script_path" \
        --reference-root "$reference_root" \
        --corpus-root "$corpus_root" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    vppStellarLpiWrapperInventory)
      env \
        VPP_REFERENCE_ROOT="$reference_root" \
        VPP_STELLAR_LPI_ROOT="$wrapper_root" \
        LIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root" \
        "$script_path" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    libprotoidentAndroidBuildProbe)
      env \
        VPP_REFERENCE_ROOT="$reference_root" \
        LIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root" \
        LIBPROTOIDENT_ANDROID_PROBE_BUILD_ROOT="$probe_root" \
        "$script_path" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    stellarLpiWrapperAndroidBuildProbe)
      env \
        VPP_REFERENCE_ROOT="$reference_root" \
        VPP_STELLAR_LPI_ROOT="$wrapper_root" \
        LIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root" \
        STELLAR_LPI_WRAPPER_ANDROID_PROBE_BUILD_ROOT="$probe_root" \
        "$script_path" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    stellarLpiWrapperHostPayloadProbe)
      env \
        VPP_REFERENCE_ROOT="$reference_root" \
        VPP_STELLAR_LPI_ROOT="$wrapper_root" \
        LIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root" \
        STELLAR_LPI_WRAPPER_HOST_PROBE_BUILD_ROOT="$probe_root" \
        "$script_path" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
    stellarLpiWrapperHostPcapProbe)
      env \
        VPP_REFERENCE_ROOT="$reference_root" \
        VPP_LPI_CORPUS_ROOT="$corpus_root" \
        VPP_STELLAR_LPI_ROOT="$wrapper_root" \
        LIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root" \
        STELLAR_LPI_WRAPPER_HOST_PCAP_PROBE_BUILD_ROOT="$probe_root" \
        "$script_path" \
        >"$stdout_path" \
        2>"$stderr_path"
      status=$?
      ;;
  esac
  set -e

  probe_exit_code["$probe_key"]="$status"

  if [[ "$status" -eq 0 ]]; then
    probe_status["$probe_key"]="PASS"
    probe_reason["$probe_key"]="completed"
    if [[ "$probe_key" == "vppLpiSourceShapeInventory" ]] &&
      ! grep -q '^sourceShapeStatus=AVAILABLE$' "$stdout_path"; then
      probe_status["$probe_key"]="UNAVAILABLE"
      probe_reason["$probe_key"]="source_shape_not_available"
    fi
  else
    probe_status["$probe_key"]="FAIL"
    probe_reason["$probe_key"]="exit_nonzero"
  fi

  write_properties
}

write_properties

for probe_key in "${probe_keys[@]}"; do
  unavailable_reason=""
  if ! unavailable_reason="$(required_reference_reason "$probe_key")"; then
    mark_unavailable "$probe_key" "$unavailable_reason"
    if [[ "$continue_on_fail" -eq 0 ]]; then
      cat "$properties_file"
      exit 1
    fi
    continue
  fi

  run_probe_command "$probe_key"
  if [[ "${probe_status[$probe_key]}" != "PASS" && "$continue_on_fail" -eq 0 ]]; then
    cat "$properties_file"
    exit 1
  fi
done

write_properties
cat "$properties_file"

if grep -q '^s61ReferenceProbes=PASS$' "$properties_file"; then
  exit 0
fi

exit 1
