#!/usr/bin/env bash
set -euo pipefail

# Emits a stable, machine-readable source-shape inventory for the modified
# backup VPP stellar_lpi wrapper and its vendored libprotoident tree. This is
# reference-only evidence: it reads the backup tree in place, writes only an
# inventory under the requested output root, does not copy source/corpus/license
# files into this repository, and does not claim provider enablement.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/protocol_identification/probe_generation.sh"

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
repo_build_output_root="${repo_root}/build-output"
output_root="${VPP_LPI_SOURCE_SHAPE_INVENTORY_OUTPUT_ROOT:-${repo_build_output_root}/protocol-identification/source-shape}"
strict=0

show_help() {
    cat <<EOF
Usage: $0 [--vpp-root PATH] [--output-root PATH] [--strict]

Reads the backup VPP reference tree in place and writes:
  source-shape-inventory.properties

Default reference tree:
  $reference_root

Default output root:
  $output_root

Environment overrides:
  VPP_REFERENCE_ROOT
  VPP_LPI_SOURCE_SHAPE_INVENTORY_OUTPUT_ROOT

Safety:
  Missing reference paths emit reference_only skip markers and exit 0 by
  default. Use --strict to make missing reference paths fail after writing the
  skip inventory.
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
            output_root="$2"
            shift 2
            ;;
        --strict)
            strict=1
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

wrapper_root="${reference_root}/src/plugins/stellar_lpi"
libprotoident_root="${wrapper_root}/libprotoident"
corpus_root="${reference_root}/test/decoders/stellar_lpi/test_pcap"
output_file="${output_root}/source-shape-inventory.properties"

count_files() {
    local root="$1"
    local pattern="$2"

    if [[ -d "$root" ]]; then
        find "$root" -type f -name "$pattern" | wc -l | tr -d ' '
    else
        printf '0'
    fi
}

count_top_level_files() {
    local root="$1"
    local pattern="$2"

    if [[ -d "$root" ]]; then
        find "$root" -maxdepth 1 -type f -name "$pattern" | wc -l | tr -d ' '
    else
        printf '0'
    fi
}

count_source_path() {
    local root="$1"
    local pattern="$2"

    if [[ -d "$root" ]]; then
        protocol_identification_probe_count_matching_sources "$root" "$pattern"
    else
        printf '0'
    fi
}

bool_file() {
    local path="$1"

    [[ -f "$path" ]] && printf 'true' || printf 'false'
}

bool_dir() {
    local path="$1"

    [[ -d "$path" ]] && printf 'true' || printf 'false'
}

bool_contains() {
    local path="$1"
    local text="$2"

    [[ -f "$path" ]] && grep -Fq "$text" "$path" && printf 'true' || printf 'false'
}

bool_reference_git_available() {
    git -C "$reference_root" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
        && printf 'true' \
        || printf 'false'
}

git_value_or_dash() {
    local git_args=("$@")

    git -C "$reference_root" "${git_args[@]}" 2>/dev/null || printf '-'
}

source_tree_sha256_or_dash() {
    local root="$1"

    if [[ -d "$root" ]]; then
        protocol_identification_probe_source_tree_sha256 "$root"
    else
        printf '-'
    fi
}

mkdir -p "$output_root"

reference_available="$(bool_dir "$reference_root")"
wrapper_available="$(bool_dir "$wrapper_root")"
libprotoident_available="$(bool_dir "$libprotoident_root")"
corpus_available="$(bool_dir "$corpus_root")"
git_available="false"
git_branch="-"
git_head="-"
git_upstream="-"

if [[ "$reference_available" == "true" ]]; then
    git_available="$(bool_reference_git_available)"
    if [[ "$git_available" == "true" ]]; then
        git_branch="$(git_value_or_dash symbolic-ref --short -q HEAD)"
        [[ "$git_branch" != "-" ]] || git_branch="detached"
        git_head="$(git_value_or_dash rev-parse HEAD)"
        git_upstream="$(git_value_or_dash rev-parse --abbrev-ref --symbolic-full-name '@{u}')"
    fi
fi

source_shape_status="SKIP_UNAVAILABLE"
if [[ "$reference_available" == "true" && "$wrapper_available" == "true" && "$libprotoident_available" == "true" ]]; then
    source_shape_status="AVAILABLE"
elif [[ "$reference_available" == "true" ]]; then
    source_shape_status="PARTIAL"
fi

top_level_c="$(count_top_level_files "$wrapper_root" '*.c')"
top_level_h="$(count_top_level_files "$wrapper_root" '*.h')"
wrapper_c="$(count_files "$wrapper_root" '*.c')"
wrapper_h="$(count_files "$wrapper_root" '*.h')"
libprotoident_top_level_cc="$(count_top_level_files "$libprotoident_root" '*.cc')"
libprotoident_tcp_cc="$(count_source_path "$libprotoident_root" "$libprotoident_root/tcp/*.cc")"
libprotoident_udp_cc="$(count_source_path "$libprotoident_root" "$libprotoident_root/udp/*.cc")"
libprotoident_total_cc="$(count_files "$libprotoident_root" '*.cc')"
corpus_pcap="$(count_files "$corpus_root" '*.pcap')"
corpus_pcapng="$(count_files "$corpus_root" '*.pcapng')"
corpus_cap="$(count_files "$corpus_root" '*.cap')"
expected_json="$(count_files "$corpus_root" '*.json')"
corpus_capture_total=$((corpus_pcap + corpus_pcapng + corpus_cap))

libprotoident_header="${libprotoident_root}/libprotoident.h"
plugin_source="${wrapper_root}/stellar_lpi_plugin.c"
libprotoident_lgpl="false"
if [[ "$(bool_contains "$libprotoident_header" "GNU Lesser General Public License")" == "true" ]] &&
    [[ "$(bool_contains "$libprotoident_header" "either version 3 of the License, or")" == "true" ]]; then
    libprotoident_lgpl="true"
fi

plugin_apache_placeholder="false"
if [[ "$(bool_contains "$plugin_source" "Copyright (c) <current-year> <your-organization>")" == "true" ]] &&
    [[ "$(bool_contains "$plugin_source" "Apache License, Version 2.0")" == "true" ]]; then
    plugin_apache_placeholder="true"
fi

{
    printf 'inventory=vpp-lpi-source-shape\n'
    printf 'sourceShapeEvidence=reference_only\n'
    printf 'sourceShapeStatus=%s\n' "$source_shape_status"
    printf 'realProviderEnabled=not_claimed\n'
    printf 'sourceImported=not_claimed\n'
    printf 'corpusImported=not_claimed\n'
    printf 'protocolRule=out_of_scope\n'
    printf 'policy.copiesSourceIntoRepo=false\n'
    printf 'policy.copiesPcapIntoRepo=false\n'
    printf 'policy.copiesExpectedJsonIntoRepo=false\n'
    printf 'policy.copiesLicenseFilesIntoRepo=false\n'
    printf 'referenceRoot=%s\n' "$reference_root"
    printf 'referenceRoot.available=%s\n' "$reference_available"
    printf 'git.available=%s\n' "$git_available"
    printf 'git.branch=%s\n' "$git_branch"
    printf 'git.head=%s\n' "$git_head"
    printf 'git.upstream=%s\n' "$git_upstream"
    printf 'wrapperRoot=%s\n' "$wrapper_root"
    printf 'wrapperRoot.available=%s\n' "$wrapper_available"
    printf 'libprotoidentRoot=%s\n' "$libprotoident_root"
    printf 'libprotoidentRoot.available=%s\n' "$libprotoident_available"
    printf 'corpusRoot=%s\n' "$corpus_root"
    printf 'corpusRoot.available=%s\n' "$corpus_available"
    printf 'keyFile.stellar_lpi.api=%s\n' "$(bool_file "$wrapper_root/stellar_lpi.api")"
    printf 'keyFile.CMakeLists.txt=%s\n' "$(bool_file "$wrapper_root/CMakeLists.txt")"
    printf 'keyFile.stellar_lpi_core.c=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_core.c")"
    printf 'keyFile.stellar_lpi_core.h=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_core.h")"
    printf 'keyFile.stellar_lpi_extend.c=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_extend.c")"
    printf 'keyFile.stellar_lpi_extend.h=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_extend.h")"
    printf 'keyFile.stellar_lpi_plugin.c=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_plugin.c")"
    printf 'keyFile.stellar_lpi_plugin.h=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_plugin.h")"
    printf 'keyFile.stellar_lpi_test.c=%s\n' "$(bool_file "$wrapper_root/stellar_lpi_test.c")"
    printf 'keyFile.libprotoident.CMakeLists.txt=%s\n' "$(bool_file "$libprotoident_root/CMakeLists.txt")"
    printf 'keyFile.libprotoident.libprotoident.h=%s\n' "$(bool_file "$libprotoident_header")"
    printf 'source.wrapperTopLevelC=%s\n' "$top_level_c"
    printf 'source.wrapperTopLevelH=%s\n' "$top_level_h"
    printf 'source.wrapperC=%s\n' "$wrapper_c"
    printf 'source.wrapperH=%s\n' "$wrapper_h"
    printf 'source.wrapperCoreTopLevelC=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_core*.c')"
    printf 'source.wrapperCoreTopLevelH=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_core*.h')"
    printf 'source.wrapperExtendTopLevelC=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_extend*.c')"
    printf 'source.wrapperExtendTopLevelH=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_extend*.h')"
    printf 'source.wrapperPluginTopLevelC=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_plugin*.c')"
    printf 'source.wrapperPluginTopLevelH=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_plugin*.h')"
    printf 'source.wrapperTestTopLevelC=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_test*.c')"
    printf 'source.wrapperTestTopLevelH=%s\n' "$(count_top_level_files "$wrapper_root" 'stellar_lpi_test*.h')"
    printf 'source.libprotoidentTopLevelCc=%s\n' "$libprotoident_top_level_cc"
    printf 'source.libprotoidentTcpCc=%s\n' "$libprotoident_tcp_cc"
    printf 'source.libprotoidentUdpCc=%s\n' "$libprotoident_udp_cc"
    printf 'source.libprotoidentTotalCc=%s\n' "$libprotoident_total_cc"
    printf 'hash.wrapperSourceTreeSha256=%s\n' "$(source_tree_sha256_or_dash "$wrapper_root")"
    printf 'hash.libprotoidentSourceTreeSha256=%s\n' "$(source_tree_sha256_or_dash "$libprotoident_root")"
    printf 'license.libprotoidentHeaderLgplTextPresent=%s\n' "$libprotoident_lgpl"
    printf 'license.libprotoidentAdjacentLICENSE=%s\n' "$(bool_file "$libprotoident_root/LICENSE")"
    printf 'license.libprotoidentAdjacentCOPYING=%s\n' "$(bool_file "$libprotoident_root/COPYING")"
    printf 'license.libprotoidentAdjacentNOTICE=%s\n' "$(bool_file "$libprotoident_root/NOTICE")"
    printf 'license.libprotoidentAdjacentLicenseOrNoticePresent=%s\n' "$([[ -f "$libprotoident_root/LICENSE" || -f "$libprotoident_root/COPYING" || -f "$libprotoident_root/NOTICE" ]] && printf 'true' || printf 'false')"
    printf 'license.pluginApachePlaceholderTextPresent=%s\n' "$plugin_apache_placeholder"
    printf 'corpus.excludedCaptureFiles=%s\n' "$corpus_capture_total"
    printf 'corpus.excludedPcap=%s\n' "$corpus_pcap"
    printf 'corpus.excludedPcapng=%s\n' "$corpus_pcapng"
    printf 'corpus.excludedCap=%s\n' "$corpus_cap"
    printf 'expectedJson.excluded=%s\n' "$expected_json"
    printf 'outputFile=%s\n' "$output_file"
} | tee "$output_file"

if [[ "$strict" -eq 1 && "$source_shape_status" != "AVAILABLE" ]]; then
    echo "strict source-shape inventory requires available reference, wrapper, and libprotoident roots" >&2
    exit 1
fi
