#!/usr/bin/env bash
set -euo pipefail

# Emits a stable, machine-readable inventory of the modified backup VPP
# stellar_lpi wrapper. This script reads the reference tree in place, does not
# copy source into this repository, and does not decide the S61 provider-source
# strategy.
#
# Key outputs include api.exported, api.signature.lpi_detect_context_update,
# dependency.coreUsesAllocMacros, dependency.coreUsesUthash,
# dependency.coreIncludesStellarLpiExtend, dependency.extendAddsOpenVpnState,
# mapping.entries, mapping.containsForkLocalIds, build.vppPluginUsesAddVppPlugin,
# build.linksLibprotoident, and license facts.
# Stable output keys include api.exported, api.signature.lpi_detect_context_update,
# dependency.* facts, mapping.* facts, and build.* facts; the Android contract
# test greps those keys to keep this read-only inventory from drifting.

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
wrapper_root="${VPP_STELLAR_LPI_ROOT:-${reference_root}/src/plugins/stellar_lpi}"
libprotoident_root="${LIBPROTOIDENT_SOURCE_ROOT:-${wrapper_root}/libprotoident}"

die() {
  echo "error: $*" >&2
  exit 1
}

count_files() {
  local root="$1"
  local pattern="$2"
  find "$root" -type f -name "$pattern" | wc -l | tr -d ' '
}

count_path_sources() {
  local root="$1"
  local pattern="$2"
  find "$root" -type f -path "$pattern" | wc -l | tr -d ' '
}

[[ -d "$reference_root" ]] || die "missing VPP reference root: $reference_root"
[[ -d "$wrapper_root" ]] || die "missing stellar_lpi wrapper root: $wrapper_root"
[[ -d "$libprotoident_root" ]] || die "missing libprotoident source root: $libprotoident_root"

header="$wrapper_root/stellar_lpi_core.h"
core_source="$wrapper_root/stellar_lpi_core.c"
extend_header="$wrapper_root/stellar_lpi_extend.h"
extend_source="$wrapper_root/stellar_lpi_extend.c"
plugin_source="$wrapper_root/stellar_lpi_plugin.c"
cmake_file="$wrapper_root/CMakeLists.txt"
libprotoident_cmake_file="$libprotoident_root/CMakeLists.txt"
api_file="$wrapper_root/stellar_lpi.api"

for required in "$header" "$core_source" "$extend_header" "$extend_source" "$plugin_source" "$cmake_file" "$libprotoident_cmake_file" "$api_file"; do
  [[ -f "$required" ]] || die "missing required wrapper file: $required"
done

python3 - "$header" "$core_source" "$extend_header" "$extend_source" "$plugin_source" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

header = Path(sys.argv[1])
core = Path(sys.argv[2])
extend_header = Path(sys.argv[3])
extend_source = Path(sys.argv[4])
plugin = Path(sys.argv[5])

header_text = header.read_text(encoding="utf-8")
core_text = core.read_text(encoding="utf-8")
extend_header_text = extend_header.read_text(encoding="utf-8")
extend_source_text = extend_source.read_text(encoding="utf-8")
plugin_text = plugin.read_text(encoding="utf-8")

def clean_signature(signature: str) -> str:
    return " ".join(signature.replace("\n", " ").split()).rstrip(";")

signature_patterns = {
    "lpi_detector_new": r"struct\s+lpi_detector\s*\*\s*lpi_detector_new\s*\([^;]*\);",
    "lpi_detector_free": r"void\s+lpi_detector_free\s*\([^;]*\);",
    "lpi_detect_context_new": r"struct\s+lpi_detect_context\s*\*\s*lpi_detect_context_new\s*\([^;]*\);",
    "lpi_detect_context_free": r"void\s+lpi_detect_context_free\s*\([^;]*\);",
    "lpi_detect_context_update": r"void\s+lpi_detect_context_update\s*\([^;]*\);",
    "lpi_detect": r"int\s+lpi_detect\s*\([^;]*\);",
    "lpi_appid2name": r"const\s+char\s*\*\s*lpi_appid2name\s*\([^;]*\);",
}

exports = []
signatures = {}
for name, pattern in signature_patterns.items():
    match = re.search(pattern, header_text, flags=re.MULTILINE | re.DOTALL)
    if match:
        exports.append(name)
        signatures[name] = clean_signature(match.group(0))

includes = sorted(set(re.findall(r'^\s*#include\s+[<"]([^>"]+)[>"]', core_text, flags=re.MULTILINE)))
plugin_includes = sorted(set(re.findall(r'^\s*#include\s+[<"]([^>"]+)[>"]', plugin_text, flags=re.MULTILINE)))

mapping_entries = re.findall(
    r'\{\s*"([^"]+)"\s*,\s*([0-9]+)\s*,\s*"([^"]+)"\s*\}',
    core_text,
)
unique_app_names = sorted({entry[2] for entry in mapping_entries})

print(f"api.exported={','.join(exports)}")
for name in exports:
    print(f"api.signature.{name}={signatures[name]}")
print(f"core.includes={','.join(includes)}")
print(f"plugin.includes.vppCount={sum(1 for item in plugin_includes if item.startswith(('vlib', 'vnet', 'vpp', 'vppinfra', 'vat')))}")
print(f"plugin.includes.stellarCount={sum(1 for item in plugin_includes if item.startswith('stellar_'))}")
print(f"dependency.coreUsesAllocMacros={str('ALLOC(' in core_text and 'FREE(' in core_text).lower()}")
print(f"dependency.coreUsesUthash={str('uthash' in core_text and 'HASH_' in core_text).lower()}")
print(f"dependency.coreIncludesStellarLpiExtend={str('stellar_lpi_extend.h' in core_text).lower()}")
print(f"dependency.extendUsesLibprotoidentTypes={str('libprotoident/libprotoident.h' in extend_header_text).lower()}")
print(f"dependency.extendAddsOpenVpnState={str('struct ovpn_ctx' in extend_header_text).lower()}")
print(f"dependency.extendUsesPayloadHeuristics={str('lpi_plus_extended_guess' in extend_source_text).lower()}")
print(f"mapping.entries={len(mapping_entries)}")
print(f"mapping.uniqueAppNames={len(unique_app_names)}")
print(f"mapping.containsForkLocalIds={str(any(int(entry[1]) >= 8000 for entry in mapping_entries)).lower()}")
print(f"mapping.sample={','.join(f'{entry[0]}:{entry[1]}:{entry[2]}' for entry in mapping_entries[:8])}")
PY

printf 'inventory=stellar-lpi-wrapper\n'
printf 'source=%s\n' "$reference_root"
printf 'wrapperRoot=%s\n' "$wrapper_root"
printf 'libprotoidentRoot=%s\n' "$libprotoident_root"
printf 'policy.copiesSourceIntoRepo=false\n'
printf 'policy.providerSourceDecision=false\n'
printf 'policy.protocolRuleDecision=false\n'
printf 'file.header=%s\n' "$header"
printf 'file.core=%s\n' "$core_source"
printf 'file.extendHeader=%s\n' "$extend_header"
printf 'file.extendSource=%s\n' "$extend_source"
printf 'file.plugin=%s\n' "$plugin_source"
printf 'file.api=%s\n' "$api_file"
printf 'file.cmake=%s\n' "$cmake_file"
printf 'file.libprotoidentCmake=%s\n' "$libprotoident_cmake_file"
printf 'call.lifecycle=lpi_detector_new,lpi_detect_context_new,lpi_detect_context_update,lpi_detect,lpi_appid2name,lpi_detect_context_free,lpi_detector_free\n'
printf 'call.perPacket=lpi_detect_context_update,lpi_detect\n'
printf 'call.providerStopSignal=stop_detect\n'
printf 'source.wrapperC=%s\n' "$(count_files "$wrapper_root" '*.c')"
printf 'source.wrapperH=%s\n' "$(count_files "$wrapper_root" '*.h')"
printf 'source.libprotoidentTopLevelCc=%s\n' "$(find "$libprotoident_root" -maxdepth 1 -type f -name '*.cc' | wc -l | tr -d ' ')"
printf 'source.libprotoidentTcpCc=%s\n' "$(count_path_sources "$libprotoident_root" "$libprotoident_root/tcp/*.cc")"
printf 'source.libprotoidentUdpCc=%s\n' "$(count_path_sources "$libprotoident_root" "$libprotoident_root/udp/*.cc")"
printf 'build.vppPluginUsesAddVppPlugin=%s\n' "$(grep -q 'add_vpp_plugin(stellar_lpi' "$cmake_file" && echo true || echo false)"
printf 'build.linksLibprotoident=%s\n' "$(grep -q 'LINK_LIBRARIES' "$cmake_file" && grep -q 'libprotoident' "$cmake_file" && echo true || echo false)"
printf 'build.includesStellarLpiExtend=%s\n' "$(grep -q 'stellar_lpi_extend.c' "$cmake_file" && echo true || echo false)"
printf 'build.libprotoidentStatic=%s\n' "$(grep -q 'add_library(libprotoident STATIC' "$libprotoident_cmake_file" && echo true || echo false)"
printf 'build.libprotoidentCxxStandard=%s\n' "$(grep -q 'CXX_STANDARD 11' "$libprotoident_cmake_file" && echo 11 || echo unknown)"
printf 'build.libprotoidentPic=%s\n' "$(grep -q 'POSITION_INDEPENDENT_CODE ON' "$libprotoident_cmake_file" && echo true || echo false)"
printf 'build.libprotoidentDefinitions=%s\n' "$(grep -o -- '-D[^ )]*' "$libprotoident_cmake_file" | paste -sd, -)"
printf 'build.libprotoidentLinks=%s\n' "$(awk '/target_link_libraries\(libprotoident/{flag=1;next}/\)/{if(flag){flag=0;next}}flag{gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if(length($0)) print $0}' "$libprotoident_cmake_file" | paste -sd, -)"
printf 'license.pluginHeaderApachePlaceholder=%s\n' "$(grep -q 'Copyright (c) <current-year> <your-organization>' "$plugin_source" && grep -q 'Apache License, Version 2.0' "$plugin_source" && echo true || echo false)"
printf 'license.libprotoidentLgpl3OrLater=%s\n' "$(grep -q 'GNU Lesser General Public License' "$libprotoident_root/libprotoident.h" && grep -q 'either version 3 of the License, or' "$libprotoident_root/libprotoident.h" && echo true || echo false)"
printf 'license.libprotoidentAdjacentCopying=%s\n' "$([[ -f "$libprotoident_root/COPYING" || -f "$libprotoident_root/LICENSE" || -f "$libprotoident_root/LICENSE.txt" ]] && echo true || echo false)"
