#!/usr/bin/env bash
set -euo pipefail

# Builds a throwaway Android/NDK compile/link probe against the modified backup
# VPP vendored libprotoident source. This script does not copy libprotoident
# into this repository and does not decide the S61 provider-source strategy.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/dev/dev-ndk-env.sh"

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
libprotoident_root="${LIBPROTOIDENT_SOURCE_ROOT:-${reference_root}/src/plugins/stellar_lpi/libprotoident}"
repo_build_output_root="${repo_root}/build-output"
build_root_input="${LIBPROTOIDENT_ANDROID_PROBE_BUILD_ROOT:-${repo_build_output_root}/protocol-identification/libprotoident-android-probe}"
build_root="$build_root_input"
generated_source_dir="$build_root/generated-source"
cmake_build_dir="$build_root/cmake"
android_abi="${ANDROID_ABI:-arm64-v8a}"
android_platform="${ANDROID_PLATFORM:-android-${SNORT_ANDROID_API}}"
configure_only=0

show_help() {
    cat <<EOF
Usage: $0 [--configure-only]

Compiles a local Android/NDK build probe against:
  $libprotoident_root

Outputs only generated probe files under:
  $build_root

Environment overrides:
  VPP_REFERENCE_ROOT
  LIBPROTOIDENT_SOURCE_ROOT
  LIBPROTOIDENT_ANDROID_PROBE_BUILD_ROOT
  ANDROID_ABI
  ANDROID_PLATFORM
EOF
}

path_is_inside_repo_build_output() {
    [[ "$1" == "$2" || "$1" == "$2"/* ]]
}

canonicalize_path() {
    python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=False))' "$1"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --configure-only)
            configure_only=1
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

command -v python3 >/dev/null 2>&1 || {
    echo "python3 was not found on PATH" >&2
    exit 1
}

canonical_repo_build_output_root="$(canonicalize_path "$repo_build_output_root")"
build_root="$(canonicalize_path "$build_root_input")"
path_is_inside_repo_build_output "$build_root" "$canonical_repo_build_output_root" || {
    echo "unsafe probe build root outside repo build-output: $build_root_input (resolved to $build_root)" >&2
    exit 1
}
generated_source_dir="$build_root/generated-source"
cmake_build_dir="$build_root/cmake"

[[ -d "$libprotoident_root" ]] || {
    echo "missing libprotoident source root: $libprotoident_root" >&2
    exit 1
}

command -v cmake >/dev/null 2>&1 || {
    echo "cmake was not found on PATH" >&2
    exit 1
}

ndk_root="$(snort_ndk_require)"

source_tree_sha256() {
    local tree="$1"
    (
        cd -- "$tree"
        find . -type f -print0 | sort -z | xargs -0 -r sha256sum
    ) | sha256sum | awk '{print $1}'
}

count_sources() {
    local pattern="$1"
    find "$libprotoident_root" -type f -path "$pattern" | wc -l | tr -d ' '
}

mkdir -p "$generated_source_dir" "$cmake_build_dir"

cat >"$generated_source_dir/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.18)
project(libprotoident_android_probe LANGUAGES CXX)

set(LIBPROTOIDENT_SOURCE_ROOT "" CACHE PATH "Path to the reference libprotoident source root")
if(NOT IS_DIRECTORY "${LIBPROTOIDENT_SOURCE_ROOT}")
  message(FATAL_ERROR "LIBPROTOIDENT_SOURCE_ROOT is not a directory: ${LIBPROTOIDENT_SOURCE_ROOT}")
endif()

add_definitions(
  -D__FAVOR_BSD
  -DHAVE_NET_ETHERNET_H
  -DHAVE_ICMPHDR=1
  -DHAVE_TCP_STATES=1
  -DHAVE_BSD_UDPHDR=1
  -DHAVE_BSD_TCPHDR=1
)

file(GLOB LPI_CORE_SRC CONFIGURE_DEPENDS "${LIBPROTOIDENT_SOURCE_ROOT}/*.cc")
file(GLOB LPI_TCP_SRC CONFIGURE_DEPENDS "${LIBPROTOIDENT_SOURCE_ROOT}/tcp/*.cc")
file(GLOB LPI_UDP_SRC CONFIGURE_DEPENDS "${LIBPROTOIDENT_SOURCE_ROOT}/udp/*.cc")

add_library(libprotoident_probe STATIC
  ${LPI_CORE_SRC}
  ${LPI_TCP_SRC}
  ${LPI_UDP_SRC}
)
target_include_directories(libprotoident_probe PUBLIC "${LIBPROTOIDENT_SOURCE_ROOT}")
target_compile_features(libprotoident_probe PUBLIC cxx_std_11)
target_compile_options(libprotoident_probe PRIVATE
  -Wall
  -Wextra
  -Wno-unused-function
  -Wno-unused-parameter
)
set_target_properties(libprotoident_probe PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(libprotoident_android_probe main.cpp)
target_link_libraries(libprotoident_android_probe PRIVATE libprotoident_probe)
CMAKE

cat >"$generated_source_dir/main.cpp" <<'CPP'
#include "libprotoident.h"

#include <cstdint>

int main() {
    if (lpi_init_library() != 0) {
        return 2;
    }

    lpi_data_t data;
    lpi_init_data(&data);
    data.trans_proto = 6;
    data.client_port = 49152;
    data.server_port = 80;
    data.payload[0] =
        (static_cast<std::uint32_t>('G') << 24U)
        | (static_cast<std::uint32_t>('E') << 16U)
        | (static_cast<std::uint32_t>('T') << 8U)
        | static_cast<std::uint32_t>(' ');
    data.payload_len[0] = 4;
    data.observed[0] = 4;

    lpi_module_t *module = lpi_guess_protocol(&data);
    const bool matched = module != nullptr && module->name != nullptr;

    lpi_free_library();
    return matched ? 0 : 3;
}
CPP

echo "probe=libprotoident-android-build"
echo "source=$libprotoident_root"
echo "buildRoot=$build_root"
echo "ndkRoot=$ndk_root"
echo "androidAbi=$android_abi"
echo "androidPlatform=$android_platform"
echo "sourceTreeSha256=$(source_tree_sha256 "$libprotoident_root")"
echo "source.topLevelCc=$(find "$libprotoident_root" -maxdepth 1 -type f -name '*.cc' | wc -l | tr -d ' ')"
echo "source.tcpCc=$(count_sources "$libprotoident_root/tcp/*.cc")"
echo "source.udpCc=$(count_sources "$libprotoident_root/udp/*.cc")"
echo "policy.copiesSourceIntoRepo=false"
echo "policy.providerVendoringDecision=false"
echo "probe.scope=compile-link-only"
echo "probe.wrapper=generated-cmake-with-external-source"

cmake \
    -S "$generated_source_dir" \
    -B "$cmake_build_dir" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE="$ndk_root/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$android_abi" \
    -DANDROID_PLATFORM="$android_platform" \
    -DANDROID_STL=c++_static \
    -DLIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root"

if [[ "$configure_only" -ne 0 ]]; then
    echo "probe.result=PASS_CONFIGURE_ONLY"
    exit 0
fi

cmake --build "$cmake_build_dir" --target libprotoident_android_probe
echo "probe.result=PASS"
