#!/usr/bin/env bash
set -euo pipefail

# Builds a throwaway Android/NDK compile/link probe against the modified backup
# VPP stellar_lpi wrapper plus its vendored libprotoident source. This script
# reads the reference tree in place, writes generated shims only under
# build-output, does not copy recognizer source into this repository, and does
# not decide the S61 provider-source strategy.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/dev/dev-ndk-env.sh"

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
wrapper_root="${VPP_STELLAR_LPI_ROOT:-${reference_root}/src/plugins/stellar_lpi}"
libprotoident_root="${LIBPROTOIDENT_SOURCE_ROOT:-${wrapper_root}/libprotoident}"
repo_build_output_root="${repo_root}/build-output"
build_root_input="${STELLAR_LPI_WRAPPER_ANDROID_PROBE_BUILD_ROOT:-${repo_build_output_root}/protocol-identification/stellar-lpi-wrapper-android-probe}"
build_root="$build_root_input"
generated_source_dir="$build_root/generated-source"
generated_include_dir="$generated_source_dir/include"
cmake_build_dir="$build_root/cmake"
android_abi="${ANDROID_ABI:-arm64-v8a}"
android_platform="${ANDROID_PLATFORM:-android-${SNORT_ANDROID_API}}"
configure_only=0

show_help() {
    cat <<EOF
Usage: $0 [--configure-only]

Compiles a local Android/NDK build probe against:
  wrapper:       $wrapper_root
  libprotoident: $libprotoident_root

Outputs only generated probe files under:
  $build_root

Environment overrides:
  VPP_REFERENCE_ROOT
  VPP_STELLAR_LPI_ROOT
  LIBPROTOIDENT_SOURCE_ROOT
  STELLAR_LPI_WRAPPER_ANDROID_PROBE_BUILD_ROOT
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
generated_include_dir="$generated_source_dir/include"
cmake_build_dir="$build_root/cmake"

[[ -d "$reference_root" ]] || {
    echo "missing VPP reference root: $reference_root" >&2
    exit 1
}
[[ -d "$wrapper_root" ]] || {
    echo "missing stellar_lpi wrapper root: $wrapper_root" >&2
    exit 1
}
[[ -d "$libprotoident_root" ]] || {
    echo "missing libprotoident source root: $libprotoident_root" >&2
    exit 1
}
[[ -f "$wrapper_root/stellar_lpi_core.c" ]] || {
    echo "missing stellar_lpi_core.c under: $wrapper_root" >&2
    exit 1
}
[[ -f "$wrapper_root/stellar_lpi_extend.c" ]] || {
    echo "missing stellar_lpi_extend.c under: $wrapper_root" >&2
    exit 1
}
[[ -f "$reference_root/src/vlib/uthash/uthash.h" ]] || {
    echo "missing reference uthash header under: $reference_root/src/vlib/uthash" >&2
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

mkdir -p "$generated_include_dir/vlib/utils" "$generated_source_dir" "$cmake_build_dir"

cat >"$generated_include_dir/vlib/utils/utils.h" <<'H'
#pragma once

#include <stdlib.h>

#ifndef ALLOC
#define ALLOC(type, number) ((type *) calloc((number), sizeof(type)))
#endif

#ifndef FREE
#define FREE(p)                                                               \
    do                                                                        \
    {                                                                         \
        if ((p) != NULL)                                                       \
        {                                                                     \
            free((void *)(p));                                                 \
            (p) = NULL;                                                        \
        }                                                                     \
    } while (0)
#endif
H

cat >"$generated_source_dir/CMakeLists.txt" <<'CMAKE'
cmake_minimum_required(VERSION 3.18)
project(stellar_lpi_wrapper_android_probe LANGUAGES C CXX)

set(VPP_REFERENCE_ROOT "" CACHE PATH "Path to the modified VPP reference root")
set(VPP_STELLAR_LPI_ROOT "" CACHE PATH "Path to the reference stellar_lpi wrapper root")
set(LIBPROTOIDENT_SOURCE_ROOT "" CACHE PATH "Path to the reference libprotoident source root")

foreach(required_dir IN ITEMS VPP_REFERENCE_ROOT VPP_STELLAR_LPI_ROOT LIBPROTOIDENT_SOURCE_ROOT)
  if(NOT IS_DIRECTORY "${${required_dir}}")
    message(FATAL_ERROR "${required_dir} is not a directory: ${${required_dir}}")
  endif()
endforeach()

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

add_library(stellar_lpi_wrapper_probe STATIC
  "${VPP_STELLAR_LPI_ROOT}/stellar_lpi_core.c"
  "${VPP_STELLAR_LPI_ROOT}/stellar_lpi_extend.c"
)
target_include_directories(stellar_lpi_wrapper_probe PUBLIC
  "${CMAKE_CURRENT_LIST_DIR}/include"
  "${VPP_REFERENCE_ROOT}/src"
  "${VPP_STELLAR_LPI_ROOT}"
)
target_compile_options(stellar_lpi_wrapper_probe PRIVATE
  -Wall
  -Wextra
  -Wno-unused-function
  -Wno-unused-parameter
  -Wno-sign-compare
)
set_target_properties(stellar_lpi_wrapper_probe PROPERTIES
  C_STANDARD 11
  C_EXTENSIONS ON
  POSITION_INDEPENDENT_CODE ON
)
target_link_libraries(stellar_lpi_wrapper_probe PUBLIC libprotoident_probe)

add_executable(stellar_lpi_wrapper_android_probe main.cpp)
target_link_libraries(stellar_lpi_wrapper_android_probe PRIVATE stellar_lpi_wrapper_probe)
CMAKE

cat >"$generated_source_dir/main.cpp" <<'CPP'
#include "stellar_lpi_core.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

int main() {
    auto *detector = lpi_detector_new();
    if (detector == nullptr) {
        return 2;
    }

    auto *context = lpi_detect_context_new(false, 49152, 80, 6);
    if (context == nullptr) {
        lpi_detector_free(detector);
        return 3;
    }

    constexpr char payload[] = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const auto payload_length = static_cast<unsigned int>(std::strlen(payload));
    lpi_detect_context_update(context, payload, payload_length, false);

    unsigned int stop_detect = 0;
    const int appid = lpi_detect(
        detector,
        context,
        payload,
        static_cast<std::size_t>(payload_length),
        &stop_detect);

    if (appid > 0) {
        static_cast<void>(lpi_appid2name(detector, appid));
    }

    lpi_detect_context_free(context);
    lpi_detector_free(detector);
    return 0;
}
CPP

echo "probe=stellar-lpi-wrapper-android-build"
echo "source=$reference_root"
echo "wrapperRoot=$wrapper_root"
echo "libprotoidentRoot=$libprotoident_root"
echo "buildRoot=$build_root"
echo "ndkRoot=$ndk_root"
echo "androidAbi=$android_abi"
echo "androidPlatform=$android_platform"
echo "wrapperSourceTreeSha256=$(source_tree_sha256 "$wrapper_root")"
echo "libprotoidentSourceTreeSha256=$(source_tree_sha256 "$libprotoident_root")"
echo "source.wrapperCoreC=stellar_lpi_core.c"
echo "source.wrapperExtendC=stellar_lpi_extend.c"
echo "source.libprotoidentTopLevelCc=$(find "$libprotoident_root" -maxdepth 1 -type f -name '*.cc' | wc -l | tr -d ' ')"
echo "source.libprotoidentTcpCc=$(count_sources "$libprotoident_root/tcp/*.cc")"
echo "source.libprotoidentUdpCc=$(count_sources "$libprotoident_root/udp/*.cc")"
echo "policy.copiesSourceIntoRepo=false"
echo "policy.providerVendoringDecision=false"
echo "policy.providerRuntimeWiring=false"
echo "policy.protocolRuleDecision=false"
echo "probe.scope=compile-link-only"
echo "probe.wrapper=stellar_lpi_core-plus-extend-with-generated-compat-shim"
echo "probe.generatedUtilsShim=true"
echo "probe.referenceUthashInPlace=true"

cmake \
    -S "$generated_source_dir" \
    -B "$cmake_build_dir" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE="$ndk_root/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI="$android_abi" \
    -DANDROID_PLATFORM="$android_platform" \
    -DANDROID_STL=c++_static \
    -DVPP_REFERENCE_ROOT="$reference_root" \
    -DVPP_STELLAR_LPI_ROOT="$wrapper_root" \
    -DLIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root"

if [[ "$configure_only" -ne 0 ]]; then
    echo "probe.result=PASS_CONFIGURE_ONLY"
    exit 0
fi

cmake --build "$cmake_build_dir" --target stellar_lpi_wrapper_android_probe
echo "probe.result=PASS"
