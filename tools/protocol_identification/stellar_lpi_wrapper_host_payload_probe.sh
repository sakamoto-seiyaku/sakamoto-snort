#!/usr/bin/env bash
set -euo pipefail

# Builds and runs a throwaway host probe against the modified backup VPP
# stellar_lpi wrapper plus its vendored libprotoident source. The probe reads
# the reference source in place, writes generated build files only under
# build-output, and does not wire a Sakamoto product runtime provider.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
wrapper_root="${VPP_STELLAR_LPI_ROOT:-${reference_root}/src/plugins/stellar_lpi}"
libprotoident_root="${LIBPROTOIDENT_SOURCE_ROOT:-${wrapper_root}/libprotoident}"
repo_build_output_root="${repo_root}/build-output"
build_root_input="${STELLAR_LPI_WRAPPER_HOST_PROBE_BUILD_ROOT:-${repo_build_output_root}/protocol-identification/stellar-lpi-wrapper-host-payload-probe}"
build_root="$build_root_input"
generated_source_dir="$build_root/generated-source"
generated_include_dir="$generated_source_dir/include"
cmake_build_dir="$build_root/cmake"
configure_only=0

show_help() {
    cat <<EOF
Usage: $0 [--configure-only]

Compiles and runs a local host payload probe against:
  wrapper:       $wrapper_root
  libprotoident: $libprotoident_root

Outputs only generated probe files under:
  $build_root

Environment overrides:
  VPP_REFERENCE_ROOT
  VPP_STELLAR_LPI_ROOT
  LIBPROTOIDENT_SOURCE_ROOT
  STELLAR_LPI_WRAPPER_HOST_PROBE_BUILD_ROOT
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
project(stellar_lpi_wrapper_host_payload_probe LANGUAGES C CXX)

set(VPP_REFERENCE_ROOT "" CACHE PATH "Path to the modified VPP reference root")
set(VPP_STELLAR_LPI_ROOT "" CACHE PATH "Path to the reference stellar_lpi wrapper root")
set(LIBPROTOIDENT_SOURCE_ROOT "" CACHE PATH "Path to the reference libprotoident source root")
set(REPO_ROOT "" CACHE PATH "Path to the Sakamoto repo root")

foreach(required_dir IN ITEMS VPP_REFERENCE_ROOT VPP_STELLAR_LPI_ROOT LIBPROTOIDENT_SOURCE_ROOT REPO_ROOT)
  if(NOT IS_DIRECTORY "${${required_dir}}")
    message(FATAL_ERROR "${required_dir} is not a directory: ${${required_dir}}")
  endif()
endforeach()

find_package(Threads REQUIRED)

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
target_link_libraries(libprotoident_probe PUBLIC Threads::Threads)

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

add_library(sakamoto_lpi_pipeline_probe STATIC
  "${REPO_ROOT}/src/core/flow/FlowSteering.cpp"
  "${REPO_ROOT}/src/core/protocol/LpiRecognitionAdapter.cpp"
  "${REPO_ROOT}/src/core/protocol/LpiRecognitionProvider.cpp"
)
target_include_directories(sakamoto_lpi_pipeline_probe PUBLIC
  "${REPO_ROOT}/src"
  "${REPO_ROOT}/src/core/flow"
  "${REPO_ROOT}/src/core/protocol"
)
target_compile_features(sakamoto_lpi_pipeline_probe PUBLIC cxx_std_20)
target_compile_options(sakamoto_lpi_pipeline_probe PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Werror
  -Wno-missing-field-initializers
)

add_executable(stellar_lpi_wrapper_host_payload_probe main.cpp)
target_compile_features(stellar_lpi_wrapper_host_payload_probe PRIVATE cxx_std_20)
target_link_libraries(
  stellar_lpi_wrapper_host_payload_probe
  PRIVATE
    stellar_lpi_wrapper_probe
    sakamoto_lpi_pipeline_probe
)
CMAKE

cat >"$generated_source_dir/main.cpp" <<'CPP'
#include <core/flow/FlowSteering.hpp>
#include <core/protocol/ApplicationProtocolCatalog.hpp>
#include <core/protocol/LpiRecognitionProvider.hpp>

#include "stellar_lpi_core.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace Catalog = sucre::protocol;
namespace Flow = SnortDatapath::Flow;
namespace Protocol = SnortDatapath::Protocol;

struct DetectionCase {
    std::string key;
    std::string expected_name;
    int expected_appid;
    std::optional<Catalog::ApplicationProtocolId> expected_sakamoto_protocol;
    bool current_is_s2c_flow;
    std::uint16_t client_port;
    std::uint16_t server_port;
    std::uint8_t trans_proto;
    std::vector<unsigned char> payload;
};

class Detector final {
public:
    Detector() : detector_(lpi_detector_new()) {}
    ~Detector() {
        if (detector_ != nullptr) {
            lpi_detector_free(detector_);
        }
    }

    Detector(const Detector &) = delete;
    Detector &operator=(const Detector &) = delete;

    [[nodiscard]] lpi_detector *get() const { return detector_; }

private:
    lpi_detector *detector_;
};

class Context final {
public:
    explicit Context(const DetectionCase &test_case)
        : context_(lpi_detect_context_new(
              test_case.current_is_s2c_flow,
              test_case.client_port,
              test_case.server_port,
              test_case.trans_proto)) {}

    ~Context() {
        if (context_ != nullptr) {
            lpi_detect_context_free(context_);
        }
    }

    Context(const Context &) = delete;
    Context &operator=(const Context &) = delete;

    [[nodiscard]] lpi_detect_context *get() const { return context_; }

private:
    lpi_detect_context *context_;
};

[[nodiscard]] std::vector<unsigned char> bytes(const char *payload) {
    const auto *begin = reinterpret_cast<const unsigned char *>(payload);
    return std::vector<unsigned char>(begin, begin + std::strlen(payload));
}

[[nodiscard]] std::vector<unsigned char> dnsQueryPayload() {
    return {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x04, 't',  'e',  's',
        't',  0x00, 0x00, 0x01, 0x00, 0x01,
    };
}

[[nodiscard]] std::string aliasFor(std::string app_name) {
    std::transform(app_name.begin(), app_name.end(), app_name.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return "lpi:" + app_name;
}

[[nodiscard]] std::uint32_t transportHeaderBytesFor(
    const DetectionCase &test_case) noexcept {
    return test_case.trans_proto == 17 ? 8U : 20U;
}

[[nodiscard]] Flow::PacketFacts packetFactsFor(
    const DetectionCase &test_case) noexcept {
    const auto transport_header_bytes = transportHeaderBytesFor(test_case);
    const auto payload_offset = 20U + transport_header_bytes;
    const auto total_length =
        payload_offset + static_cast<std::uint32_t>(test_case.payload.size());

    return Flow::PacketFacts{
        .source = Flow::IpAddress::v4({10, 61, 0, 1}),
        .destination = Flow::IpAddress::v4({198, 51, 100, 61}),
        .ipProtocol = test_case.trans_proto,
        .sourcePort = test_case.client_port,
        .destinationPort = test_case.server_port,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = Flow::ParseStatus::Ready,
        .deviceDirection = Flow::DevicePacketDirection::Output,
        .originalLength = total_length,
        .boundedPrefixLength = total_length,
        .transportPayloadOffset = payload_offset,
        .transportPayloadLength =
            static_cast<std::uint32_t>(test_case.payload.size()),
        .domain = Flow::FlowDomain{
            .adapter = Flow::AdapterKind::RootNfqueue,
            .linuxUid = 10061,
            .uidKnown = true,
            .captureQueue = 7,
            .networkContext = 61,
            .runtimeProfile = 1,
            .interfaceIndex = 3,
        },
    };
}

[[nodiscard]] std::vector<std::byte> l3PacketFor(
    const DetectionCase &test_case) {
    const auto facts = packetFactsFor(test_case);
    std::vector<std::byte> packet(
        facts.transportPayloadOffset + test_case.payload.size());
    for (std::size_t index = 0; index < test_case.payload.size(); ++index) {
        packet[facts.transportPayloadOffset + index] =
            static_cast<std::byte>(test_case.payload[index]);
    }
    return packet;
}

[[nodiscard]] bool runCase(Detector &detector, const DetectionCase &test_case) {
    Context context(test_case);
    if (context.get() == nullptr) {
        std::cerr << "case." << test_case.key << ".error=context-null\n";
        return false;
    }

    const auto *payload = reinterpret_cast<const char *>(test_case.payload.data());
    const auto payload_size = test_case.payload.size();
    lpi_detect_context_update(
        context.get(),
        payload,
        static_cast<unsigned int>(payload_size),
        test_case.current_is_s2c_flow);

    unsigned int stop_detect = 0;
    const int appid = lpi_detect(detector.get(), context.get(), payload, payload_size, &stop_detect);
    const char *raw_name = appid > 0 ? lpi_appid2name(detector.get(), appid) : nullptr;
    const std::string app_name = raw_name != nullptr ? raw_name : "";

    std::cout << "case." << test_case.key << ".expectedName=" << test_case.expected_name << "\n";
    std::cout << "case." << test_case.key << ".expectedAppId=" << test_case.expected_appid << "\n";
    std::cout << "case." << test_case.key << ".appId=" << appid << "\n";
    std::cout << "case." << test_case.key << ".appName=" << app_name << "\n";
    std::cout << "case." << test_case.key << ".alias=" << aliasFor(app_name) << "\n";
    std::cout << "case." << test_case.key << ".stopDetect=" << stop_detect << "\n";

    const bool passed = appid == test_case.expected_appid && app_name == test_case.expected_name;
    std::cout << "case." << test_case.key << ".result=" << (passed ? "PASS" : "FAIL") << "\n";
    return passed;
}

class WrapperProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override {
        return detector_.get() != nullptr;
    }

    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "backup-vpp-stellar-lpi-wrapper";
    }

    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        if (detector_.get() == nullptr || submission.transportPayload.empty()) {
            return std::nullopt;
        }

        const DetectionCase request{
            .key = "pipeline",
            .expected_name = {},
            .expected_appid = 0,
            .expected_sakamoto_protocol = std::nullopt,
            .current_is_s2c_flow = false,
            .client_port = submission.facts.sourcePort,
            .server_port = submission.facts.destinationPort,
            .trans_proto = submission.facts.ipProtocol,
            .payload = {},
        };
        Context context(request);
        if (context.get() == nullptr) {
            return std::nullopt;
        }

        const auto *payload = reinterpret_cast<const char *>(
            submission.transportPayload.data());
        const auto payload_size = submission.transportPayload.size();
        if (payload_size > static_cast<std::size_t>(
                std::numeric_limits<unsigned int>::max())) {
            return std::nullopt;
        }

        lpi_detect_context_update(
            context.get(),
            payload,
            static_cast<unsigned int>(payload_size),
            false);

        unsigned int stop_detect = 0;
        const int appid = lpi_detect(
            detector_.get(), context.get(), payload, payload_size, &stop_detect);
        const char *raw_name =
            appid > 0 ? lpi_appid2name(detector_.get(), appid) : nullptr;
        if (raw_name == nullptr || raw_name[0] == '\0') {
            return std::nullopt;
        }

        latest_alias_ = aliasFor(raw_name);
        return Protocol::LpiProviderFact{
            .providerAlias = latest_alias_,
            .detectorDone = stop_detect != 0,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        };
    }

private:
    Detector detector_;
    std::string latest_alias_;
};

[[nodiscard]] bool runPipelineCase(const DetectionCase &test_case) {
    Flow::BoundedFlowTable table(1);
    const auto facts = packetFactsFor(test_case);
    if (!table.observeAccepted(facts, 61).has_value()) {
        std::cerr << "pipeline." << test_case.key << ".error=flow-not-created\n";
        return false;
    }

    WrapperProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const auto packet = l3PacketFor(test_case);
    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{packet.data(), packet.size()},
        facts);

    const bool expected_mapped = test_case.expected_sakamoto_protocol.has_value();
    const auto latest = outcome.adapterOutcome.has_value()
        && outcome.adapterOutcome->flowUpdate.has_value()
        ? outcome.adapterOutcome->flowUpdate->latestExactResult
        : std::optional<Catalog::ApplicationProtocolId>{};
    const auto state = table.lpiRecognitionStateFor(facts);

    std::cout << "pipeline." << test_case.key << ".providerAvailable="
              << (outcome.providerAvailable ? "true" : "false") << "\n";
    std::cout << "pipeline." << test_case.key << ".providerProducedFact="
              << (outcome.providerProducedFact ? "true" : "false") << "\n";
    std::cout << "pipeline." << test_case.key << ".mapped="
              << (outcome.adapterOutcome.has_value()
                      && outcome.adapterOutcome->mappedProviderResult
                  ? "true"
                  : "false")
              << "\n";
    std::cout << "pipeline." << test_case.key << ".unmapped="
              << (outcome.adapterOutcome.has_value()
                      && outcome.adapterOutcome->unmappedProviderResult
                  ? "true"
                  : "false")
              << "\n";
    std::cout << "pipeline." << test_case.key << ".payloadPackets="
              << (state.has_value() ? state->payloadPacketsSubmitted : 0U) << "\n";

    const bool common_pass =
        outcome.observed
        && outcome.payloadEligible
        && outcome.providerAvailable
        && outcome.submittedToProvider
        && outcome.providerProducedFact
        && outcome.adapterOutcome.has_value()
        && outcome.adapterOutcome->flowUpdate.has_value()
        && outcome.adapterOutcome->flowUpdate->payloadSubmitted
        && state.has_value()
        && state->payloadPacketsSubmitted == 1U;

    const bool mapping_pass = expected_mapped
        ? outcome.adapterOutcome->mappedProviderResult
            && !outcome.adapterOutcome->unmappedProviderResult
            && latest == test_case.expected_sakamoto_protocol
        : !outcome.adapterOutcome->mappedProviderResult
            && outcome.adapterOutcome->unmappedProviderResult
            && !latest.has_value();
    const bool passed = common_pass && mapping_pass;
    std::cout << "pipeline." << test_case.key << ".result="
              << (passed ? "PASS" : "FAIL") << "\n";
    return passed;
}

} // namespace

int main() {
    const std::vector<DetectionCase> cases = {
        {
            "http",
            "HTTP",
            67,
            Catalog::ApplicationProtocolId::HTTP,
            false,
            49152,
            80,
            6,
            bytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        },
        {
            "dns",
            "DNS",
            32,
            Catalog::ApplicationProtocolId::DNS,
            false,
            49152,
            53,
            17,
            dnsQueryPayload(),
        },
        {
            "socks5",
            "SOCKS",
            8005,
            std::nullopt,
            false,
            49152,
            1080,
            6,
            {0x05, 0x01, 0x00},
        },
    };

    std::cout << "probe.syntheticCases=HTTP,DNS,SOCKS5\n";
    std::cout << "probe.realWrapperCalls=lpi_detector_new,lpi_detect_context_new,lpi_detect_context_update,lpi_detect,lpi_appid2name,lpi_detect_context_free,lpi_detector_free\n";
    std::cout << "probe.sakamotoPipeline=LpiRecognitionPipeline,LpiRecognitionAdapter,BoundedFlowTable\n";

    int passed_count = 0;
    {
        Detector detector;
        if (detector.get() == nullptr) {
            std::cerr << "probe.error=detector-null\n";
            return 2;
        }
        for (const auto &test_case : cases) {
            if (runCase(detector, test_case)) {
                ++passed_count;
            }
        }
    }

    std::cout << "probe.detectedCases=" << passed_count << "\n";
    if (passed_count != static_cast<int>(cases.size())) {
        std::cout << "probe.result=FAIL\n";
        return 3;
    }

    int pipeline_passed_count = 0;
    for (const auto &test_case : cases) {
        if (runPipelineCase(test_case)) {
            ++pipeline_passed_count;
        }
    }

    std::cout << "probe.pipelineCases=" << pipeline_passed_count << "\n";
    if (pipeline_passed_count != static_cast<int>(cases.size())) {
        std::cout << "probe.result=FAIL\n";
        return 4;
    }

    std::cout << "probe.result=PASS\n";
    return 0;
}
CPP

echo "probe=stellar-lpi-wrapper-host-payload"
echo "source=$reference_root"
echo "wrapperRoot=$wrapper_root"
echo "libprotoidentRoot=$libprotoident_root"
echo "buildRoot=$build_root"
echo "wrapperSourceTreeSha256=$(source_tree_sha256 "$wrapper_root")"
echo "libprotoidentSourceTreeSha256=$(source_tree_sha256 "$libprotoident_root")"
echo "source.wrapperCoreC=stellar_lpi_core.c"
echo "source.wrapperExtendC=stellar_lpi_extend.c"
echo "source.libprotoidentTopLevelCc=$(find "$libprotoident_root" -maxdepth 1 -type f -name '*.cc' | wc -l | tr -d ' ')"
echo "source.libprotoidentTcpCc=$(count_sources "$libprotoident_root/tcp/*.cc")"
echo "source.libprotoidentUdpCc=$(count_sources "$libprotoident_root/udp/*.cc")"
echo "policy.copiesSourceIntoRepo=false"
echo "policy.copiesPcapIntoRepo=false"
echo "policy.usesSyntheticPayloads=true"
echo "policy.providerVendoringDecision=false"
echo "policy.providerRuntimeWiring=false"
echo "policy.protocolRuleDecision=false"
echo "probe.scope=host-compile-link-run-synthetic-payload-recognition"
echo "probe.sakamotoPipeline=LpiRecognitionPipeline,LpiRecognitionAdapter,BoundedFlowTable"
echo "probe.wrapper=stellar_lpi_core-plus-extend-with-generated-compat-shim"
echo "probe.generatedUtilsShim=true"
echo "probe.referenceUthashInPlace=true"
echo "probe.payloadBoundary=application-payload-bytes-only"

cmake \
    -S "$generated_source_dir" \
    -B "$cmake_build_dir" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DREPO_ROOT="$repo_root" \
    -DVPP_REFERENCE_ROOT="$reference_root" \
    -DVPP_STELLAR_LPI_ROOT="$wrapper_root" \
    -DLIBPROTOIDENT_SOURCE_ROOT="$libprotoident_root"

if [[ "$configure_only" -ne 0 ]]; then
    echo "probe.result=PASS_CONFIGURE_ONLY"
    exit 0
fi

cmake --build "$cmake_build_dir" --target stellar_lpi_wrapper_host_payload_probe
"$cmake_build_dir/stellar_lpi_wrapper_host_payload_probe"
