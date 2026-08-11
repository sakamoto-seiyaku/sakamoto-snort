#!/usr/bin/env bash
set -euo pipefail

# Builds and runs a throwaway host PCAP probe against the modified backup VPP
# stellar_lpi wrapper plus its vendored libprotoident source. The probe reads
# selected reference PCAP/expected JSON files in place, writes generated build
# files only under build-output, and does not wire a Sakamoto product runtime
# provider or import corpus fixtures.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

repo_build_output_root="${repo_root}/build-output"
reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
corpus_root="${VPP_LPI_CORPUS_ROOT:-${reference_root}/test/decoders/stellar_lpi/test_pcap}"
wrapper_root="${VPP_STELLAR_LPI_ROOT:-${reference_root}/src/plugins/stellar_lpi}"
libprotoident_root="${LIBPROTOIDENT_SOURCE_ROOT:-${wrapper_root}/libprotoident}"
build_root_input="${STELLAR_LPI_WRAPPER_HOST_PCAP_PROBE_BUILD_ROOT:-${repo_build_output_root}/protocol-identification/stellar-lpi-wrapper-host-pcap-probe}"
build_root="$build_root_input"
generated_source_dir="$build_root/generated-source"
generated_include_dir="$generated_source_dir/include"
cmake_build_dir="$build_root/cmake"
configure_only=0

show_help() {
    cat <<EOF
Usage: $0 [--configure-only]

Compiles and runs a local host PCAP probe against:
  wrapper:       $wrapper_root
  libprotoident: $libprotoident_root
  corpus:        $corpus_root

Outputs only generated probe files under:
  $build_root

Environment overrides:
  VPP_REFERENCE_ROOT
  VPP_LPI_CORPUS_ROOT
  VPP_STELLAR_LPI_ROOT
  LIBPROTOIDENT_SOURCE_ROOT
  STELLAR_LPI_WRAPPER_HOST_PCAP_PROBE_BUILD_ROOT
EOF
}

path_is_inside_repo_build_output() {
    [[ "$1" == "$2" || "$1" == "$2"/* ]]
}

canonicalize_path() {
    python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve(strict=False))' "$1"
}

validate_selected_expected_json() {
    python3 - \
        "$selected_mixed_expected_json" "$selected_http_pcap" "01-http-not-ftp.pcap" "117.146.23.226:63007-211.95.50.57:80-6-0" "HTTP" "67" "-" "-" "-" \
        "$selected_mixed_expected_json" "$selected_dns_pcap" "37-dns-response-4029-53-115.24.235.11-8.210.152.150.pcap" "115.24.235.11:4029-8.210.152.150:53-17-0" "DNS" "32" "-" "-" "-" \
        "$selected_mixed_expected_json" "$selected_quic_pcap" "21-iquic-29-192.168.50.29.61891-31.13.77.35.443.pcap" "192.168.50.29:61891-31.13.77.35:443-17-0" "QUIC" "2521" "-" "-" "-" \
        "$selected_mixed_expected_json" "$selected_unknown_pcap" "39-pop3-mistake-redis.pcap" "192.168.40.82:41450-192.168.44.230:7002-6-0" "__ABSENT__" "UNKNOWN" "SYMMETRIC" "TCP" "LPI_RESULT_18" \
        "$selected_socks_expected_json" "$selected_socks_pcap" "1-socks45-http-example.pcap" "10.180.156.185:53535-10.180.156.249:1080-6-0" "SOCKS,HTTP" "8005,67" "SYMMETRIC" "TCP" "LPI_RESULT_6" <<'PY'
import json
import pathlib
import sys

raw_cases = sys.argv[1:]
if len(raw_cases) % 9 != 0:
    raise SystemExit("internal error: selected JSON validation cases are malformed")

rows_by_json_path = {}

for offset in range(0, len(raw_cases), 9):
    (
        raw_json_path,
        pcap_path,
        expected_filename,
        expected_session,
        raw_expected_app_names,
        raw_expected_appids,
        expected_flow_direction,
        expected_session_type,
        expected_label,
    ) = raw_cases[offset:offset + 9]
    json_path = pathlib.Path(raw_json_path)
    if json_path not in rows_by_json_path:
        try:
            rows = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise SystemExit(f"failed to parse selected expected JSON {json_path}: {exc}") from exc
        if not isinstance(rows, list):
            raise SystemExit(f"selected expected JSON must contain a top-level array: {json_path}")
        rows_by_json_path[json_path] = rows

    expected_app_names = None if raw_expected_app_names == "__ABSENT__" else raw_expected_app_names.split(",")
    expected_appids = raw_expected_appids if raw_expected_appids == "UNKNOWN" else [
        int(raw) for raw in raw_expected_appids.split(",")
    ]
    expected_app_names_desc = "absent" if expected_app_names is None else expected_app_names
    actual_filename = pathlib.Path(pcap_path).name
    if actual_filename != expected_filename:
        raise SystemExit(
            f"selected fixture mismatch for {raw_expected_app_names}: "
            f"expected {expected_filename}, got {actual_filename}")

    matches = [
        row for row in rows_by_json_path[json_path]
        if isinstance(row, dict)
        and row.get("SESSION_ADDRESS") == expected_session
        and (("APP_NAME" not in row) if expected_app_names is None else row.get("APP_NAME") == expected_app_names)
        and row.get("APP_ID") == expected_appids
        and (expected_flow_direction == "-" or row.get("FLOW_DIRECTION") == expected_flow_direction)
        and (expected_session_type == "-" or row.get("SESSION_TYPE") == expected_session_type)
        and (expected_label == "-" or row.get("LABEL") == expected_label)
    ]
    if not matches:
        raise SystemExit(
            f"missing selected expected JSON row for {raw_expected_app_names}: "
            f"SESSION_ADDRESS={expected_session}, APP_NAME={expected_app_names_desc}, APP_ID={expected_appids}")

print("selectedExpectedJsonValidation=PASS")
PY
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

[[ -d "$reference_root" ]] || {
    echo "missing VPP reference root: $reference_root" >&2
    exit 1
}
[[ -d "$corpus_root" ]] || {
    echo "missing VPP LPI corpus root: $corpus_root" >&2
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
command -v python3 >/dev/null 2>&1 || {
    echo "python3 was not found on PATH" >&2
    exit 1
}
command -v cmake >/dev/null 2>&1 || {
    echo "cmake was not found on PATH" >&2
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
probe_executable_stderr_log="$build_root/stellar_lpi_wrapper_host_pcap_probe.stderr.log"

selected_http_pcap="$corpus_root/mixed_pcap/01-http-not-ftp.pcap"
selected_dns_pcap="$corpus_root/mixed_pcap/37-dns-response-4029-53-115.24.235.11-8.210.152.150.pcap"
selected_quic_pcap="$corpus_root/mixed_pcap/21-iquic-29-192.168.50.29.61891-31.13.77.35.443.pcap"
selected_unknown_pcap="$corpus_root/mixed_pcap/39-pop3-mistake-redis.pcap"
selected_socks_pcap="$corpus_root/socks_pcap/1-socks45-http-example.pcap"
selected_mixed_expected_json="$corpus_root/mixed_pcap/mixed_pcap.json"
selected_socks_expected_json="$corpus_root/socks_pcap/socks_pcap.json"

for selected in "$selected_http_pcap" "$selected_dns_pcap" "$selected_quic_pcap" "$selected_unknown_pcap" "$selected_socks_pcap" "$selected_mixed_expected_json" "$selected_socks_expected_json"; do
    [[ -f "$selected" ]] || {
        echo "missing selected reference fixture: $selected" >&2
        exit 1
    }
done

validate_selected_expected_json

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
project(stellar_lpi_wrapper_host_pcap_probe LANGUAGES C CXX)

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

add_executable(stellar_lpi_wrapper_host_pcap_probe main.cpp)
target_compile_features(stellar_lpi_wrapper_host_pcap_probe PRIVATE cxx_std_20)
target_link_libraries(
  stellar_lpi_wrapper_host_pcap_probe
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
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace Catalog = sucre::protocol;
namespace Flow = SnortDatapath::Flow;
namespace Protocol = SnortDatapath::Protocol;

constexpr std::uint32_t kEthernetLinkType = 1;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint16_t kEtherTypeVlan = 0x8100;
constexpr std::uint8_t kTcpProtocol = 6;
constexpr std::uint8_t kUdpProtocol = 17;

struct Ipv4 {
    std::array<std::uint8_t, 4> bytes{};

    friend bool operator==(const Ipv4 &, const Ipv4 &) = default;
};

struct DetectionCase {
    std::string key;
    std::string pcap_path;
    std::string expected_json_path;
    std::string expected_session_address;
    std::string expected_name;
    int expected_appid;
    std::optional<Catalog::ApplicationProtocolId> expected_sakamoto_protocol;
    std::optional<std::string> expected_followup_name;
    int expected_followup_appid = 0;
    std::optional<Catalog::ApplicationProtocolId> expected_followup_sakamoto_protocol;
    bool expected_no_result = false;
    std::size_t expected_matched_payload_packets = 0;
    Ipv4 client_ip;
    std::uint16_t client_port;
    Ipv4 server_ip;
    std::uint16_t server_port;
    std::uint8_t trans_proto;
};

struct ParsedPacket {
    std::size_t pcap_packet_index = 0;
    std::uint32_t link_type = 0;
    std::vector<std::byte> l3_packet;
    Ipv4 source;
    Ipv4 destination;
    std::uint8_t ip_protocol = 0;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::uint32_t transport_payload_offset = 0;
    std::uint32_t transport_payload_length = 0;
    bool fragmented = false;
};

struct CaseRunResult {
    bool pass = false;
    std::string app_name;
    int appid = 0;
    unsigned int stop_detect = 0;
    std::size_t packets_seen = 0;
    std::size_t matched_payload_packets = 0;
    std::size_t first_matching_packet = 0;
    std::vector<int> appids;
    std::vector<std::string> app_names;
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
    Context(
        bool current_is_s2c_flow,
        std::uint16_t client_port,
        std::uint16_t server_port,
        std::uint8_t trans_proto)
        : context_(lpi_detect_context_new(
              current_is_s2c_flow,
              client_port,
              server_port,
              trans_proto)) {}

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

[[nodiscard]] Ipv4 ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
    return Ipv4{{a, b, c, d}};
}

[[nodiscard]] std::string ipString(const Ipv4 value) {
    std::ostringstream out;
    out << static_cast<int>(value.bytes[0]) << "."
        << static_cast<int>(value.bytes[1]) << "."
        << static_cast<int>(value.bytes[2]) << "."
        << static_cast<int>(value.bytes[3]);
    return out.str();
}

[[nodiscard]] std::uint16_t be16(const std::byte *p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(std::to_integer<unsigned char>(p[0])) << 8U)
        | static_cast<std::uint16_t>(std::to_integer<unsigned char>(p[1])));
}

[[nodiscard]] std::uint32_t le32(const std::byte *p) noexcept {
    return static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[0]))
        | (static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[1])) << 8U)
        | (static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[2])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[3])) << 24U);
}

[[nodiscard]] std::uint32_t be32(const std::byte *p) noexcept {
    return (static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[0])) << 24U)
        | (static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[1])) << 16U)
        | (static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[2])) << 8U)
        | static_cast<std::uint32_t>(std::to_integer<unsigned char>(p[3]));
}

[[nodiscard]] std::string aliasFor(std::string app_name) {
    if (app_name.empty()) {
        return {};
    }
    std::transform(app_name.begin(), app_name.end(), app_name.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return "lpi:" + app_name;
}

void appendUnique(std::vector<std::string> &values, const std::string &value) {
    if (!value.empty()
        && std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

void appendUnique(std::vector<int> &values, const int value) {
    if (value > 0 && std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

[[nodiscard]] std::string join(const std::vector<std::string> &values) {
    std::ostringstream out;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0U) {
            out << ",";
        }
        out << values[index];
    }
    return out.str();
}

[[nodiscard]] std::string join(const std::vector<int> &values) {
    std::ostringstream out;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0U) {
            out << ",";
        }
        out << values[index];
    }
    return out.str();
}

[[nodiscard]] std::vector<std::string> aliasesFor(
    const std::vector<std::string> &app_names) {
    std::vector<std::string> aliases;
    aliases.reserve(app_names.size());
    for (const auto &app_name : app_names) {
        appendUnique(aliases, aliasFor(app_name));
    }
    return aliases;
}

[[nodiscard]] bool containsOrderedDetection(
    const std::vector<std::string> &app_names,
    const std::vector<int> &appids,
    const std::string &first_name,
    const int first_appid,
    const std::string &second_name,
    const int second_appid) {
    bool saw_first = false;
    for (std::size_t index = 0; index < app_names.size() && index < appids.size(); ++index) {
        if (!saw_first
            && app_names[index] == first_name
            && appids[index] == first_appid) {
            saw_first = true;
            continue;
        }
        if (saw_first
            && app_names[index] == second_name
            && appids[index] == second_appid) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool isClientToServer(
    const ParsedPacket &packet,
    const DetectionCase &test_case) noexcept {
    return packet.source == test_case.client_ip
        && packet.destination == test_case.server_ip
        && packet.source_port == test_case.client_port
        && packet.destination_port == test_case.server_port;
}

[[nodiscard]] bool isServerToClient(
    const ParsedPacket &packet,
    const DetectionCase &test_case) noexcept {
    return packet.source == test_case.server_ip
        && packet.destination == test_case.client_ip
        && packet.source_port == test_case.server_port
        && packet.destination_port == test_case.client_port;
}

[[nodiscard]] bool matchesCase(
    const ParsedPacket &packet,
    const DetectionCase &test_case) noexcept {
    return packet.ip_protocol == test_case.trans_proto
        && packet.transport_payload_length > 0
        && !packet.fragmented
        && (isClientToServer(packet, test_case) || isServerToClient(packet, test_case));
}

[[nodiscard]] Flow::PacketFacts packetFactsFor(
    const ParsedPacket &packet,
    const DetectionCase &test_case) noexcept {
    return Flow::PacketFacts{
        .source = Flow::IpAddress::v4(packet.source.bytes),
        .destination = Flow::IpAddress::v4(packet.destination.bytes),
        .ipProtocol = packet.ip_protocol,
        .sourcePort = packet.source_port,
        .destinationPort = packet.destination_port,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = Flow::ParseStatus::Ready,
        .deviceDirection = isClientToServer(packet, test_case)
            ? Flow::DevicePacketDirection::Output
            : Flow::DevicePacketDirection::Input,
        .originalLength = static_cast<std::uint32_t>(packet.l3_packet.size()),
        .boundedPrefixLength = static_cast<std::uint32_t>(packet.l3_packet.size()),
        .transportPayloadOffset = packet.transport_payload_offset,
        .transportPayloadLength = packet.transport_payload_length,
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

[[nodiscard]] std::vector<std::byte> readFile(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open " + path);
    }
    const std::vector<char> chars{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
    std::vector<std::byte> bytes;
    bytes.reserve(chars.size());
    for (const char ch : chars) {
        bytes.push_back(static_cast<std::byte>(
            static_cast<unsigned char>(ch)));
    }
    return bytes;
}

[[nodiscard]] std::vector<ParsedPacket> parsePcap(const std::string &path) {
    const auto data = readFile(path);
    if (data.size() < 24U) {
        throw std::runtime_error("pcap too small: " + path);
    }

    const auto magic_le = le32(data.data());
    const auto magic_be = be32(data.data());
    const bool little_endian = magic_le == 0xa1b2c3d4U || magic_le == 0xa1b23c4dU;
    const bool big_endian = magic_be == 0xa1b2c3d4U || magic_be == 0xa1b23c4dU;
    if (!little_endian && !big_endian) {
        throw std::runtime_error("unsupported pcap magic: " + path);
    }
    const auto read32 = [little_endian](const std::byte *p) {
        return little_endian ? le32(p) : be32(p);
    };
    const auto link_type = read32(data.data() + 20U);

    std::vector<ParsedPacket> packets;
    std::size_t offset = 24U;
    std::size_t packet_index = 0;
    while (offset + 16U <= data.size()) {
        ++packet_index;
        const auto included_length = static_cast<std::size_t>(read32(data.data() + offset + 8U));
        offset += 16U;
        if (offset + included_length > data.size()) {
            throw std::runtime_error("truncated pcap record: " + path);
        }
        const auto *packet = data.data() + offset;
        offset += included_length;

        if (link_type != kEthernetLinkType || included_length < 14U) {
            continue;
        }

        std::size_t l3_offset = 14U;
        auto ether_type = be16(packet + 12U);
        if (ether_type == kEtherTypeVlan) {
            if (included_length < 18U) {
                continue;
            }
            ether_type = be16(packet + 16U);
            l3_offset = 18U;
        }
        if (ether_type != kEtherTypeIpv4 || included_length < l3_offset + 20U) {
            continue;
        }

        const auto *l3 = packet + l3_offset;
        const auto version = std::to_integer<unsigned char>(l3[0]) >> 4U;
        const auto ihl = static_cast<std::size_t>(std::to_integer<unsigned char>(l3[0]) & 0x0fU) * 4U;
        if (version != 4U || ihl < 20U || included_length < l3_offset + ihl) {
            continue;
        }
        const auto total_length = static_cast<std::size_t>(be16(l3 + 2U));
        if (total_length < ihl || included_length < l3_offset + total_length) {
            continue;
        }

        const auto fragment_field = be16(l3 + 6U);
        const bool fragmented = (fragment_field & 0x3fffU) != 0U;
        const auto proto = std::to_integer<unsigned char>(l3[9]);
        if (proto != kTcpProtocol && proto != kUdpProtocol) {
            continue;
        }

        const auto source = Ipv4{{
            std::to_integer<unsigned char>(l3[12]),
            std::to_integer<unsigned char>(l3[13]),
            std::to_integer<unsigned char>(l3[14]),
            std::to_integer<unsigned char>(l3[15]),
        }};
        const auto destination = Ipv4{{
            std::to_integer<unsigned char>(l3[16]),
            std::to_integer<unsigned char>(l3[17]),
            std::to_integer<unsigned char>(l3[18]),
            std::to_integer<unsigned char>(l3[19]),
        }};

        if (total_length < ihl + 4U) {
            continue;
        }
        const auto source_port = be16(l3 + ihl);
        const auto destination_port = be16(l3 + ihl + 2U);

        std::size_t transport_payload_offset = 0U;
        if (proto == kUdpProtocol) {
            if (total_length < ihl + 8U) {
                continue;
            }
            transport_payload_offset = ihl + 8U;
        } else {
            if (total_length < ihl + 20U) {
                continue;
            }
            const auto tcp_header_length =
                static_cast<std::size_t>(std::to_integer<unsigned char>(l3[ihl + 12U]) >> 4U) * 4U;
            if (tcp_header_length < 20U || total_length < ihl + tcp_header_length) {
                continue;
            }
            transport_payload_offset = ihl + tcp_header_length;
        }

        packets.push_back(ParsedPacket{
            .pcap_packet_index = packet_index,
            .link_type = link_type,
            .l3_packet = std::vector<std::byte>(l3, l3 + total_length),
            .source = source,
            .destination = destination,
            .ip_protocol = proto,
            .source_port = source_port,
            .destination_port = destination_port,
            .transport_payload_offset = static_cast<std::uint32_t>(transport_payload_offset),
            .transport_payload_length = static_cast<std::uint32_t>(total_length - transport_payload_offset),
            .fragmented = fragmented,
        });
    }
    return packets;
}

[[nodiscard]] CaseRunResult runWrapperCase(
    Detector &detector,
    const DetectionCase &test_case,
    const std::vector<ParsedPacket> &packets) {
    std::optional<Context> context;
    CaseRunResult result{.packets_seen = packets.size()};

    for (const auto &packet : packets) {
        if (!matchesCase(packet, test_case)) {
            continue;
        }
        if (result.first_matching_packet == 0U) {
            result.first_matching_packet = packet.pcap_packet_index;
        }
        ++result.matched_payload_packets;
        const bool current_is_s2c = isServerToClient(packet, test_case);
        if (!context.has_value()) {
            context.emplace(
                current_is_s2c,
                packet.source_port,
                packet.destination_port,
                test_case.trans_proto);
            if (context->get() == nullptr) {
                std::cerr << "case." << test_case.key << ".error=context-null\n";
                return result;
            }
        }

        const auto payload_offset = static_cast<std::size_t>(packet.transport_payload_offset);
        const auto *payload = reinterpret_cast<const char *>(packet.l3_packet.data() + payload_offset);
        const auto payload_size = static_cast<std::size_t>(packet.transport_payload_length);
        if (payload_size > static_cast<std::size_t>(std::numeric_limits<unsigned int>::max())) {
            std::cerr << "case." << test_case.key << ".error=payload-too-large\n";
            return result;
        }

        lpi_detect_context_update(
            context->get(),
            payload,
            static_cast<unsigned int>(payload_size),
            current_is_s2c);
        const int detected_appid = lpi_detect(
            detector.get(),
            context->get(),
            payload,
            payload_size,
            &result.stop_detect);
        const char *raw_name =
            detected_appid > 0 ? lpi_appid2name(detector.get(), detected_appid) : nullptr;
        const std::string detected_app_name = raw_name != nullptr ? raw_name : "";
        appendUnique(result.appids, detected_appid);
        appendUnique(result.app_names, detected_app_name);
        if (!result.pass) {
            result.appid = detected_appid;
            result.app_name = detected_app_name;
        }
        if (detected_appid == test_case.expected_appid
            && detected_app_name == test_case.expected_name) {
            result.pass = true;
            result.appid = detected_appid;
            result.app_name = detected_app_name;
        }
    }

    if (test_case.expected_no_result) {
        result.pass = !result.appids.empty() ? false
            : !result.app_names.empty() ? false
            : result.appid != 0 ? false
            : !result.app_name.empty() ? false
            : test_case.expected_matched_payload_packets == 0U
                ? result.matched_payload_packets > 0U
                : result.matched_payload_packets == test_case.expected_matched_payload_packets;
        return result;
    }

    if (test_case.expected_followup_name.has_value()) {
        result.pass = result.pass && containsOrderedDetection(
            result.app_names,
            result.appids,
            test_case.expected_name,
            test_case.expected_appid,
            *test_case.expected_followup_name,
            test_case.expected_followup_appid);
    }
    return result;
}

class WrapperProvider final : public Protocol::LpiRecognitionProvider {
public:
    explicit WrapperProvider(const DetectionCase &test_case) : test_case_(test_case) {}

    [[nodiscard]] bool available() const noexcept override {
        return detector_.get() != nullptr;
    }

    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "backup-vpp-stellar-lpi-wrapper-pcap";
    }

    [[nodiscard]] std::string_view latestAlias() const noexcept {
        return latest_alias_;
    }

    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        const auto packet = packetView(submission.facts);
        if (!packet.has_value()) {
            return std::nullopt;
        }
        const bool current_is_s2c = isServerToClient(*packet, test_case_);
        if (!context_.has_value()) {
            context_.emplace(
                current_is_s2c,
                submission.facts.sourcePort,
                submission.facts.destinationPort,
                test_case_.trans_proto);
            if (context_->get() == nullptr) {
                return std::nullopt;
            }
        }

        const auto *payload = reinterpret_cast<const char *>(
            submission.transportPayload.data());
        const auto payload_size = submission.transportPayload.size();
        if (payload_size > static_cast<std::size_t>(
                std::numeric_limits<unsigned int>::max())) {
            return std::nullopt;
        }
        lpi_detect_context_update(
            context_->get(),
            payload,
            static_cast<unsigned int>(payload_size),
            current_is_s2c);
        unsigned int stop_detect = 0;
        const int appid = lpi_detect(
            detector_.get(),
            context_->get(),
            payload,
            payload_size,
            &stop_detect);
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
    [[nodiscard]] static std::optional<ParsedPacket> packetView(
        const Flow::PacketFacts &facts) noexcept {
        if (!facts.portsAvailable || facts.parseStatus != Flow::ParseStatus::Ready) {
            return std::nullopt;
        }
        auto toIpv4 = [](const Flow::IpAddress &address) -> std::optional<Ipv4> {
            if (address.family != Flow::AddressFamily::Ipv4) {
                return std::nullopt;
            }
            return Ipv4{{address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3]}};
        };
        auto source = toIpv4(facts.source);
        auto destination = toIpv4(facts.destination);
        if (!source.has_value() || !destination.has_value()) {
            return std::nullopt;
        }
        return ParsedPacket{
            .source = *source,
            .destination = *destination,
            .ip_protocol = facts.ipProtocol,
            .source_port = facts.sourcePort,
            .destination_port = facts.destinationPort,
            .transport_payload_offset = facts.transportPayloadOffset,
            .transport_payload_length = facts.transportPayloadLength,
            .fragmented = facts.fragmented,
        };
    }

    const DetectionCase &test_case_;
    Detector detector_;
    std::optional<Context> context_;
    std::string latest_alias_;
};

[[nodiscard]] bool runPipelineCase(
    const DetectionCase &test_case,
    const std::vector<ParsedPacket> &packets) {
    Flow::BoundedFlowTable table(1);
    WrapperProvider provider(test_case);
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);

    std::size_t submitted_payload_packets = 0;
    std::optional<Catalog::ApplicationProtocolId> latest;
    std::optional<Protocol::LpiPipelineOutcome> latest_outcome;
    std::optional<Flow::PacketFacts> state_query_facts;
    std::vector<std::string> provider_aliases;
    bool saw_expected_mapped = false;
    bool saw_expected_unmapped = false;
    bool saw_mapped = false;
    bool saw_unmapped = false;
    bool saw_mapped_after_unmapped = false;
    bool saw_expected_followup_mapped_after_unmapped = false;
    bool saw_payload_eligible = false;
    bool saw_submitted_to_provider = false;
    bool saw_provider_produced_fact = false;
    for (const auto &packet : packets) {
        if (!matchesCase(packet, test_case)) {
            continue;
        }
        const auto facts = packetFactsFor(packet, test_case);
        if (!state_query_facts.has_value()) {
            state_query_facts = facts;
        }
        if (!table.observeAccepted(facts, 61).has_value()) {
            std::cerr << "pipeline." << test_case.key << ".error=flow-not-created\n";
            return false;
        }
        const auto outcome = pipeline.submitBeforeAdapterCompletion(
            std::span<const std::byte>{packet.l3_packet.data(), packet.l3_packet.size()},
            facts);
        latest_outcome = outcome;
        saw_payload_eligible = saw_payload_eligible || outcome.payloadEligible;
        saw_submitted_to_provider = saw_submitted_to_provider || outcome.submittedToProvider;
        saw_provider_produced_fact =
            saw_provider_produced_fact || outcome.providerProducedFact;
        if (outcome.payloadEligible && outcome.submittedToProvider) {
            ++submitted_payload_packets;
        }
        if (outcome.adapterOutcome.has_value()
            && outcome.adapterOutcome->flowUpdate.has_value()) {
            latest = outcome.adapterOutcome->flowUpdate->latestExactResult;
        }
        if (outcome.providerProducedFact) {
            appendUnique(provider_aliases, std::string{provider.latestAlias()});
        }
        if (outcome.adapterOutcome.has_value()
            && outcome.adapterOutcome->mappedProviderResult
            && latest == test_case.expected_sakamoto_protocol) {
            saw_expected_mapped = true;
        }
        if (outcome.adapterOutcome.has_value()
            && outcome.adapterOutcome->mappedProviderResult) {
            saw_mapped = true;
        }
        if (outcome.adapterOutcome.has_value()
            && outcome.adapterOutcome->unmappedProviderResult) {
            saw_unmapped = true;
            if (provider.latestAlias() == aliasFor(test_case.expected_name)) {
                saw_expected_unmapped = true;
            }
        } else if (outcome.adapterOutcome.has_value()
            && outcome.adapterOutcome->mappedProviderResult
            && saw_unmapped) {
            saw_mapped_after_unmapped = true;
            if (test_case.expected_followup_sakamoto_protocol.has_value()
                && saw_expected_unmapped
                && latest == test_case.expected_followup_sakamoto_protocol) {
                saw_expected_followup_mapped_after_unmapped = true;
            }
        }
        if (test_case.expected_sakamoto_protocol.has_value()
            && saw_expected_mapped) {
            break;
        }
    }

    const auto state = state_query_facts.has_value()
        ? table.lpiRecognitionStateFor(*state_query_facts)
        : std::optional<Flow::LpiRecognitionState>{};

    const bool expected_mapped = test_case.expected_sakamoto_protocol.has_value();
    const bool expected_followup_mapped =
        test_case.expected_followup_sakamoto_protocol.has_value();
    const auto status = pipeline.status();
    const bool expected_payload_count_pass =
        test_case.expected_matched_payload_packets == 0U
            ? submitted_payload_packets > 0U
            : submitted_payload_packets == test_case.expected_matched_payload_packets;
    const bool mapping_pass = test_case.expected_no_result
        ? latest_outcome.has_value()
            && state.has_value()
            && expected_payload_count_pass
            && saw_payload_eligible
            && saw_submitted_to_provider
            && !saw_provider_produced_fact
            && !saw_mapped
            && !saw_unmapped
            && !latest.has_value()
            && !state->latestExactResult().has_value()
            && status.counters.providerNoResultPackets == submitted_payload_packets
        : expected_mapped
            ? saw_expected_mapped
            : expected_followup_mapped
                ? saw_expected_unmapped
                    && saw_expected_followup_mapped_after_unmapped
                    && state.has_value()
                    && state->latestExactResult() == test_case.expected_followup_sakamoto_protocol
                : saw_expected_unmapped;
    const bool passed = latest_outcome.has_value()
        && state.has_value()
        && expected_payload_count_pass
        && mapping_pass;

    std::cout << "pipeline." << test_case.key << ".submittedPayloadPackets="
              << submitted_payload_packets << "\n";
    std::cout << "pipeline." << test_case.key << ".payloadEligible="
              << (saw_payload_eligible ? "true" : "false") << "\n";
    std::cout << "pipeline." << test_case.key << ".submittedToProvider="
              << (saw_submitted_to_provider ? "true" : "false") << "\n";
    std::cout << "pipeline." << test_case.key << ".providerProducedFact="
              << (saw_provider_produced_fact ? "true" : "false") << "\n";
    std::cout << "pipeline." << test_case.key << ".mapped="
              << ((saw_expected_mapped || saw_expected_followup_mapped_after_unmapped)
                      ? "true"
                      : "false")
              << "\n";
    std::cout << "pipeline." << test_case.key << ".unmapped="
              << (saw_expected_unmapped ? "true" : "false")
              << "\n";
    std::cout << "pipeline." << test_case.key << ".providerAliases="
              << join(provider_aliases)
              << "\n";
    std::cout << "pipeline." << test_case.key << ".mappedAfterUnmapped="
              << (saw_mapped_after_unmapped ? "true" : "false")
              << "\n";
    std::cout << "pipeline." << test_case.key << ".latestProtocol="
              << (latest.has_value() ? Catalog::applicationProtocolKey(*latest) : "none")
              << "\n";
    std::cout << "pipeline." << test_case.key << ".providerNoResultPackets="
              << status.counters.providerNoResultPackets << "\n";
    std::cout << "pipeline." << test_case.key << ".result="
              << (passed ? "PASS" : "FAIL") << "\n";
    return passed;
}

[[nodiscard]] bool runCase(const DetectionCase &test_case) {
    const auto packets = parsePcap(test_case.pcap_path);
    Detector detector;
    if (detector.get() == nullptr) {
        std::cerr << "case." << test_case.key << ".error=detector-null\n";
        return false;
    }

    const auto wrapper = runWrapperCase(detector, test_case, packets);
    const bool pipeline_passed = runPipelineCase(test_case, packets);
    const bool passed = wrapper.pass && pipeline_passed;

    std::cout << "case." << test_case.key << ".pcap=" << test_case.pcap_path << "\n";
    std::cout << "case." << test_case.key << ".expectedJson=" << test_case.expected_json_path << "\n";
    std::cout << "case." << test_case.key << ".expectedSessionAddress="
              << test_case.expected_session_address << "\n";
    std::cout << "case." << test_case.key << ".linkType=1\n";
    std::cout << "case." << test_case.key << ".linkTypeName=DLT_EN10MB\n";
    std::cout << "case." << test_case.key << ".l3=IPv4\n";
    std::cout << "case." << test_case.key << ".transportProtocol="
              << static_cast<int>(test_case.trans_proto) << "\n";
    std::cout << "case." << test_case.key << ".client="
              << ipString(test_case.client_ip) << ":" << test_case.client_port << "\n";
    std::cout << "case." << test_case.key << ".server="
              << ipString(test_case.server_ip) << ":" << test_case.server_port << "\n";
    std::cout << "case." << test_case.key << ".pcapPacketsParsed=" << packets.size() << "\n";
    std::cout << "case." << test_case.key << ".matchedPayloadPackets="
              << wrapper.matched_payload_packets << "\n";
    std::cout << "case." << test_case.key << ".firstMatchingPcapPacket="
              << wrapper.first_matching_packet << "\n";
    std::cout << "case." << test_case.key << ".expectedName="
              << (test_case.expected_no_result ? "absent" : test_case.expected_name)
              << "\n";
    std::cout << "case." << test_case.key << ".expectedAppId="
              << (test_case.expected_no_result
                      ? std::string{"UNKNOWN"}
                      : std::to_string(test_case.expected_appid))
              << "\n";
    std::cout << "case." << test_case.key << ".expectedNoResult="
              << (test_case.expected_no_result ? "true" : "false") << "\n";
    if (test_case.expected_followup_name.has_value()) {
        std::cout << "case." << test_case.key << ".expectedFollowupName="
                  << *test_case.expected_followup_name << "\n";
        std::cout << "case." << test_case.key << ".expectedFollowupAppId="
                  << test_case.expected_followup_appid << "\n";
    }
    std::cout << "case." << test_case.key << ".appId=" << wrapper.appid << "\n";
    std::cout << "case." << test_case.key << ".appName=" << wrapper.app_name << "\n";
    std::cout << "case." << test_case.key << ".alias=" << aliasFor(wrapper.app_name) << "\n";
    std::cout << "case." << test_case.key << ".appIds=" << join(wrapper.appids) << "\n";
    std::cout << "case." << test_case.key << ".appNames=" << join(wrapper.app_names) << "\n";
    std::cout << "case." << test_case.key << ".aliases="
              << join(aliasesFor(wrapper.app_names)) << "\n";
    std::cout << "case." << test_case.key << ".stopDetect=" << wrapper.stop_detect << "\n";
    std::cout << "case." << test_case.key << ".result="
              << (passed ? "PASS" : "FAIL") << "\n";
    return passed;
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <vpp-lpi-corpus-root>\n";
        return 2;
    }

    const std::string corpus_root = argv[1];
    const std::string mixed_json = corpus_root + "/mixed_pcap/mixed_pcap.json";
    const std::string socks_json = corpus_root + "/socks_pcap/socks_pcap.json";
    const std::vector<DetectionCase> cases = {
        {
            .key = "http",
            .pcap_path = corpus_root + "/mixed_pcap/01-http-not-ftp.pcap",
            .expected_json_path = mixed_json,
            .expected_session_address = "117.146.23.226:63007-211.95.50.57:80-6-0",
            .expected_name = "HTTP",
            .expected_appid = 67,
            .expected_sakamoto_protocol = Catalog::ApplicationProtocolId::HTTP,
            .client_ip = ip(117, 146, 23, 226),
            .client_port = 63007,
            .server_ip = ip(211, 95, 50, 57),
            .server_port = 80,
            .trans_proto = kTcpProtocol,
        },
        {
            .key = "dns",
            .pcap_path = corpus_root + "/mixed_pcap/37-dns-response-4029-53-115.24.235.11-8.210.152.150.pcap",
            .expected_json_path = mixed_json,
            .expected_session_address = "115.24.235.11:4029-8.210.152.150:53-17-0",
            .expected_name = "DNS",
            .expected_appid = 32,
            .expected_sakamoto_protocol = Catalog::ApplicationProtocolId::DNS,
            .client_ip = ip(115, 24, 235, 11),
            .client_port = 4029,
            .server_ip = ip(8, 210, 152, 150),
            .server_port = 53,
            .trans_proto = kUdpProtocol,
        },
        {
            .key = "quic",
            .pcap_path = corpus_root + "/mixed_pcap/21-iquic-29-192.168.50.29.61891-31.13.77.35.443.pcap",
            .expected_json_path = mixed_json,
            .expected_session_address = "192.168.50.29:61891-31.13.77.35:443-17-0",
            .expected_name = "QUIC",
            .expected_appid = 2521,
            .expected_sakamoto_protocol = Catalog::ApplicationProtocolId::QUIC,
            .client_ip = ip(192, 168, 50, 29),
            .client_port = 61891,
            .server_ip = ip(31, 13, 77, 35),
            .server_port = 443,
            .trans_proto = kUdpProtocol,
        },
        {
            .key = "unknown",
            .pcap_path = corpus_root + "/mixed_pcap/39-pop3-mistake-redis.pcap",
            .expected_json_path = mixed_json,
            .expected_session_address = "192.168.40.82:41450-192.168.44.230:7002-6-0",
            .expected_name = "",
            .expected_appid = 0,
            .expected_sakamoto_protocol = std::nullopt,
            .expected_no_result = true,
            .expected_matched_payload_packets = 4,
            .client_ip = ip(192, 168, 40, 82),
            .client_port = 41450,
            .server_ip = ip(192, 168, 44, 230),
            .server_port = 7002,
            .trans_proto = kTcpProtocol,
        },
        {
            .key = "socks",
            .pcap_path = corpus_root + "/socks_pcap/1-socks45-http-example.pcap",
            .expected_json_path = socks_json,
            .expected_session_address = "10.180.156.185:53535-10.180.156.249:1080-6-0",
            .expected_name = "SOCKS",
            .expected_appid = 8005,
            .expected_sakamoto_protocol = std::nullopt,
            .expected_followup_name = "HTTP",
            .expected_followup_appid = 67,
            .expected_followup_sakamoto_protocol = Catalog::ApplicationProtocolId::HTTP,
            .client_ip = ip(10, 180, 156, 185),
            .client_port = 53535,
            .server_ip = ip(10, 180, 156, 249),
            .server_port = 1080,
            .trans_proto = kTcpProtocol,
        },
    };

    std::cout << "probe.realPcapCases=HTTP,DNS,QUIC,UNKNOWN,SOCKS\n";
    std::cout << "probe.realWrapperCalls=lpi_detector_new,lpi_detect_context_new,lpi_detect_context_update,lpi_detect,lpi_appid2name,lpi_detect_context_free,lpi_detector_free\n";
    std::cout << "probe.sakamotoPipeline=LpiRecognitionPipeline,LpiRecognitionAdapter,BoundedFlowTable\n";

    int passed_count = 0;
    for (const auto &test_case : cases) {
        if (runCase(test_case)) {
            ++passed_count;
        }
    }

    std::cout << "probe.detectedCases=" << passed_count << "\n";
    if (passed_count != static_cast<int>(cases.size())) {
        std::cout << "probe.result=FAIL\n";
        return 3;
    }

    std::cout << "probe.result=PASS\n";
    return 0;
}
CPP

echo "probe=stellar-lpi-wrapper-host-pcap"
echo "source=$reference_root"
echo "corpusRoot=$corpus_root"
echo "wrapperRoot=$wrapper_root"
echo "libprotoidentRoot=$libprotoident_root"
echo "buildRoot=$build_root"
echo "wrapperSourceTreeSha256=$(source_tree_sha256 "$wrapper_root")"
echo "libprotoidentSourceTreeSha256=$(source_tree_sha256 "$libprotoident_root")"
echo "selectedPcap.http=mixed_pcap/01-http-not-ftp.pcap"
echo "selectedPcap.dns=mixed_pcap/37-dns-response-4029-53-115.24.235.11-8.210.152.150.pcap"
echo "selectedPcap.quic=mixed_pcap/21-iquic-29-192.168.50.29.61891-31.13.77.35.443.pcap"
echo "selectedPcap.unknown=mixed_pcap/39-pop3-mistake-redis.pcap"
echo "selectedPcap.socks=socks_pcap/1-socks45-http-example.pcap"
echo "selectedExpectedJson=mixed_pcap/mixed_pcap.json,socks_pcap/socks_pcap.json"
echo "selectedExpectedRows=HTTP,DNS,QUIC,UNKNOWN,SOCKS+HTTP"
echo "source.wrapperCoreC=stellar_lpi_core.c"
echo "source.wrapperExtendC=stellar_lpi_extend.c"
echo "source.libprotoidentTopLevelCc=$(find "$libprotoident_root" -maxdepth 1 -type f -name '*.cc' | wc -l | tr -d ' ')"
echo "source.libprotoidentTcpCc=$(count_sources "$libprotoident_root/tcp/*.cc")"
echo "source.libprotoidentUdpCc=$(count_sources "$libprotoident_root/udp/*.cc")"
echo "policy.copiesSourceIntoRepo=false"
echo "policy.copiesPcapIntoRepo=false"
echo "policy.copiesExpectedJsonIntoRepo=false"
echo "policy.usesReferencePcapInPlace=true"
echo "policy.providerVendoringDecision=false"
echo "policy.providerRuntimeWiring=false"
echo "policy.protocolRuleDecision=false"
echo "probe.scope=host-compile-link-run-selected-reference-pcap-recognition"
echo "probe.sakamotoPipeline=LpiRecognitionPipeline,LpiRecognitionAdapter,BoundedFlowTable"
echo "probe.wrapper=stellar_lpi_core-plus-extend-with-generated-compat-shim"
echo "probe.generatedUtilsShim=true"
echo "probe.referenceUthashInPlace=true"
echo "probe.packetParser=classic-pcap-ethernet-ipv4-tcp-udp"
echo "probe.corpusAccuracyClaim=false"

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

cmake --build "$cmake_build_dir" --target stellar_lpi_wrapper_host_pcap_probe

probe_executable="$cmake_build_dir/stellar_lpi_wrapper_host_pcap_probe"
set +e
"$probe_executable" "$corpus_root" 2>"$probe_executable_stderr_log"
probe_executable_status=$?
set -e

probe_executable_stderr_line_count="$(wc -l <"$probe_executable_stderr_log" | tr -d ' ')"
echo "probe.executableStderrLog=$probe_executable_stderr_log"
echo "probe.executableStderrLineCount=$probe_executable_stderr_line_count"

if [[ "$probe_executable_status" -ne 0 ]]; then
    if [[ -s "$probe_executable_stderr_log" ]]; then
        echo "generated executable stderr follows: $probe_executable_stderr_log" >&2
        sed 's/^/[stellar_lpi_wrapper_host_pcap_probe stderr] /' \
            "$probe_executable_stderr_log" >&2
    else
        echo "generated executable produced no stderr: $probe_executable_stderr_log" >&2
    fi
    exit "$probe_executable_status"
fi
