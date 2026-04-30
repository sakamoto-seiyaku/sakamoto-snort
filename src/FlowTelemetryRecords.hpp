/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowTelemetryAbi.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <DomainPolicySources.hpp>

namespace FlowTelemetryRecords {

// ---- FLOW payload v1 ---------------------------------------------------------
//
// Payloads are little-endian with explicit offsets; evolution is append-only using payloadVersion.

enum class FlowRecordKind : std::uint8_t {
    Begin = 1,
    Update = 2,
    End = 3,
};

// Flags for FLOW payload v1.
inline constexpr std::uint8_t kFlowFlagHasRuleId = 1u << 0;
inline constexpr std::uint8_t kFlowFlagIsIpv6 = 1u << 1;
inline constexpr std::uint8_t kFlowFlagPickedUpMidStream = 1u << 2; // reserved (future)

// Fixed payload layout (explicit ABI). Offsets are from the beginning of the payload.
inline constexpr std::uint8_t kFlowPayloadVersionV1 = 1;

inline constexpr std::uint32_t kFlowV1OffsetPayloadVersion = 0; // u8
inline constexpr std::uint32_t kFlowV1OffsetKind = 1;           // u8 (FlowRecordKind)
inline constexpr std::uint32_t kFlowV1OffsetCtState = 2;        // u8 (Conntrack::CtState)
inline constexpr std::uint32_t kFlowV1OffsetCtDir = 3;          // u8 (Conntrack::CtDirection)
inline constexpr std::uint32_t kFlowV1OffsetReasonId = 4;       // u8 (PacketReasonId)
inline constexpr std::uint32_t kFlowV1OffsetIfaceKindBit = 5;   // u8 (iface kind bit)
inline constexpr std::uint32_t kFlowV1OffsetFlags = 6;          // u8 (kFlowFlag*)
inline constexpr std::uint32_t kFlowV1OffsetReserved0 = 7;      // u8

inline constexpr std::uint32_t kFlowV1OffsetTimestampNs = 8;    // u64
inline constexpr std::uint32_t kFlowV1OffsetFlowInstanceId = 16; // u64
inline constexpr std::uint32_t kFlowV1OffsetRecordSeq = 24;     // u64

inline constexpr std::uint32_t kFlowV1OffsetUid = 32;           // u32
inline constexpr std::uint32_t kFlowV1OffsetUserId = 36;        // u32
inline constexpr std::uint32_t kFlowV1OffsetIfindex = 40;       // u32

inline constexpr std::uint32_t kFlowV1OffsetProto = 44;         // u8
inline constexpr std::uint32_t kFlowV1OffsetReserved1 = 45;     // u8
inline constexpr std::uint32_t kFlowV1OffsetSrcPort = 46;       // u16
inline constexpr std::uint32_t kFlowV1OffsetDstPort = 48;       // u16

inline constexpr std::uint32_t kFlowV1OffsetSrcAddr = 50;       // 16 bytes (IPv4 uses first 4 bytes)
inline constexpr std::uint32_t kFlowV1OffsetDstAddr = 66;       // 16 bytes (IPv4 uses first 4 bytes)

inline constexpr std::uint32_t kFlowV1OffsetTotalPackets = 82;  // u64
inline constexpr std::uint32_t kFlowV1OffsetTotalBytes = 90;    // u64

inline constexpr std::uint32_t kFlowV1OffsetRuleId = 98;        // u32 (valid only if kFlowFlagHasRuleId)
inline constexpr std::uint32_t kFlowV1Bytes = 102;

static_assert(kFlowV1Bytes <= FlowTelemetryAbi::kMaxPayloadBytes,
              "FLOW payload v1 must fit within one slot");

struct EncodedPayload {
    std::array<std::byte, FlowTelemetryAbi::kMaxPayloadBytes> bytes{};
    std::uint32_t size = 0;

    [[nodiscard]] std::span<const std::byte> span() const noexcept {
        return std::span<const std::byte>(bytes.data(), size);
    }
};

// Encodes one FLOW payload v1 into `out`. Returns false if inputs cannot be encoded.
//
// Address encoding:
// - If isIpv6=false: srcAddr/dstAddr must point to 4 bytes each (IPv4 network order).
// - If isIpv6=true: srcAddr/dstAddr must point to 16 bytes each (IPv6 network order).
bool encodeFlowV1(EncodedPayload &out, FlowRecordKind kind, std::uint8_t ctState, std::uint8_t ctDir,
                  std::uint8_t reasonId, std::uint8_t ifaceKindBit, bool isIpv6,
                  std::uint64_t timestampNs, std::uint64_t flowInstanceId, std::uint64_t recordSeq,
                  std::uint32_t uid, std::uint32_t userId, std::uint32_t ifindex, std::uint8_t proto,
                  std::uint16_t srcPort, std::uint16_t dstPort,
                  std::span<const std::byte> srcAddr, std::span<const std::byte> dstAddr,
                  std::uint64_t totalPackets, std::uint64_t totalBytes,
                  const std::optional<std::uint32_t> &ruleId) noexcept;

// ---- DNS_DECISION payload v1 ------------------------------------------------
//
// DNS_DECISION is blocked-only (for common UI timeline). It is intentionally NOT joined with
// FlowRecord and must not carry response IP details.
//
// Payloads are little-endian with explicit offsets; evolution is append-only using payloadVersion.

inline constexpr std::uint8_t kDnsDecisionPayloadVersionV1 = 1;
inline constexpr std::uint8_t kDnsDecisionFlagHasRuleId = 1u << 0;
inline constexpr std::uint8_t kDnsDecisionFlagQueryNameTruncated = 1u << 1;

inline constexpr std::uint16_t kDnsDecisionMaxQueryNameBytes = 255;

inline constexpr std::uint32_t kDnsV1OffsetPayloadVersion = 0;  // u8
inline constexpr std::uint32_t kDnsV1OffsetFlags = 1;           // u8
inline constexpr std::uint32_t kDnsV1OffsetPolicySource = 2;    // u8 (DomainPolicySource)
inline constexpr std::uint32_t kDnsV1OffsetReserved0 = 3;       // u8
inline constexpr std::uint32_t kDnsV1OffsetQueryNameLen = 4;    // u16
inline constexpr std::uint32_t kDnsV1OffsetReserved1 = 6;       // u16

inline constexpr std::uint32_t kDnsV1OffsetTimestampNs = 8;     // u64
inline constexpr std::uint32_t kDnsV1OffsetUid = 16;            // u32
inline constexpr std::uint32_t kDnsV1OffsetUserId = 20;         // u32
inline constexpr std::uint32_t kDnsV1OffsetRuleId = 24;         // u32 (0 if absent)
inline constexpr std::uint32_t kDnsV1OffsetReserved2 = 28;      // u32
inline constexpr std::uint32_t kDnsV1OffsetQueryName = 32;      // bytes[queryNameLen]

inline constexpr std::uint32_t kDnsV1FixedBytes = 32;

static_assert(kDnsV1FixedBytes + kDnsDecisionMaxQueryNameBytes <= FlowTelemetryAbi::kMaxPayloadBytes,
              "DNS_DECISION payload v1 must fit within one slot");

// Encodes one blocked-only DNS_DECISION payload v1 into `out`. `queryName` is stored as raw bytes
// (not NUL-terminated) and is truncated to 255 bytes when needed (flagged).
bool encodeDnsDecisionV1(EncodedPayload &out, std::uint64_t timestampNs, std::uint32_t uid,
                         std::uint32_t userId, DomainPolicySource policySource,
                         const std::optional<std::uint32_t> &ruleId,
                         std::string_view queryName) noexcept;

} // namespace FlowTelemetryRecords
