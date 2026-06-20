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
// Payloads are little-endian with explicit offsets. FLOW v1 is intentionally replaced in-place
// by the raw-facts-complete layout; do not depend on C++ struct layout for this public ABI.

enum class FlowRecordKind : std::uint8_t {
    Begin = 1,
    Update = 2,
    End = 3,
};

enum class FlowObservationKind : std::uint8_t {
    Normal = 0,
    L3Observation = 1,
};

enum class FlowPacketDirection : std::uint8_t {
    Unknown = 0,
    In = 1,
    Out = 2,
};

enum class FlowVerdict : std::uint8_t {
    Unknown = 0,
    Allow = 1,
    Block = 2,
};

enum class FlowEndReason : std::uint8_t {
    None = 0,
    IdleTimeout = 1,
    TcpEndDetected = 2,
    ResourceEvicted = 3,
    TelemetryDisabled = 4,
};

// Flags for FLOW payload v1.
inline constexpr std::uint8_t kFlowFlagHasRuleId = 1u << 0;
inline constexpr std::uint8_t kFlowFlagIsIpv6 = 1u << 1;
inline constexpr std::uint8_t kFlowFlagPickedUpMidStream = 1u << 2;
inline constexpr std::uint8_t kFlowFlagUidKnown = 1u << 3;
inline constexpr std::uint8_t kFlowFlagIfindexKnown = 1u << 4;
inline constexpr std::uint8_t kFlowFlagPortsAvailable = 1u << 5;

// Fixed payload layout (explicit ABI). Offsets are from the beginning of the payload.
inline constexpr std::uint8_t kFlowPayloadVersionV1 = 1;

inline constexpr std::uint32_t kFlowV1OffsetPayloadVersion = 0;   // u8
inline constexpr std::uint32_t kFlowV1OffsetKind = 1;             // u8 (FlowRecordKind)
inline constexpr std::uint32_t kFlowV1OffsetObservationKind = 2;  // u8 (FlowObservationKind)
inline constexpr std::uint32_t kFlowV1OffsetCtState = 3;          // u8 (Conntrack::CtState)
inline constexpr std::uint32_t kFlowV1OffsetCtDir = 4;            // u8 (Conntrack::CtDirection)
inline constexpr std::uint32_t kFlowV1OffsetPacketDir = 5;        // u8 (FlowPacketDirection)
inline constexpr std::uint32_t kFlowV1OffsetFlowOriginDir = 6;    // u8 (FlowPacketDirection)
inline constexpr std::uint32_t kFlowV1OffsetVerdict = 7;          // u8 (FlowVerdict)
inline constexpr std::uint32_t kFlowV1OffsetReasonId = 8;         // u8 (PacketReasonId)
inline constexpr std::uint32_t kFlowV1OffsetIfaceKindBit = 9;     // u8 (iface kind bit)
inline constexpr std::uint32_t kFlowV1OffsetL4Status = 10;        // u8 (L4Status)
inline constexpr std::uint32_t kFlowV1OffsetFlags = 11;           // u8 (kFlowFlag*)
inline constexpr std::uint32_t kFlowV1OffsetEndReason = 12;       // u8 (FlowEndReason)
inline constexpr std::uint32_t kFlowV1OffsetProto = 13;           // u8
inline constexpr std::uint32_t kFlowV1OffsetSrcPort = 14;         // u16
inline constexpr std::uint32_t kFlowV1OffsetDstPort = 16;         // u16
inline constexpr std::uint32_t kFlowV1OffsetIcmpType = 18;        // u8
inline constexpr std::uint32_t kFlowV1OffsetIcmpCode = 19;        // u8
inline constexpr std::uint32_t kFlowV1OffsetIcmpId = 20;          // u16
inline constexpr std::uint32_t kFlowV1OffsetReserved0 = 22;       // u16

inline constexpr std::uint32_t kFlowV1OffsetTimestampNs = 24;     // u64
inline constexpr std::uint32_t kFlowV1OffsetFirstSeenNs = 32;     // u64
inline constexpr std::uint32_t kFlowV1OffsetLastSeenNs = 40;      // u64
inline constexpr std::uint32_t kFlowV1OffsetFlowInstanceId = 48;  // u64
inline constexpr std::uint32_t kFlowV1OffsetRecordSeq = 56;       // u64

inline constexpr std::uint32_t kFlowV1OffsetUid = 64;             // u32
inline constexpr std::uint32_t kFlowV1OffsetUserId = 68;          // u32
inline constexpr std::uint32_t kFlowV1OffsetIfindex = 72;         // u32

inline constexpr std::uint32_t kFlowV1OffsetSrcAddr = 76;         // 16 bytes (IPv4 uses first 4 bytes)
inline constexpr std::uint32_t kFlowV1OffsetDstAddr = 92;         // 16 bytes (IPv4 uses first 4 bytes)

inline constexpr std::uint32_t kFlowV1OffsetTotalPackets = 108;   // u64
inline constexpr std::uint32_t kFlowV1OffsetTotalBytes = 116;     // u64
inline constexpr std::uint32_t kFlowV1OffsetInPackets = 124;      // u64
inline constexpr std::uint32_t kFlowV1OffsetInBytes = 132;        // u64
inline constexpr std::uint32_t kFlowV1OffsetOutPackets = 140;     // u64
inline constexpr std::uint32_t kFlowV1OffsetOutBytes = 148;       // u64

inline constexpr std::uint32_t kFlowV1OffsetRuleId = 156;         // u32 (valid only if kFlowFlagHasRuleId)
inline constexpr std::uint32_t kFlowV1Bytes = 160;

static_assert(kFlowV1Bytes <= FlowTelemetryAbi::kMaxPayloadBytes,
              "FLOW payload v1 must fit within one slot");

struct EncodedPayload {
    std::array<std::byte, FlowTelemetryAbi::kMaxPayloadBytes> bytes{};
    std::uint32_t size = 0;

    [[nodiscard]] std::span<const std::byte> span() const noexcept {
        return std::span<const std::byte>(bytes.data(), size);
    }
};

struct FlowV1Fields {
    FlowRecordKind kind = FlowRecordKind::Begin;
    FlowObservationKind observationKind = FlowObservationKind::Normal;
    std::uint8_t ctState = 0;
    std::uint8_t ctDir = 0;
    FlowPacketDirection packetDir = FlowPacketDirection::Unknown;
    FlowPacketDirection flowOriginDir = FlowPacketDirection::Unknown;
    FlowVerdict verdict = FlowVerdict::Unknown;
    std::uint8_t reasonId = 0;
    std::uint8_t ifaceKindBit = 0;
    std::uint8_t l4Status = 0;
    FlowEndReason endReason = FlowEndReason::None;
    std::uint8_t proto = 0;
    bool isIpv6 = false;
    bool pickedUpMidStream = false;
    bool uidKnown = false;
    bool ifindexKnown = false;
    bool portsAvailable = false;
    std::uint16_t srcPort = 0;
    std::uint16_t dstPort = 0;
    std::uint8_t icmpType = 0;
    std::uint8_t icmpCode = 0;
    std::uint16_t icmpId = 0;
    std::uint64_t timestampNs = 0;
    std::uint64_t firstSeenNs = 0;
    std::uint64_t lastSeenNs = 0;
    std::uint64_t flowInstanceId = 0;
    std::uint64_t recordSeq = 0;
    std::uint32_t uid = 0;
    std::uint32_t userId = 0;
    std::uint32_t ifindex = 0;
    std::span<const std::byte> srcAddr;
    std::span<const std::byte> dstAddr;
    std::uint64_t totalPackets = 0;
    std::uint64_t totalBytes = 0;
    std::uint64_t inPackets = 0;
    std::uint64_t inBytes = 0;
    std::uint64_t outPackets = 0;
    std::uint64_t outBytes = 0;
    std::optional<std::uint32_t> ruleId = std::nullopt;
};

// Encodes one FLOW payload v1 into `out`. Returns false if inputs cannot be encoded.
//
// Address encoding:
// - If isIpv6=false: srcAddr/dstAddr must point to 4 bytes each (IPv4 network order).
// - If isIpv6=true: srcAddr/dstAddr must point to 16 bytes each (IPv6 network order).
bool encodeFlowV1(EncodedPayload &out, const FlowV1Fields &fields) noexcept;

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
