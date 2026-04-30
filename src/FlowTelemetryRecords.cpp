/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowTelemetryRecords.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace FlowTelemetryRecords {

static void writeBytes(std::span<std::byte> out, const std::size_t off,
                       std::span<const std::byte> in) noexcept {
    std::memcpy(out.data() + off, in.data(), in.size());
}

bool encodeFlowV1(EncodedPayload &out, const FlowRecordKind kind, const std::uint8_t ctState,
                  const std::uint8_t ctDir, const std::uint8_t reasonId,
                  const std::uint8_t ifaceKindBit, const bool isIpv6,
                  const std::uint64_t timestampNs, const std::uint64_t flowInstanceId,
                  const std::uint64_t recordSeq, const std::uint32_t uid,
                  const std::uint32_t userId, const std::uint32_t ifindex,
                  const std::uint8_t proto, const std::uint16_t srcPort,
                  const std::uint16_t dstPort, const std::span<const std::byte> srcAddr,
                  const std::span<const std::byte> dstAddr, const std::uint64_t totalPackets,
                  const std::uint64_t totalBytes,
                  const std::optional<std::uint32_t> &ruleId) noexcept {
    out = EncodedPayload{};

    const std::size_t wantAddrBytes = isIpv6 ? 16u : 4u;
    if (srcAddr.size() != wantAddrBytes || dstAddr.size() != wantAddrBytes) {
        return false;
    }

    std::span<std::byte> buf(out.bytes.data(), out.bytes.size());
    // Zero out fixed size v1.
    std::fill(buf.begin(), buf.begin() + kFlowV1Bytes, std::byte{0});

    buf[kFlowV1OffsetPayloadVersion] = static_cast<std::byte>(kFlowPayloadVersionV1);
    buf[kFlowV1OffsetKind] = static_cast<std::byte>(kind);
    buf[kFlowV1OffsetCtState] = static_cast<std::byte>(ctState);
    buf[kFlowV1OffsetCtDir] = static_cast<std::byte>(ctDir);
    buf[kFlowV1OffsetReasonId] = static_cast<std::byte>(reasonId);
    buf[kFlowV1OffsetIfaceKindBit] = static_cast<std::byte>(ifaceKindBit);

    std::uint8_t flags = 0;
    if (isIpv6) {
        flags |= kFlowFlagIsIpv6;
    }
    if (ruleId.has_value()) {
        flags |= kFlowFlagHasRuleId;
    }
    buf[kFlowV1OffsetFlags] = static_cast<std::byte>(flags);

    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetTimestampNs, timestampNs);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetFlowInstanceId, flowInstanceId);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetRecordSeq, recordSeq);

    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetUid, uid);
    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetUserId, userId);
    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetIfindex, ifindex);

    buf[kFlowV1OffsetProto] = static_cast<std::byte>(proto);
    FlowTelemetryAbi::writeU16Le(buf, kFlowV1OffsetSrcPort, srcPort);
    FlowTelemetryAbi::writeU16Le(buf, kFlowV1OffsetDstPort, dstPort);

    if (isIpv6) {
        writeBytes(buf, kFlowV1OffsetSrcAddr, srcAddr);
        writeBytes(buf, kFlowV1OffsetDstAddr, dstAddr);
    } else {
        // IPv4 stored in the first 4 bytes, remaining bytes are 0.
        writeBytes(buf, kFlowV1OffsetSrcAddr, srcAddr);
        writeBytes(buf, kFlowV1OffsetDstAddr, dstAddr);
    }

    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetTotalPackets, totalPackets);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetTotalBytes, totalBytes);

    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetRuleId, ruleId.value_or(0u));

    out.size = kFlowV1Bytes;
    return true;
}

bool encodeDnsDecisionV1(EncodedPayload &out, const std::uint64_t timestampNs, const std::uint32_t uid,
                         const std::uint32_t userId, const DomainPolicySource policySource,
                         const std::optional<std::uint32_t> &ruleId,
                         const std::string_view queryName) noexcept {
    out = EncodedPayload{};

    std::uint8_t flags = 0;
    if (ruleId.has_value()) {
        flags |= kDnsDecisionFlagHasRuleId;
    }

    const std::size_t want = queryName.size();
    const std::size_t capped = (want > kDnsDecisionMaxQueryNameBytes) ? kDnsDecisionMaxQueryNameBytes : want;
    if (capped < want) {
        flags |= kDnsDecisionFlagQueryNameTruncated;
    }

    const std::size_t totalBytes = static_cast<std::size_t>(kDnsV1FixedBytes) + capped;
    if (totalBytes > out.bytes.size()) {
        return false;
    }

    std::span<std::byte> buf(out.bytes.data(), out.bytes.size());
    std::fill(buf.begin(), buf.begin() + totalBytes, std::byte{0});

    buf[kDnsV1OffsetPayloadVersion] = static_cast<std::byte>(kDnsDecisionPayloadVersionV1);
    buf[kDnsV1OffsetFlags] = static_cast<std::byte>(flags);
    buf[kDnsV1OffsetPolicySource] = static_cast<std::byte>(policySource);

    FlowTelemetryAbi::writeU16Le(buf, kDnsV1OffsetQueryNameLen, static_cast<std::uint16_t>(capped));
    FlowTelemetryAbi::writeU64Le(buf, kDnsV1OffsetTimestampNs, timestampNs);
    FlowTelemetryAbi::writeU32Le(buf, kDnsV1OffsetUid, uid);
    FlowTelemetryAbi::writeU32Le(buf, kDnsV1OffsetUserId, userId);
    FlowTelemetryAbi::writeU32Le(buf, kDnsV1OffsetRuleId, ruleId.value_or(0u));

    if (capped != 0) {
        const auto in = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(queryName.data()), capped);
        writeBytes(buf, kDnsV1OffsetQueryName, in);
    }

    out.size = static_cast<std::uint32_t>(totalBytes);
    return true;
}

} // namespace FlowTelemetryRecords
