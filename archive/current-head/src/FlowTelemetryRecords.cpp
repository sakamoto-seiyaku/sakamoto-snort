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

bool encodeFlowV1(EncodedPayload &out, const FlowV1Fields &fields) noexcept {
    out = EncodedPayload{};

    const std::size_t wantAddrBytes = fields.isIpv6 ? 16u : 4u;
    if (fields.srcAddr.size() != wantAddrBytes || fields.dstAddr.size() != wantAddrBytes) {
        return false;
    }

    std::span<std::byte> buf(out.bytes.data(), out.bytes.size());
    // Zero out fixed size v1.
    std::fill(buf.begin(), buf.begin() + kFlowV1Bytes, std::byte{0});

    buf[kFlowV1OffsetPayloadVersion] = static_cast<std::byte>(kFlowPayloadVersionV1);
    buf[kFlowV1OffsetKind] = static_cast<std::byte>(fields.kind);
    buf[kFlowV1OffsetObservationKind] = static_cast<std::byte>(fields.observationKind);
    buf[kFlowV1OffsetCtState] = static_cast<std::byte>(fields.ctState);
    buf[kFlowV1OffsetCtDir] = static_cast<std::byte>(fields.ctDir);
    buf[kFlowV1OffsetPacketDir] = static_cast<std::byte>(fields.packetDir);
    buf[kFlowV1OffsetFlowOriginDir] = static_cast<std::byte>(fields.flowOriginDir);
    buf[kFlowV1OffsetVerdict] = static_cast<std::byte>(fields.verdict);
    buf[kFlowV1OffsetReasonId] = static_cast<std::byte>(fields.reasonId);
    buf[kFlowV1OffsetIfaceKindBit] = static_cast<std::byte>(fields.ifaceKindBit);
    buf[kFlowV1OffsetL4Status] = static_cast<std::byte>(fields.l4Status);
    buf[kFlowV1OffsetEndReason] = static_cast<std::byte>(fields.endReason);
    buf[kFlowV1OffsetProto] = static_cast<std::byte>(fields.proto);
    FlowTelemetryAbi::writeU16Le(buf, kFlowV1OffsetSrcPort, fields.portsAvailable ? fields.srcPort : 0u);
    FlowTelemetryAbi::writeU16Le(buf, kFlowV1OffsetDstPort, fields.portsAvailable ? fields.dstPort : 0u);
    buf[kFlowV1OffsetIcmpType] = static_cast<std::byte>(fields.icmpType);
    buf[kFlowV1OffsetIcmpCode] = static_cast<std::byte>(fields.icmpCode);
    FlowTelemetryAbi::writeU16Le(buf, kFlowV1OffsetIcmpId, fields.icmpId);

    std::uint8_t flags = 0;
    if (fields.isIpv6) {
        flags |= kFlowFlagIsIpv6;
    }
    if (fields.ruleId.has_value()) {
        flags |= kFlowFlagHasRuleId;
    }
    if (fields.pickedUpMidStream) {
        flags |= kFlowFlagPickedUpMidStream;
    }
    if (fields.uidKnown) {
        flags |= kFlowFlagUidKnown;
    }
    if (fields.ifindexKnown) {
        flags |= kFlowFlagIfindexKnown;
    }
    if (fields.portsAvailable) {
        flags |= kFlowFlagPortsAvailable;
    }
    buf[kFlowV1OffsetFlags] = static_cast<std::byte>(flags);

    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetTimestampNs, fields.timestampNs);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetFirstSeenNs, fields.firstSeenNs);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetLastSeenNs, fields.lastSeenNs);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetFlowInstanceId, fields.flowInstanceId);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetRecordSeq, fields.recordSeq);

    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetUid, fields.uid);
    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetUserId, fields.userId);
    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetIfindex, fields.ifindex);

    if (fields.isIpv6) {
        writeBytes(buf, kFlowV1OffsetSrcAddr, fields.srcAddr);
        writeBytes(buf, kFlowV1OffsetDstAddr, fields.dstAddr);
    } else {
        // IPv4 stored in the first 4 bytes, remaining bytes are 0.
        writeBytes(buf, kFlowV1OffsetSrcAddr, fields.srcAddr);
        writeBytes(buf, kFlowV1OffsetDstAddr, fields.dstAddr);
    }

    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetTotalPackets, fields.totalPackets);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetTotalBytes, fields.totalBytes);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetInPackets, fields.inPackets);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetInBytes, fields.inBytes);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetOutPackets, fields.outPackets);
    FlowTelemetryAbi::writeU64Le(buf, kFlowV1OffsetOutBytes, fields.outBytes);
    FlowTelemetryAbi::writeU32Le(buf, kFlowV1OffsetRuleId, fields.ruleId.value_or(0u));

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
