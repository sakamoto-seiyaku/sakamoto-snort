/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowTelemetryRecords.hpp>

#include <gtest/gtest.h>

#include <arpa/inet.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

using namespace FlowTelemetryRecords;

namespace {

std::array<std::byte, 4> ipv4Bytes(const std::uint32_t hostOrder) {
    const std::uint32_t net = htonl(hostOrder);
    std::array<std::byte, 4> out{};
    std::memcpy(out.data(), &net, out.size());
    return out;
}

FlowV1Fields baseFlowFields(std::span<const std::byte> src, std::span<const std::byte> dst) {
    FlowV1Fields f{};
    f.kind = FlowRecordKind::Begin;
    f.observationKind = FlowObservationKind::Normal;
    f.ctState = 1;
    f.ctDir = 1;
    f.packetDir = FlowPacketDirection::In;
    f.flowOriginDir = FlowPacketDirection::In;
    f.verdict = FlowVerdict::Allow;
    f.reasonId = 2;
    f.ifaceKindBit = 0x2;
    f.l4Status = 0;
    f.proto = 6;
    f.portsAvailable = true;
    f.srcPort = 1000;
    f.dstPort = 80;
    f.timestampNs = 123;
    f.firstSeenNs = 111;
    f.lastSeenNs = 123;
    f.flowInstanceId = 456;
    f.recordSeq = 7;
    f.uid = 10123;
    f.userId = 0;
    f.uidKnown = true;
    f.ifindex = 5;
    f.ifindexKnown = true;
    f.srcAddr = src;
    f.dstAddr = dst;
    f.totalPackets = 9;
    f.totalBytes = 10;
    f.inPackets = 6;
    f.inBytes = 7;
    f.outPackets = 3;
    f.outBytes = 3;
    return f;
}

} // namespace

TEST(FlowTelemetryRecords, FlowV1ReplacementLayoutConstantsMatchSpec) {
    EXPECT_EQ(kFlowV1Bytes, 160u);
    EXPECT_LE(kFlowV1Bytes, FlowTelemetryAbi::kMaxPayloadBytes);
    EXPECT_EQ(kFlowV1OffsetPayloadVersion, 0u);
    EXPECT_EQ(kFlowV1OffsetKind, 1u);
    EXPECT_EQ(kFlowV1OffsetObservationKind, 2u);
    EXPECT_EQ(kFlowV1OffsetCtState, 3u);
    EXPECT_EQ(kFlowV1OffsetCtDir, 4u);
    EXPECT_EQ(kFlowV1OffsetPacketDir, 5u);
    EXPECT_EQ(kFlowV1OffsetFlowOriginDir, 6u);
    EXPECT_EQ(kFlowV1OffsetVerdict, 7u);
    EXPECT_EQ(kFlowV1OffsetReasonId, 8u);
    EXPECT_EQ(kFlowV1OffsetIfaceKindBit, 9u);
    EXPECT_EQ(kFlowV1OffsetL4Status, 10u);
    EXPECT_EQ(kFlowV1OffsetFlags, 11u);
    EXPECT_EQ(kFlowV1OffsetEndReason, 12u);
    EXPECT_EQ(kFlowV1OffsetProto, 13u);
    EXPECT_EQ(kFlowV1OffsetSrcPort, 14u);
    EXPECT_EQ(kFlowV1OffsetDstPort, 16u);
    EXPECT_EQ(kFlowV1OffsetIcmpType, 18u);
    EXPECT_EQ(kFlowV1OffsetIcmpCode, 19u);
    EXPECT_EQ(kFlowV1OffsetIcmpId, 20u);
    EXPECT_EQ(kFlowV1OffsetTimestampNs, 24u);
    EXPECT_EQ(kFlowV1OffsetFirstSeenNs, 32u);
    EXPECT_EQ(kFlowV1OffsetLastSeenNs, 40u);
    EXPECT_EQ(kFlowV1OffsetFlowInstanceId, 48u);
    EXPECT_EQ(kFlowV1OffsetRecordSeq, 56u);
    EXPECT_EQ(kFlowV1OffsetUid, 64u);
    EXPECT_EQ(kFlowV1OffsetUserId, 68u);
    EXPECT_EQ(kFlowV1OffsetIfindex, 72u);
    EXPECT_EQ(kFlowV1OffsetSrcAddr, 76u);
    EXPECT_EQ(kFlowV1OffsetDstAddr, 92u);
    EXPECT_EQ(kFlowV1OffsetTotalPackets, 108u);
    EXPECT_EQ(kFlowV1OffsetTotalBytes, 116u);
    EXPECT_EQ(kFlowV1OffsetInPackets, 124u);
    EXPECT_EQ(kFlowV1OffsetInBytes, 132u);
    EXPECT_EQ(kFlowV1OffsetOutPackets, 140u);
    EXPECT_EQ(kFlowV1OffsetOutBytes, 148u);
    EXPECT_EQ(kFlowV1OffsetRuleId, 156u);
}

TEST(FlowTelemetryRecords, EncodesFlowV1Ipv4TcpRawFacts) {
    EncodedPayload payload{};
    const auto src = ipv4Bytes(0x0A000001u);
    const auto dst = ipv4Bytes(0xC0A80102u);
    FlowV1Fields f = baseFlowFields(src, dst);

    ASSERT_TRUE(encodeFlowV1(payload, f));
    ASSERT_EQ(payload.size, kFlowV1Bytes);

    const auto bytes = payload.span();
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetPayloadVersion]), kFlowPayloadVersionV1);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowRecordKind::Begin));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetObservationKind]),
              static_cast<std::uint8_t>(FlowObservationKind::Normal));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetPacketDir]),
              static_cast<std::uint8_t>(FlowPacketDirection::In));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlowOriginDir]),
              static_cast<std::uint8_t>(FlowPacketDirection::In));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetVerdict]),
              static_cast<std::uint8_t>(FlowVerdict::Allow));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagHasRuleId, 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagIsIpv6, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagUidKnown, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagIfindexKnown, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagPortsAvailable, 0u);

    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetSrcPort), 1000u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetDstPort), 80u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetTimestampNs), 123u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetFirstSeenNs), 111u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetLastSeenNs), 123u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetFlowInstanceId), 456u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetRecordSeq), 7u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetUid), 10123u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetIfindex), 5u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetTotalPackets), 9u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetTotalBytes), 10u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetInPackets), 6u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetInBytes), 7u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetOutPackets), 3u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetOutBytes), 3u);

    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(bytes[kFlowV1OffsetSrcAddr + i], src[i]);
        EXPECT_EQ(bytes[kFlowV1OffsetDstAddr + i], dst[i]);
    }
    for (size_t i = 4; i < 16; ++i) {
        EXPECT_EQ(bytes[kFlowV1OffsetSrcAddr + i], std::byte{0});
        EXPECT_EQ(bytes[kFlowV1OffsetDstAddr + i], std::byte{0});
    }
}

TEST(FlowTelemetryRecords, EncodesFlowV1RuleIdZeroAsPresent) {
    EncodedPayload payload{};
    const auto src = ipv4Bytes(0x0A000001u);
    const auto dst = ipv4Bytes(0xC0A80102u);
    FlowV1Fields f = baseFlowFields(src, dst);
    f.ruleId = 0u;

    ASSERT_TRUE(encodeFlowV1(payload, f));

    const auto bytes = payload.span();
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagHasRuleId, 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetRuleId), 0u);
}

TEST(FlowTelemetryRecords, EncodesFlowV1Ipv6UdpWithRuleAndOutDirection) {
    EncodedPayload payload{};
    std::array<std::byte, 16> src{};
    std::array<std::byte, 16> dst{};
    for (size_t i = 0; i < 16; ++i) {
        src[i] = static_cast<std::byte>(i);
        dst[i] = static_cast<std::byte>(0xF0u + i);
    }
    FlowV1Fields f = baseFlowFields(src, dst);
    f.kind = FlowRecordKind::Update;
    f.isIpv6 = true;
    f.packetDir = FlowPacketDirection::Out;
    f.flowOriginDir = FlowPacketDirection::In;
    f.verdict = FlowVerdict::Block;
    f.proto = 17;
    f.srcPort = 5353;
    f.dstPort = 5353;
    f.ruleId = 123u;
    f.pickedUpMidStream = true;

    ASSERT_TRUE(encodeFlowV1(payload, f));

    const auto bytes = payload.span();
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagIsIpv6, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagHasRuleId, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagPickedUpMidStream, 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetPacketDir]),
              static_cast<std::uint8_t>(FlowPacketDirection::Out));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetVerdict]),
              static_cast<std::uint8_t>(FlowVerdict::Block));
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetRuleId), 123u);
    for (size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(bytes[kFlowV1OffsetSrcAddr + i], src[i]);
        EXPECT_EQ(bytes[kFlowV1OffsetDstAddr + i], dst[i]);
    }
}

TEST(FlowTelemetryRecords, EncodesFlowV1IcmpFactsWithoutPorts) {
    EncodedPayload payload{};
    const auto src = ipv4Bytes(0x0A000001u);
    const auto dst = ipv4Bytes(0x0A000002u);
    FlowV1Fields f = baseFlowFields(src, dst);
    f.proto = 1;
    f.portsAvailable = false;
    f.srcPort = 1000;
    f.dstPort = 80;
    f.icmpType = 8;
    f.icmpCode = 0;
    f.icmpId = 0x1234;

    ASSERT_TRUE(encodeFlowV1(payload, f));
    const auto bytes = payload.span();
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetSrcPort), 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetDstPort), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetIcmpType]), 8u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetIcmpCode]), 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetIcmpId), 0x1234u);
}

TEST(FlowTelemetryRecords, EncodesFlowV1Icmp6FactsWithoutPorts) {
    EncodedPayload payload{};
    std::array<std::byte, 16> src{};
    std::array<std::byte, 16> dst{};
    src[15] = std::byte{1};
    dst[15] = std::byte{2};
    FlowV1Fields f = baseFlowFields(src, dst);
    f.isIpv6 = true;
    f.proto = 58;
    f.portsAvailable = false;
    f.icmpType = 128;
    f.icmpCode = 0;
    f.icmpId = 0xBEEF;

    ASSERT_TRUE(encodeFlowV1(payload, f));
    const auto bytes = payload.span();
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagIsIpv6, 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetSrcPort), 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetDstPort), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetIcmpType]), 128u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetIcmpId), 0xBEEFu);
}

TEST(FlowTelemetryRecords, EncodesFlowV1EndReasons) {
    const auto src = ipv4Bytes(0x0A000001u);
    const auto dst = ipv4Bytes(0x0A000002u);
    for (const auto reason : {FlowEndReason::IdleTimeout,
                              FlowEndReason::TcpEndDetected,
                              FlowEndReason::ResourceEvicted,
                              FlowEndReason::TelemetryDisabled}) {
        EncodedPayload payload{};
        FlowV1Fields f = baseFlowFields(src, dst);
        f.kind = FlowRecordKind::End;
        f.endReason = reason;
        ASSERT_TRUE(encodeFlowV1(payload, f));
        EXPECT_EQ(static_cast<std::uint8_t>(payload.span()[kFlowV1OffsetEndReason]),
                  static_cast<std::uint8_t>(reason));
    }
}

TEST(FlowTelemetryRecords, EncodesFlowV1L3ObservationStatuses) {
    const auto src = ipv4Bytes(0x0A000001u);
    const auto dst = ipv4Bytes(0x0A000002u);
    for (const std::uint8_t l4Status : {std::uint8_t{2}, std::uint8_t{3}}) {
        EncodedPayload payload{};
        FlowV1Fields f = baseFlowFields(src, dst);
        f.observationKind = FlowObservationKind::L3Observation;
        f.ctState = 3;
        f.ctDir = 0;
        f.l4Status = l4Status;
        f.portsAvailable = false;
        f.srcPort = 111;
        f.dstPort = 222;
        ASSERT_TRUE(encodeFlowV1(payload, f));
        const auto bytes = payload.span();
        EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetObservationKind]),
                  static_cast<std::uint8_t>(FlowObservationKind::L3Observation));
        EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetL4Status]), l4Status);
        EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetSrcPort), 0u);
        EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetDstPort), 0u);
        EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagPortsAvailable, 0u);
    }
}

TEST(FlowTelemetryRecords, EncodesDnsDecisionV1BlockedOnlyWithBoundedQueryName) {
    EncodedPayload payload{};

    const std::string name = "example.com";
    ASSERT_TRUE(encodeDnsDecisionV1(payload,
                                    /*timestampNs=*/1234,
                                    /*uid=*/10001,
                                    /*userId=*/10,
                                    /*policySource=*/DomainPolicySource::CUSTOM_BLACKLIST,
                                    /*ruleId=*/std::nullopt,
                                    name));

    const auto bytes = payload.span();
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kDnsV1OffsetPayloadVersion]), kDnsDecisionPayloadVersionV1);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kDnsV1OffsetFlags]) & kDnsDecisionFlagHasRuleId, 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kDnsV1OffsetFlags]) & kDnsDecisionFlagQueryNameTruncated, 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kDnsV1OffsetPolicySource]),
              static_cast<std::uint8_t>(DomainPolicySource::CUSTOM_BLACKLIST));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kDnsV1OffsetTimestampNs), 1234u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kDnsV1OffsetUid), 10001u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kDnsV1OffsetUserId), 10u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kDnsV1OffsetRuleId), 0u);

    const auto qlen = FlowTelemetryAbi::readU16Le(bytes, kDnsV1OffsetQueryNameLen);
    ASSERT_EQ(qlen, name.size());
    ASSERT_EQ(payload.size, kDnsV1FixedBytes + qlen);
    for (size_t i = 0; i < name.size(); ++i) {
        EXPECT_EQ(bytes[kDnsV1OffsetQueryName + i], static_cast<std::byte>(name[i]));
    }
}

TEST(FlowTelemetryRecords, EncodesDnsDecisionV1TruncatesOverlongQueryNameAndSetsFlag) {
    EncodedPayload payload{};

    std::string name;
    name.resize(kDnsDecisionMaxQueryNameBytes + 10, 'a');
    name[0] = 'x';

    ASSERT_TRUE(encodeDnsDecisionV1(payload,
                                    /*timestampNs=*/9,
                                    /*uid=*/42,
                                    /*userId=*/0,
                                    /*policySource=*/DomainPolicySource::MASK_FALLBACK,
                                    /*ruleId=*/123u,
                                    name));

    const auto bytes = payload.span();
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kDnsV1OffsetFlags]) & kDnsDecisionFlagHasRuleId, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kDnsV1OffsetFlags]) & kDnsDecisionFlagQueryNameTruncated, 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kDnsV1OffsetRuleId), 123u);

    const auto qlen = FlowTelemetryAbi::readU16Le(bytes, kDnsV1OffsetQueryNameLen);
    EXPECT_EQ(qlen, kDnsDecisionMaxQueryNameBytes);
    EXPECT_EQ(payload.size, kDnsV1FixedBytes + qlen);
    EXPECT_EQ(bytes[kDnsV1OffsetQueryName + 0], static_cast<std::byte>('x'));
}
