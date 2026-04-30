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

TEST(FlowTelemetryRecords, EncodesFlowV1Ipv4WithoutRuleId) {
    EncodedPayload payload{};

    const std::uint32_t srcIpHost = 0x0A000001u; // 10.0.0.1
    const std::uint32_t dstIpHost = 0xC0A80102u; // 192.168.1.2
    const std::uint32_t srcIpNet = htonl(srcIpHost);
    const std::uint32_t dstIpNet = htonl(dstIpHost);
    std::array<std::byte, 4> src{};
    std::array<std::byte, 4> dst{};
    std::memcpy(src.data(), &srcIpNet, 4);
    std::memcpy(dst.data(), &dstIpNet, 4);

    ASSERT_TRUE(encodeFlowV1(payload, FlowRecordKind::Begin,
                             /*ctState=*/1, /*ctDir=*/1, /*reasonId=*/2, /*ifaceKindBit=*/0x2,
                             /*isIpv6=*/false,
                             /*timestampNs=*/123, /*flowInstanceId=*/456, /*recordSeq=*/7,
                             /*uid=*/10123, /*userId=*/0, /*ifindex=*/5, /*proto=*/6,
                             /*srcPort=*/1000, /*dstPort=*/80,
                             std::span<const std::byte>(src), std::span<const std::byte>(dst),
                             /*totalPackets=*/9, /*totalBytes=*/10,
                             /*ruleId=*/std::nullopt));
    ASSERT_EQ(payload.size, kFlowV1Bytes);

    const auto bytes = payload.span();
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetPayloadVersion]), kFlowPayloadVersionV1);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowRecordKind::Begin));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagHasRuleId, 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagIsIpv6, 0u);

    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetTimestampNs), 123u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetFlowInstanceId), 456u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetRecordSeq), 7u);

    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetUid), 10123u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetUserId), 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetIfindex), 5u);

    EXPECT_EQ(static_cast<std::uint8_t>(bytes[kFlowV1OffsetProto]), 6u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetSrcPort), 1000u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, kFlowV1OffsetDstPort), 80u);

    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetTotalPackets), 9u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, kFlowV1OffsetTotalBytes), 10u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetRuleId), 0u);

    // IPv4 addresses occupy first 4 bytes; remaining bytes must be 0.
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(bytes[kFlowV1OffsetSrcAddr + i], src[i]);
        EXPECT_EQ(bytes[kFlowV1OffsetDstAddr + i], dst[i]);
    }
    for (size_t i = 4; i < 16; ++i) {
        EXPECT_EQ(bytes[kFlowV1OffsetSrcAddr + i], std::byte{0});
        EXPECT_EQ(bytes[kFlowV1OffsetDstAddr + i], std::byte{0});
    }
}

TEST(FlowTelemetryRecords, EncodesFlowV1Ipv6WithRuleId) {
    EncodedPayload payload{};

    std::array<std::byte, 16> src{};
    std::array<std::byte, 16> dst{};
    for (size_t i = 0; i < 16; ++i) {
        src[i] = static_cast<std::byte>(i);
        dst[i] = static_cast<std::byte>(0xF0u + i);
    }

    ASSERT_TRUE(encodeFlowV1(payload, FlowRecordKind::Update,
                             /*ctState=*/2, /*ctDir=*/2, /*reasonId=*/4, /*ifaceKindBit=*/0x4,
                             /*isIpv6=*/true,
                             /*timestampNs=*/999, /*flowInstanceId=*/42, /*recordSeq=*/3,
                             /*uid=*/11001, /*userId=*/10, /*ifindex=*/7, /*proto=*/17,
                             /*srcPort=*/5353, /*dstPort=*/5353,
                             std::span<const std::byte>(src), std::span<const std::byte>(dst),
                             /*totalPackets=*/100, /*totalBytes=*/200,
                             /*ruleId=*/123u));

    const auto bytes = payload.span();
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagIsIpv6, 0u);
    EXPECT_NE(static_cast<std::uint8_t>(bytes[kFlowV1OffsetFlags]) & kFlowFlagHasRuleId, 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(bytes, kFlowV1OffsetRuleId), 123u);

    for (size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(bytes[kFlowV1OffsetSrcAddr + i], src[i]);
        EXPECT_EQ(bytes[kFlowV1OffsetDstAddr + i], dst[i]);
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
