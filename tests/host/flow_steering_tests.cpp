/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowSteering.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

namespace {

using namespace SnortDatapath::Flow;

PacketFacts tcpPacket(const AdapterKind adapter, const DevicePacketDirection direction,
                     const std::array<std::uint8_t, 4> source,
                     const std::array<std::uint8_t, 4> destination,
                     const std::uint16_t sourcePort, const std::uint16_t destinationPort) {
    return PacketFacts{
        .source = IpAddress::v4(source),
        .destination = IpAddress::v4(destination),
        .ipProtocol = 6,
        .sourcePort = sourcePort,
        .destinationPort = destinationPort,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = ParseStatus::Ready,
        .deviceDirection = direction,
        .originalLength = 128,
        .boundedPrefixLength = 128,
        .domain = FlowDomain{
            .adapter = adapter,
            .linuxUid = 10001,
            .captureQueue = 7,
            .networkContext = 2,
            .runtimeProfile = 3,
        },
    };
}

TEST(FlowSteeringTest, CanonicalReverseDirectionsShareOwnerAcrossAdapters) {
    const auto layout = WorkerLayout{4, 0x1234};
    const OwnerSelector selector(layout);
    const auto forward = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                   {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    auto reverse = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                             {192, 0, 2, 1}, {10, 0, 0, 1}, 443, 40000);

    const auto forwardKey = CanonicalFlowKey::from(forward);
    const auto reverseKey = CanonicalFlowKey::from(reverse);
    ASSERT_TRUE(forwardKey.has_value());
    ASSERT_TRUE(reverseKey.has_value());
    EXPECT_EQ(*forwardKey, *reverseKey);
    EXPECT_EQ(selector.ownerFor(*forwardKey), selector.ownerFor(*reverseKey));

    reverse.domain.linuxUid = 20002;
    reverse.domain.captureQueue = 99;
    reverse.domain.networkContext = 8;
    reverse.domain.runtimeProfile = 42;
    EXPECT_EQ(selector.ownerFor(*CanonicalFlowKey::from(reverse)),
              selector.ownerFor(*forwardKey));
}

TEST(FlowSteeringTest, IPv6AndProtocolArePartOfCanonicalKey) {
    auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                           {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    facts.source = IpAddress::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 1});
    facts.destination = IpAddress::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 2});
    const auto tcpKey = CanonicalFlowKey::from(facts);
    ASSERT_TRUE(tcpKey.has_value());
    facts.ipProtocol = 17;
    const auto udpKey = CanonicalFlowKey::from(facts);
    ASSERT_TRUE(udpKey.has_value());
    EXPECT_NE(*tcpKey, *udpKey);
}

TEST(FlowSteeringTest, RejectsFragmentsAndUnavailablePorts) {
    auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                           {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    facts.fragmented = true;
    EXPECT_FALSE(CanonicalFlowKey::from(facts).has_value());
    facts.fragmented = false;
    facts.portsAvailable = false;
    EXPECT_FALSE(CanonicalFlowKey::from(facts).has_value());
    facts.portsAvailable = true;
    facts.ipProtocol = 1;
    EXPECT_FALSE(CanonicalFlowKey::from(facts).has_value());
    facts.ipProtocol = 6;
    facts.boundedPrefixLength = facts.originalLength + 1;
    EXPECT_FALSE(CanonicalFlowKey::from(facts).has_value());
}

TEST(FlowSteeringTest, DistributesDirectlyAndDropsOnlyOnCapacity) {
    const OwnerSelector selector(WorkerLayout{2, 9});
    PrimarySoftwareDistribution distribution(selector.layout(), 1);
    auto first = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                           {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    auto second = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                             {192, 0, 2, 1}, {10, 0, 0, 1}, 443, 40000);
    std::array packets{PacketEnvelope{.facts = first}, PacketEnvelope{.facts = second}};

    const auto queued = distribution.submit(std::span{packets});
    EXPECT_EQ(queued, 1U);
    EXPECT_EQ(distribution.counters().directPackets, 1U);
    EXPECT_EQ(distribution.counters().normalWorkerHandoffs, 0U);
    EXPECT_EQ(distribution.counters().capacityDrops, 1U);
    EXPECT_EQ(distribution.counters().directPackets + distribution.counters().capacityDrops,
              2U);
    EXPECT_TRUE(packets[0].lease.isTerminal() || packets[1].lease.isTerminal());
}

TEST(FlowSteeringTest, OwnerGuardAllowsOneCorrectionThenDrops) {
    OwnerGuard guard;
    PacketLease lease;
    EXPECT_EQ(guard.check(0, 1, lease), OwnerGuardDecision::CorrectiveHandoff);
    EXPECT_EQ(lease.correctionCount(), 1U);
    EXPECT_EQ(guard.check(2, 1, lease), OwnerGuardDecision::Drop);
    EXPECT_EQ(lease.outcome(), PacketLeaseOutcome::Dropped);
    EXPECT_EQ(guard.counters().correctiveHandoffs, 1U);
    EXPECT_EQ(guard.counters().secondMismatchDrops, 1U);
}

TEST(FlowSteeringTest, PacketLeaseHasOneTerminalOutcome) {
    PacketLease lease;
    EXPECT_TRUE(lease.accept());
    EXPECT_FALSE(lease.drop());
    EXPECT_EQ(lease.outcome(), PacketLeaseOutcome::Accepted);
    EXPECT_EQ(lease.duplicateTerminalAttempts(), 1U);
}

} // namespace
