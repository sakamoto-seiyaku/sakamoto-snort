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

TEST(FlowSteeringTest, IPv4UsesCanonicalLeadingBytes) {
    const auto address = IpAddress::v4({1, 2, 3, 4});
    const std::array<std::uint8_t, 16> expected{1, 2, 3, 4};

    EXPECT_EQ(address.family, AddressFamily::Ipv4);
    EXPECT_EQ(address.bytes, expected);
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

TEST(FlowSteeringTest, AcceptsBoundedPrefixWithinOriginalPacketLength) {
    auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                           {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    facts.originalLength = 1500;
    facts.boundedPrefixLength = 512;

    EXPECT_TRUE(facts.isCanonicalizable());
    EXPECT_TRUE(CanonicalFlowKey::from(facts).has_value());
}

TEST(FlowSteeringTest, DistributesDirectlyAndDropsOnlyOnCapacity) {
    const OwnerSelector selector(WorkerLayout{2, 9});
    PrimarySoftwareDistribution distribution(selector.layout(), 1);
    auto first = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                           {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    auto second = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                             {192, 0, 2, 1}, {10, 0, 0, 1}, 443, 40000);
    const std::array packets{first, second};

    const auto queued = distribution.submit(std::span<const PacketFacts>{packets});
    EXPECT_EQ(queued, 1U);
    EXPECT_EQ(distribution.counters().directPackets, 1U);
    EXPECT_EQ(distribution.counters().normalWorkerHandoffs, 0U);
    EXPECT_EQ(distribution.counters().capacityDrops, 1U);
    EXPECT_EQ(distribution.counters().directPackets + distribution.counters().capacityDrops,
              2U);

    const auto key = CanonicalFlowKey::from(first);
    ASSERT_TRUE(key.has_value());
    const auto owner = selector.ownerFor(*key);
    EXPECT_EQ(distribution.queueDepth(owner), 1U);

    const auto descriptorId = distribution.dequeue(owner);
    ASSERT_TRUE(descriptorId.has_value());
    const auto *descriptor = distribution.descriptor(*descriptorId);
    ASSERT_NE(descriptor, nullptr);
    EXPECT_EQ(descriptor->targetWorker, owner);
    EXPECT_EQ(descriptor->facts.originalLength, 128U);
    EXPECT_EQ(descriptor->facts.boundedPrefixLength, 128U);
    EXPECT_EQ(descriptor->lease.outcome(), PacketLeaseOutcome::Open);

    EXPECT_TRUE(distribution.complete(*descriptorId, PacketLeaseOutcome::Accepted));
    EXPECT_EQ(distribution.descriptor(*descriptorId), nullptr);
    EXPECT_FALSE(distribution.complete(*descriptorId, PacketLeaseOutcome::Dropped));
    EXPECT_EQ(distribution.counters().staleDescriptorHandles, 1U);
    EXPECT_EQ(distribution.queueDepth(owner), 0U);
}

TEST(FlowSteeringTest, OwnerGuardAllowsOneCorrectionThenDrops) {
    const auto layout = WorkerLayout{2, 9};
    const OwnerSelector selector(layout);
    const auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    const auto key = CanonicalFlowKey::from(facts);
    ASSERT_TRUE(key.has_value());
    const auto expectedWorker = selector.ownerFor(*key);
    const auto mismatchedWorker = (expectedWorker + 1U) % layout.workerCount();

    OwnerGuard guard(layout);
    PacketLease lease;
    EXPECT_EQ(guard.check(mismatchedWorker, facts, lease),
              OwnerGuardDecision::CorrectiveHandoff);
    EXPECT_EQ(lease.correctionCount(), 1U);
    EXPECT_EQ(guard.check(mismatchedWorker, facts, lease), OwnerGuardDecision::Drop);
    EXPECT_EQ(lease.outcome(), PacketLeaseOutcome::Dropped);
    EXPECT_EQ(guard.counters().correctiveHandoffs, 1U);
    EXPECT_EQ(guard.counters().secondMismatchDrops, 1U);
}

TEST(FlowSteeringTest, SharedRuntimeUsesOneWorkerLayoutForSelectionAndGuard) {
    const auto layout = WorkerLayout{3, 0x55aa};
    FlowSteeringRuntime runtime(layout, 2);
    const auto facts = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                                 {192, 0, 2, 1}, {10, 0, 0, 1}, 443, 40000);
    const auto key = CanonicalFlowKey::from(facts);
    ASSERT_TRUE(key.has_value());
    const auto expectedWorker = runtime.distribution().selector().ownerFor(*key);

    PacketLease lease;
    EXPECT_EQ(runtime.ownerGuard().check(expectedWorker, facts, lease),
              OwnerGuardDecision::Local);
    EXPECT_EQ(runtime.ownerGuard().counters().localPass, 1U);

    const std::array packets{facts};
    EXPECT_EQ(runtime.distribution().submit(std::span<const PacketFacts>{packets}), 1U);
    const auto descriptorId = runtime.distribution().dequeue(expectedWorker);
    ASSERT_TRUE(descriptorId.has_value());
    const auto *descriptor = runtime.distribution().descriptor(*descriptorId);
    ASSERT_NE(descriptor, nullptr);
    EXPECT_EQ(descriptor->targetWorker, expectedWorker);
    EXPECT_TRUE(runtime.distribution().complete(*descriptorId, PacketLeaseOutcome::Accepted));
}

TEST(FlowSteeringTest, PacketLeaseHasOneTerminalOutcome) {
    PacketLease lease;
    EXPECT_TRUE(lease.accept());
    EXPECT_FALSE(lease.drop());
    EXPECT_EQ(lease.outcome(), PacketLeaseOutcome::Accepted);
    EXPECT_EQ(lease.duplicateTerminalAttempts(), 1U);
}

TEST(FlowSteeringTest, DescriptorHandlesRejectReusedStaleIds) {
    PrimarySoftwareDistribution distribution(WorkerLayout{1, 7}, 1);
    const auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    const auto key = CanonicalFlowKey::from(facts);
    ASSERT_TRUE(key.has_value());
    const auto owner = distribution.selector().ownerFor(*key);
    const std::array first{facts};
    ASSERT_EQ(distribution.submit(std::span<const PacketFacts>{first}), 1U);
    const auto firstId = distribution.dequeue(owner);
    ASSERT_TRUE(firstId.has_value());
    ASSERT_TRUE(distribution.complete(*firstId, PacketLeaseOutcome::Accepted));

    ASSERT_EQ(distribution.submit(std::span<const PacketFacts>{first}), 1U);
    const auto secondId = distribution.dequeue(owner);
    ASSERT_TRUE(secondId.has_value());
    EXPECT_NE(*firstId, *secondId);
    EXPECT_FALSE(distribution.complete(*firstId, PacketLeaseOutcome::Dropped));
    EXPECT_TRUE(distribution.complete(*secondId, PacketLeaseOutcome::Accepted));
}

TEST(FlowSteeringTest, SubmissionRejectsCapacityWithTerminalLease) {
    PrimarySoftwareDistribution distribution(WorkerLayout{1, 7}, 1);
    const auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    std::array submissions{
        PacketSubmission{.facts = facts},
        PacketSubmission{.facts = facts},
    };

    EXPECT_EQ(distribution.submit(std::span<PacketSubmission>{submissions}), 1U);
    EXPECT_EQ(distribution.counters().capacityDrops, 1U);
    EXPECT_TRUE(submissions[0].lease.isTerminal());
    EXPECT_TRUE(submissions[1].lease.isTerminal());
}

TEST(FlowSteeringTest, CorrectiveRequeueRejectsNonOwnerTarget) {
    PrimarySoftwareDistribution distribution(WorkerLayout{2, 7}, 1);
    const auto facts = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    const auto key = CanonicalFlowKey::from(facts);
    ASSERT_TRUE(key.has_value());
    const auto owner = distribution.selector().ownerFor(*key);
    const auto wrongOwner = (owner + 1U) % 2U;
    const std::array packets{facts};
    ASSERT_EQ(distribution.submit(std::span<const PacketFacts>{packets}), 1U);
    const auto descriptorId = distribution.dequeue(owner);
    ASSERT_TRUE(descriptorId.has_value());
    auto *descriptor = distribution.descriptor(*descriptorId);
    ASSERT_NE(descriptor, nullptr);
    ASSERT_TRUE(descriptor->lease.requestCorrectiveHandoff());

    EXPECT_FALSE(distribution.requeueCorrective(*descriptorId, wrongOwner));
    EXPECT_EQ(distribution.descriptor(*descriptorId), nullptr);
}

} // namespace
