/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphInjection.hpp>

#include <gtest/gtest.h>

namespace {

using namespace SnortDatapath::Flow;

PacketFacts facts(const AdapterKind adapter, const bool reverse = false) {
    return PacketFacts{
        .source = IpAddress::v4(reverse
                                    ? std::array<std::uint8_t, 4>{192, 0, 2, 1}
                                    : std::array<std::uint8_t, 4>{10, 0, 0, 1}),
        .destination = IpAddress::v4(reverse
                                         ? std::array<std::uint8_t, 4>{10, 0, 0, 1}
                                         : std::array<std::uint8_t, 4>{192, 0, 2, 1}),
        .ipProtocol = 6,
        .sourcePort = static_cast<std::uint16_t>(reverse ? 443 : 40000),
        .destinationPort = static_cast<std::uint16_t>(reverse ? 40000 : 443),
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = ParseStatus::Ready,
        .deviceDirection = reverse ? DevicePacketDirection::Output
                                   : DevicePacketDirection::Input,
        .originalLength = 1500,
        .boundedPrefixLength = 512,
        .domain = FlowDomain{
            .adapter = adapter,
            .linuxUid = 10001,
            .captureQueue = 7,
            .networkContext = 2,
            .runtimeProfile = 3,
        },
    };
}

TEST(VppGraphInjectionTest, RootAndVpnUseOneDirectOwnerGraphGate) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x1234}, 4);
    FlowGraphInjectionGate gate(runtime);
    const auto rootFacts = facts(AdapterKind::RootNfqueue);
    const auto vpnFacts = facts(AdapterKind::VpnTun, true);
    const auto key = CanonicalFlowKey::from(rootFacts);
    ASSERT_TRUE(key.has_value());
    const auto owner = runtime.distribution().selector().ownerFor(*key);

    PacketSubmission root{.facts = rootFacts};
    PacketSubmission vpn{.facts = vpnFacts};
    EXPECT_EQ(gate.inject(root, owner), GraphInjectionResult::Accepted);
    EXPECT_EQ(gate.inject(vpn, owner), GraphInjectionResult::Accepted);
    EXPECT_EQ(gate.counters().injectedPackets, 2U);
    EXPECT_EQ(gate.counters().acceptedPackets, 2U);
    EXPECT_EQ(gate.counters().correctiveHandoffs, 0U);
    EXPECT_EQ(runtime.distribution().counters().normalWorkerHandoffs, 0U);
}

TEST(VppGraphInjectionTest, GraphGateBoundsOneCorrectiveHandoff) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x55aa}, 2);
    FlowGraphInjectionGate gate(runtime);
    const auto packetFacts = facts(AdapterKind::VpnTun);
    const auto key = CanonicalFlowKey::from(packetFacts);
    ASSERT_TRUE(key.has_value());
    const auto owner = runtime.distribution().selector().ownerFor(*key);
    const auto wrongWorker = (owner + 1U) % 2U;
    PacketSubmission submission{.facts = packetFacts};

    EXPECT_EQ(gate.inject(submission, wrongWorker), GraphInjectionResult::Accepted);
    EXPECT_EQ(gate.counters().correctiveHandoffs, 1U);
    EXPECT_EQ(gate.counters().ownerFaultDrops, 0U);

    OwnerGuard guard(WorkerLayout{2, 0x55aa});
    PacketLease lease;
    EXPECT_EQ(guard.check(wrongWorker, packetFacts, lease), OwnerGuardDecision::CorrectiveHandoff);
    EXPECT_EQ(guard.check(wrongWorker, packetFacts, lease), OwnerGuardDecision::Drop);
    EXPECT_EQ(guard.counters().secondMismatchDrops, 1U);
}

TEST(VppGraphInjectionTest, GraphGateReportsBoundedTargetCongestion) {
    FlowSteeringRuntime runtime(WorkerLayout{1, 0x55aa}, 1);
    FlowGraphInjectionGate gate(runtime);
    PacketSubmission blocker{.facts = facts(AdapterKind::RootNfqueue)};
    ASSERT_EQ(runtime.distribution().submit(std::span<PacketSubmission>(&blocker, 1)), 1U);

    PacketSubmission congested{.facts = facts(AdapterKind::VpnTun, true)};
    EXPECT_EQ(gate.inject(congested, 0), GraphInjectionResult::CapacityDrop);
    EXPECT_EQ(gate.counters().capacityDrops, 1U);

    const auto owner = runtime.distribution().selector().ownerFor(
        *CanonicalFlowKey::from(blocker.facts));
    const auto blockerId = runtime.distribution().dequeue(owner);
    ASSERT_TRUE(blockerId.has_value());
    EXPECT_TRUE(runtime.distribution().complete(*blockerId, PacketLeaseOutcome::Accepted));
}

TEST(VppGraphInjectionTest, GraphGateRejectsNonCanonicalPacketDeterministically) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x55aa}, 2);
    FlowGraphInjectionGate gate(runtime);
    auto packetFacts = facts(AdapterKind::VpnTun);
    packetFacts.parseStatus = ParseStatus::UnsupportedProtocol;
    PacketSubmission submission{.facts = packetFacts};

    EXPECT_EQ(gate.inject(submission, 0), GraphInjectionResult::ParseDrop);
    EXPECT_TRUE(submission.lease.isTerminal());
    EXPECT_EQ(gate.counters().parseDrops, 1U);
}

} // namespace
