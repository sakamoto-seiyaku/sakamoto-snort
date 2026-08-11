/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphInjection.hpp>

#include <gtest/gtest.h>

namespace {

using namespace SnortDatapath::Flow;

namespace Policy = SnortDatapath::Policy;

class DropUidPolicy final : public SnortDatapath::Policy::PacketPolicySnapshot {
public:
    explicit DropUidPolicy(
        const std::uint32_t uid,
        const Policy::PacketPolicyStage stage = Policy::PacketPolicyStage::L4) noexcept
        : uid_(uid), stage_(stage) {}

    [[nodiscard]] Policy::PacketPolicyDecision evaluate(
        const PacketFacts &packetFacts) const noexcept override {
        if (packetFacts.domain.uidKnown && packetFacts.domain.linuxUid == uid_) {
            return Policy::PacketPolicyDecision::drop(17, 42, 7, stage_);
        }
        return Policy::PacketPolicyDecision::passNext();
    }

private:
    std::uint32_t uid_;
    Policy::PacketPolicyStage stage_;
};

class PassRevisionPolicy final : public SnortDatapath::Policy::PacketPolicySnapshot {
public:
    explicit PassRevisionPolicy(const std::uint64_t revision) noexcept
        : revision_(revision) {}

    [[nodiscard]] Policy::PacketPolicyDecision evaluate(
        const PacketFacts &packetFacts) const noexcept override {
        static_cast<void>(packetFacts);
        auto decision = Policy::PacketPolicyDecision::passNext();
        decision.revision = revision_;
        return decision;
    }

    [[nodiscard]] std::uint64_t revision() const noexcept override {
        return revision_;
    }

private:
    std::uint64_t revision_ = 0;
};

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
            .uidKnown = true,
            .captureQueue = 7,
            .networkContext = 2,
            .runtimeProfile = 3,
        },
    };
}

TEST(VppGraphInjectionTest, PacketPolicyDecisionCarriesStageAndAttribution) {
    const auto pass = Policy::PacketPolicyDecision::passNext();
    EXPECT_EQ(pass.verdict, Policy::PacketPolicyVerdict::PASS_NEXT);
    EXPECT_EQ(pass.stage, Policy::PacketPolicyStage::None);

    const auto l4Drop = Policy::PacketPolicyDecision::drop(17, 42, 7);
    EXPECT_EQ(l4Drop.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(l4Drop.stage, Policy::PacketPolicyStage::L4);
    EXPECT_EQ(l4Drop.reasonId, 17U);
    EXPECT_EQ(l4Drop.ruleId, 42U);
    EXPECT_EQ(l4Drop.revision, 7U);

    const auto networkGateDrop = Policy::PacketPolicyDecision::drop(
        23, 99, 11, Policy::PacketPolicyStage::NetworkGate);
    EXPECT_EQ(networkGateDrop.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(networkGateDrop.stage, Policy::PacketPolicyStage::NetworkGate);
    EXPECT_EQ(networkGateDrop.reasonId, 23U);
    EXPECT_EQ(networkGateDrop.ruleId, 99U);
    EXPECT_EQ(networkGateDrop.revision, 11U);
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
    EXPECT_EQ(gate.counters().policyDrops, 0U);
    EXPECT_EQ(runtime.distribution().counters().normalWorkerHandoffs, 0U);
    EXPECT_EQ(runtime.flowTable().size(), 1U);
    ASSERT_TRUE(gate.lastFlowEntryObservation().has_value());
    EXPECT_EQ(gate.lastFlowEntryObservation()->relativeDirection, FlowRelativeDirection::Reply);
    EXPECT_EQ(gate.lastFlowEntryObservation()->flowOriginDir,
              DevicePacketDirection::Input);
    EXPECT_EQ(gate.lastFlowEntryObservation()->packets, 2U);
}

TEST(VppGraphInjectionTest, DefaultEmptyPolicySnapshotPreservesAcceptedGraphPath) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x7777}, 4);
    FlowGraphInjectionGate gate(runtime);
    const auto packetFacts = facts(AdapterKind::RootNfqueue);
    const auto emptyDecision =
        Policy::emptyPacketPolicySnapshot().evaluate(packetFacts);
    EXPECT_EQ(emptyDecision.verdict, Policy::PacketPolicyVerdict::PASS_NEXT);
    EXPECT_EQ(emptyDecision.stage, Policy::PacketPolicyStage::None);
    const auto key = CanonicalFlowKey::from(packetFacts);
    ASSERT_TRUE(key.has_value());
    const auto owner = runtime.distribution().selector().ownerFor(*key);
    PacketSubmission submission{.facts = packetFacts};

    EXPECT_EQ(gate.inject(submission, owner), GraphInjectionResult::Accepted);
    EXPECT_EQ(gate.counters().acceptedPackets, 1U);
    EXPECT_EQ(gate.counters().policyDrops, 0U);
    ASSERT_TRUE(gate.lastFlowEntryObservation().has_value());
    EXPECT_TRUE(gate.lastFlowEntryObservation()->created);
    EXPECT_EQ(gate.lastFlowEntryObservation()->relativeDirection, FlowRelativeDirection::Orig);
    EXPECT_EQ(runtime.flowTable().size(), 1U);
}

TEST(VppGraphInjectionTest, PolicyDropShortCircuitsBeforeAcceptedTerminalPath) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x7777}, 4);
    DropUidPolicy policy(10001, Policy::PacketPolicyStage::NetworkGate);
    FlowGraphInjectionGate gate(runtime, policy);
    const auto packetFacts = facts(AdapterKind::RootNfqueue);
    const auto dropDecision = policy.evaluate(packetFacts);
    EXPECT_EQ(dropDecision.stage, Policy::PacketPolicyStage::NetworkGate);
    const auto key = CanonicalFlowKey::from(packetFacts);
    ASSERT_TRUE(key.has_value());
    const auto owner = runtime.distribution().selector().ownerFor(*key);
    PacketSubmission submission{.facts = packetFacts};

    EXPECT_EQ(gate.inject(submission, owner), GraphInjectionResult::PolicyDrop);
    EXPECT_EQ(gate.counters().acceptedPackets, 0U);
    EXPECT_EQ(gate.counters().policyDrops, 1U);
    EXPECT_EQ(gate.counters().ownerFaultDrops, 0U);
    EXPECT_EQ(runtime.flowTable().size(), 0U);
    EXPECT_FALSE(gate.lastFlowEntryObservation().has_value());
}

TEST(VppGraphInjectionTest, LateResolvedAttributionReevaluatesSubsequentUnknownPacket) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x5600}, 8);
    DropUidPolicy policy(20002);
    FlowGraphInjectionGate gate(runtime, policy);
    auto firstFacts = facts(AdapterKind::VpnTun);
    firstFacts.domain.linuxUid = 0;
    firstFacts.domain.uidKnown = false;
    const auto key = CanonicalFlowKey::from(firstFacts);
    ASSERT_TRUE(key.has_value());
    const auto owner = runtime.distribution().selector().ownerFor(*key);
    PacketSubmission first{.facts = firstFacts};

    EXPECT_EQ(gate.inject(first, owner), GraphInjectionResult::Accepted);
    ASSERT_TRUE(gate.lastFlowEntryObservation().has_value());
    EXPECT_TRUE(gate.lastFlowEntryObservation()->created);
    EXPECT_FALSE(gate.lastFlowEntryObservation()->uidKnown);
    EXPECT_EQ(runtime.flowTable().counters().creates, 1U);

    const auto attribution = runtime.flowTable().applyResolvedAttribution(firstFacts, 20002);
    ASSERT_TRUE(attribution.has_value());
    EXPECT_TRUE(attribution->found);
    EXPECT_TRUE(attribution->updated);
    EXPECT_EQ(attribution->currentLinuxUid, 20002U);
    EXPECT_TRUE(attribution->currentUidKnown);

    auto laterFacts = facts(AdapterKind::VpnTun, true);
    laterFacts.domain.linuxUid = 0;
    laterFacts.domain.uidKnown = false;
    PacketSubmission later{.facts = laterFacts};

    EXPECT_EQ(gate.inject(later, owner), GraphInjectionResult::PolicyDrop);
    ASSERT_TRUE(gate.lastPolicyDropDecision().has_value());
    EXPECT_EQ(gate.lastPolicyDropDecision()->stage, Policy::PacketPolicyStage::L4);
    EXPECT_EQ(runtime.flowTable().counters().attributionResolutions, 1U);
    EXPECT_EQ(runtime.flowTable().counters().updates, 0U);
    EXPECT_EQ(runtime.flowTable().counters().creates, 1U);
    const auto *entry = runtime.flowTable().find(*key);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->packets, 1U);
    EXPECT_EQ(entry->linuxUid, 20002U);
    EXPECT_TRUE(entry->uidKnown);
}

TEST(VppGraphInjectionTest, ExistingFlowEntryRevisionMismatchLazyReevaluatesNextPacket) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x7777}, 4);
    PassRevisionPolicy revisionSeven(7);
    FlowGraphInjectionGate firstGate(runtime, revisionSeven);
    auto firstFacts = facts(AdapterKind::RootNfqueue);
    const auto key = CanonicalFlowKey::from(firstFacts);
    ASSERT_TRUE(key.has_value());
    const auto owner = runtime.distribution().selector().ownerFor(*key);
    PacketSubmission first{.facts = firstFacts};
    ASSERT_EQ(firstGate.inject(first, owner), GraphInjectionResult::Accepted);
    const auto *created = runtime.flowTable().find(*key);
    ASSERT_NE(created, nullptr);
    EXPECT_TRUE(created->decisionStateValid);
    EXPECT_EQ(created->policyRevision, 7U);

    PassRevisionPolicy revisionEight(8);
    FlowGraphInjectionGate secondGate(runtime, revisionEight);
    PacketSubmission second{.facts = facts(AdapterKind::RootNfqueue, true)};
    EXPECT_EQ(secondGate.inject(second, owner), GraphInjectionResult::Accepted);
    const auto *reevaluated = runtime.flowTable().find(*key);
    ASSERT_NE(reevaluated, nullptr);
    EXPECT_TRUE(reevaluated->decisionStateValid);
    EXPECT_EQ(reevaluated->policyRevision, 8U);
    EXPECT_EQ(reevaluated->decisionStateClears, 1U);
    EXPECT_EQ(reevaluated->packets, 2U);
    EXPECT_EQ(runtime.flowTable().counters().decisionStateClears, 1U);
    ASSERT_TRUE(secondGate.lastFlowEntryObservation().has_value());
    EXPECT_TRUE(secondGate.lastFlowEntryObservation()->decisionStateCleared);
    EXPECT_EQ(secondGate.lastFlowEntryObservation()->relativeDirection,
              FlowRelativeDirection::Reply);
}

TEST(VppGraphInjectionTest, OwnerSelectionIgnoresUidWhilePolicyCanDropByUid) {
    FlowSteeringRuntime runtime(WorkerLayout{4, 0x2468}, 4);
    DropUidPolicy policy(10002);
    FlowGraphInjectionGate gate(runtime, policy);
    auto firstFacts = facts(AdapterKind::RootNfqueue);
    auto secondFacts = firstFacts;
    secondFacts.domain.linuxUid = 10002;

    const auto firstKey = CanonicalFlowKey::from(firstFacts);
    const auto secondKey = CanonicalFlowKey::from(secondFacts);
    ASSERT_TRUE(firstKey.has_value());
    ASSERT_TRUE(secondKey.has_value());
    EXPECT_EQ(*firstKey, *secondKey);
    const auto owner = runtime.distribution().selector().ownerFor(*firstKey);
    EXPECT_EQ(runtime.distribution().selector().ownerFor(*secondKey), owner);

    PacketSubmission first{.facts = firstFacts};
    PacketSubmission second{.facts = secondFacts};
    EXPECT_EQ(gate.inject(first, owner), GraphInjectionResult::Accepted);
    EXPECT_EQ(gate.inject(second, owner), GraphInjectionResult::PolicyDrop);
    EXPECT_EQ(gate.counters().acceptedPackets, 1U);
    EXPECT_EQ(gate.counters().policyDrops, 1U);
    EXPECT_FALSE(gate.lastFlowEntryObservation().has_value());
    ASSERT_TRUE(gate.lastPolicyDropDecision().has_value());
    EXPECT_EQ(runtime.flowTable().size(), 1U);
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
