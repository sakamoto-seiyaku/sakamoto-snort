/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowSteering.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace {

using namespace SnortDatapath::Flow;
namespace Protocol = sucre::protocol;

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
            .uidKnown = true,
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

TEST(FlowSteeringTest, FlowEntryCreationPacketDefinesOrigIndependentOfCanonicalEndpoint) {
    BoundedFlowTable table(4);
    const auto first = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Output,
                                 {192, 0, 2, 10}, {10, 0, 0, 9}, 443, 40000);
    const auto key = CanonicalFlowKey::from(first);
    ASSERT_TRUE(key.has_value());
    ASSERT_EQ(key->endpointA, IpAddress::v4({10, 0, 0, 9}));
    ASSERT_EQ(key->portA, 40000);

    const auto created = table.observeAccepted(first, 7);
    ASSERT_TRUE(created.has_value());
    EXPECT_TRUE(created->created);
    EXPECT_EQ(created->relativeDirection, FlowRelativeDirection::Orig);
    EXPECT_EQ(created->flowOriginDir, DevicePacketDirection::Output);
    EXPECT_TRUE(created->decisionStateValid);
    EXPECT_EQ(created->policyRevision, 7U);
    EXPECT_EQ(table.size(), 1U);

    const auto *entry = table.find(*key);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->originSource, IpAddress::v4({192, 0, 2, 10}));
    EXPECT_EQ(entry->originDestination, IpAddress::v4({10, 0, 0, 9}));
    EXPECT_EQ(entry->originSourcePort, 443U);
    EXPECT_EQ(entry->originDestinationPort, 40000U);
    EXPECT_EQ(entry->flowOriginDir, DevicePacketDirection::Output);
    EXPECT_EQ(entry->linuxUid, 10001U);
    EXPECT_TRUE(entry->uidKnown);
    EXPECT_TRUE(entry->decisionStateValid);
    EXPECT_EQ(entry->policyRevision, 7U);

    const auto reverse = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                   {10, 0, 0, 9}, {192, 0, 2, 10}, 40000, 443);
    ASSERT_EQ(*CanonicalFlowKey::from(reverse), *key);
    const auto updated = table.observeAccepted(reverse, 7);
    ASSERT_TRUE(updated.has_value());
    EXPECT_FALSE(updated->created);
    EXPECT_EQ(updated->relativeDirection, FlowRelativeDirection::Reply);
    EXPECT_EQ(updated->flowOriginDir, DevicePacketDirection::Output);
    EXPECT_EQ(updated->packets, 2U);
    EXPECT_EQ(table.counters().creates, 1U);
    EXPECT_EQ(table.counters().updates, 1U);
}

TEST(FlowSteeringTest, LateAttributionOnlyUpdatesExistingFlowEntry) {
    BoundedFlowTable table(4);
    auto first = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                           {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    first.domain.linuxUid = 0;
    first.domain.uidKnown = false;
    const auto key = CanonicalFlowKey::from(first);
    ASSERT_TRUE(key.has_value());

    const auto created = table.observeAccepted(first, 7);
    ASSERT_TRUE(created.has_value());
    EXPECT_TRUE(created->created);
    EXPECT_FALSE(created->uidKnown);

    auto miss = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                          {10, 0, 0, 2}, {192, 0, 2, 2}, 40001, 443);
    miss.domain.linuxUid = 0;
    miss.domain.uidKnown = false;
    const auto missingAttribution = table.applyResolvedAttribution(miss, 20002);
    ASSERT_TRUE(missingAttribution.has_value());
    EXPECT_FALSE(missingAttribution->found);
    EXPECT_EQ(table.size(), 1U);
    EXPECT_EQ(table.counters().attributionMisses, 1U);

    const auto attribution = table.applyResolvedAttribution(first, 20002);
    ASSERT_TRUE(attribution.has_value());
    EXPECT_TRUE(attribution->found);
    EXPECT_TRUE(attribution->updated);
    EXPECT_FALSE(attribution->previousUidKnown);
    EXPECT_EQ(attribution->currentLinuxUid, 20002U);
    EXPECT_TRUE(attribution->currentUidKnown);
    EXPECT_EQ(attribution->attributionUpdates, 1U);

    const auto resolved = table.factsWithResolvedAttribution(first);
    EXPECT_EQ(resolved.domain.linuxUid, 20002U);
    EXPECT_TRUE(resolved.domain.uidKnown);
    EXPECT_EQ(table.counters().attributionUpdates, 1U);
    EXPECT_EQ(table.counters().attributionResolutions, 1U);

    const auto *entry = table.find(*key);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->linuxUid, 20002U);
    EXPECT_TRUE(entry->uidKnown);
    EXPECT_EQ(entry->packets, 1U);
}

TEST(FlowSteeringTest, PolicyRevisionMismatchClearsDecisionStateWithoutLosingFlowFacts) {
    BoundedFlowTable table(4);
    const auto first = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Output,
                                 {192, 0, 2, 10}, {10, 0, 0, 9}, 443, 40000);
    const auto key = CanonicalFlowKey::from(first);
    ASSERT_TRUE(key.has_value());
    ASSERT_TRUE(table.observeAccepted(first, 7).has_value());

    auto reverse = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                             {10, 0, 0, 9}, {192, 0, 2, 10}, 40000, 443);
    const auto reconciled = table.reconcilePolicyRevision(reverse, 8);
    ASSERT_TRUE(reconciled.has_value());
    EXPECT_TRUE(reconciled->found);
    EXPECT_TRUE(reconciled->decisionStateCleared);
    EXPECT_EQ(reconciled->previousPolicyRevision, 7U);
    EXPECT_EQ(reconciled->currentPolicyRevision, 8U);

    const auto *entryAfterClear = table.find(*key);
    ASSERT_NE(entryAfterClear, nullptr);
    EXPECT_EQ(entryAfterClear->originSource, IpAddress::v4({192, 0, 2, 10}));
    EXPECT_EQ(entryAfterClear->originDestination, IpAddress::v4({10, 0, 0, 9}));
    EXPECT_EQ(entryAfterClear->packets, 1U);
    EXPECT_EQ(entryAfterClear->bytes, 128U);
    EXPECT_FALSE(entryAfterClear->decisionStateValid);
    EXPECT_EQ(entryAfterClear->policyRevision, 8U);
    EXPECT_EQ(entryAfterClear->decisionStateClears, 1U);
    EXPECT_EQ(table.counters().decisionStateClears, 1U);

    const auto updated = table.observeAccepted(reverse, 8);
    ASSERT_TRUE(updated.has_value());
    EXPECT_FALSE(updated->created);
    EXPECT_TRUE(updated->decisionStateValid);
    EXPECT_TRUE(updated->decisionStateCleared);
    EXPECT_EQ(updated->policyRevision, 8U);
    EXPECT_EQ(updated->relativeDirection, FlowRelativeDirection::Reply);
    EXPECT_EQ(updated->packets, 2U);
}

TEST(FlowSteeringTest, BoundedFlowEntryCapacityMissDoesNotCreateUnboundedState) {
    BoundedFlowTable table(1);
    const auto first = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    const auto second = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                  {10, 0, 0, 2}, {192, 0, 2, 2}, 40001, 443);

    ASSERT_TRUE(table.observeAccepted(first).has_value());
    EXPECT_FALSE(table.observeAccepted(second).has_value());
    EXPECT_EQ(table.size(), 1U);
    EXPECT_EQ(table.counters().capacityMisses, 1U);
}

TEST(FlowSteeringTest, LpiRecognitionAttachesToExistingFlowEntryWithOrderedDedupedIds) {
    BoundedFlowTable table(4);
    const auto first = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    auto reply = tcpPacket(AdapterKind::RootNfqueue, DevicePacketDirection::Output,
                           {192, 0, 2, 1}, {10, 0, 0, 1}, 443, 40000);
    const auto key = CanonicalFlowKey::from(first);
    ASSERT_TRUE(key.has_value());
    ASSERT_TRUE(table.observeAccepted(first, 7).has_value());

    const auto http = table.recordLpiRecognition(
        first, true, Protocol::ApplicationProtocolId::HTTP, true, false, false);
    ASSERT_TRUE(http.has_value());
    EXPECT_TRUE(http->found);
    EXPECT_TRUE(http->payloadSubmitted);
    EXPECT_TRUE(http->mappedResultAppended);
    EXPECT_EQ(http->direction, FlowRelativeDirection::Orig);
    EXPECT_EQ(http->payloadPacketSequence, 1U);

    const auto duplicateHttp = table.recordLpiRecognition(
        reply, true, Protocol::ApplicationProtocolId::HTTP, true, false, false);
    ASSERT_TRUE(duplicateHttp.has_value());
    EXPECT_TRUE(duplicateHttp->duplicateMappedResult);
    EXPECT_EQ(duplicateHttp->direction, FlowRelativeDirection::Reply);
    EXPECT_EQ(duplicateHttp->payloadPacketSequence, 2U);

    const auto quic = table.recordLpiRecognition(
        reply, true, Protocol::ApplicationProtocolId::QUIC, true, false, false);
    ASSERT_TRUE(quic.has_value());
    EXPECT_TRUE(quic->mappedResultAppended);
    EXPECT_EQ(quic->mappedResultCount, 2U);
    ASSERT_TRUE(quic->latestExactResult.has_value());
    EXPECT_EQ(*quic->latestExactResult, Protocol::ApplicationProtocolId::QUIC);

    const auto *entry = table.find(*key);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(table.size(), 1U);
    EXPECT_EQ(entry->lpiRecognition.payloadPacketsSubmitted, 3U);
    const auto mappedResults = entry->lpiRecognition.mappedResults();
    ASSERT_EQ(mappedResults.size(), 2U);
    EXPECT_EQ(mappedResults[0].protocolId,
              Protocol::ApplicationProtocolId::HTTP);
    EXPECT_EQ(mappedResults[0].firstPayloadPacketSequence, 1U);
    EXPECT_EQ(mappedResults[0].direction,
              FlowRelativeDirection::Orig);
    EXPECT_EQ(mappedResults[1].protocolId,
              Protocol::ApplicationProtocolId::QUIC);
    EXPECT_EQ(mappedResults[1].firstPayloadPacketSequence, 3U);
    EXPECT_EQ(mappedResults[1].direction,
              FlowRelativeDirection::Reply);
    EXPECT_EQ(table.counters().lpiPayloadPackets, 3U);
    EXPECT_EQ(table.counters().lpiMappedResults, 2U);
    EXPECT_EQ(table.counters().lpiDuplicateMappedResults, 1U);
}

TEST(FlowSteeringTest, LpiRecognitionUnmappedAndTerminalStatesDoNotCreateTempIdsOrRetry) {
    BoundedFlowTable table(4);
    const auto first = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                                 {10, 0, 0, 1}, {192, 0, 2, 1}, 40000, 443);
    const auto other = tcpPacket(AdapterKind::VpnTun, DevicePacketDirection::Output,
                                 {10, 0, 0, 2}, {192, 0, 2, 2}, 40001, 443);
    ASSERT_TRUE(table.observeAccepted(first, 7).has_value());

    const auto miss = table.recordLpiRecognition(
        other, true, Protocol::ApplicationProtocolId::DNS, true, false, false);
    ASSERT_TRUE(miss.has_value());
    EXPECT_FALSE(miss->found);
    EXPECT_EQ(table.counters().lpiFlowMisses, 1U);
    EXPECT_EQ(table.size(), 1U);

    const auto exhausted = table.recordLpiRecognition(
        first, true, std::nullopt, true, false, true);
    ASSERT_TRUE(exhausted.has_value());
    EXPECT_TRUE(exhausted->found);
    EXPECT_TRUE(exhausted->payloadSubmitted);
    EXPECT_TRUE(exhausted->unmappedResult);
    EXPECT_EQ(exhausted->terminalState, LpiRecognitionTerminalState::Exhausted);
    EXPECT_FALSE(exhausted->latestExactResult.has_value());

    const auto afterTerminal = table.recordLpiRecognition(
        first, true, Protocol::ApplicationProtocolId::DNS, true, true, false);
    ASSERT_TRUE(afterTerminal.has_value());
    EXPECT_TRUE(afterTerminal->terminalSkip);
    EXPECT_FALSE(afterTerminal->payloadSubmitted);
    EXPECT_EQ(afterTerminal->terminalState, LpiRecognitionTerminalState::Exhausted);
    EXPECT_EQ(afterTerminal->mappedResultCount, 0U);
    EXPECT_EQ(table.counters().lpiPayloadPackets, 1U);
    EXPECT_EQ(table.counters().lpiUnmappedResults, 1U);
    EXPECT_EQ(table.counters().lpiTerminalSkips, 1U);
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
    const auto *descriptor = distribution.descriptor(*descriptorId);
    ASSERT_NE(descriptor, nullptr);
    EXPECT_TRUE(distribution.requestCorrectiveHandoff(*descriptorId));

    EXPECT_FALSE(distribution.requeueCorrective(*descriptorId, wrongOwner));
    EXPECT_EQ(distribution.descriptor(*descriptorId), nullptr);
}

} // namespace
