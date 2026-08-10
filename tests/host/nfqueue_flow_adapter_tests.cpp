/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <sstream>
#include <utility>
#include <vector>

namespace {

using namespace SnortDatapath::Nfqueue;
namespace Flow = SnortDatapath::Flow;
namespace Policy = SnortDatapath::Policy;

constexpr std::byte byte(const std::uint8_t value) noexcept {
    return static_cast<std::byte>(value);
}

void putU16(std::span<std::byte> bytes, const std::size_t offset,
            const std::uint16_t value) noexcept {
    bytes[offset] = byte(static_cast<std::uint8_t>(value >> 8U));
    bytes[offset + 1] = byte(static_cast<std::uint8_t>(value & 0xffU));
}

std::array<std::uint8_t, 40> tcpPacket(const bool reverse = false) {
    std::array<std::uint8_t, 40> packet{};
    packet[0] = 0x45;
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{packet}), 2, 40);
    packet[8] = 64;
    packet[9] = 6;
    const std::array<std::uint8_t, 4> source = reverse
        ? std::array<std::uint8_t, 4>{192, 0, 2, 1}
        : std::array<std::uint8_t, 4>{10, 0, 0, 1};
    const std::array<std::uint8_t, 4> destination = reverse
        ? std::array<std::uint8_t, 4>{10, 0, 0, 1}
        : std::array<std::uint8_t, 4>{192, 0, 2, 1};
    for (std::size_t index = 0; index < 4; ++index) {
        packet[12 + index] = source[index];
        packet[16 + index] = destination[index];
    }
    packet[20] = static_cast<std::uint8_t>((reverse ? 443 : 40000) >> 8U);
    packet[21] = static_cast<std::uint8_t>(reverse ? 443 : 40000);
    packet[22] = static_cast<std::uint8_t>((reverse ? 40000 : 443) >> 8U);
    packet[23] = static_cast<std::uint8_t>(reverse ? 40000 : 443);
    packet[32] = 0x50;
    return packet;
}

std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> tcpFragments(
    const std::uint16_t identification) {
    const auto packet = tcpPacket();
    std::vector<std::uint8_t> first(packet.begin(), packet.end());
    first.insert(first.end(), {0xa1, 0xa2, 0xa3, 0xa4});
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{first}), 2,
           static_cast<std::uint16_t>(first.size()));
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{first}), 4,
           identification);
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{first}), 6, 0x2000);

    std::vector<std::uint8_t> final(packet.begin(), packet.begin() + 20);
    final.insert(final.end(), {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8});
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{final}), 2,
           static_cast<std::uint16_t>(final.size()));
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{final}), 4,
           identification);
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{final}), 6, 3);
    return {std::move(first), std::move(final)};
}

struct VerdictIntent final {
    std::uint32_t packetId = 0;
    NfqueuePacketLeaseVerdict verdict = NfqueuePacketLeaseVerdict::Drop;
};

NfqueuePacketLeaseAdapter makeLeaseAdapter(
    std::vector<VerdictIntent> &intents, const std::uint32_t queueNumber) {
    return NfqueuePacketLeaseAdapter(
        NfqueuePacketLeaseAdapterConfig{
            .pendingCapacity = 8,
            .laneGeneration = 19,
            .queueNumber = queueNumber,
            .completionTimeout = std::chrono::seconds(30),
        },
        [&intents](const std::uint32_t packetId,
                   const NfqueuePacketLeaseVerdict verdict) {
            intents.push_back(VerdictIntent{.packetId = packetId, .verdict = verdict});
            return true;
        });
}

class DropUidPolicy final : public Policy::PacketPolicySnapshot {
public:
    explicit DropUidPolicy(const std::uint32_t linuxUid) noexcept
        : linuxUid_(linuxUid) {}

    [[nodiscard]] Policy::PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept override {
        if (facts.domain.linuxUid == linuxUid_) {
            return Policy::PacketPolicyDecision::drop(
                17, 42, 7, Policy::PacketPolicyStage::NetworkGate);
        }
        return Policy::PacketPolicyDecision::passNext();
    }

private:
    std::uint32_t linuxUid_ = 0;
};

std::string readRepoFile(const std::filesystem::path &relativePath) {
    std::ifstream input(
        std::filesystem::path(SUCRE_SNORT_SOURCE_ROOT) / relativePath,
        std::ios::in | std::ios::binary);
    if (!input.is_open()) {
        return {};
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

TEST(NfqueueFlowAdapterTest, SourceUsesGraphIngressParserNotPacketCaptureAdapter) {
    const auto source = readRepoFile("src/datapath/nfqueue/NfqueueFlowAdapter.cpp");
    ASSERT_FALSE(source.empty());
    EXPECT_NE(source.find("FlowGraphIngress"), std::string::npos);
    EXPECT_EQ(source.find("PacketCaptureAdapter"), std::string::npos);
    EXPECT_EQ(source.find("FragmentSteering"), std::string::npos);
    EXPECT_EQ(source.find("FragmentSubmitStatus"), std::string::npos);
}

TEST(NfqueueFlowAdapterTest, NormalizesAndRunsSharedOwnerGate) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
    });
    const auto forward = tcpPacket();
    const auto reverse = tcpPacket(true);

    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalIn,
                               std::span<const std::uint8_t>{forward}, 1500),
              NfqueueFlowAdapterResult::FlowAccepted);
    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalOut,
                               std::span<const std::uint8_t>{reverse}, 1500),
              NfqueueFlowAdapterResult::FlowAccepted);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.packetsSeen, 2U);
    EXPECT_EQ(counters.normalizedPackets, 2U);
    EXPECT_EQ(counters.acceptedPackets, 2U);
    EXPECT_EQ(counters.parsePassThroughPackets, 0U);
    EXPECT_EQ(counters.ownerFaultPassThroughPackets, 0U);
    EXPECT_EQ(counters.directPackets, 2U);
    EXPECT_EQ(counters.ownerGuardPasses, 2U);
    EXPECT_EQ(counters.ownerGuardMismatches, 0U);
    EXPECT_EQ(counters.normalWorkerHandoffs, 0U);
}

TEST(NfqueueFlowAdapterTest, PolicyDropCompletesRetainedLeaseWithDropVerdict) {
    DropUidPolicy policy(10001);
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
        .packetPolicy = &policy,
    });
    std::vector<VerdictIntent> intents;
    auto lane = makeLeaseAdapter(intents, 21);
    const auto admission = lane.admit(3001);
    ASSERT_TRUE(admission.identity.has_value());
    const auto packet = tcpPacket();

    const auto result = adapter.process(
        21, kNfqueueHookLocalIn,
        std::span<const std::uint8_t>{packet}, packet.size(),
        NfqueuePacketMetadata{.linuxUid = 10001});

    EXPECT_EQ(result, NfqueueFlowAdapterResult::FlowDropped);
    EXPECT_EQ(lane.complete(*admission.identity, terminalReasonFor(result)),
              NfqueuePacketLeaseCompletionStatus::Completed);
    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].packetId, 3001U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(lane.counters().dropped, 1U);
    EXPECT_EQ(lane.counters().failOpen, 0U);
    EXPECT_EQ(lane.counters().accepted, 0U);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.acceptedPackets, 0U);
    EXPECT_EQ(counters.droppedPackets, 1U);
    EXPECT_EQ(counters.parsePassThroughPackets, 0U);
    EXPECT_EQ(counters.capacityPassThroughPackets, 0U);
    EXPECT_EQ(counters.ownerFaultPassThroughPackets, 0U);
}

TEST(NfqueueFlowAdapterTest, RuntimeAppliedPolicyControlsExistingAdapterPacketPath) {
    Policy::RuntimePacketPolicySnapshot policy;
    NfqueueFlowAdapterConfig config{};
    config.packetPolicy = &policy;
    NfqueueFlowAdapter adapter(config);

    Policy::PacketPolicySubjectView subject;
    subject.linuxUid = 12546;
    subject.networkGate.blockedNetworkContexts = {0};
    policy.apply(std::vector<Policy::PacketPolicySubjectView>{std::move(subject)}, 68);

    const auto result = adapter.process(
        2, kNfqueueHookLocalOut, std::span<const std::uint8_t>{tcpPacket()}, 40,
        NfqueuePacketMetadata{.linuxUid = 12546, .networkContext = 0});

    EXPECT_EQ(result, NfqueueFlowAdapterResult::FlowDropped);
    EXPECT_EQ(adapter.counters().droppedPackets, 1U);
    EXPECT_EQ(adapter.counters().acceptedPackets, 0U);
}

TEST(NfqueueFlowAdapterTest, RecordsBoundedLiveMetadataObservation) {
    NfqueueFlowAdapter adapter;

    const auto accepted = adapter.process(
        2, kNfqueueHookLocalOut, std::span<const std::uint8_t>{tcpPacket()}, 40,
        NfqueuePacketMetadata{
            .linuxUid = 12546,
            .inputInterfaceIndex = 11,
            .outputInterfaceIndex = 22,
            .networkContext = 0,
            .uidMetadataPresent = true,
        });
    EXPECT_EQ(accepted, NfqueueFlowAdapterResult::FlowAccepted);

    auto counters = adapter.counters();
    EXPECT_EQ(counters.uidMetadataPresentPackets, 1U);
    EXPECT_EQ(counters.uidMetadataMissingPackets, 0U);
    EXPECT_EQ(counters.lastObservedLinuxUid, 12546U);
    EXPECT_EQ(counters.lastObservedNetworkContext, 0U);
    EXPECT_EQ(counters.lastObservedHook, kNfqueueHookLocalOut);
    EXPECT_EQ(counters.lastObservedInputInterfaceIndex, 11U);
    EXPECT_EQ(counters.lastObservedOutputInterfaceIndex, 22U);
    EXPECT_EQ(counters.lastObservedResult, "FlowAccepted");

    const auto missing = adapter.process(
        2, 0xff, std::span<const std::uint8_t>{tcpPacket()}, 40,
        NfqueuePacketMetadata{
            .linuxUid = 0,
            .inputInterfaceIndex = 33,
            .outputInterfaceIndex = 44,
            .networkContext = 7,
            .uidMetadataPresent = false,
        });
    EXPECT_EQ(missing, NfqueueFlowAdapterResult::FailOpenParse);

    counters = adapter.counters();
    EXPECT_EQ(counters.uidMetadataPresentPackets, 1U);
    EXPECT_EQ(counters.uidMetadataMissingPackets, 1U);
    EXPECT_EQ(counters.lastObservedLinuxUid, 0U);
    EXPECT_EQ(counters.lastObservedNetworkContext, 7U);
    EXPECT_EQ(counters.lastObservedHook, 0xffU);
    EXPECT_EQ(counters.lastObservedInputInterfaceIndex, 33U);
    EXPECT_EQ(counters.lastObservedOutputInterfaceIndex, 44U);
    EXPECT_EQ(counters.lastObservedResult, "FailOpenParse");
}

TEST(NfqueueFlowAdapterTest, FragmentsAndBadHooksFailOpenWithoutPorts) {
    NfqueueFlowAdapter adapter;
    auto fragment = tcpPacket();
    fragment[6] = 0x20;
    fragment[7] = 0;

    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{fragment}, fragment.size()),
              NfqueueFlowAdapterResult::FragmentMalformed);
    EXPECT_EQ(adapter.process(1, 0xff,
                              std::span<const std::uint8_t>{fragment}, fragment.size()),
              NfqueueFlowAdapterResult::FailOpenParse);
    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentPassThroughPackets, 1U);
    EXPECT_EQ(counters.parsePassThroughPackets, 2U);
    EXPECT_EQ(counters.directPackets, 0U);
}

TEST(NfqueueFlowAdapterTest, ReassemblesAndUsesTheSameGraphGate) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 4,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
    });
    const auto [first, final] = tcpFragments(0x4242);

    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FlowAccepted);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentBufferedPackets, 1U);
    EXPECT_EQ(counters.fragmentReassembledPackets, 1U);
    EXPECT_EQ(counters.fragmentOwnerMetadataPackets, 1U);
    EXPECT_EQ(counters.fragmentPassThroughPackets, 1U);
    EXPECT_EQ(counters.acceptedPackets, 1U);
    EXPECT_EQ(counters.directPackets, 1U);
    EXPECT_EQ(counters.ownerGuardPasses, 1U);
    EXPECT_EQ(counters.correctiveHandoffs, 0U);
}

TEST(NfqueueFlowAdapterTest, DuplicateFragmentDoesNotEnterPortPolicy) {
    NfqueueFlowAdapter adapter;
    const auto [first, final] = tcpFragments(0x5151);

    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentDuplicate);
    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FlowAccepted);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentDuplicatePackets, 1U);
    EXPECT_EQ(counters.fragmentReassembledPackets, 1U);
    EXPECT_EQ(counters.directPackets, 1U);
}

TEST(NfqueueFlowAdapterTest, FragmentLeaseVerdictsReturnToOriginalLanes) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 4,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
        .fragmentLeaseCapacityPerDatagram = 4,
    });
    std::vector<VerdictIntent> firstIntents;
    std::vector<VerdictIntent> finalIntents;
    auto firstLane = makeLeaseAdapter(firstIntents, 10);
    auto finalLane = makeLeaseAdapter(finalIntents, 11);
    NfqueueFragmentLeaseCompletionMailbox firstMailbox(8);
    NfqueueFragmentLeaseCompletionMailbox finalMailbox(8);
    const auto [first, final] = tcpFragments(0x7373);
    const auto firstAdmission = firstLane.admit(2001);
    const auto finalAdmission = finalLane.admit(2002);
    ASSERT_TRUE(firstAdmission.identity.has_value());
    ASSERT_TRUE(finalAdmission.identity.has_value());

    bool firstRouted = false;
    EXPECT_EQ(adapter.process(
                  10, kNfqueueHookLocalIn,
                  std::span<const std::uint8_t>{first}, first.size(), {},
                  NfqueueFragmentLeaseContext{
                      .identity = firstAdmission.identity,
                      .mailbox = &firstMailbox,
                      .routed = &firstRouted}),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_TRUE(firstRouted);
    EXPECT_EQ(firstLane.pending(), 1U);

    bool finalRouted = false;
    EXPECT_EQ(adapter.process(
                  11, kNfqueueHookLocalIn,
                  std::span<const std::uint8_t>{final}, final.size(), {},
                  NfqueueFragmentLeaseContext{
                      .identity = finalAdmission.identity,
                      .mailbox = &finalMailbox,
                      .routed = &finalRouted}),
              NfqueueFlowAdapterResult::FlowAccepted);
    EXPECT_FALSE(finalRouted);

    EXPECT_EQ(finalLane.complete(
                  *finalAdmission.identity,
                  NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(firstMailbox.drain(firstLane), 1U);
    EXPECT_EQ(firstLane.pending(), 0U);
    ASSERT_EQ(firstIntents.size(), 1U);
    ASSERT_EQ(finalIntents.size(), 1U);
    EXPECT_EQ(firstIntents[0].verdict, NfqueuePacketLeaseVerdict::Accept);
    EXPECT_EQ(finalIntents[0].verdict, NfqueuePacketLeaseVerdict::Accept);
}

TEST(NfqueueFlowAdapterTest, ReassembledPolicyDropCompletesHeldLeasesWithDrop) {
    DropUidPolicy policy(10001);
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
        .packetPolicy = &policy,
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 4,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
        .fragmentLeaseCapacityPerDatagram = 4,
    });
    std::vector<VerdictIntent> firstIntents;
    std::vector<VerdictIntent> finalIntents;
    auto firstLane = makeLeaseAdapter(firstIntents, 22);
    auto finalLane = makeLeaseAdapter(finalIntents, 23);
    NfqueueFragmentLeaseCompletionMailbox firstMailbox(8);
    NfqueueFragmentLeaseCompletionMailbox finalMailbox(8);
    const auto [first, final] = tcpFragments(0x7676);
    const auto firstAdmission = firstLane.admit(3002);
    const auto finalAdmission = finalLane.admit(3003);
    ASSERT_TRUE(firstAdmission.identity.has_value());
    ASSERT_TRUE(finalAdmission.identity.has_value());

    bool firstRouted = false;
    EXPECT_EQ(adapter.process(
                  22, kNfqueueHookLocalIn,
                  std::span<const std::uint8_t>{first}, first.size(),
                  NfqueuePacketMetadata{.linuxUid = 10001},
                  NfqueueFragmentLeaseContext{
                      .identity = firstAdmission.identity,
                      .mailbox = &firstMailbox,
                      .routed = &firstRouted}),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_TRUE(firstRouted);

    bool finalRouted = false;
    const auto result = adapter.process(
        23, kNfqueueHookLocalIn,
        std::span<const std::uint8_t>{final}, final.size(),
        NfqueuePacketMetadata{.linuxUid = 10001},
        NfqueueFragmentLeaseContext{
            .identity = finalAdmission.identity,
            .mailbox = &finalMailbox,
            .routed = &finalRouted});
    EXPECT_EQ(result, NfqueueFlowAdapterResult::FlowDropped);
    EXPECT_FALSE(finalRouted);

    EXPECT_EQ(finalLane.complete(*finalAdmission.identity, terminalReasonFor(result)),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(firstMailbox.drain(firstLane), 1U);
    EXPECT_EQ(firstLane.pending(), 0U);
    ASSERT_EQ(firstIntents.size(), 1U);
    ASSERT_EQ(finalIntents.size(), 1U);
    EXPECT_EQ(firstIntents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(finalIntents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(firstLane.counters().dropped, 1U);
    EXPECT_EQ(finalLane.counters().dropped, 1U);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentReassembledPackets, 1U);
    EXPECT_EQ(counters.droppedPackets, 1U);
    EXPECT_EQ(counters.parsePassThroughPackets, 1U);
    EXPECT_EQ(counters.capacityPassThroughPackets, 0U);
    EXPECT_EQ(counters.ownerFaultPassThroughPackets, 0U);
}

TEST(NfqueueFlowAdapterTest, FragmentLeaseBookExpiresBeforeLeaseWatchdog) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 2,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 1,
        },
        .fragmentLeaseCapacityPerDatagram = 4,
    });
    std::vector<VerdictIntent> intents;
    auto lane = makeLeaseAdapter(intents, 12);
    NfqueueFragmentLeaseCompletionMailbox mailbox(4);
    const auto [first, unusedFinal] = tcpFragments(0x7474);
    static_cast<void>(unusedFinal);
    const auto admission = lane.admit(2003);
    ASSERT_TRUE(admission.identity.has_value());

    bool routed = false;
    EXPECT_EQ(adapter.process(
                  12, kNfqueueHookLocalIn,
                  std::span<const std::uint8_t>{first}, first.size(), {},
                  NfqueueFragmentLeaseContext{
                      .identity = admission.identity,
                      .mailbox = &mailbox,
                      .routed = &routed}),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_TRUE(routed);
    adapter.expireFragments(2);
    EXPECT_EQ(mailbox.drain(lane), 1U);
    EXPECT_EQ(lane.pending(), 0U);
    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(lane.counters().timeout, 1U);
}

TEST(NfqueueFlowAdapterTest, ReassembledNonL4DatagramCompletesHeldLeasesFailOpen) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 2,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
        .fragmentLeaseCapacityPerDatagram = 4,
    });
    std::vector<VerdictIntent> intents;
    auto lane = makeLeaseAdapter(intents, 13);
    NfqueueFragmentLeaseCompletionMailbox mailbox(4);
    auto [first, final] = tcpFragments(0x7575);
    first[9] = 1;
    final[9] = 1;
    const auto admission = lane.admit(2004);
    ASSERT_TRUE(admission.identity.has_value());

    bool routed = false;
    EXPECT_EQ(adapter.process(
                  13, kNfqueueHookLocalIn,
                  std::span<const std::uint8_t>{first}, first.size(), {},
                  NfqueueFragmentLeaseContext{
                      .identity = admission.identity,
                      .mailbox = &mailbox,
                      .routed = &routed}),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_TRUE(routed);
    EXPECT_EQ(adapter.process(13, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FragmentMalformed);
    EXPECT_EQ(mailbox.drain(lane), 1U);
    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Accept);
    EXPECT_EQ(lane.counters().failOpen, 1U);
}

TEST(NfqueueFlowAdapterTest, TimeoutAndCapacityHaveDeterministicFragmentResults) {
    const auto [first, final] = tcpFragments(0x6161);
    const auto [otherFirst, unusedFinal] = tcpFragments(0x6262);
    static_cast<void>(unusedFinal);

    NfqueueFlowAdapter timeoutAdapter(NfqueueFlowAdapterConfig{
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 2,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 2,
        },
    });
    EXPECT_EQ(timeoutAdapter.process(1, kNfqueueHookLocalIn,
                                     std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    const auto normal = tcpPacket();
    EXPECT_EQ(timeoutAdapter.process(1, kNfqueueHookLocalIn,
                                     std::span<const std::uint8_t>{normal}, normal.size()),
              NfqueueFlowAdapterResult::FlowAccepted);
    timeoutAdapter.expireFragments(2);
    EXPECT_EQ(timeoutAdapter.process(1, kNfqueueHookLocalIn,
                                     std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(timeoutAdapter.counters().fragmentTimeoutPackets, 0U);

    NfqueueFlowAdapter capacityAdapter(NfqueueFlowAdapterConfig{
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 1,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
    });
    EXPECT_EQ(capacityAdapter.process(1, kNfqueueHookLocalIn,
                                      std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(capacityAdapter.process(1, kNfqueueHookLocalIn,
                                      std::span<const std::uint8_t>{otherFirst}, otherFirst.size()),
              NfqueueFlowAdapterResult::FragmentCapacity);
    EXPECT_EQ(capacityAdapter.counters().fragmentCapacityPackets, 1U);
}

TEST(NfqueueFlowAdapterTest, RejectsInvalidQueueCapacity) {
    EXPECT_THROW(
        NfqueueFlowAdapter(NfqueueFlowAdapterConfig{.queueCapacity = 0}),
        std::invalid_argument);
}

} // namespace
