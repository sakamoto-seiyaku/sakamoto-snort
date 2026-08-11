/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphFragmentIngress.hpp>
#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace {

using namespace SnortDatapath::Flow;
namespace Policy = SnortDatapath::Policy;
namespace Protocol = SnortDatapath::Protocol;
namespace Catalog = sucre::protocol;

constexpr std::byte byte(const std::uint8_t value) noexcept {
    return static_cast<std::byte>(value);
}

void put16(std::span<std::byte> bytes, const std::size_t offset,
           const std::uint16_t value) noexcept {
    bytes[offset] = byte(static_cast<std::uint8_t>(value >> 8U));
    bytes[offset + 1] = byte(static_cast<std::uint8_t>(value & 0xffU));
}

std::vector<std::byte> ipv4Fragment(const std::uint16_t identification,
                                    const std::uint16_t offsetBytes,
                                    const bool moreFragments,
                                    const std::span<const std::byte> payload) {
    std::vector<std::byte> packet(20U + payload.size());
    packet[0] = byte(0x45);
    put16(packet, 2, static_cast<std::uint16_t>(packet.size()));
    put16(packet, 4, identification);
    const auto offsetUnits = static_cast<std::uint16_t>(offsetBytes / 8U);
    put16(packet, 6, static_cast<std::uint16_t>(
                      (moreFragments ? 0x2000U : 0U) | (offsetUnits & 0x1fffU)));
    packet[8] = byte(64);
    packet[9] = byte(6);
    packet[12] = byte(10);
    packet[15] = byte(1);
    packet[16] = byte(192);
    packet[18] = byte(2);
    packet[19] = byte(1);
    std::ranges::copy(payload, packet.begin() + 20);
    return packet;
}

std::array<std::byte, 24> firstPayload() {
    return {
        byte(0x9c), byte(0x40), byte(0x01), byte(0xbb),
        byte(0x01), byte(0x02), byte(0x03), byte(0x04),
        byte(0x05), byte(0x06), byte(0x07), byte(0x08),
        byte(0x50), byte(0x00), byte(0x00), byte(0x00),
        byte(0x0d), byte(0x0e), byte(0x0f), byte(0x10),
        byte(0x11), byte(0x12), byte(0x13), byte(0x14),
    };
}

std::array<std::byte, 8> secondPayload() {
    return {byte(0x21), byte(0x22), byte(0x23), byte(0x24),
            byte(0x25), byte(0x26), byte(0x27), byte(0x28)};
}

std::array<std::byte, 8> conflictingPayload() {
    return {byte(0xe1), byte(0xe2), byte(0xe3), byte(0xe4),
            byte(0xe5), byte(0xe6), byte(0xe7), byte(0xe8)};
}

std::array<std::byte, 7> malformedMorePayload() {
    return {byte(0x31), byte(0x32), byte(0x33), byte(0x34),
            byte(0x35), byte(0x36), byte(0x37)};
}

FragmentSteeringConfig fragmentConfig(const std::size_t maxDatagrams = 4U,
                                      const std::size_t maxFragments = 4U,
                                      const std::uint64_t timeoutTicks = 10U) {
    return FragmentSteeringConfig{
        .maxDatagrams = maxDatagrams,
        .maxFragmentsPerDatagram = maxFragments,
        .maxPacketBytes = 128,
        .timeoutTicks = timeoutTicks,
    };
}

FlowGraphIngressMetadata metadata(const std::uint32_t uid = 10001) {
    return FlowGraphIngressMetadata{
        .direction = DevicePacketDirection::Input,
        .originalLength = 0,
        .domain = FlowDomain{
            .adapter = AdapterKind::RootNfqueue,
            .linuxUid = uid,
            .uidKnown = true,
            .captureQueue = 7,
            .networkContext = 2,
        },
    };
}

FlowGraphIngressMetadata metadataFor(const std::vector<std::byte> &packet,
                                     const std::uint32_t uid = 10001) {
    auto result = metadata(uid);
    result.originalLength = static_cast<std::uint32_t>(packet.size());
    return result;
}

class CountingPolicy final : public Policy::PacketPolicySnapshot {
public:
    explicit CountingPolicy(const bool drop = false) noexcept : drop_(drop) {}

    [[nodiscard]] Policy::PacketPolicyDecision evaluate(
        const PacketFacts &facts) const noexcept override {
        ++evaluations_;
        lastFacts_ = facts;
        if (drop_) {
            return Policy::PacketPolicyDecision::drop(
                17, 42, 7, Policy::PacketPolicyStage::L4);
        }
        return Policy::PacketPolicyDecision::passNext();
    }

    [[nodiscard]] std::uint32_t evaluations() const noexcept {
        return evaluations_;
    }
    [[nodiscard]] const PacketFacts &lastFacts() const noexcept {
        return lastFacts_;
    }

private:
    bool drop_ = false;
    mutable std::uint32_t evaluations_ = 0;
    mutable PacketFacts lastFacts_;
};

class FixedLpiProvider final : public Protocol::LpiRecognitionProvider {
public:
    explicit FixedLpiProvider(std::string_view alias) noexcept : alias_(alias) {}

    [[nodiscard]] bool available() const noexcept override { return true; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-lpi";
    }
    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        ++calls;
        lastPayloadLength = submission.transportPayload.size();
        return Protocol::LpiProviderFact{
            .providerAlias = alias_,
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        };
    }

    std::uint32_t calls = 0;
    std::size_t lastPayloadLength = 0;

private:
    std::string_view alias_;
};

TEST(FlowGraphFragmentIngressTest,
     NonInitialFragmentBuffersWithoutPortFactsOrPolicyVerdict) {
    FlowSteeringRuntime runtime(WorkerLayout{2, 0x1234}, 4);
    CountingPolicy policy;
    FlowGraphFragmentIngress ingress(
        runtime, policy, FlowGraphIngressConfig{}, fragmentConfig());
    const auto nonInitial = ipv4Fragment(0x4242, 24, false, secondPayload());

    const auto result = ingress.processL3Packet(
        nonInitial, metadataFor(nonInitial), 1);

    EXPECT_EQ(result.status, FlowGraphIngressStatus::FragmentBuffered);
    EXPECT_TRUE(result.datagramKey.has_value());
    EXPECT_FALSE(result.fragmentOwnerMetadata);
    EXPECT_FALSE(result.fragmentReassembled);
    EXPECT_EQ(policy.evaluations(), 0U);
    EXPECT_EQ(runtime.distribution().counters().directPackets, 0U);
}

TEST(FlowGraphFragmentIngressTest,
     ReassemblyEntersFinalOwnerAndPolicyPath) {
    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    CountingPolicy policy;
    FlowGraphFragmentIngress ingress(
        runtime, policy, FlowGraphIngressConfig{}, fragmentConfig());
    const auto first = ipv4Fragment(0x5151, 0, true, firstPayload());
    const auto final = ipv4Fragment(0x5151, 24, false, secondPayload());

    EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
              FlowGraphIngressStatus::FragmentBuffered);
    const auto result = ingress.processL3Packet(final, metadataFor(final), 2);

    EXPECT_EQ(result.status, FlowGraphIngressStatus::Accepted);
    EXPECT_TRUE(result.fragmentReassembled);
    EXPECT_TRUE(result.fragmentOwnerMetadata);
    EXPECT_EQ(policy.evaluations(), 1U);
    EXPECT_TRUE(policy.lastFacts().portsAvailable);
    EXPECT_FALSE(policy.lastFacts().fragmented);
    EXPECT_EQ(policy.lastFacts().sourcePort, 40000U);
    EXPECT_EQ(policy.lastFacts().destinationPort, 443U);
    EXPECT_EQ(runtime.distribution().counters().directPackets, 1U);
    EXPECT_EQ(runtime.ownerGuard().counters().localPass, 1U);
    EXPECT_EQ(runtime.ownerGuard().counters().correctiveHandoffs, 0U);
}

TEST(FlowGraphFragmentIngressTest,
     ReassembledFragmentAcceptedSubmitsLpiAndUpdatesObservation) {
    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    CountingPolicy policy;
    FixedLpiProvider provider("lpi:http");
    FlowGraphFragmentIngress ingress(
        runtime, policy, FlowGraphIngressConfig{}, fragmentConfig(), &provider);
    const auto first = ipv4Fragment(0x5555, 0, true, firstPayload());
    const auto final = ipv4Fragment(0x5555, 24, false, secondPayload());

    EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
              FlowGraphIngressStatus::FragmentBuffered);
    EXPECT_EQ(provider.calls, 0U);
    const auto result = ingress.processL3Packet(final, metadataFor(final), 2);

    EXPECT_EQ(result.status, FlowGraphIngressStatus::Accepted);
    EXPECT_TRUE(result.fragmentReassembled);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lastPayloadLength, 12U);
    ASSERT_TRUE(result.lpiRecognition.has_value());
    EXPECT_TRUE(result.lpiRecognition->observed);
    EXPECT_TRUE(result.lpiRecognition->payloadEligible);
    EXPECT_TRUE(result.lpiRecognition->providerAvailable);
    EXPECT_TRUE(result.lpiRecognition->submittedToProvider);
    EXPECT_TRUE(result.lpiRecognition->providerProducedFact);
    ASSERT_TRUE(result.lpiRecognition->stateAfterSubmit.has_value());
    EXPECT_EQ(result.lpiRecognition->stateAfterSubmit->payloadPacketsSubmitted, 1U);
    ASSERT_TRUE(result.lpiRecognition->stateAfterSubmit->latestExactResult()
                    .has_value());
    EXPECT_EQ(*result.lpiRecognition->stateAfterSubmit->latestExactResult(),
              Catalog::ApplicationProtocolId::HTTP);
    const auto mappedResults =
        result.lpiRecognition->stateAfterSubmit->mappedResults();
    ASSERT_EQ(mappedResults.size(), 1U);
    EXPECT_EQ(mappedResults[0].firstPayloadPacketSequence, 1U);
    EXPECT_EQ(mappedResults[0].direction, FlowRelativeDirection::Orig);
    ASSERT_TRUE(result.flowEntryObservation.has_value());
    EXPECT_EQ(result.flowEntryObservation->lpiRecognition.payloadPacketsSubmitted, 1U);
    ASSERT_TRUE(result.flowEntryObservation->lpiRecognition.latestExactResult()
                    .has_value());
    EXPECT_EQ(*result.flowEntryObservation->lpiRecognition.latestExactResult(),
              Catalog::ApplicationProtocolId::HTTP);
}

TEST(FlowGraphFragmentIngressTest, ReassembledPolicyDropIsGraphPolicyDrop) {
    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    CountingPolicy policy(/*drop=*/true);
    FlowGraphFragmentIngress ingress(
        runtime, policy, FlowGraphIngressConfig{}, fragmentConfig());
    const auto first = ipv4Fragment(0x6161, 0, true, firstPayload());
    const auto final = ipv4Fragment(0x6161, 24, false, secondPayload());

    EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
              FlowGraphIngressStatus::FragmentBuffered);
    const auto result = ingress.processL3Packet(final, metadataFor(final), 2);

    EXPECT_EQ(result.status, FlowGraphIngressStatus::PolicyDrop);
    EXPECT_TRUE(result.fragmentReassembled);
    EXPECT_EQ(policy.evaluations(), 1U);
}

TEST(FlowGraphFragmentIngressTest,
     ReassembledFragmentPolicyDropDoesNotSubmitLpi) {
    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    CountingPolicy policy(/*drop=*/true);
    FixedLpiProvider provider("lpi:http");
    FlowGraphFragmentIngress ingress(
        runtime, policy, FlowGraphIngressConfig{}, fragmentConfig(), &provider);
    const auto first = ipv4Fragment(0x6565, 0, true, firstPayload());
    const auto final = ipv4Fragment(0x6565, 24, false, secondPayload());

    EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
              FlowGraphIngressStatus::FragmentBuffered);
    const auto result = ingress.processL3Packet(final, metadataFor(final), 2);

    EXPECT_EQ(result.status, FlowGraphIngressStatus::PolicyDrop);
    EXPECT_TRUE(result.fragmentReassembled);
    EXPECT_EQ(provider.calls, 0U);
    EXPECT_FALSE(result.lpiRecognition.has_value());
    EXPECT_FALSE(result.flowEntryObservation.has_value());
    EXPECT_EQ(ingress.lpiProviderStatus().counters.packetsObserved, 0U);
}

TEST(FlowGraphFragmentIngressTest, BufferedFragmentsDoNotSubmitLpi) {
    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    CountingPolicy policy;
    FixedLpiProvider provider("lpi:http");
    FlowGraphFragmentIngress ingress(
        runtime, policy, FlowGraphIngressConfig{}, fragmentConfig(), &provider);
    const auto initial = ipv4Fragment(0x8585, 0, true, firstPayload());
    const auto nonInitial = ipv4Fragment(0x8686, 24, false, secondPayload());

    const auto initialResult = ingress.processL3Packet(
        initial, metadataFor(initial), 1);
    const auto nonInitialResult = ingress.processL3Packet(
        nonInitial, metadataFor(nonInitial), 2);

    EXPECT_EQ(initialResult.status, FlowGraphIngressStatus::FragmentBuffered);
    EXPECT_FALSE(initialResult.lpiRecognition.has_value());
    EXPECT_EQ(nonInitialResult.status, FlowGraphIngressStatus::FragmentBuffered);
    EXPECT_FALSE(nonInitialResult.lpiRecognition.has_value());
    EXPECT_EQ(provider.calls, 0U);
    EXPECT_EQ(ingress.lpiProviderStatus().counters.packetsObserved, 0U);
}

TEST(FlowGraphFragmentIngressTest,
     FragmentFaultsDoNotEvaluatePolicyOrBecomePolicyDrop) {
    {
        FlowSteeringRuntime runtime(WorkerLayout{2, 0x1234}, 4);
        CountingPolicy policy(/*drop=*/true);
        FlowGraphFragmentIngress ingress(
            runtime, policy, FlowGraphIngressConfig{}, fragmentConfig());
        const auto malformed = ipv4Fragment(0x7171, 0, true, malformedMorePayload());

        const auto result = ingress.processL3Packet(
            malformed, metadataFor(malformed), 1);

        EXPECT_EQ(result.status, FlowGraphIngressStatus::FragmentMalformed);
        EXPECT_EQ(policy.evaluations(), 0U);
    }
    {
        FlowSteeringRuntime runtime(WorkerLayout{2, 0x1234}, 4);
        CountingPolicy policy(/*drop=*/true);
        FlowGraphFragmentIngress ingress(
            runtime, policy, FlowGraphIngressConfig{}, fragmentConfig());
        const auto first = ipv4Fragment(0x7272, 0, true, firstPayload());
        const auto overlap = ipv4Fragment(0x7272, 16, true, conflictingPayload());

        EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
                  FlowGraphIngressStatus::FragmentBuffered);
        const auto result = ingress.processL3Packet(
            overlap, metadataFor(overlap), 2);

        EXPECT_EQ(result.status, FlowGraphIngressStatus::FragmentConflict);
        EXPECT_EQ(policy.evaluations(), 0U);
    }
    {
        FlowSteeringRuntime runtime(WorkerLayout{2, 0x1234}, 4);
        CountingPolicy policy(/*drop=*/true);
        FlowGraphFragmentIngress ingress(
            runtime, policy, FlowGraphIngressConfig{}, fragmentConfig(4, 4, 2));
        const auto first = ipv4Fragment(0x7373, 0, true, firstPayload());
        const auto final = ipv4Fragment(0x7373, 24, false, secondPayload());

        EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
                  FlowGraphIngressStatus::FragmentBuffered);
        const auto result = ingress.processL3Packet(final, metadataFor(final), 3);

        EXPECT_EQ(result.status, FlowGraphIngressStatus::FragmentTimeout);
        EXPECT_EQ(policy.evaluations(), 0U);
    }
    {
        FlowSteeringRuntime runtime(WorkerLayout{2, 0x1234}, 4);
        CountingPolicy policy(/*drop=*/true);
        FlowGraphFragmentIngress ingress(
            runtime, policy, FlowGraphIngressConfig{}, fragmentConfig(1));
        const auto first = ipv4Fragment(0x7474, 0, true, firstPayload());
        const auto otherFirst = ipv4Fragment(0x7575, 0, true, firstPayload());

        EXPECT_EQ(ingress.processL3Packet(first, metadataFor(first), 1).status,
                  FlowGraphIngressStatus::FragmentBuffered);
        const auto result = ingress.processL3Packet(
            otherFirst, metadataFor(otherFirst), 2);

        EXPECT_EQ(result.status, FlowGraphIngressStatus::FragmentCapacity);
        EXPECT_EQ(policy.evaluations(), 0U);
    }
}

} // namespace
