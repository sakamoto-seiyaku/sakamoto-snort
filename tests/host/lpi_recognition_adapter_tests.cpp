/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionAdapter.hpp>
#include <core/protocol/LpiRecognitionProvider.hpp>

#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <span>

namespace {

using namespace SnortDatapath;

namespace Flow = SnortDatapath::Flow;
namespace Protocol = SnortDatapath::Protocol;
namespace Catalog = sucre::protocol;

Flow::PacketFacts tcpPacket(const bool reverse = false) {
    return Flow::PacketFacts{
        .source = Flow::IpAddress::v4(reverse
                                      ? std::array<std::uint8_t, 4>{192, 0, 2, 1}
                                      : std::array<std::uint8_t, 4>{10, 0, 0, 1}),
        .destination = Flow::IpAddress::v4(reverse
                                           ? std::array<std::uint8_t, 4>{10, 0, 0, 1}
                                           : std::array<std::uint8_t, 4>{192, 0, 2, 1}),
        .ipProtocol = 6,
        .sourcePort = static_cast<std::uint16_t>(reverse ? 443 : 40000),
        .destinationPort = static_cast<std::uint16_t>(reverse ? 40000 : 443),
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = Flow::ParseStatus::Ready,
        .deviceDirection = reverse ? Flow::DevicePacketDirection::Output
                                   : Flow::DevicePacketDirection::Input,
        .originalLength = 1500,
        .boundedPrefixLength = 512,
        .transportPayloadOffset = 40,
        .transportPayloadLength = 472,
        .domain = Flow::FlowDomain{
            .adapter = Flow::AdapterKind::RootNfqueue,
            .linuxUid = 10001,
            .uidKnown = true,
            .captureQueue = 7,
            .networkContext = 2,
            .runtimeProfile = 3,
        },
    };
}

TEST(LpiRecognitionAdapterTest, ProviderAliasMapsIntoExistingFlowEntryForCurrentPacket) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    Protocol::LpiRecognitionAdapter adapter(table);

    const auto outcome = adapter.submitProviderFact(
        packet,
        Protocol::LpiProviderFact{
            .providerAlias = "lpi:http",
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        });

    ASSERT_TRUE(outcome.flowUpdate.has_value());
    EXPECT_EQ(outcome.cutoff, Protocol::RecognitionDecisionCutoff::CurrentPacket);
    EXPECT_TRUE(outcome.mappedProviderResult);
    EXPECT_TRUE(outcome.flowUpdate->mappedResultAppended);
    EXPECT_EQ(outcome.flowUpdate->direction, Flow::FlowRelativeDirection::Orig);
    ASSERT_TRUE(outcome.flowUpdate->latestExactResult.has_value());
    EXPECT_EQ(*outcome.flowUpdate->latestExactResult, Catalog::ApplicationProtocolId::HTTP);
    EXPECT_EQ(table.size(), 1U);
}

TEST(LpiRecognitionAdapterTest, AsyncProviderFactOnlyAffectsFuturePackets) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    const auto reply = tcpPacket(true);
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    Protocol::LpiRecognitionAdapter adapter(table);

    const auto outcome = adapter.submitProviderFact(
        reply,
        Protocol::LpiProviderFact{
            .providerAlias = "lpi:quic",
            .detectorDone = true,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = false,
        });

    ASSERT_TRUE(outcome.flowUpdate.has_value());
    EXPECT_EQ(outcome.cutoff, Protocol::RecognitionDecisionCutoff::FuturePacketsOnly);
    EXPECT_TRUE(outcome.mappedProviderResult);
    EXPECT_EQ(outcome.flowUpdate->terminalState, Flow::LpiRecognitionTerminalState::Done);
    EXPECT_EQ(outcome.flowUpdate->direction, Flow::FlowRelativeDirection::Reply);
    ASSERT_TRUE(outcome.flowUpdate->latestExactResult.has_value());
    EXPECT_EQ(*outcome.flowUpdate->latestExactResult, Catalog::ApplicationProtocolId::QUIC);
}

TEST(LpiRecognitionAdapterTest, UnmappedProviderResultCreatesNoTemporaryProtocolId) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    Protocol::LpiRecognitionAdapter adapter(table);

    const auto outcome = adapter.submitProviderFact(
        packet,
        Protocol::LpiProviderFact{
            .providerAlias = "lpi:unknown-long-tail",
            .detectorDone = false,
            .budgetExhausted = true,
            .producedBeforeAdapterCompletion = true,
        });

    ASSERT_TRUE(outcome.flowUpdate.has_value());
    EXPECT_FALSE(outcome.mappedProviderResult);
    EXPECT_TRUE(outcome.unmappedProviderResult);
    EXPECT_TRUE(outcome.flowUpdate->unmappedResult);
    EXPECT_EQ(outcome.flowUpdate->mappedResultCount, 0U);
    EXPECT_FALSE(outcome.flowUpdate->latestExactResult.has_value());
    EXPECT_EQ(outcome.flowUpdate->terminalState,
              Flow::LpiRecognitionTerminalState::Exhausted);
    EXPECT_EQ(table.counters().lpiUnmappedResults, 1U);
}

TEST(LpiRecognitionAdapterTest, MissingFlowDoesNotCreateParallelRecognitionTable) {
    Flow::BoundedFlowTable table(4);
    Protocol::LpiRecognitionAdapter adapter(table);

    const auto outcome = adapter.submitProviderFact(
        tcpPacket(),
        Protocol::LpiProviderFact{
            .providerAlias = "lpi:dns",
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        });

    ASSERT_TRUE(outcome.flowUpdate.has_value());
    EXPECT_FALSE(outcome.flowUpdate->found);
    EXPECT_EQ(table.size(), 0U);
    EXPECT_EQ(table.counters().lpiFlowMisses, 1U);
}

TEST(LpiRecognitionAdapterTest, EmptyTransportPayloadDoesNotConsumeRecognitionBudget) {
    Flow::BoundedFlowTable table(4);
    auto packet = tcpPacket();
    packet.boundedPrefixLength = 40;
    packet.transportPayloadOffset = 40;
    packet.transportPayloadLength = 0;
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    Protocol::LpiRecognitionAdapter adapter(table);

    const auto outcome = adapter.submitProviderFact(
        packet,
        Protocol::LpiProviderFact{
            .providerAlias = "lpi:http",
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        });

    ASSERT_TRUE(outcome.flowUpdate.has_value());
    EXPECT_TRUE(outcome.mappedProviderResult);
    EXPECT_FALSE(outcome.unmappedProviderResult);
    EXPECT_FALSE(outcome.flowUpdate->payloadSubmitted);
    EXPECT_FALSE(outcome.flowUpdate->mappedResultAppended);
    EXPECT_EQ(outcome.flowUpdate->payloadPacketSequence, 0U);
    EXPECT_EQ(table.counters().lpiPayloadPackets, 0U);
    EXPECT_EQ(table.counters().lpiMappedResults, 0U);
}

TEST(LpiRecognitionAdapterTest, LatestExactResultUpdatesAfterBoundedSequenceFull) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());

    for (std::uint32_t index = 0;
         index < Flow::LpiRecognitionState::kMaxMappedResults;
         ++index) {
        const auto update = table.recordLpiRecognition(
            packet,
            true,
            static_cast<Catalog::ApplicationProtocolId>(2000 + index),
            true,
            false,
            false);
        ASSERT_TRUE(update.has_value());
        EXPECT_TRUE(update->mappedResultAppended);
    }

    const auto latestOnlyProtocol =
        static_cast<Catalog::ApplicationProtocolId>(3000);
    const auto update = table.recordLpiRecognition(
        packet, true, latestOnlyProtocol, true, false, false);

    ASSERT_TRUE(update.has_value());
    EXPECT_FALSE(update->mappedResultAppended);
    EXPECT_EQ(update->mappedResultCount, Flow::LpiRecognitionState::kMaxMappedResults);
    ASSERT_TRUE(update->latestExactResult.has_value());
    EXPECT_EQ(*update->latestExactResult, latestOnlyProtocol);
    EXPECT_EQ(table.counters().lpiResultCapacityMisses, 1U);
    const auto state = table.lpiRecognitionStateFor(packet);
    ASSERT_TRUE(state.has_value());
    ASSERT_TRUE(state->latestExactResult().has_value());
    EXPECT_EQ(*state->latestExactResult(), latestOnlyProtocol);
    EXPECT_EQ(state->mappedResults.size(), Flow::LpiRecognitionState::kMaxMappedResults);
}

class NoResultProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return true; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-no-result";
    }
    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        ++calls;
        lastPayloadLength = submission.transportPayload.size();
        return std::nullopt;
    }

    std::uint32_t calls = 0;
    std::size_t lastPayloadLength = 0;
};

TEST(LpiRecognitionProviderTest, DisabledProviderIsObservableWithoutMutatingFlowState) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    Protocol::LpiRecognitionPipeline pipeline(table);
    const std::array<std::byte, 512> l3Packet{};

    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(outcome.observed);
    EXPECT_TRUE(outcome.payloadEligible);
    EXPECT_FALSE(outcome.providerAvailable);
    EXPECT_FALSE(outcome.submittedToProvider);
    EXPECT_FALSE(outcome.adapterOutcome.has_value());
    const auto status = pipeline.status();
    EXPECT_FALSE(status.available);
    EXPECT_EQ(status.providerName, "disabled");
    EXPECT_EQ(status.counters.payloadEligiblePackets, 1U);
    EXPECT_EQ(status.counters.providerUnavailablePackets, 1U);
    EXPECT_EQ(table.counters().lpiPayloadPackets, 0U);
    const auto state = table.lpiRecognitionStateFor(packet);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->payloadPacketsSubmitted, 0U);
}

TEST(LpiRecognitionProviderTest, ProviderNoResultConsumesBudgetWithoutUnmappedResult) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    NoResultProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(outcome.providerAvailable);
    EXPECT_TRUE(outcome.submittedToProvider);
    EXPECT_FALSE(outcome.providerProducedFact);
    ASSERT_TRUE(outcome.adapterOutcome.has_value());
    ASSERT_TRUE(outcome.adapterOutcome->flowUpdate.has_value());
    EXPECT_TRUE(outcome.adapterOutcome->flowUpdate->payloadSubmitted);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->unmappedResult);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lastPayloadLength, 472U);
    EXPECT_EQ(table.counters().lpiPayloadPackets, 1U);
    EXPECT_EQ(table.counters().lpiUnmappedResults, 0U);
    const auto state = table.lpiRecognitionStateFor(packet);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->payloadPacketsSubmitted, 1U);
    EXPECT_TRUE(state->mappedResults.empty());
}

TEST(LpiRecognitionProviderTest, NoResultProviderStopsAtInternalPayloadBudget) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    NoResultProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    for (std::uint32_t index = 1;
         index <= Flow::LpiRecognitionState::kMaxPayloadPackets;
         ++index) {
        const auto outcome = pipeline.submitBeforeAdapterCompletion(
            std::span<const std::byte>{l3Packet}, packet);
        EXPECT_TRUE(outcome.submittedToProvider);
        ASSERT_TRUE(outcome.adapterOutcome.has_value());
        ASSERT_TRUE(outcome.adapterOutcome->flowUpdate.has_value());
        EXPECT_EQ(outcome.adapterOutcome->flowUpdate->payloadPacketSequence, index);
    }

    EXPECT_EQ(provider.calls, Flow::LpiRecognitionState::kMaxPayloadPackets);
    auto state = table.lpiRecognitionStateFor(packet);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->payloadPacketsSubmitted,
              Flow::LpiRecognitionState::kMaxPayloadPackets);
    EXPECT_EQ(state->terminalState, Flow::LpiRecognitionTerminalState::Exhausted);

    const auto afterExhaustion = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);
    EXPECT_TRUE(afterExhaustion.terminalSkipped);
    EXPECT_FALSE(afterExhaustion.submittedToProvider);
    EXPECT_EQ(provider.calls, Flow::LpiRecognitionState::kMaxPayloadPackets);
    EXPECT_EQ(pipeline.status().counters.terminalSkippedPackets, 1U);
}

} // namespace
