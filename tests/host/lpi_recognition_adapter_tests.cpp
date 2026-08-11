/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionAdapter.hpp>

#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <gtest/gtest.h>

#include <array>

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

} // namespace
