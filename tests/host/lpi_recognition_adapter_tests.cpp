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
#include <memory>
#include <span>
#include <vector>

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
    EXPECT_EQ(state->mappedResultCount, Flow::LpiRecognitionState::kMaxMappedResults);
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

struct TrackingContextLifecycle {
    std::uint32_t constructed = 0;
    std::uint32_t live = 0;
    std::uint32_t destroyed = 0;
};

class TrackingContext final : public Flow::LpiProviderFlowContext {
public:
    TrackingContext(std::shared_ptr<TrackingContextLifecycle> contextLifecycle,
                    const std::uint32_t contextId) noexcept
        : lifecycle(contextLifecycle), id(contextId) {
        ++lifecycle->constructed;
        ++lifecycle->live;
    }

    ~TrackingContext() noexcept override {
        --lifecycle->live;
        ++lifecycle->destroyed;
    }

    std::shared_ptr<TrackingContextLifecycle> lifecycle;
    std::uint32_t id = 0;
};

class MappedDoneProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return true; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-mapped-done";
    }
    [[nodiscard]] std::unique_ptr<Flow::LpiProviderFlowContext> createFlowContext(
        const Protocol::LpiProviderFlowInit &) noexcept override {
        ++createCalls;
        return std::make_unique<TrackingContext>(lifecycle, createCalls);
    }
    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        ++calls;
        lastPayloadLength = submission.transportPayload.size();
        if (const auto *tracking =
                dynamic_cast<const TrackingContext *>(&submission.flowContext);
            tracking != nullptr) {
            contextIds.push_back(tracking->id);
        }
        return Protocol::LpiProviderFact{
            .providerAlias = "lpi:http",
            .detectorDone = true,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        };
    }

    std::uint32_t createCalls = 0;
    std::uint32_t calls = 0;
    std::size_t lastPayloadLength = 0;
    std::shared_ptr<TrackingContextLifecycle> lifecycle =
        std::make_shared<TrackingContextLifecycle>();
    std::vector<std::uint32_t> contextIds;
};

class TrackingContextProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return availableFlag; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-tracking-context";
    }
    [[nodiscard]] std::unique_ptr<Flow::LpiProviderFlowContext> createFlowContext(
        const Protocol::LpiProviderFlowInit &init) noexcept override {
        ++createCalls;
        initDirections.push_back(init.packetDirection);
        initIpProtocols.push_back(init.ipProtocol);
        initOriginSourcePorts.push_back(init.originSourcePort);
        initOriginDestinationPorts.push_back(init.originDestinationPort);
        return std::make_unique<TrackingContext>(lifecycle, createCalls);
    }
    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        ++calls;
        directions.push_back(submission.packetDirection);
        if (const auto *tracking =
                dynamic_cast<const TrackingContext *>(&submission.flowContext);
            tracking != nullptr) {
            contextIds.push_back(tracking->id);
        }
        return std::nullopt;
    }

    std::uint32_t createCalls = 0;
    std::uint32_t calls = 0;
    bool availableFlag = true;
    std::vector<Flow::FlowRelativeDirection> initDirections;
    std::vector<std::uint8_t> initIpProtocols;
    std::vector<std::uint16_t> initOriginSourcePorts;
    std::vector<std::uint16_t> initOriginDestinationPorts;
    std::vector<Flow::FlowRelativeDirection> directions;
    std::shared_ptr<TrackingContextLifecycle> lifecycle =
        std::make_shared<TrackingContextLifecycle>();
    std::vector<std::uint32_t> contextIds;
};

class UnavailableTrackingProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return false; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-unavailable";
    }
    [[nodiscard]] std::unique_ptr<Flow::LpiProviderFlowContext> createFlowContext(
        const Protocol::LpiProviderFlowInit &) noexcept override {
        ++createCalls;
        return std::make_unique<Flow::LpiProviderFlowContext>();
    }
    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &) noexcept override {
        ++calls;
        return std::nullopt;
    }

    std::uint32_t createCalls = 0;
    std::uint32_t calls = 0;
};

class NullContextProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return true; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-null-context";
    }
    [[nodiscard]] std::unique_ptr<Flow::LpiProviderFlowContext> createFlowContext(
        const Protocol::LpiProviderFlowInit &) noexcept override {
        ++createCalls;
        return nullptr;
    }
    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &) noexcept override {
        ++calls;
        return std::nullopt;
    }

    std::uint32_t createCalls = 0;
    std::uint32_t calls = 0;
};

TEST(LpiRecognitionProviderTest, DisabledProviderIsObservableWithoutMutatingFlowState) {
    EXPECT_FALSE(Protocol::kRealLpiProviderEnabledByDefault);
    EXPECT_EQ(Protocol::kDisabledLpiProviderName, "disabled");

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

TEST(LpiRecognitionProviderTest, UnavailableProviderDoesNotCreateFlowContext) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    UnavailableTrackingProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(outcome.observed);
    EXPECT_TRUE(outcome.payloadEligible);
    EXPECT_FALSE(outcome.providerAvailable);
    EXPECT_FALSE(outcome.submittedToProvider);
    EXPECT_FALSE(outcome.adapterOutcome.has_value());
    EXPECT_EQ(provider.createCalls, 0U);
    EXPECT_EQ(provider.calls, 0U);
    const auto status = pipeline.status();
    EXPECT_EQ(status.counters.providerUnavailablePackets, 1U);
    EXPECT_EQ(status.counters.packetsSubmittedToProvider, 0U);
}

TEST(LpiRecognitionProviderTest, AvailableProviderWithoutContextDoesNotRecognize) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    NullContextProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(outcome.observed);
    EXPECT_TRUE(outcome.payloadEligible);
    EXPECT_TRUE(outcome.providerAvailable);
    EXPECT_FALSE(outcome.submittedToProvider);
    EXPECT_FALSE(outcome.adapterOutcome.has_value());
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 0U);
    const auto status = pipeline.status();
    EXPECT_EQ(status.counters.providerUnavailablePackets, 0U);
    EXPECT_EQ(status.counters.providerContextUnavailablePackets, 1U);
    EXPECT_EQ(status.counters.packetsSubmittedToProvider, 0U);
}

TEST(LpiRecognitionProviderTest, AvailableProviderReusesFlowContextAndSeesOriginDirection) {
    Flow::BoundedFlowTable table(4);
    const auto originNotCanonical = tcpPacket(true);
    const auto reply = tcpPacket(false);
    ASSERT_TRUE(table.observeAccepted(originNotCanonical, 7).has_value());
    TrackingContextProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto first = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, originNotCanonical);
    const auto second = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, reply);

    EXPECT_TRUE(first.submittedToProvider);
    EXPECT_TRUE(second.submittedToProvider);
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 2U);
    ASSERT_EQ(provider.initDirections.size(), 1U);
    EXPECT_EQ(provider.initDirections[0], Flow::FlowRelativeDirection::Orig);
    ASSERT_EQ(provider.initIpProtocols.size(), 1U);
    EXPECT_EQ(provider.initIpProtocols[0], 6U);
    ASSERT_EQ(provider.initOriginSourcePorts.size(), 1U);
    EXPECT_EQ(provider.initOriginSourcePorts[0], 443U);
    ASSERT_EQ(provider.initOriginDestinationPorts.size(), 1U);
    EXPECT_EQ(provider.initOriginDestinationPorts[0], 40000U);
    ASSERT_EQ(provider.directions.size(), 2U);
    EXPECT_EQ(provider.directions[0], Flow::FlowRelativeDirection::Orig);
    EXPECT_EQ(provider.directions[1], Flow::FlowRelativeDirection::Reply);
    ASSERT_EQ(provider.contextIds.size(), 2U);
    EXPECT_EQ(provider.contextIds[0], 1U);
    EXPECT_EQ(provider.contextIds[1], 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 1U);
    EXPECT_EQ(provider.lifecycle->destroyed, 0U);
    const auto state = table.lpiRecognitionStateFor(originNotCanonical);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->payloadPacketsSubmitted, 2U);
}

TEST(LpiRecognitionProviderTest, ProviderUnavailableClearsExistingFlowContext) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    TrackingContextProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto first = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(first.submittedToProvider);
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 1U);
    ASSERT_EQ(provider.contextIds.size(), 1U);
    EXPECT_EQ(provider.contextIds[0], 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 1U);
    EXPECT_EQ(provider.lifecycle->destroyed, 0U);

    provider.availableFlag = false;
    const auto unavailable = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(unavailable.observed);
    EXPECT_TRUE(unavailable.payloadEligible);
    EXPECT_FALSE(unavailable.providerAvailable);
    EXPECT_FALSE(unavailable.submittedToProvider);
    EXPECT_FALSE(unavailable.adapterOutcome.has_value());
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 0U);
    EXPECT_EQ(provider.lifecycle->destroyed, 1U);
    const auto status = pipeline.status();
    EXPECT_EQ(status.counters.providerUnavailablePackets, 1U);
    EXPECT_EQ(status.counters.packetsSubmittedToProvider, 1U);
}

TEST(LpiRecognitionProviderTest, TerminalSkipClearsExternallyTerminalFlowContext) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    TrackingContextProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto first = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(first.submittedToProvider);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 1U);
    EXPECT_EQ(provider.lifecycle->destroyed, 0U);

    const auto externalDone = table.recordLpiRecognition(
        packet,
        true,
        Catalog::ApplicationProtocolId::HTTP,
        true,
        true,
        false);
    ASSERT_TRUE(externalDone.has_value());
    EXPECT_EQ(externalDone->terminalState, Flow::LpiRecognitionTerminalState::Done);

    const auto terminalSkip = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(terminalSkip.terminalSkipped);
    EXPECT_FALSE(terminalSkip.submittedToProvider);
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 0U);
    EXPECT_EQ(provider.lifecycle->destroyed, 1U);
}

TEST(LpiRecognitionProviderTest, MissingFlowDoesNotCreateProviderContextOrTableState) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    TrackingContextProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(outcome.observed);
    EXPECT_TRUE(outcome.payloadEligible);
    EXPECT_TRUE(outcome.providerAvailable);
    EXPECT_FALSE(outcome.submittedToProvider);
    EXPECT_FALSE(outcome.adapterOutcome.has_value());
    EXPECT_FALSE(outcome.stateAfterSubmit.has_value());
    EXPECT_EQ(provider.createCalls, 0U);
    EXPECT_EQ(provider.calls, 0U);
    EXPECT_EQ(table.size(), 0U);
    const auto status = pipeline.status();
    EXPECT_EQ(status.counters.providerUnavailablePackets, 0U);
    EXPECT_EQ(status.counters.flowSlotUnavailablePackets, 1U);
    EXPECT_EQ(status.counters.providerContextUnavailablePackets, 0U);
    EXPECT_EQ(status.counters.packetsSubmittedToProvider, 0U);
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
    EXPECT_TRUE(state->mappedResultsEmpty());
}

TEST(LpiRecognitionProviderTest, TruncatedL3PacketDoesNotSubmitPartialPayload) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    NoResultProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 48> truncatedL3Packet{};

    const auto outcome = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{truncatedL3Packet}, packet);

    EXPECT_TRUE(outcome.observed);
    EXPECT_FALSE(outcome.payloadEligible);
    EXPECT_TRUE(outcome.providerAvailable);
    EXPECT_FALSE(outcome.submittedToProvider);
    EXPECT_FALSE(outcome.adapterOutcome.has_value());
    EXPECT_EQ(provider.calls, 0U);
    const auto status = pipeline.status();
    EXPECT_EQ(status.counters.packetsObserved, 1U);
    EXPECT_EQ(status.counters.payloadEligiblePackets, 0U);
    EXPECT_EQ(status.counters.packetsSubmittedToProvider, 0U);
    EXPECT_EQ(table.counters().lpiPayloadPackets, 0U);
    const auto state = table.lpiRecognitionStateFor(packet);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->payloadPacketsSubmitted, 0U);
}

TEST(LpiRecognitionProviderTest, TruncatedL3PacketPreservesExistingFlowContext) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    TrackingContextProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto first = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(first.submittedToProvider);
    ASSERT_EQ(provider.contextIds.size(), 1U);
    EXPECT_EQ(provider.contextIds[0], 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 1U);
    EXPECT_EQ(provider.lifecycle->destroyed, 0U);

    const std::array<std::byte, 48> truncatedL3Packet{};
    const auto truncated = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{truncatedL3Packet}, packet);

    EXPECT_TRUE(truncated.observed);
    EXPECT_FALSE(truncated.payloadEligible);
    EXPECT_FALSE(truncated.submittedToProvider);
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 1U);
    EXPECT_EQ(provider.lifecycle->destroyed, 0U);
    const auto status = pipeline.status();
    EXPECT_EQ(status.counters.payloadEligiblePackets, 1U);
    EXPECT_EQ(status.counters.packetsSubmittedToProvider, 1U);
}

TEST(LpiRecognitionProviderTest, TerminalDoneFlowSkipsLaterPayloadsWithoutProviderCall) {
    Flow::BoundedFlowTable table(4);
    const auto packet = tcpPacket();
    ASSERT_TRUE(table.observeAccepted(packet, 7).has_value());
    MappedDoneProvider provider;
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 512> l3Packet{};

    const auto first = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(first.providerAvailable);
    EXPECT_TRUE(first.submittedToProvider);
    EXPECT_TRUE(first.providerProducedFact);
    ASSERT_TRUE(first.adapterOutcome.has_value());
    ASSERT_TRUE(first.adapterOutcome->flowUpdate.has_value());
    EXPECT_TRUE(first.adapterOutcome->mappedProviderResult);
    EXPECT_EQ(first.adapterOutcome->flowUpdate->terminalState,
              Flow::LpiRecognitionTerminalState::Done);
    ASSERT_TRUE(first.adapterOutcome->flowUpdate->latestExactResult.has_value());
    EXPECT_EQ(*first.adapterOutcome->flowUpdate->latestExactResult,
              Catalog::ApplicationProtocolId::HTTP);
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lastPayloadLength, 472U);
    ASSERT_EQ(provider.contextIds.size(), 1U);
    EXPECT_EQ(provider.contextIds[0], 1U);
    ASSERT_TRUE(first.stateAfterSubmit.has_value());
    EXPECT_EQ(first.stateAfterSubmit->terminalState,
              Flow::LpiRecognitionTerminalState::Done);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 0U);
    EXPECT_EQ(provider.lifecycle->destroyed, 1U);

    const auto second = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);

    EXPECT_TRUE(second.observed);
    EXPECT_TRUE(second.payloadEligible);
    EXPECT_TRUE(second.providerAvailable);
    EXPECT_TRUE(second.terminalSkipped);
    EXPECT_FALSE(second.submittedToProvider);
    EXPECT_FALSE(second.providerProducedFact);
    EXPECT_FALSE(second.adapterOutcome.has_value());
    EXPECT_EQ(provider.createCalls, 1U);
    EXPECT_EQ(provider.calls, 1U);
    EXPECT_EQ(provider.lifecycle->constructed, 1U);
    EXPECT_EQ(provider.lifecycle->live, 0U);
    EXPECT_EQ(provider.lifecycle->destroyed, 1U);
    ASSERT_TRUE(second.stateAfterSubmit.has_value());
    EXPECT_EQ(second.stateAfterSubmit->terminalState,
              Flow::LpiRecognitionTerminalState::Done);
    EXPECT_EQ(second.stateAfterSubmit->payloadPacketsSubmitted, 1U);
    ASSERT_TRUE(second.stateAfterSubmit->latestExactResult().has_value());
    EXPECT_EQ(*second.stateAfterSubmit->latestExactResult(),
              Catalog::ApplicationProtocolId::HTTP);
    const auto status = pipeline.status();
    EXPECT_EQ(status.payloadBudgetPackets,
              Flow::LpiRecognitionState::kMaxPayloadPackets);
    EXPECT_EQ(status.mappedResultCapacity,
              Flow::LpiRecognitionState::kMaxMappedResults);
    EXPECT_EQ(status.counters.terminalSkippedPackets, 1U);
    EXPECT_EQ(status.counters.detectorDonePackets, 1U);
    EXPECT_EQ(status.counters.budgetExhaustedPackets, 0U);
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
    const auto status = pipeline.status();
    EXPECT_EQ(status.payloadBudgetPackets,
              Flow::LpiRecognitionState::kMaxPayloadPackets);
    EXPECT_EQ(status.mappedResultCapacity,
              Flow::LpiRecognitionState::kMaxMappedResults);
    EXPECT_EQ(status.counters.terminalSkippedPackets, 1U);
    EXPECT_EQ(status.counters.detectorDonePackets, 0U);
    EXPECT_EQ(status.counters.budgetExhaustedPackets, 1U);
}

} // namespace
