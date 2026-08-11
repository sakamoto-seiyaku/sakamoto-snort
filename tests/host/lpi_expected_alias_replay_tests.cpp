/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionAdapter.hpp>
#include <core/protocol/LpiRecognitionProvider.hpp>

#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace Flow = SnortDatapath::Flow;
namespace Protocol = SnortDatapath::Protocol;
namespace Catalog = sucre::protocol;

enum class ReplayKind : std::uint8_t {
    Mapped,
    Unmapped,
    NoResult,
};

struct ReplayEvent {
    ReplayKind kind = ReplayKind::NoResult;
    std::string expectedAppName;
    std::optional<std::string> providerAlias;
    std::optional<Catalog::ApplicationProtocolId> expectedProtocol;
};

struct AggregateCounts {
    std::uint32_t dns = 0;
    std::uint32_t http = 0;
    std::uint32_t quic = 0;
    std::uint32_t ssl = 0;
    std::uint32_t unmapped = 0;
    std::uint32_t noResult = 0;

    [[nodiscard]] std::uint32_t mapped() const noexcept {
        return dns + http + quic + ssl;
    }

    [[nodiscard]] std::uint32_t total() const noexcept {
        return mapped() + unmapped + noResult;
    }
};

constexpr AggregateCounts kExpectedBaseline{
    .dns = 145,
    .http = 36,
    .quic = 21,
    .ssl = 4,
    .unmapped = 81,
    .noResult = 6,
};

struct UnmappedExpectedAppCount {
    std::string_view appName;
    std::uint32_t count = 0;
};

constexpr std::array<UnmappedExpectedAppCount, 19> kUnmappedExpectedApps{{
    {"DHCP", 1},
    {"DTLS", 1},
    {"FTP", 5},
    {"IMAP", 2},
    {"ISAKMP", 1},
    {"NETBIOS", 4},
    {"OPENVPN", 12},
    {"POP3", 4},
    {"PPTP", 1},
    {"QQ", 2},
    {"RDP", 1},
    {"RTCP", 1},
    {"RTP", 1},
    {"SMTP", 9},
    {"SMTPS", 1},
    {"SOCKS", 28},
    {"STUN", 2},
    {"WECHAT", 2},
    {"WIREGUARD", 3},
}};

[[nodiscard]] std::string providerAliasForExpectedApp(
    const std::string_view appName) {
    std::string alias{"lpi:"};
    alias.reserve(alias.size() + appName.size());
    for (const auto ch : appName) {
        alias.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(ch))));
    }
    return alias;
}

void appendRepeated(std::vector<ReplayEvent> &events,
                    const std::string_view appName,
                    const std::string_view providerAlias,
                    const Catalog::ApplicationProtocolId expectedProtocol,
                    const std::uint32_t count) {
    for (std::uint32_t index = 0; index < count; ++index) {
        events.push_back(ReplayEvent{
            .kind = ReplayKind::Mapped,
            .expectedAppName = std::string{appName},
            .providerAlias = std::string{providerAlias},
            .expectedProtocol = expectedProtocol,
        });
    }
}

[[nodiscard]] std::vector<ReplayEvent> buildExpectedAliasReplayFixture() {
    std::vector<ReplayEvent> events;
    events.reserve(kExpectedBaseline.total());

    appendRepeated(events, "DNS", "lpi:dns",
                   Catalog::ApplicationProtocolId::DNS,
                   kExpectedBaseline.dns);
    appendRepeated(events, "HTTP", "lpi:http",
                   Catalog::ApplicationProtocolId::HTTP,
                   kExpectedBaseline.http);
    appendRepeated(events, "QUIC", "lpi:quic",
                   Catalog::ApplicationProtocolId::QUIC,
                   kExpectedBaseline.quic);
    appendRepeated(events, "SSL", "lpi:ssl",
                   Catalog::ApplicationProtocolId::TLS,
                   kExpectedBaseline.ssl);

    auto unmappedCount = std::uint32_t{0};
    for (const auto &app : kUnmappedExpectedApps) {
        unmappedCount += app.count;
        for (std::uint32_t index = 0; index < app.count; ++index) {
            events.push_back(ReplayEvent{
                .kind = ReplayKind::Unmapped,
                .expectedAppName = std::string{app.appName},
                .providerAlias = providerAliasForExpectedApp(app.appName),
                .expectedProtocol = std::nullopt,
            });
        }
    }
    if (unmappedCount != kExpectedBaseline.unmapped) {
        throw std::logic_error{"unmapped fixture count drift"};
    }

    for (std::uint32_t index = 0; index < kExpectedBaseline.noResult; ++index) {
        events.push_back(ReplayEvent{
            .kind = ReplayKind::NoResult,
            .expectedAppName = "UNKNOWN",
            .providerAlias = std::nullopt,
            .expectedProtocol = std::nullopt,
        });
    }

    return events;
}

[[nodiscard]] Flow::PacketFacts syntheticTcpPacket(
    const std::uint32_t sequence,
    const bool reverse = false) {
    const auto third = static_cast<std::uint8_t>((sequence / 250U) % 250U);
    const auto fourth = static_cast<std::uint8_t>((sequence % 250U) + 1U);
    const auto sourcePort = static_cast<std::uint16_t>(10000U + sequence);
    const auto destinationPort =
        static_cast<std::uint16_t>(443U + (sequence % 100U));

    return Flow::PacketFacts{
        .source = Flow::IpAddress::v4(reverse
            ? std::array<std::uint8_t, 4>{198, 51, third, fourth}
            : std::array<std::uint8_t, 4>{10, 61, third, fourth}),
        .destination = Flow::IpAddress::v4(reverse
            ? std::array<std::uint8_t, 4>{10, 61, third, fourth}
            : std::array<std::uint8_t, 4>{198, 51, third, fourth}),
        .ipProtocol = 6,
        .sourcePort = reverse ? destinationPort : sourcePort,
        .destinationPort = reverse ? sourcePort : destinationPort,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = Flow::ParseStatus::Ready,
        .deviceDirection = reverse ? Flow::DevicePacketDirection::Output
                                   : Flow::DevicePacketDirection::Input,
        .originalLength = 128,
        .boundedPrefixLength = 128,
        .transportPayloadOffset = 40,
        .transportPayloadLength = 64,
        .domain = Flow::FlowDomain{
            .adapter = Flow::AdapterKind::RootNfqueue,
            .linuxUid = 10001U + sequence,
            .uidKnown = true,
            .captureQueue = 7,
            .networkContext = 61,
            .runtimeProfile = 1,
        },
    };
}

class ScriptedProvider final : public Protocol::LpiRecognitionProvider {
public:
    explicit ScriptedProvider(const std::span<const ReplayEvent> events) noexcept
        : events_(events) {}

    [[nodiscard]] bool available() const noexcept override { return true; }

    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "scripted-vpp-expected-alias-fixture";
    }

    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        ++calls;
        lastPayloadLength = submission.transportPayload.size();
        lastL3PacketLength = submission.l3Packet.size();
        if (next_ >= events_.size()) {
            exhaustedCalls += 1;
            return std::nullopt;
        }

        const auto &event = events_[next_];
        ++next_;
        if (!event.providerAlias.has_value()) {
            return std::nullopt;
        }

        return Protocol::LpiProviderFact{
            .providerAlias = *event.providerAlias,
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        };
    }

    [[nodiscard]] std::size_t consumed() const noexcept { return next_; }

    std::uint32_t calls = 0;
    std::uint32_t exhaustedCalls = 0;
    std::size_t lastPayloadLength = 0;
    std::size_t lastL3PacketLength = 0;

private:
    std::span<const ReplayEvent> events_;
    std::size_t next_ = 0;
};

void expectMappedOutcome(const Protocol::LpiPipelineOutcome &outcome,
                         const Catalog::ApplicationProtocolId expectedProtocol) {
    EXPECT_TRUE(outcome.providerProducedFact);
    ASSERT_TRUE(outcome.adapterOutcome.has_value());
    EXPECT_TRUE(outcome.adapterOutcome->mappedProviderResult);
    EXPECT_FALSE(outcome.adapterOutcome->unmappedProviderResult);
    ASSERT_TRUE(outcome.adapterOutcome->flowUpdate.has_value());
    EXPECT_TRUE(outcome.adapterOutcome->flowUpdate->payloadSubmitted);
    EXPECT_TRUE(outcome.adapterOutcome->flowUpdate->mappedResultAppended);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->duplicateMappedResult);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->unmappedResult);
    EXPECT_EQ(outcome.adapterOutcome->flowUpdate->payloadPacketSequence, 1U);
    EXPECT_EQ(outcome.adapterOutcome->flowUpdate->mappedResultCount, 1U);
    ASSERT_TRUE(outcome.adapterOutcome->flowUpdate->latestExactResult.has_value());
    EXPECT_EQ(*outcome.adapterOutcome->flowUpdate->latestExactResult,
              expectedProtocol);
    ASSERT_TRUE(outcome.stateAfterSubmit.has_value());
    EXPECT_EQ(outcome.stateAfterSubmit->payloadPacketsSubmitted, 1U);
    EXPECT_EQ(outcome.stateAfterSubmit->mappedResultCount, 1U);
    ASSERT_TRUE(outcome.stateAfterSubmit->latestExactResult().has_value());
    EXPECT_EQ(*outcome.stateAfterSubmit->latestExactResult(), expectedProtocol);
}

void expectUnmappedOutcome(const Protocol::LpiPipelineOutcome &outcome) {
    EXPECT_TRUE(outcome.providerProducedFact);
    ASSERT_TRUE(outcome.adapterOutcome.has_value());
    EXPECT_FALSE(outcome.adapterOutcome->mappedProviderResult);
    EXPECT_TRUE(outcome.adapterOutcome->unmappedProviderResult);
    ASSERT_TRUE(outcome.adapterOutcome->flowUpdate.has_value());
    EXPECT_TRUE(outcome.adapterOutcome->flowUpdate->payloadSubmitted);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->mappedResultAppended);
    EXPECT_TRUE(outcome.adapterOutcome->flowUpdate->unmappedResult);
    EXPECT_EQ(outcome.adapterOutcome->flowUpdate->payloadPacketSequence, 1U);
    EXPECT_EQ(outcome.adapterOutcome->flowUpdate->mappedResultCount, 0U);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->latestExactResult.has_value());
    ASSERT_TRUE(outcome.stateAfterSubmit.has_value());
    EXPECT_EQ(outcome.stateAfterSubmit->payloadPacketsSubmitted, 1U);
    EXPECT_TRUE(outcome.stateAfterSubmit->mappedResultsEmpty());
    EXPECT_FALSE(outcome.stateAfterSubmit->latestExactResult().has_value());
}

void expectNoResultOutcome(const Protocol::LpiPipelineOutcome &outcome) {
    EXPECT_FALSE(outcome.providerProducedFact);
    ASSERT_TRUE(outcome.adapterOutcome.has_value());
    EXPECT_FALSE(outcome.adapterOutcome->mappedProviderResult);
    EXPECT_FALSE(outcome.adapterOutcome->unmappedProviderResult);
    ASSERT_TRUE(outcome.adapterOutcome->flowUpdate.has_value());
    EXPECT_TRUE(outcome.adapterOutcome->flowUpdate->payloadSubmitted);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->mappedResultAppended);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->unmappedResult);
    EXPECT_EQ(outcome.adapterOutcome->flowUpdate->payloadPacketSequence, 1U);
    EXPECT_EQ(outcome.adapterOutcome->flowUpdate->mappedResultCount, 0U);
    EXPECT_FALSE(outcome.adapterOutcome->flowUpdate->latestExactResult.has_value());
    ASSERT_TRUE(outcome.stateAfterSubmit.has_value());
    EXPECT_EQ(outcome.stateAfterSubmit->payloadPacketsSubmitted, 1U);
    EXPECT_TRUE(outcome.stateAfterSubmit->mappedResultsEmpty());
}

TEST(LpiExpectedAliasReplayTest,
     AggregateBaselineShapesReplayThroughPipelineAdapterAndFlowTable) {
    const auto events = buildExpectedAliasReplayFixture();
    ASSERT_EQ(events.size(), kExpectedBaseline.total());

    Flow::BoundedFlowTable table(events.size());
    ScriptedProvider provider(std::span<const ReplayEvent>{events});
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 128> l3Packet{};

    AggregateCounts observed{};
    auto previousUnmappedCounter = std::uint64_t{0};

    for (std::uint32_t index = 0; index < events.size(); ++index) {
        const auto &event = events[index];
        const auto packet = syntheticTcpPacket(index + 1U);
        ASSERT_TRUE(table.observeAccepted(packet, 61).has_value())
            << event.expectedAppName;

        const auto outcome = pipeline.submitBeforeAdapterCompletion(
            std::span<const std::byte>{l3Packet}, packet);
        EXPECT_TRUE(outcome.observed);
        EXPECT_TRUE(outcome.payloadEligible);
        EXPECT_TRUE(outcome.providerAvailable);
        EXPECT_TRUE(outcome.submittedToProvider);
        ASSERT_EQ(provider.lastPayloadLength, 64U);
        ASSERT_EQ(provider.lastL3PacketLength, l3Packet.size());

        switch (event.kind) {
        case ReplayKind::Mapped:
            ASSERT_TRUE(event.expectedProtocol.has_value());
            expectMappedOutcome(outcome, *event.expectedProtocol);
            if (event.expectedAppName == "DNS") {
                ++observed.dns;
            } else if (event.expectedAppName == "HTTP") {
                ++observed.http;
            } else if (event.expectedAppName == "QUIC") {
                ++observed.quic;
            } else if (event.expectedAppName == "SSL") {
                ++observed.ssl;
            } else {
                ADD_FAILURE() << "unexpected mapped app "
                              << event.expectedAppName;
            }
            break;
        case ReplayKind::Unmapped:
            expectUnmappedOutcome(outcome);
            ++observed.unmapped;
            previousUnmappedCounter += 1U;
            EXPECT_EQ(table.counters().lpiUnmappedResults,
                      previousUnmappedCounter);
            break;
        case ReplayKind::NoResult:
            expectNoResultOutcome(outcome);
            ++observed.noResult;
            EXPECT_EQ(table.counters().lpiUnmappedResults,
                      previousUnmappedCounter);
            break;
        }
    }

    EXPECT_EQ(observed.dns, kExpectedBaseline.dns);
    EXPECT_EQ(observed.http, kExpectedBaseline.http);
    EXPECT_EQ(observed.quic, kExpectedBaseline.quic);
    EXPECT_EQ(observed.ssl, kExpectedBaseline.ssl);
    EXPECT_EQ(observed.unmapped, kExpectedBaseline.unmapped);
    EXPECT_EQ(observed.noResult, kExpectedBaseline.noResult);

    EXPECT_EQ(provider.calls, kExpectedBaseline.total());
    EXPECT_EQ(provider.consumed(), events.size());
    EXPECT_EQ(provider.exhaustedCalls, 0U);
    EXPECT_EQ(table.size(), events.size());
    EXPECT_EQ(table.counters().lpiPayloadPackets, kExpectedBaseline.total());
    EXPECT_EQ(table.counters().lpiMappedResults, kExpectedBaseline.mapped());
    EXPECT_EQ(table.counters().lpiUnmappedResults, kExpectedBaseline.unmapped);
    EXPECT_EQ(table.counters().lpiDuplicateMappedResults, 0U);
    EXPECT_EQ(table.counters().lpiFlowMisses, 0U);

    const auto status = pipeline.status();
    EXPECT_TRUE(status.available);
    EXPECT_EQ(status.providerName, "scripted-vpp-expected-alias-fixture");
    EXPECT_EQ(status.counters.payloadEligiblePackets, kExpectedBaseline.total());
    EXPECT_EQ(status.counters.packetsSubmittedToProvider,
              kExpectedBaseline.total());
    EXPECT_EQ(status.counters.providerFactPackets,
              kExpectedBaseline.mapped() + kExpectedBaseline.unmapped);
    EXPECT_EQ(status.counters.providerNoResultPackets,
              kExpectedBaseline.noResult);
}

TEST(LpiExpectedAliasReplayTest,
     CompoundUnmappedThenMappedResultKeepsLatestExactProtocol) {
    std::vector<ReplayEvent> events{
        ReplayEvent{
            .kind = ReplayKind::Unmapped,
            .expectedAppName = "SOCKS",
            .providerAlias = "lpi:socks",
            .expectedProtocol = std::nullopt,
        },
        ReplayEvent{
            .kind = ReplayKind::Mapped,
            .expectedAppName = "HTTP",
            .providerAlias = "lpi:http",
            .expectedProtocol = Catalog::ApplicationProtocolId::HTTP,
        },
    };

    Flow::BoundedFlowTable table(1);
    const auto packet = syntheticTcpPacket(1000U);
    ASSERT_TRUE(table.observeAccepted(packet, 61).has_value());
    ScriptedProvider provider(std::span<const ReplayEvent>{events});
    Protocol::LpiRecognitionPipeline pipeline(table, &provider);
    const std::array<std::byte, 128> l3Packet{};

    const auto socks = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);
    expectUnmappedOutcome(socks);

    const auto http = pipeline.submitBeforeAdapterCompletion(
        std::span<const std::byte>{l3Packet}, packet);
    EXPECT_TRUE(http.providerProducedFact);
    ASSERT_TRUE(http.adapterOutcome.has_value());
    EXPECT_TRUE(http.adapterOutcome->mappedProviderResult);
    EXPECT_FALSE(http.adapterOutcome->unmappedProviderResult);
    ASSERT_TRUE(http.adapterOutcome->flowUpdate.has_value());
    EXPECT_TRUE(http.adapterOutcome->flowUpdate->mappedResultAppended);
    EXPECT_EQ(http.adapterOutcome->flowUpdate->payloadPacketSequence, 2U);
    EXPECT_EQ(http.adapterOutcome->flowUpdate->mappedResultCount, 1U);
    ASSERT_TRUE(http.adapterOutcome->flowUpdate->latestExactResult.has_value());
    EXPECT_EQ(*http.adapterOutcome->flowUpdate->latestExactResult,
              Catalog::ApplicationProtocolId::HTTP);

    const auto state = table.lpiRecognitionStateFor(packet);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->payloadPacketsSubmitted, 2U);
    ASSERT_EQ(state->mappedResults().size(), 1U);
    EXPECT_EQ(state->mappedResults()[0].protocolId,
              Catalog::ApplicationProtocolId::HTTP);
    EXPECT_EQ(state->mappedResults()[0].firstPayloadPacketSequence, 2U);
    EXPECT_EQ(state->mappedResults()[0].direction,
              Flow::FlowRelativeDirection::Orig);
    ASSERT_TRUE(state->latestExactResult().has_value());
    EXPECT_EQ(*state->latestExactResult(), Catalog::ApplicationProtocolId::HTTP);
    EXPECT_EQ(table.counters().lpiMappedResults, 1U);
    EXPECT_EQ(table.counters().lpiUnmappedResults, 1U);
}

} // namespace
