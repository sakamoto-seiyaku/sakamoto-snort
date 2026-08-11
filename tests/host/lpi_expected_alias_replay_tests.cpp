/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionAdapter.hpp>
#include <core/protocol/LpiRecognitionProvider.hpp>

#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

namespace {

namespace Flow = SnortDatapath::Flow;
namespace Protocol = SnortDatapath::Protocol;
namespace Catalog = sucre::protocol;
namespace fs = std::filesystem;

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
    auto previousSeparator = false;
    for (const auto ch : appName) {
        const auto byte = static_cast<unsigned char>(ch);
        if (std::isalnum(byte)) {
            alias.push_back(static_cast<char>(std::tolower(byte)));
            previousSeparator = false;
            continue;
        }
        if (!previousSeparator && alias.back() != ':') {
            alias.push_back('-');
            previousSeparator = true;
        }
    }
    if (alias.back() == '-') {
        alias.pop_back();
    }
    return alias;
}

[[nodiscard]] std::string trimCopy(const std::string_view input) {
    auto begin = std::size_t{0};
    while (begin < input.size() &&
           std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
        ++begin;
    }
    auto end = input.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(input[end - 1U])) != 0) {
        --end;
    }
    return std::string{input.substr(begin, end - begin)};
}

[[nodiscard]] std::string normalizeAppName(const std::string_view value) {
    auto normalized = trimCopy(value);
    for (auto &ch : normalized) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return normalized;
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

struct ReferenceJsonStats {
    AggregateCounts counts;
    std::uint32_t expectedRows = 0;
    std::uint32_t rowsWithoutAppName = 0;
    std::uint32_t unknownRows = 0;
    std::uint32_t multiResultRows = 0;
    std::uint32_t appNameOccurrences = 0;
    std::map<std::string, std::uint32_t> unmappedAppCounts;
};

struct ReferenceJsonFixture {
    std::vector<ReplayEvent> events;
    ReferenceJsonStats stats;
};

[[nodiscard]] std::string readTextFile(const fs::path &path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error{"failed to open " + path.string()};
    }
    return std::string{std::istreambuf_iterator<char>{input},
                       std::istreambuf_iterator<char>{}};
}

[[nodiscard]] bool appIdIsUnknown(const rapidjson::Value &row) {
    const auto member = row.FindMember("APP_ID");
    return member != row.MemberEnd() && member->value.IsString() &&
           std::string_view{member->value.GetString(),
                            member->value.GetStringLength()} == "UNKNOWN";
}

[[nodiscard]] std::vector<std::string> appNamesFromRow(
    const rapidjson::Value &row,
    const fs::path &sourcePath) {
    const auto member = row.FindMember("APP_NAME");
    if (member == row.MemberEnd()) {
        return {};
    }

    std::vector<std::string> names;
    if (member->value.IsString()) {
        const auto normalized = normalizeAppName(std::string_view{
            member->value.GetString(), member->value.GetStringLength()});
        if (!normalized.empty()) {
            names.push_back(normalized);
        }
        return names;
    }

    if (!member->value.IsArray()) {
        throw std::runtime_error{"APP_NAME must be string or array in " +
                                 sourcePath.string()};
    }
    for (const auto &name : member->value.GetArray()) {
        if (!name.IsString()) {
            throw std::runtime_error{"APP_NAME array contains non-string in " +
                                     sourcePath.string()};
        }
        const auto normalized = normalizeAppName(
            std::string_view{name.GetString(), name.GetStringLength()});
        if (!normalized.empty()) {
            names.push_back(normalized);
        }
    }
    return names;
}

void appendReferenceExpectedJsonRows(
    const fs::path &path,
    ReferenceJsonFixture &fixture) {
    rapidjson::Document document;
    const auto content = readTextFile(path);
    document.Parse(content.data(), content.size());
    if (document.HasParseError()) {
        throw std::runtime_error{
            "invalid JSON in " + path.string() + ": " +
            rapidjson::GetParseError_En(document.GetParseError())};
    }
    if (!document.IsArray()) {
        throw std::runtime_error{"expected top-level array in " +
                                 path.string()};
    }

    for (const auto &row : document.GetArray()) {
        if (!row.IsObject()) {
            throw std::runtime_error{"expected object row in " + path.string()};
        }
        ++fixture.stats.expectedRows;
        const auto names = appNamesFromRow(row, path);
        if (names.empty()) {
            ++fixture.stats.rowsWithoutAppName;
            if (!appIdIsUnknown(row)) {
                throw std::runtime_error{
                    "row without APP_NAME must use APP_ID UNKNOWN in " +
                    path.string()};
            }
            ++fixture.stats.unknownRows;
            fixture.events.push_back(ReplayEvent{
                .kind = ReplayKind::NoResult,
                .expectedAppName = "UNKNOWN",
                .providerAlias = std::nullopt,
                .expectedProtocol = std::nullopt,
            });
            continue;
        }

        if (names.size() > 1U) {
            ++fixture.stats.multiResultRows;
        }
        for (const auto &name : names) {
            ++fixture.stats.appNameOccurrences;
            const auto alias = providerAliasForExpectedApp(name);
            const auto mapped =
                Catalog::applicationProtocolIdForProviderAlias(alias);
            if (!mapped.has_value()) {
                ++fixture.stats.counts.unmapped;
                ++fixture.stats.unmappedAppCounts[name];
                fixture.events.push_back(ReplayEvent{
                    .kind = ReplayKind::Unmapped,
                    .expectedAppName = name,
                    .providerAlias = alias,
                    .expectedProtocol = std::nullopt,
                });
                continue;
            }
            if (*mapped == Catalog::ApplicationProtocolId::DNS) {
                ++fixture.stats.counts.dns;
            } else if (*mapped == Catalog::ApplicationProtocolId::HTTP) {
                ++fixture.stats.counts.http;
            } else if (*mapped == Catalog::ApplicationProtocolId::QUIC) {
                ++fixture.stats.counts.quic;
            } else if (*mapped == Catalog::ApplicationProtocolId::TLS) {
                ++fixture.stats.counts.ssl;
            }
            fixture.events.push_back(ReplayEvent{
                .kind = ReplayKind::Mapped,
                .expectedAppName = name,
                .providerAlias = alias,
                .expectedProtocol = mapped,
            });
        }
    }
}

[[nodiscard]] ReferenceJsonFixture loadReferenceExpectedJsonFixture(
    const fs::path &corpusRoot) {
    std::vector<fs::path> jsonPaths;
    for (const auto &entry : fs::recursive_directory_iterator(corpusRoot)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            jsonPaths.push_back(entry.path());
        }
    }
    std::sort(jsonPaths.begin(), jsonPaths.end());
    if (jsonPaths.empty()) {
        throw std::runtime_error{"no expected JSON files under " +
                                 corpusRoot.string()};
    }

    ReferenceJsonFixture fixture;
    for (const auto &path : jsonPaths) {
        appendReferenceExpectedJsonRows(path, fixture);
    }
    fixture.stats.counts.noResult = fixture.stats.unknownRows;
    return fixture;
}

[[nodiscard]] fs::path referenceCorpusRoot() {
    if (const auto *overridePath = std::getenv("VPP_LPI_CORPUS_ROOT");
        overridePath != nullptr && std::string_view{overridePath}.size() > 0U) {
        return fs::path{overridePath};
    }
    return fs::path{
        "/home/js/backup/backup/Git/vpp/test/decoders/stellar_lpi/test_pcap"};
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

void expectReplayFixtureMatchesPipelineBaseline(
    const std::vector<ReplayEvent> &events) {
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
     AggregateBaselineShapesReplayThroughPipelineAdapterAndFlowTable) {
    const auto events = buildExpectedAliasReplayFixture();
    ASSERT_EQ(events.size(), kExpectedBaseline.total());
    expectReplayFixtureMatchesPipelineBaseline(events);
}

TEST(LpiExpectedAliasReplayTest,
     ReferenceExpectedJsonRowsReplayThroughPipelineWhenAvailable) {
    const auto corpusRoot = referenceCorpusRoot();
    if (!fs::is_directory(corpusRoot)) {
        GTEST_SKIP() << "VPP LPI reference corpus is not present: "
                     << corpusRoot;
    }

    const auto fixture = loadReferenceExpectedJsonFixture(corpusRoot);
    EXPECT_EQ(fixture.stats.expectedRows, 267U);
    EXPECT_EQ(fixture.stats.rowsWithoutAppName, 6U);
    EXPECT_EQ(fixture.stats.unknownRows, 6U);
    EXPECT_EQ(fixture.stats.multiResultRows, 25U);
    EXPECT_EQ(fixture.stats.appNameOccurrences, 287U);
    EXPECT_EQ(fixture.stats.counts.dns, kExpectedBaseline.dns);
    EXPECT_EQ(fixture.stats.counts.http, kExpectedBaseline.http);
    EXPECT_EQ(fixture.stats.counts.quic, kExpectedBaseline.quic);
    EXPECT_EQ(fixture.stats.counts.ssl, kExpectedBaseline.ssl);
    EXPECT_EQ(fixture.stats.counts.unmapped, kExpectedBaseline.unmapped);
    EXPECT_EQ(fixture.stats.counts.noResult, kExpectedBaseline.noResult);
    EXPECT_EQ(fixture.stats.unmappedAppCounts.size(),
              kUnmappedExpectedApps.size());
    for (const auto &app : kUnmappedExpectedApps) {
        const auto observed =
            fixture.stats.unmappedAppCounts.find(std::string{app.appName});
        ASSERT_NE(observed, fixture.stats.unmappedAppCounts.end())
            << app.appName;
        EXPECT_EQ(observed->second, app.count) << app.appName;
    }
    ASSERT_EQ(fixture.events.size(), kExpectedBaseline.total());
    expectReplayFixtureMatchesPipelineBaseline(fixture.events);
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
