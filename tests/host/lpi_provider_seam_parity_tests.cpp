/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>
#include <VpnTunFlowAdapter.hpp>

#include <core/packet/NfqueueTopology.hpp>
#include <core/protocol/ApplicationProtocolCatalog.hpp>
#include <core/protocol/LpiRecognitionProvider.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace Catalog = sucre::protocol;
namespace Flow = SnortDatapath::Flow;
namespace Nfqueue = SnortDatapath::Nfqueue;
namespace Protocol = SnortDatapath::Protocol;
namespace Tun = SnortDatapath::Tun;

constexpr std::byte byte(const std::uint8_t value) noexcept {
    return static_cast<std::byte>(value);
}

void putU16(std::span<std::byte> bytes, const std::size_t offset,
            const std::uint16_t value) noexcept {
    bytes[offset] = byte(static_cast<std::uint8_t>(value >> 8U));
    bytes[offset + 1] = byte(static_cast<std::uint8_t>(value & 0xffU));
}

std::array<std::uint8_t, 60> ipv4TcpPacketWithPayload() {
    std::array<std::uint8_t, 60> packet{};
    packet[0] = 0x45;
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{packet}), 2, 60);
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 10;
    packet[15] = 1;
    packet[16] = 192;
    packet[17] = 0;
    packet[18] = 2;
    packet[19] = 1;
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{packet}), 20, 40000);
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{packet}), 22, 443);
    packet[32] = 0x50;
    for (std::size_t index = 40; index < packet.size(); ++index) {
        packet[index] = static_cast<std::uint8_t>(index);
    }
    return packet;
}

struct ProviderSubmission final {
    Flow::AdapterKind adapter = Flow::AdapterKind::RootNfqueue;
    Flow::FlowRelativeDirection direction = Flow::FlowRelativeDirection::Orig;
    std::uint32_t linuxUid = 0;
    std::uint32_t networkContext = 0;
    std::uint8_t ipProtocol = 0;
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    std::size_t l3Bytes = 0;
    std::size_t payloadBytes = 0;
    bool uidKnown = false;
};

class RecordingLpiProvider final : public Protocol::LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return true; }

    [[nodiscard]] std::string_view providerName() const noexcept override {
        return "fake-shared-lpi";
    }

    [[nodiscard]] std::optional<Protocol::LpiProviderFact> recognize(
        const Protocol::LpiPacketSubmission &submission) noexcept override {
        submissions.push_back(ProviderSubmission{
            .adapter = submission.facts.domain.adapter,
            .direction = submission.packetDirection,
            .linuxUid = submission.facts.domain.linuxUid,
            .networkContext = submission.facts.domain.networkContext,
            .ipProtocol = submission.facts.ipProtocol,
            .sourcePort = submission.facts.sourcePort,
            .destinationPort = submission.facts.destinationPort,
            .l3Bytes = submission.l3Packet.size(),
            .payloadBytes = submission.transportPayload.size(),
            .uidKnown = submission.facts.domain.uidKnown,
        });
        return Protocol::LpiProviderFact{
            .providerAlias = "lpi:http",
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        };
    }

    std::vector<ProviderSubmission> submissions;
};

TEST(LpiProviderSeamParityTest,
     RootNfqueueAndVpnTunSubmitThroughTheSameProviderInterface) {
    RecordingLpiProvider provider;
    Nfqueue::NfqueueFlowAdapter rootAdapter(Nfqueue::NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
        .lpiProvider = &provider,
    });
    Tun::VpnTunFlowAdapter vpnAdapter(Tun::VpnTunFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .lpiProvider = &provider,
    });
    const auto packet = ipv4TcpPacketWithPayload();

    EXPECT_EQ(rootAdapter.process(
                  2, kNfqueueHookLocalOut,
                  std::span<const std::uint8_t>{packet}, 1500,
                  Nfqueue::NfqueuePacketMetadata{
                      .linuxUid = 12546,
                      .inputInterfaceIndex = 0,
                      .outputInterfaceIndex = 9,
                      .networkContext = 7,
                      .uidMetadataPresent = true,
                  }),
              Nfqueue::NfqueueFlowAdapterResult::FlowAccepted);
    EXPECT_EQ(vpnAdapter.process(
                  Tun::VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{packet}, packet.size(),
                  Tun::VpnTunPacketMetadata{
                      .linuxUid = 12546,
                      .networkContext = 7,
                      .interfaceIndex = 9,
                      .uidKnown = true,
                  }),
              Tun::VpnTunFlowAdapterResult::FlowForwarded);

    ASSERT_EQ(provider.submissions.size(), 2U);
    EXPECT_EQ(provider.submissions[0].adapter, Flow::AdapterKind::RootNfqueue);
    EXPECT_EQ(provider.submissions[1].adapter, Flow::AdapterKind::VpnTun);
    for (const auto &submission : provider.submissions) {
        EXPECT_EQ(submission.direction, Flow::FlowRelativeDirection::Orig);
        EXPECT_EQ(submission.linuxUid, 12546U);
        EXPECT_TRUE(submission.uidKnown);
        EXPECT_EQ(submission.networkContext, 7U);
        EXPECT_EQ(submission.ipProtocol, 6U);
        EXPECT_EQ(submission.sourcePort, 40000U);
        EXPECT_EQ(submission.destinationPort, 443U);
        EXPECT_EQ(submission.l3Bytes, packet.size());
        EXPECT_EQ(submission.payloadBytes, 20U);
    }

    const auto rootCounters = rootAdapter.counters();
    EXPECT_TRUE(rootCounters.lpiProvider.available);
    EXPECT_EQ(rootCounters.lpiProvider.providerName, "fake-shared-lpi");
    EXPECT_EQ(rootCounters.lpiProvider.counters.payloadEligiblePackets, 1U);
    EXPECT_EQ(rootCounters.lpiProvider.counters.packetsSubmittedToProvider, 1U);
    EXPECT_EQ(rootCounters.lpiProvider.counters.providerFactPackets, 1U);
    ASSERT_TRUE(rootCounters.allowedFlowActivity.lastLpiRecognition
                    .latestExactResult()
                    .has_value());
    EXPECT_EQ(*rootCounters.allowedFlowActivity.lastLpiRecognition
                   .latestExactResult(),
              Catalog::ApplicationProtocolId::HTTP);

    const auto vpnCounters = vpnAdapter.counters();
    EXPECT_TRUE(vpnCounters.lpiProvider.available);
    EXPECT_EQ(vpnCounters.lpiProvider.providerName, "fake-shared-lpi");
    EXPECT_EQ(vpnCounters.lpiProvider.counters.payloadEligiblePackets, 1U);
    EXPECT_EQ(vpnCounters.lpiProvider.counters.packetsSubmittedToProvider, 1U);
    EXPECT_EQ(vpnCounters.lpiProvider.counters.providerFactPackets, 1U);
    ASSERT_TRUE(vpnCounters.allowedFlowActivity.lastLpiRecognition
                    .latestExactResult()
                    .has_value());
    EXPECT_EQ(*vpnCounters.allowedFlowActivity.lastLpiRecognition
                   .latestExactResult(),
              Catalog::ApplicationProtocolId::HTTP);
}

} // namespace
