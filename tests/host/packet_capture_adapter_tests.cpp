/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphIngress.hpp>
#include <PacketCaptureAdapter.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

using namespace SnortDatapath::Flow;

constexpr std::byte byte(const std::uint8_t value) noexcept {
    return static_cast<std::byte>(value);
}

void putU16(std::span<std::byte> bytes, const std::size_t offset,
            const std::uint16_t value) noexcept {
    bytes[offset] = byte(static_cast<std::uint8_t>(value >> 8U));
    bytes[offset + 1] = byte(static_cast<std::uint8_t>(value & 0xffU));
}

std::array<std::byte, 40> ipv4TcpPacket(const bool reverse = false) {
    std::array<std::byte, 40> packet{};
    packet[0] = byte(0x45);
    putU16(packet, 2, 40);
    packet[8] = byte(64);
    packet[9] = byte(6);
    const std::array<std::uint8_t, 4> source = reverse
        ? std::array<std::uint8_t, 4>{192, 0, 2, 1}
        : std::array<std::uint8_t, 4>{10, 0, 0, 1};
    const std::array<std::uint8_t, 4> destination = reverse
        ? std::array<std::uint8_t, 4>{10, 0, 0, 1}
        : std::array<std::uint8_t, 4>{192, 0, 2, 1};
    for (std::size_t index = 0; index < 4; ++index) {
        packet[12 + index] = byte(source[index]);
        packet[16 + index] = byte(destination[index]);
    }
    putU16(packet, 20, reverse ? 443 : 40000);
    putU16(packet, 22, reverse ? 40000 : 443);
    packet[32] = byte(0x50);
    return packet;
}

std::vector<std::byte> ipv4TcpPacketWithPayload(const std::size_t payloadLength) {
    auto header = ipv4TcpPacket();
    std::vector<std::byte> packet(header.begin(), header.end());
    packet.resize(header.size() + payloadLength);
    putU16(packet, 2, static_cast<std::uint16_t>(packet.size()));
    for (std::size_t index = 0; index < payloadLength; ++index) {
        packet[header.size() + index] = byte(static_cast<std::uint8_t>(index + 1U));
    }
    return packet;
}

std::array<std::byte, 48> ipv6UdpPacket() {
    std::array<std::byte, 48> packet{};
    packet[0] = byte(0x60);
    putU16(packet, 4, 8);
    packet[6] = byte(17);
    packet[7] = byte(64);
    packet[8] = byte(0x20);
    packet[9] = byte(0x01);
    packet[10] = byte(0x0d);
    packet[11] = byte(0xb8);
    packet[23] = byte(1);
    packet[24] = byte(0x20);
    packet[25] = byte(0x01);
    packet[26] = byte(0x0d);
    packet[27] = byte(0xb8);
    packet[39] = byte(2);
    putU16(packet, 40, 5353);
    putU16(packet, 42, 53);
    putU16(packet, 44, 8);
    return packet;
}

std::vector<std::byte> ipv6UdpPacketWithPayload(const std::size_t payloadLength) {
    auto header = ipv6UdpPacket();
    std::vector<std::byte> packet(header.begin(), header.end());
    packet.resize(header.size() + payloadLength);
    putU16(packet, 4, static_cast<std::uint16_t>(8U + payloadLength));
    putU16(packet, 44, static_cast<std::uint16_t>(8U + payloadLength));
    for (std::size_t index = 0; index < payloadLength; ++index) {
        packet[header.size() + index] = byte(static_cast<std::uint8_t>(0xa0U + index));
    }
    return packet;
}

std::array<std::byte, 48> ipv6FragmentPacket() {
    auto packet = ipv6UdpPacket();
    packet[6] = byte(44);
    packet[40] = byte(6);
    putU16(packet, 42, 1);
    return packet;
}

template <typename T>
std::span<const std::byte> packetSpan(const T &packet) noexcept {
    return std::span<const std::byte>(packet.data(), packet.size());
}

FlowDomain domain(const AdapterKind adapter) {
    return FlowDomain{
        .adapter = adapter,
        .linuxUid = 10001,
        .uidKnown = true,
        .captureQueue = 7,
        .networkContext = 2,
        .runtimeProfile = 3,
    };
}

FlowGraphIngressMetadata metadata(
    const AdapterKind adapter,
    const DevicePacketDirection direction = DevicePacketDirection::Input,
    const std::uint32_t originalLength = 1500) {
    return FlowGraphIngressMetadata{
        .direction = direction,
        .originalLength = originalLength,
        .domain = domain(adapter),
    };
}

TEST(FlowGraphIngressParserTest, RootAndVpnParseIntoOneRuntimeOwner) {
    FlowGraphIngressParser parser;
    const auto forwardPacket = ipv4TcpPacket();
    const auto reversePacket = ipv4TcpPacket(true);

    const auto forward = parser.parseL3Packet(
        packetSpan(forwardPacket),
        metadata(AdapterKind::RootNfqueue, DevicePacketDirection::Input));
    const auto reverse = parser.parseL3Packet(
        packetSpan(reversePacket),
        metadata(AdapterKind::VpnTun, DevicePacketDirection::Output));

    EXPECT_EQ(forward.domain.adapter, AdapterKind::RootNfqueue);
    EXPECT_EQ(reverse.domain.adapter, AdapterKind::VpnTun);
    EXPECT_EQ(forward.deviceDirection, DevicePacketDirection::Input);
    EXPECT_EQ(reverse.deviceDirection, DevicePacketDirection::Output);
    EXPECT_EQ(forward.parseStatus, ParseStatus::Ready);
    EXPECT_EQ(reverse.parseStatus, ParseStatus::Ready);
    EXPECT_TRUE(forward.portsAvailable);
    EXPECT_TRUE(reverse.portsAvailable);
    EXPECT_EQ(forward.boundedPrefixLength, 40U);
    EXPECT_EQ(reverse.boundedPrefixLength, 40U);
    EXPECT_EQ(forward.transportPayloadOffset, 40U);
    EXPECT_EQ(forward.transportPayloadLength, 0U);
    EXPECT_FALSE(forward.hasTransportPayload());

    const auto forwardKey = CanonicalFlowKey::from(forward);
    const auto reverseKey = CanonicalFlowKey::from(reverse);
    ASSERT_TRUE(forwardKey.has_value());
    ASSERT_TRUE(reverseKey.has_value());
    EXPECT_EQ(*forwardKey, *reverseKey);

    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    const auto expectedWorker = runtime.distribution().selector().ownerFor(*forwardKey);
    EXPECT_EQ(runtime.distribution().selector().ownerFor(*reverseKey), expectedWorker);
}

TEST(FlowGraphIngressParserTest, PreservesCompleteLinuxUidNetworkAndInterfaceMetadata) {
    FlowGraphIngressParser parser;
    const auto packet = ipv4TcpPacket();
    const auto facts = parser.parseL3Packet(
        packetSpan(packet),
        FlowGraphIngressMetadata{
            .direction = DevicePacketDirection::Output,
            .originalLength = static_cast<std::uint32_t>(packet.size()),
            .domain = FlowDomain{
                .adapter = AdapterKind::RootNfqueue,
                .linuxUid = 112233,
                .uidKnown = true,
                .captureQueue = 42,
                .networkContext = 9,
                .runtimeProfile = 4,
                .interfaceIndex = 77,
            },
        });

    EXPECT_EQ(facts.parseStatus, ParseStatus::Ready);
    EXPECT_EQ(facts.deviceDirection, DevicePacketDirection::Output);
    EXPECT_EQ(facts.domain.adapter, AdapterKind::RootNfqueue);
    EXPECT_EQ(facts.domain.linuxUid, 112233U);
    EXPECT_TRUE(facts.domain.uidKnown);
    EXPECT_EQ(facts.domain.captureQueue, 42U);
    EXPECT_EQ(facts.domain.networkContext, 9U);
    EXPECT_EQ(facts.domain.runtimeProfile, 4U);
    EXPECT_EQ(facts.domain.interfaceIndex, 77U);
}

TEST(FlowGraphIngressParserTest, ParsesIpv6UdpWithPlatformMetadata) {
    FlowGraphIngressParser parser;
    const auto packet = ipv6UdpPacket();
    const auto facts = parser.parseL3Packet(
        packetSpan(packet),
        FlowGraphIngressMetadata{
            .direction = DevicePacketDirection::Output,
            .originalLength = static_cast<std::uint32_t>(packet.size()),
            .domain = FlowDomain{
                .adapter = AdapterKind::VpnTun,
                .linuxUid = 20002,
                .uidKnown = true,
                .captureQueue = 0,
                .networkContext = 6,
                .runtimeProfile = 1,
                .interfaceIndex = 12,
            },
        });

    EXPECT_EQ(facts.source.family, AddressFamily::Ipv6);
    EXPECT_EQ(facts.destination.family, AddressFamily::Ipv6);
    EXPECT_EQ(facts.ipProtocol, 17U);
    EXPECT_EQ(facts.sourcePort, 5353U);
    EXPECT_EQ(facts.destinationPort, 53U);
    EXPECT_TRUE(facts.portsAvailable);
    EXPECT_EQ(facts.parseStatus, ParseStatus::Ready);
    EXPECT_EQ(facts.domain.adapter, AdapterKind::VpnTun);
    EXPECT_EQ(facts.domain.linuxUid, 20002U);
    EXPECT_TRUE(facts.domain.uidKnown);
    EXPECT_EQ(facts.domain.networkContext, 6U);
    EXPECT_EQ(facts.domain.interfaceIndex, 12U);
    EXPECT_EQ(facts.transportPayloadOffset, 48U);
    EXPECT_EQ(facts.transportPayloadLength, 0U);
    EXPECT_FALSE(facts.hasTransportPayload());
}

TEST(FlowGraphIngressParserTest, RecordsOnlyBoundedTcpPayloadBytesForRecognition) {
    FlowGraphIngressParser parser(FlowGraphIngressConfig{.maxL3Bytes = 44});
    const auto packet = ipv4TcpPacketWithPayload(12);
    const auto facts = parser.parseL3Packet(
        packetSpan(packet),
        metadata(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                 static_cast<std::uint32_t>(packet.size())));

    EXPECT_EQ(facts.parseStatus, ParseStatus::Ready);
    EXPECT_TRUE(facts.portsAvailable);
    EXPECT_EQ(facts.boundedPrefixLength, 44U);
    EXPECT_EQ(facts.transportPayloadOffset, 40U);
    EXPECT_EQ(facts.transportPayloadLength, 4U);
    EXPECT_TRUE(facts.hasTransportPayload());
}

TEST(FlowGraphIngressParserTest, RecordsUdpPayloadBytesButZeroPayloadIsNotBearing) {
    FlowGraphIngressParser parser;
    const auto payloadPacket = ipv6UdpPacketWithPayload(5);
    const auto payloadFacts = parser.parseL3Packet(
        packetSpan(payloadPacket),
        metadata(AdapterKind::VpnTun, DevicePacketDirection::Output,
                 static_cast<std::uint32_t>(payloadPacket.size())));

    EXPECT_EQ(payloadFacts.parseStatus, ParseStatus::Ready);
    EXPECT_TRUE(payloadFacts.portsAvailable);
    EXPECT_EQ(payloadFacts.transportPayloadOffset, 48U);
    EXPECT_EQ(payloadFacts.transportPayloadLength, 5U);
    EXPECT_TRUE(payloadFacts.hasTransportPayload());

    const auto zeroPayloadPacket = ipv6UdpPacket();
    const auto zeroPayloadFacts = parser.parseL3Packet(
        packetSpan(zeroPayloadPacket),
        metadata(AdapterKind::VpnTun, DevicePacketDirection::Output,
                 static_cast<std::uint32_t>(zeroPayloadPacket.size())));

    EXPECT_EQ(zeroPayloadFacts.parseStatus, ParseStatus::Ready);
    EXPECT_EQ(zeroPayloadFacts.transportPayloadOffset, 48U);
    EXPECT_EQ(zeroPayloadFacts.transportPayloadLength, 0U);
    EXPECT_FALSE(zeroPayloadFacts.hasTransportPayload());
}

TEST(FlowGraphIngressParserTest, ConfigurableZeroBytesNeverReadsInput) {
    FlowGraphIngressParser parser(FlowGraphIngressConfig{.maxL3Bytes = 0});
    const auto packet = ipv4TcpPacket();
    const auto facts = parser.parseL3Packet(
        packetSpan(packet),
        metadata(AdapterKind::RootNfqueue, DevicePacketDirection::Input,
                 static_cast<std::uint32_t>(packet.size())));

    EXPECT_EQ(facts.boundedPrefixLength, 0U);
    EXPECT_EQ(facts.parseStatus, ParseStatus::Malformed);
}

// Compatibility coverage only. Parser ownership lives in FlowGraphIngressParser.
TEST(PacketCaptureAdapterTest, RootAndVpnNormalizeIntoOneRuntimeOwner) {
    PacketCaptureAdapter root(AdapterKind::RootNfqueue);
    PacketCaptureAdapter vpn(AdapterKind::VpnTun);
    const auto forwardPacket = ipv4TcpPacket();
    const auto reversePacket = ipv4TcpPacket(true);

    const auto forward = root.normalize(packetSpan(forwardPacket), 1500,
                                         DevicePacketDirection::Input,
                                         domain(AdapterKind::RootNfqueue));
    const auto reverse = vpn.normalize(packetSpan(reversePacket), 1500,
                                       DevicePacketDirection::Output,
                                       domain(AdapterKind::RootNfqueue));

    EXPECT_EQ(forward.domain.adapter, AdapterKind::RootNfqueue);
    EXPECT_EQ(reverse.domain.adapter, AdapterKind::VpnTun);
    EXPECT_EQ(forward.deviceDirection, DevicePacketDirection::Input);
    EXPECT_EQ(reverse.deviceDirection, DevicePacketDirection::Output);
    EXPECT_EQ(forward.parseStatus, ParseStatus::Ready);
    EXPECT_EQ(reverse.parseStatus, ParseStatus::Ready);
    EXPECT_TRUE(forward.portsAvailable);
    EXPECT_TRUE(reverse.portsAvailable);
    EXPECT_EQ(forward.boundedPrefixLength, 40U);
    EXPECT_EQ(reverse.boundedPrefixLength, 40U);

    const auto forwardKey = CanonicalFlowKey::from(forward);
    const auto reverseKey = CanonicalFlowKey::from(reverse);
    ASSERT_TRUE(forwardKey.has_value());
    ASSERT_TRUE(reverseKey.has_value());
    EXPECT_EQ(*forwardKey, *reverseKey);

    FlowSteeringRuntime runtime(WorkerLayout{4, 0x1234}, 4);
    const auto expectedWorker = runtime.distribution().selector().ownerFor(*forwardKey);
    EXPECT_EQ(runtime.distribution().selector().ownerFor(*reverseKey), expectedWorker);

    const std::array facts{forward, reverse};
    EXPECT_EQ(runtime.distribution().submit(std::span<const PacketFacts>{facts}), 2U);
    for (int index = 0; index < 2; ++index) {
        const auto descriptorId = runtime.distribution().dequeue(expectedWorker);
        ASSERT_TRUE(descriptorId.has_value());
        ASSERT_NE(runtime.distribution().descriptor(*descriptorId), nullptr);
        EXPECT_EQ(runtime.distribution().checkOwner(*descriptorId, expectedWorker,
                                                     runtime.ownerGuard()),
                  OwnerGuardDecision::Local);
        EXPECT_TRUE(runtime.distribution().complete(*descriptorId,
                                                    PacketLeaseOutcome::Accepted));
    }
}

TEST(PacketCaptureAdapterTest, BoundsPrefixWithoutChangingOriginalLength) {
    PacketCaptureAdapter adapter(AdapterKind::RootNfqueue);
    std::array<std::byte, 1500> packet{};
    const auto tcp = ipv4TcpPacket();
    std::copy(tcp.begin(), tcp.end(), packet.begin());

    const auto facts = adapter.normalize(packetSpan(packet), 1500,
                                         DevicePacketDirection::Input,
                                         domain(AdapterKind::RootNfqueue));
    EXPECT_EQ(facts.originalLength, 1500U);
    EXPECT_EQ(facts.boundedPrefixLength, 512U);
    EXPECT_EQ(facts.parseStatus, ParseStatus::Ready);
    EXPECT_EQ(facts.sourcePort, 40000U);
    EXPECT_EQ(facts.destinationPort, 443U);
}

TEST(PacketCaptureAdapterTest, ParsesIpv6UdpPorts) {
    PacketCaptureAdapter adapter(AdapterKind::VpnTun);
    const auto packet = ipv6UdpPacket();
    const auto facts = adapter.normalize(packetSpan(packet), packet.size(),
                                         DevicePacketDirection::Output,
                                         domain(AdapterKind::VpnTun));

    EXPECT_EQ(facts.source.family, AddressFamily::Ipv6);
    EXPECT_EQ(facts.destination.family, AddressFamily::Ipv6);
    EXPECT_EQ(facts.ipProtocol, 17U);
    EXPECT_EQ(facts.sourcePort, 5353U);
    EXPECT_EQ(facts.destinationPort, 53U);
    EXPECT_TRUE(facts.portsAvailable);
    EXPECT_EQ(facts.parseStatus, ParseStatus::Ready);
}

TEST(PacketCaptureAdapterTest, FragmentsNeverFabricatePorts) {
    PacketCaptureAdapter adapter(AdapterKind::RootNfqueue);
    auto packet = ipv4TcpPacket();
    putU16(packet, 6, 0x2000);

    const auto facts = adapter.normalize(packetSpan(packet), packet.size(),
                                         DevicePacketDirection::Input,
                                         domain(AdapterKind::RootNfqueue));
    EXPECT_TRUE(facts.fragmented);
    EXPECT_EQ(facts.parseStatus, ParseStatus::Fragment);
    EXPECT_FALSE(facts.portsAvailable);
    EXPECT_EQ(facts.sourcePort, 0U);
    EXPECT_EQ(facts.destinationPort, 0U);

    const auto ipv6 = ipv6FragmentPacket();
    const auto ipv6Facts = adapter.normalize(packetSpan(ipv6), ipv6.size(),
                                             DevicePacketDirection::Input,
                                             domain(AdapterKind::RootNfqueue));
    EXPECT_TRUE(ipv6Facts.fragmented);
    EXPECT_EQ(ipv6Facts.parseStatus, ParseStatus::Fragment);
    EXPECT_FALSE(ipv6Facts.portsAvailable);
}

TEST(PacketCaptureAdapterTest, UnsupportedProtocolDoesNotInventPorts) {
    PacketCaptureAdapter adapter(AdapterKind::RootNfqueue);
    auto packet = ipv4TcpPacket();
    packet[9] = byte(1);

    const auto facts = adapter.normalize(packetSpan(packet), packet.size(),
                                         DevicePacketDirection::Input,
                                         domain(AdapterKind::RootNfqueue));
    EXPECT_EQ(facts.parseStatus, ParseStatus::UnsupportedProtocol);
    EXPECT_FALSE(facts.portsAvailable);
    EXPECT_EQ(facts.sourcePort, 0U);
    EXPECT_EQ(facts.destinationPort, 0U);
}

TEST(PacketCaptureAdapterTest, BadInputIsDeterministicallyMalformed) {
    PacketCaptureAdapter adapter(AdapterKind::VpnTun);
    const std::array<std::byte, 19> truncated{};
    const auto truncatedFacts = adapter.normalize(
        packetSpan(truncated), 19, DevicePacketDirection::Output,
        domain(AdapterKind::RootNfqueue));
    EXPECT_EQ(truncatedFacts.parseStatus, ParseStatus::Malformed);
    EXPECT_FALSE(truncatedFacts.portsAvailable);
    EXPECT_EQ(truncatedFacts.domain.adapter, AdapterKind::VpnTun);

    const std::array<std::byte, 1> invalid{byte(0x70)};
    const auto invalidFacts = adapter.normalize(
        packetSpan(invalid), 1, DevicePacketDirection::Input,
        domain(AdapterKind::VpnTun));
    EXPECT_EQ(invalidFacts.parseStatus, ParseStatus::Malformed);
    EXPECT_EQ(invalidFacts.originalLength, 1U);
    EXPECT_EQ(invalidFacts.boundedPrefixLength, 1U);

    auto malformedTcp = ipv4TcpPacket();
    malformedTcp[32] = byte(0x40);
    const auto malformedFacts = adapter.normalize(
        packetSpan(malformedTcp), malformedTcp.size(), DevicePacketDirection::Input,
        domain(AdapterKind::VpnTun));
    EXPECT_EQ(malformedFacts.parseStatus, ParseStatus::Malformed);
    EXPECT_FALSE(malformedFacts.portsAvailable);

    auto reservedFlagPacket = ipv4TcpPacket();
    putU16(reservedFlagPacket, 6, 0x8000);
    const auto reservedFlagFacts = adapter.normalize(
        packetSpan(reservedFlagPacket), reservedFlagPacket.size(),
        DevicePacketDirection::Input, domain(AdapterKind::VpnTun));
    EXPECT_EQ(reservedFlagFacts.parseStatus, ParseStatus::Malformed);

    std::array<std::byte, 1500> overlongPrefix{};
    const auto validTcp = ipv4TcpPacket();
    std::copy(validTcp.begin(), validTcp.end(), overlongPrefix.begin());
    const auto clampedFacts = adapter.normalize(
        packetSpan(overlongPrefix), 40, DevicePacketDirection::Input,
        domain(AdapterKind::VpnTun));
    EXPECT_EQ(clampedFacts.originalLength, 40U);
    EXPECT_EQ(clampedFacts.boundedPrefixLength, 40U);
    EXPECT_EQ(clampedFacts.parseStatus, ParseStatus::Ready);
}

TEST(PacketCaptureAdapterTest, ConfigurableZeroPrefixNeverReadsInput) {
    PacketCaptureAdapter adapter(
        AdapterKind::RootNfqueue, PacketCaptureAdapterConfig{.maxPrefixLength = 0});
    const auto packet = ipv4TcpPacket();
    const auto facts = adapter.normalize(packetSpan(packet), packet.size(),
                                         DevicePacketDirection::Input,
                                         domain(AdapterKind::RootNfqueue));

    EXPECT_EQ(facts.boundedPrefixLength, 0U);
    EXPECT_EQ(facts.parseStatus, ParseStatus::Malformed);
}

} // namespace
