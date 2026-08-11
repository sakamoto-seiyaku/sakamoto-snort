/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphIngress.hpp>

#include <algorithm>
#include <array>

namespace SnortDatapath::Flow {
namespace {

constexpr std::uint8_t kTcpProtocol = 6;
constexpr std::uint8_t kUdpProtocol = 17;
constexpr std::uint8_t kIpv4Version = 4;
constexpr std::uint8_t kIpv6Version = 6;
constexpr std::uint8_t kIpv6FragmentHeader = 44;

constexpr std::size_t kIpv4MinimumHeaderLength = 20;
constexpr std::size_t kIpv6HeaderLength = 40;
constexpr std::size_t kTcpMinimumHeaderLength = 20;
constexpr std::size_t kUdpHeaderLength = 8;

[[nodiscard]] std::uint8_t byteAt(
    const std::span<const std::byte> bytes, const std::size_t offset) noexcept {
    return std::to_integer<std::uint8_t>(bytes[offset]);
}

[[nodiscard]] std::uint16_t readNetworkU16(
    const std::span<const std::byte> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(byteAt(bytes, offset)) << 8U)
        | static_cast<std::uint16_t>(byteAt(bytes, offset + 1)));
}

[[nodiscard]] bool hasBytes(
    const std::span<const std::byte> bytes, const std::size_t offset,
    const std::size_t count) noexcept {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

void setIpv4Address(IpAddress &address, const std::span<const std::byte> bytes,
                    const std::size_t offset) noexcept {
    std::array<std::uint8_t, 4> value{};
    for (std::size_t index = 0; index < value.size(); ++index) {
        value[index] = byteAt(bytes, offset + index);
    }
    address = IpAddress::v4(value);
}

void setIpv6Address(IpAddress &address, const std::span<const std::byte> bytes,
                    const std::size_t offset) noexcept {
    std::array<std::uint8_t, 16> value{};
    for (std::size_t index = 0; index < value.size(); ++index) {
        value[index] = byteAt(bytes, offset + index);
    }
    address = IpAddress::v6(value);
}

void parseTransport(PacketFacts &facts, const std::span<const std::byte> bytes,
                    const std::size_t transportOffset,
                    const std::size_t ipPayloadLength) noexcept {
    if (transportOffset > bytes.size()) {
        facts.parseStatus = ParseStatus::Malformed;
        return;
    }

    const auto available = bytes.size() - transportOffset;
    if (facts.ipProtocol == kTcpProtocol) {
        if (ipPayloadLength < kTcpMinimumHeaderLength
            || available < kTcpMinimumHeaderLength) {
            facts.parseStatus = ParseStatus::Malformed;
            return;
        }

        const auto tcpHeaderLength = static_cast<std::size_t>(
            (byteAt(bytes, transportOffset + 12) >> 4U) * 4U);
        if (tcpHeaderLength < kTcpMinimumHeaderLength
            || tcpHeaderLength > ipPayloadLength || tcpHeaderLength > available) {
            facts.parseStatus = ParseStatus::Malformed;
            return;
        }

        facts.sourcePort = readNetworkU16(bytes, transportOffset);
        facts.destinationPort = readNetworkU16(bytes, transportOffset + 2);
        facts.portsAvailable = true;
        facts.transportPayloadOffset = static_cast<std::uint32_t>(
            transportOffset + tcpHeaderLength);
        facts.transportPayloadLength = static_cast<std::uint32_t>(
            std::min(ipPayloadLength - tcpHeaderLength,
                     available - tcpHeaderLength));
        facts.parseStatus = ParseStatus::Ready;
        return;
    }

    if (facts.ipProtocol == kUdpProtocol) {
        if (ipPayloadLength < kUdpHeaderLength || available < kUdpHeaderLength) {
            facts.parseStatus = ParseStatus::Malformed;
            return;
        }

        const auto udpLength = static_cast<std::size_t>(
            readNetworkU16(bytes, transportOffset + 4));
        if (udpLength < kUdpHeaderLength || udpLength > ipPayloadLength) {
            facts.parseStatus = ParseStatus::Malformed;
            return;
        }

        facts.sourcePort = readNetworkU16(bytes, transportOffset);
        facts.destinationPort = readNetworkU16(bytes, transportOffset + 2);
        facts.portsAvailable = true;
        facts.transportPayloadOffset = static_cast<std::uint32_t>(
            transportOffset + kUdpHeaderLength);
        facts.transportPayloadLength = static_cast<std::uint32_t>(
            std::min(udpLength - kUdpHeaderLength,
                     available - kUdpHeaderLength));
        facts.parseStatus = ParseStatus::Ready;
        return;
    }

    facts.parseStatus = ParseStatus::UnsupportedProtocol;
}

void parseIpv4(PacketFacts &facts, const std::span<const std::byte> bytes) noexcept {
    if (!hasBytes(bytes, 0, kIpv4MinimumHeaderLength)) {
        return;
    }

    const auto versionAndIhl = byteAt(bytes, 0);
    if ((versionAndIhl >> 4U) != kIpv4Version) {
        return;
    }

    const auto ihl = static_cast<std::size_t>(versionAndIhl & 0x0fU);
    const auto headerLength = ihl * 4U;
    if (ihl < 5 || !hasBytes(bytes, 0, headerLength)) {
        return;
    }

    const auto totalLength = static_cast<std::size_t>(readNetworkU16(bytes, 2));
    if (totalLength < headerLength || totalLength < kIpv4MinimumHeaderLength
        || totalLength > facts.originalLength) {
        return;
    }

    setIpv4Address(facts.source, bytes, 12);
    setIpv4Address(facts.destination, bytes, 16);
    facts.ipProtocol = byteAt(bytes, 9);

    const auto fragmentField = readNetworkU16(bytes, 6);
    if ((fragmentField & 0x8000U) != 0) {
        return;
    }
    if ((fragmentField & 0x2000U) != 0 || (fragmentField & 0x1fffU) != 0) {
        facts.fragmented = true;
        facts.parseStatus = ParseStatus::Fragment;
        return;
    }

    const auto transportOffset = headerLength;
    const auto ipPayloadLength = totalLength - headerLength;
    if (facts.ipProtocol != kTcpProtocol && facts.ipProtocol != kUdpProtocol) {
        facts.parseStatus = ParseStatus::UnsupportedProtocol;
        return;
    }
    parseTransport(facts, bytes, transportOffset, ipPayloadLength);
}

void parseIpv6(PacketFacts &facts, const std::span<const std::byte> bytes) noexcept {
    if (!hasBytes(bytes, 0, kIpv6HeaderLength)) {
        return;
    }

    if ((byteAt(bytes, 0) >> 4U) != kIpv6Version) {
        return;
    }

    const auto payloadLength = static_cast<std::size_t>(readNetworkU16(bytes, 4));
    const auto totalLength = kIpv6HeaderLength + payloadLength;
    if (totalLength < kIpv6HeaderLength || totalLength > facts.originalLength) {
        return;
    }

    setIpv6Address(facts.source, bytes, 8);
    setIpv6Address(facts.destination, bytes, 24);
    facts.ipProtocol = byteAt(bytes, 6);

    // A Fragment header is the only IPv6 extension header recognized here.
    // Fragment orchestration remains in the NFQUEUE/fragment slice for now;
    // this parser only marks the shared fact and never fabricates L4 ports.
    if (facts.ipProtocol == kIpv6FragmentHeader) {
        if (payloadLength < 8 || !hasBytes(bytes, kIpv6HeaderLength, 8)) {
            return;
        }
        facts.ipProtocol = byteAt(bytes, kIpv6HeaderLength);
        facts.fragmented = true;
        facts.parseStatus = ParseStatus::Fragment;
        return;
    }

    if (facts.ipProtocol != kTcpProtocol && facts.ipProtocol != kUdpProtocol) {
        facts.parseStatus = ParseStatus::UnsupportedProtocol;
        return;
    }
    parseTransport(facts, bytes, kIpv6HeaderLength, payloadLength);
}

} // namespace

FlowGraphIngressParser::FlowGraphIngressParser(
    const FlowGraphIngressConfig config) noexcept
    : maxL3Bytes_(config.maxL3Bytes) {}

PacketFacts FlowGraphIngressParser::parseL3Packet(
    const std::span<const std::byte> l3Packet,
    const FlowGraphIngressMetadata metadata) const noexcept {
    PacketFacts facts{};
    facts.deviceDirection = metadata.direction;
    facts.originalLength = metadata.originalLength;
    facts.domain = metadata.domain;

    const auto boundedSize = std::min(
        l3Packet.size(),
        std::min(static_cast<std::size_t>(maxL3Bytes_),
                 static_cast<std::size_t>(metadata.originalLength)));
    facts.boundedPrefixLength = static_cast<std::uint32_t>(boundedSize);
    const auto boundedPacket = l3Packet.first(boundedSize);

    if (metadata.originalLength == 0 || boundedPacket.empty()) {
        return facts;
    }

    const auto version = byteAt(boundedPacket, 0) >> 4U;
    if (version == kIpv4Version) {
        parseIpv4(facts, boundedPacket);
    } else if (version == kIpv6Version) {
        parseIpv6(facts, boundedPacket);
    }
    return facts;
}

PacketFacts parseIngressPacketFacts(
    const std::span<const std::byte> l3Packet,
    const FlowGraphIngressMetadata metadata,
    const FlowGraphIngressConfig config) noexcept {
    return FlowGraphIngressParser(config).parseL3Packet(l3Packet, metadata);
}

} // namespace SnortDatapath::Flow
