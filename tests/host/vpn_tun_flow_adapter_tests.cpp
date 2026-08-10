/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnTunFlowAdapter.hpp>
#include <VpnTunFdRuntime.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

using namespace SnortDatapath::Tun;
namespace Flow = SnortDatapath::Flow;
namespace Policy = SnortDatapath::Policy;

void closeIfOpen(int &fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

void makePacketSocketPair(int (&fds)[2]) {
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds), 0);
}

std::vector<std::uint8_t> readPacketFromFd(const int fd) {
    std::array<std::uint8_t, 2048> buffer{};
    const ssize_t bytes = ::read(fd, buffer.data(), buffer.size());
    if (bytes <= 0) {
        return {};
    }
    return std::vector<std::uint8_t>(
        buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(bytes));
}

void putU16(std::span<std::uint8_t> bytes, const std::size_t offset,
            const std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value & 0xffU);
}

std::array<std::uint8_t, 40> ipv4TcpPacket(const bool reverse = false) {
    std::array<std::uint8_t, 40> packet{};
    packet[0] = 0x45;
    putU16(packet, 2, 40);
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
    putU16(packet, 20, reverse ? 443 : 40000);
    putU16(packet, 22, reverse ? 40000 : 443);
    packet[32] = 0x50;
    return packet;
}

std::array<std::uint8_t, 28> ipv4UdpPacket() {
    std::array<std::uint8_t, 28> packet{};
    packet[0] = 0x45;
    putU16(packet, 2, 28);
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 10;
    packet[15] = 2;
    packet[16] = 203;
    packet[17] = 0;
    packet[18] = 113;
    packet[19] = 53;
    putU16(packet, 20, 53000);
    putU16(packet, 22, 53);
    putU16(packet, 24, 8);
    return packet;
}

std::array<std::uint8_t, 48> ipv6UdpPacket() {
    std::array<std::uint8_t, 48> packet{};
    packet[0] = 0x60;
    putU16(packet, 4, 8);
    packet[6] = 17;
    packet[7] = 64;
    packet[8] = 0x20;
    packet[9] = 0x01;
    packet[10] = 0x0d;
    packet[11] = 0xb8;
    packet[23] = 1;
    packet[24] = 0x20;
    packet[25] = 0x01;
    packet[26] = 0x0d;
    packet[27] = 0xb8;
    packet[39] = 2;
    putU16(packet, 40, 5353);
    putU16(packet, 42, 853);
    putU16(packet, 44, 8);
    return packet;
}

Policy::PacketPolicySubjectView networkGateDropSubject(
    const std::uint32_t linuxUid,
    const bool uidKnown,
    const std::uint32_t networkContext,
    const std::uint32_t reasonId,
    const std::uint64_t ruleId) {
    return Policy::PacketPolicySubjectView{
        .linuxUid = linuxUid,
        .uidKnown = uidKnown,
        .networkGate = Policy::NetworkGateView{
            .blockedNetworkContexts = {networkContext},
            .reasonId = reasonId,
            .ruleId = ruleId,
        },
        .l4Rules = {},
    };
}

Policy::PacketPolicySubjectView tcpDestinationDropSubject(
    const std::uint32_t linuxUid,
    const std::uint16_t destinationPort) {
    Policy::PacketPolicySubjectView subject;
    subject.linuxUid = linuxUid;
    subject.uidKnown = true;
    subject.l4Rules.push_back(Policy::L4Rule{
        .ruleId = 9001,
        .reasonId = 51,
        .priority = 0,
        .order = 0,
        .action = Policy::L4RuleAction::Drop,
        .match = Policy::L4RuleMatch{
            .family = Flow::AddressFamily::Ipv4,
            .direction = Flow::DevicePacketDirection::Output,
            .ipProtocol = 6,
            .destinationPorts = Policy::PortRange::exact(destinationPort),
        },
    });
    return subject;
}

} // namespace

TEST(VpnTunFlowAdapterTest, KnownUidUsesSharedRuntimePolicyDrop) {
    Policy::RuntimePacketPolicySnapshot policy;
    policy.apply(
        {networkGateDropSubject(12546, true, 7, 91, 7001)},
        69);
    VpnTunFlowAdapter adapter(VpnTunFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 8,
        .packetPolicy = &policy,
    });

    const auto packet = ipv4TcpPacket();
    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{packet}, packet.size(),
                  VpnTunPacketMetadata{
                      .linuxUid = 12546,
                      .networkContext = 7,
                      .interfaceIndex = 9,
                      .uidKnown = true,
                  }),
              VpnTunFlowAdapterResult::FlowDropped);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.packetsSeen, 1U);
    EXPECT_EQ(counters.normalizedPackets, 1U);
    EXPECT_EQ(counters.droppedPackets, 1U);
    EXPECT_EQ(counters.forwardedPackets, 0U);
    EXPECT_EQ(counters.uidAttributionHitPackets, 1U);
    EXPECT_EQ(counters.uidUnknownFallbackPackets, 0U);
    EXPECT_EQ(counters.lastObservedLinuxUid, 12546U);
    EXPECT_TRUE(counters.lastObservedUidKnown);
    EXPECT_EQ(counters.lastObservedNetworkContext, 7U);
    EXPECT_EQ(counters.lastObservedInterfaceIndex, 9U);
    EXPECT_EQ(counters.lastObservedResult, "FlowDropped");
}

TEST(VpnTunFlowAdapterTest, UnknownApplicationFallbackIsImmediateAndPolicyAddressable) {
    Policy::RuntimePacketPolicySnapshot policy;
    policy.apply(
        {networkGateDropSubject(0, false, 4, 92, 7002)},
        70);
    VpnTunFlowAdapter adapter(VpnTunFlowAdapterConfig{.packetPolicy = &policy});
    const auto packet = ipv4UdpPacket();

    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{packet}, packet.size(),
                  VpnTunPacketMetadata{
                      .linuxUid = 0,
                      .networkContext = 4,
                      .interfaceIndex = 10,
                      .uidKnown = false,
                  }),
              VpnTunFlowAdapterResult::FlowDropped);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.uidAttributionHitPackets, 0U);
    EXPECT_EQ(counters.uidUnknownFallbackPackets, 1U);
    EXPECT_EQ(counters.droppedPackets, 1U);
    EXPECT_EQ(counters.parsePolicyBypassPackets, 0U);
    EXPECT_FALSE(counters.lastObservedUidKnown);
}

TEST(VpnTunFlowAdapterTest, KnownUidZeroDoesNotMatchUnknownFallbackSubject) {
    Policy::RuntimePacketPolicySnapshot policy;
    policy.apply(
        {networkGateDropSubject(0, false, 4, 92, 7002)},
        71);
    VpnTunFlowAdapter adapter(VpnTunFlowAdapterConfig{.packetPolicy = &policy});
    const auto packet = ipv4UdpPacket();

    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{packet}, packet.size(),
                  VpnTunPacketMetadata{
                      .linuxUid = 0,
                      .networkContext = 4,
                      .interfaceIndex = 10,
                      .uidKnown = true,
                  }),
              VpnTunFlowAdapterResult::FlowForwarded);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.uidAttributionHitPackets, 1U);
    EXPECT_EQ(counters.uidUnknownFallbackPackets, 0U);
    EXPECT_EQ(counters.forwardedPackets, 1U);
    EXPECT_EQ(counters.droppedPackets, 0U);
}

TEST(VpnTunFlowAdapterTest, OutboundAndTransportReturnShareCanonicalOwner) {
    VpnTunFlowAdapter adapter(VpnTunFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 8,
    });
    const auto outbound = ipv4TcpPacket();
    const auto transportReturn = ipv4TcpPacket(true);

    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{outbound}, outbound.size(),
                  VpnTunPacketMetadata{.linuxUid = 12546, .uidKnown = true}),
              VpnTunFlowAdapterResult::FlowForwarded);
    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::TransportReturn,
                  std::span<const std::uint8_t>{transportReturn},
                  transportReturn.size(),
                  VpnTunPacketMetadata{.linuxUid = 12546, .uidKnown = true}),
              VpnTunFlowAdapterResult::FlowForwarded);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.forwardedPackets, 2U);
    EXPECT_EQ(counters.outboundPackets, 1U);
    EXPECT_EQ(counters.transportReturnPackets, 1U);
    EXPECT_EQ(counters.directPackets, 2U);
    EXPECT_EQ(counters.ownerGuardPasses, 2U);
    EXPECT_EQ(counters.ownerGuardMismatches, 0U);
}

TEST(VpnTunFlowAdapterTest, SupportsIpv6UdpThroughSharedParser) {
    VpnTunFlowAdapter adapter;
    const auto packet = ipv6UdpPacket();

    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{packet}, packet.size(),
                  VpnTunPacketMetadata{
                      .linuxUid = 12546,
                      .networkContext = 2,
                      .interfaceIndex = 11,
                      .uidKnown = true,
                  }),
              VpnTunFlowAdapterResult::FlowForwarded);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.forwardedPackets, 1U);
    EXPECT_EQ(counters.parsePolicyBypassPackets, 0U);
    EXPECT_EQ(counters.lastObservedInterfaceIndex, 11U);
}

TEST(VpnTunFlowAdapterTest, TransportOutcomeCountersStaySeparateFromPolicyVerdict) {
    Policy::RuntimePacketPolicySnapshot policy;
    policy.apply({tcpDestinationDropSubject(12546, 443)}, 72);
    VpnTunFlowAdapter adapter(VpnTunFlowAdapterConfig{.packetPolicy = &policy});
    const auto packet = ipv4TcpPacket();

    EXPECT_EQ(adapter.process(
                  VpnTunPacketDirection::Outbound,
                  std::span<const std::uint8_t>{packet}, packet.size(),
                  VpnTunPacketMetadata{.linuxUid = 12546, .uidKnown = true}),
              VpnTunFlowAdapterResult::FlowDropped);
    adapter.recordTransportOutcome(VpnTunTransportOutcome::Failed);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.droppedPackets, 1U);
    EXPECT_EQ(counters.forwardedPackets, 0U);
    EXPECT_EQ(counters.transportFailedPackets, 1U);
    EXPECT_EQ(counters.transportSucceededPackets, 0U);
    EXPECT_EQ(counters.transportUnsupportedPackets, 0U);
}

TEST(VpnTunFdRuntimeTest, ExposesPolicyControlWithoutClaimingAdapterReady) {
    const int tunFd = openVpnTunFdSource("/dev/null");
    ASSERT_GE(tunFd, 0);

    VpnTunFdRuntime runtime{tunFd};
    EXPECT_TRUE(runtime.start());
    EXPECT_TRUE(runtime.vpnTunFdHandoffReady());
    EXPECT_TRUE(runtime.packetPolicyControlReady());
    EXPECT_FALSE(runtime.packetAdapterReady());

    EXPECT_TRUE(runtime.applyPacketPolicy(
        {tcpDestinationDropSubject(12546, 443)},
        73));
    EXPECT_EQ(runtime.packetPolicyStatus().revision, 73U);

    Flow::PacketFacts facts;
    facts.domain.linuxUid = 12546;
    facts.domain.uidKnown = true;
    facts.source.family = Flow::AddressFamily::Ipv4;
    facts.destination.family = Flow::AddressFamily::Ipv4;
    facts.deviceDirection = Flow::DevicePacketDirection::Output;
    facts.ipProtocol = 6;
    facts.destinationPort = 443;
    facts.portsAvailable = true;

    const auto decision = runtime.evaluatePacketPolicy(facts);
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::L4);
    EXPECT_EQ(decision.revision, 73U);
}

TEST(VpnTunFdRuntimeTest, BoundedDrainReadsTunPacketIntoSharedAdapter) {
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    const auto packet = ipv4TcpPacket();
    ASSERT_EQ(::write(pipeFds[1], packet.data(), packet.size()),
              static_cast<ssize_t>(packet.size()));

    VpnTunFdRuntime runtime{pipeFds[0]};
    pipeFds[0] = -1;

    const auto drain = runtime.drainTunPackets(1);
    EXPECT_EQ(drain.packetsRead, 1U);
    EXPECT_EQ(drain.forwardedWithoutTransport, 1U);
    EXPECT_EQ(drain.policyDropped, 0U);
    EXPECT_EQ(drain.readErrors, 0U);
    EXPECT_FALSE(drain.eof);

    const auto counters = runtime.vpnTunRuntimeCounters();
    EXPECT_EQ(counters.packetsSeen, 1U);
    EXPECT_EQ(counters.forwardedPackets, 1U);
    EXPECT_EQ(counters.droppedPackets, 0U);
    EXPECT_EQ(counters.uidUnknownFallbackPackets, 1U);
    EXPECT_EQ(counters.transportUnsupportedPackets, 1U);
    EXPECT_EQ(counters.lastObservedDirection, "outbound");
    EXPECT_EQ(counters.lastObservedResult, "FlowForwarded");
    EXPECT_FALSE(runtime.packetAdapterReady());

    closeIfOpen(pipeFds[1]);
}

TEST(VpnTunFdRuntimeTest, BoundedDrainPolicyDropDoesNotRecordTransportOutcome) {
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    const auto packet = ipv4UdpPacket();
    ASSERT_EQ(::write(pipeFds[1], packet.data(), packet.size()),
              static_cast<ssize_t>(packet.size()));

    VpnTunFdRuntime runtime{pipeFds[0]};
    pipeFds[0] = -1;
    ASSERT_TRUE(runtime.applyPacketPolicy(
        {networkGateDropSubject(0, false, 4, 92, 7002)},
        74));

    const auto drain = runtime.drainTunPackets(
        1,
        VpnTunPacketMetadata{
            .linuxUid = 0,
            .networkContext = 4,
            .interfaceIndex = 12,
            .uidKnown = false,
        });
    EXPECT_EQ(drain.packetsRead, 1U);
    EXPECT_EQ(drain.forwardedWithoutTransport, 0U);
    EXPECT_EQ(drain.policyDropped, 1U);
    EXPECT_EQ(drain.readErrors, 0U);

    const auto counters = runtime.vpnTunRuntimeCounters();
    EXPECT_EQ(counters.droppedPackets, 1U);
    EXPECT_EQ(counters.forwardedPackets, 0U);
    EXPECT_EQ(counters.transportUnsupportedPackets, 0U);
    EXPECT_EQ(counters.uidUnknownFallbackPackets, 1U);
    EXPECT_EQ(counters.lastObservedInterfaceIndex, 12U);
    EXPECT_EQ(counters.lastObservedResult, "FlowDropped");

    closeIfOpen(pipeFds[1]);
}

TEST(VpnTunFdRuntimeTest, BoundedDrainReturnsImmediatelyWhenNoPacketIsReady) {
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);

    VpnTunFdRuntime runtime{pipeFds[0]};
    pipeFds[0] = -1;

    const auto drain = runtime.drainTunPackets(4);
    EXPECT_EQ(drain.packetsRead, 0U);
    EXPECT_EQ(drain.readErrors, 0U);
    EXPECT_FALSE(drain.eof);
    EXPECT_EQ(runtime.vpnTunRuntimeCounters().packetsSeen, 0U);

    closeIfOpen(pipeFds[1]);
}

TEST(VpnTunFdRuntimeTest, BoundedDrainWritesAllowedOutboundPacketToTransportFd) {
    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    const auto packet = ipv4TcpPacket();
    ASSERT_EQ(::write(tunFds[1], packet.data(), packet.size()),
              static_cast<ssize_t>(packet.size()));

    VpnTunFdRuntime runtime{tunFds[0]};
    tunFds[0] = -1;
    ASSERT_TRUE(runtime.attachVpnTransportFd(transportFds[0]));
    transportFds[0] = -1;

    const auto drain = runtime.drainTunPackets(
        1,
        VpnTunPacketMetadata{.linuxUid = 12546, .uidKnown = true});
    EXPECT_EQ(drain.packetsRead, 1U);
    EXPECT_EQ(drain.forwardedToTransport, 1U);
    EXPECT_EQ(drain.forwardedWithoutTransport, 0U);
    EXPECT_EQ(drain.policyDropped, 0U);
    EXPECT_EQ(drain.writeFailures, 0U);

    const auto transported = readPacketFromFd(transportFds[1]);
    ASSERT_EQ(transported.size(), packet.size());
    EXPECT_TRUE(std::equal(packet.begin(), packet.end(), transported.begin()));

    const auto counters = runtime.vpnTunRuntimeCounters();
    EXPECT_EQ(counters.forwardedPackets, 1U);
    EXPECT_EQ(counters.transportSucceededPackets, 1U);
    EXPECT_EQ(counters.transportUnsupportedPackets, 0U);
    EXPECT_EQ(counters.uidAttributionHitPackets, 1U);

    closeIfOpen(tunFds[1]);
    closeIfOpen(transportFds[1]);
}

TEST(VpnTunFdRuntimeTest, TransportReturnDrainWritesAcceptedPacketBackToTunFd) {
    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    const auto packet = ipv4TcpPacket(true);

    VpnTunFdRuntime runtime{tunFds[0]};
    tunFds[0] = -1;
    ASSERT_TRUE(runtime.attachVpnTransportFd(transportFds[0]));
    transportFds[0] = -1;
    ASSERT_EQ(::write(transportFds[1], packet.data(), packet.size()),
              static_cast<ssize_t>(packet.size()));

    const auto drain = runtime.drainTransportReturnPackets(
        1,
        VpnTunPacketMetadata{.linuxUid = 12546, .uidKnown = true});
    EXPECT_EQ(drain.packetsRead, 1U);
    EXPECT_EQ(drain.returnedToTun, 1U);
    EXPECT_EQ(drain.policyDropped, 0U);
    EXPECT_EQ(drain.writeFailures, 0U);

    const auto returned = readPacketFromFd(tunFds[1]);
    ASSERT_EQ(returned.size(), packet.size());
    EXPECT_TRUE(std::equal(packet.begin(), packet.end(), returned.begin()));

    const auto counters = runtime.vpnTunRuntimeCounters();
    EXPECT_EQ(counters.transportReturnPackets, 1U);
    EXPECT_EQ(counters.transportSucceededPackets, 1U);
    EXPECT_EQ(counters.lastObservedDirection, "transport-return");
    EXPECT_EQ(counters.lastObservedResult, "FlowForwarded");

    closeIfOpen(tunFds[1]);
    closeIfOpen(transportFds[1]);
}
