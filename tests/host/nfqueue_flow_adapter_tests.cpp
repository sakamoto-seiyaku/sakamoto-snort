/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

using namespace SnortDatapath::Nfqueue;
namespace Flow = SnortDatapath::Flow;

constexpr std::byte byte(const std::uint8_t value) noexcept {
    return static_cast<std::byte>(value);
}

void putU16(std::span<std::byte> bytes, const std::size_t offset,
            const std::uint16_t value) noexcept {
    bytes[offset] = byte(static_cast<std::uint8_t>(value >> 8U));
    bytes[offset + 1] = byte(static_cast<std::uint8_t>(value & 0xffU));
}

std::array<std::uint8_t, 40> tcpPacket(const bool reverse = false) {
    std::array<std::uint8_t, 40> packet{};
    packet[0] = 0x45;
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{packet}), 2, 40);
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
    packet[20] = static_cast<std::uint8_t>((reverse ? 443 : 40000) >> 8U);
    packet[21] = static_cast<std::uint8_t>(reverse ? 443 : 40000);
    packet[22] = static_cast<std::uint8_t>((reverse ? 40000 : 443) >> 8U);
    packet[23] = static_cast<std::uint8_t>(reverse ? 40000 : 443);
    packet[32] = 0x50;
    return packet;
}

std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> tcpFragments(
    const std::uint16_t identification) {
    const auto packet = tcpPacket();
    std::vector<std::uint8_t> first(packet.begin(), packet.end());
    first.insert(first.end(), {0xa1, 0xa2, 0xa3, 0xa4});
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{first}), 2,
           static_cast<std::uint16_t>(first.size()));
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{first}), 4,
           identification);
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{first}), 6, 0x2000);

    std::vector<std::uint8_t> final(packet.begin(), packet.begin() + 20);
    final.insert(final.end(), {0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8});
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{final}), 2,
           static_cast<std::uint16_t>(final.size()));
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{final}), 4,
           identification);
    putU16(std::as_writable_bytes(std::span<std::uint8_t>{final}), 6, 3);
    return {std::move(first), std::move(final)};
}

TEST(NfqueueFlowAdapterTest, NormalizesAndRunsSharedOwnerGate) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
    });
    const auto forward = tcpPacket();
    const auto reverse = tcpPacket(true);

    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalIn,
                               std::span<const std::uint8_t>{forward}, 1500),
              NfqueueFlowAdapterResult::FlowAccepted);
    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalOut,
                               std::span<const std::uint8_t>{reverse}, 1500),
              NfqueueFlowAdapterResult::FlowAccepted);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.packetsSeen, 2U);
    EXPECT_EQ(counters.normalizedPackets, 2U);
    EXPECT_EQ(counters.acceptedPackets, 2U);
    EXPECT_EQ(counters.parsePassThroughPackets, 0U);
    EXPECT_EQ(counters.ownerFaultPassThroughPackets, 0U);
    EXPECT_EQ(counters.directPackets, 2U);
    EXPECT_EQ(counters.ownerGuardPasses, 2U);
    EXPECT_EQ(counters.ownerGuardMismatches, 0U);
    EXPECT_EQ(counters.normalWorkerHandoffs, 0U);
}

TEST(NfqueueFlowAdapterTest, FragmentsAndBadHooksFailOpenWithoutPorts) {
    NfqueueFlowAdapter adapter;
    auto fragment = tcpPacket();
    fragment[6] = 0x20;
    fragment[7] = 0;

    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{fragment}, fragment.size()),
              NfqueueFlowAdapterResult::FragmentMalformed);
    EXPECT_EQ(adapter.process(1, 0xff,
                              std::span<const std::uint8_t>{fragment}, fragment.size()),
              NfqueueFlowAdapterResult::FailOpenParse);
    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentPassThroughPackets, 1U);
    EXPECT_EQ(counters.parsePassThroughPackets, 2U);
    EXPECT_EQ(counters.directPackets, 0U);
}

TEST(NfqueueFlowAdapterTest, ReassemblesAndUsesTheSameGraphGate) {
    NfqueueFlowAdapter adapter(NfqueueFlowAdapterConfig{
        .workerCount = 4,
        .hashSeed = 0x1234,
        .queueCapacity = 4,
        .copyPrefixBytes = 512,
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 4,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
    });
    const auto [first, final] = tcpFragments(0x4242);

    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(adapter.process(2, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FlowAccepted);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentBufferedPackets, 1U);
    EXPECT_EQ(counters.fragmentReassembledPackets, 1U);
    EXPECT_EQ(counters.fragmentOwnerMetadataPackets, 1U);
    EXPECT_EQ(counters.fragmentPassThroughPackets, 1U);
    EXPECT_EQ(counters.acceptedPackets, 1U);
    EXPECT_EQ(counters.directPackets, 1U);
    EXPECT_EQ(counters.ownerGuardPasses, 1U);
    EXPECT_EQ(counters.correctiveHandoffs, 0U);
}

TEST(NfqueueFlowAdapterTest, DuplicateFragmentDoesNotEnterPortPolicy) {
    NfqueueFlowAdapter adapter;
    const auto [first, final] = tcpFragments(0x5151);

    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentDuplicate);
    EXPECT_EQ(adapter.process(1, kNfqueueHookLocalIn,
                              std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FlowAccepted);

    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentDuplicatePackets, 1U);
    EXPECT_EQ(counters.fragmentReassembledPackets, 1U);
    EXPECT_EQ(counters.directPackets, 1U);
}

TEST(NfqueueFlowAdapterTest, TimeoutAndCapacityHaveDeterministicFragmentResults) {
    const auto [first, final] = tcpFragments(0x6161);
    const auto [otherFirst, unusedFinal] = tcpFragments(0x6262);
    static_cast<void>(unusedFinal);

    NfqueueFlowAdapter timeoutAdapter(NfqueueFlowAdapterConfig{
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 2,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 2,
        },
    });
    EXPECT_EQ(timeoutAdapter.process(1, kNfqueueHookLocalIn,
                                     std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    const auto normal = tcpPacket();
    EXPECT_EQ(timeoutAdapter.process(1, kNfqueueHookLocalIn,
                                     std::span<const std::uint8_t>{normal}, normal.size()),
              NfqueueFlowAdapterResult::FlowAccepted);
    EXPECT_EQ(timeoutAdapter.process(1, kNfqueueHookLocalIn,
                                     std::span<const std::uint8_t>{final}, final.size()),
              NfqueueFlowAdapterResult::FragmentTimeout);
    EXPECT_EQ(timeoutAdapter.counters().fragmentTimeoutPackets, 1U);

    NfqueueFlowAdapter capacityAdapter(NfqueueFlowAdapterConfig{
        .fragmentSteering = Flow::FragmentSteeringConfig{
            .maxDatagrams = 1,
            .maxFragmentsPerDatagram = 4,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        },
    });
    EXPECT_EQ(capacityAdapter.process(1, kNfqueueHookLocalIn,
                                      std::span<const std::uint8_t>{first}, first.size()),
              NfqueueFlowAdapterResult::FragmentBuffered);
    EXPECT_EQ(capacityAdapter.process(1, kNfqueueHookLocalIn,
                                      std::span<const std::uint8_t>{otherFirst}, otherFirst.size()),
              NfqueueFlowAdapterResult::FragmentCapacity);
    EXPECT_EQ(capacityAdapter.counters().fragmentCapacityPackets, 1U);
}

TEST(NfqueueFlowAdapterTest, RejectsInvalidQueueCapacity) {
    EXPECT_THROW(
        NfqueueFlowAdapter(NfqueueFlowAdapterConfig{.queueCapacity = 0}),
        std::invalid_argument);
}

} // namespace
