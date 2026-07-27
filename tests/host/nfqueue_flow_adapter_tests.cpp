/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace {

using namespace SnortDatapath::Nfqueue;

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
              NfqueueFlowAdapterResult::FailOpenParse);
    EXPECT_EQ(adapter.process(1, 0xff,
                              std::span<const std::uint8_t>{fragment}, fragment.size()),
              NfqueueFlowAdapterResult::FailOpenParse);
    const auto counters = adapter.counters();
    EXPECT_EQ(counters.fragmentPassThroughPackets, 2U);
    EXPECT_EQ(counters.parsePassThroughPackets, 2U);
    EXPECT_EQ(counters.directPackets, 0U);
}

TEST(NfqueueFlowAdapterTest, RejectsInvalidQueueCapacity) {
    EXPECT_THROW(
        NfqueueFlowAdapter(NfqueueFlowAdapterConfig{.queueCapacity = 0}),
        std::invalid_argument);
}

} // namespace
