/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FragmentSteering.hpp>

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

void put16(std::span<std::byte> bytes, const std::size_t offset,
           const std::uint16_t value) noexcept {
    bytes[offset] = byte(static_cast<std::uint8_t>(value >> 8U));
    bytes[offset + 1] = byte(static_cast<std::uint8_t>(value & 0xffU));
}

std::vector<std::byte> ipv4Fragment(const std::uint16_t identification,
                                    const std::uint16_t offsetBytes,
                                    const bool moreFragments,
                                    const std::span<const std::byte> payload) {
    std::vector<std::byte> packet(20U + payload.size());
    packet[0] = byte(0x45);
    put16(packet, 2, static_cast<std::uint16_t>(packet.size()));
    put16(packet, 4, identification);
    const auto offsetUnits = static_cast<std::uint16_t>(offsetBytes / 8U);
    const auto flagsAndOffset = static_cast<std::uint16_t>(
        (moreFragments ? 0x2000U : 0U) | (offsetUnits & 0x1fffU));
    put16(packet, 6, flagsAndOffset);
    packet[8] = byte(64);
    packet[9] = byte(6);
    packet[12] = byte(10);
    packet[13] = byte(0);
    packet[14] = byte(0);
    packet[15] = byte(1);
    packet[16] = byte(192);
    packet[17] = byte(0);
    packet[18] = byte(2);
    packet[19] = byte(1);
    std::ranges::copy(payload, packet.begin() + 20);
    return packet;
}

std::vector<std::byte> ipv6Fragment(const std::uint32_t identification,
                                    const std::uint16_t offsetBytes,
                                    const bool moreFragments,
                                    const std::span<const std::byte> payload) {
    std::vector<std::byte> packet(48U + payload.size());
    packet[0] = byte(0x60);
    put16(packet, 4, static_cast<std::uint16_t>(8U + payload.size()));
    packet[6] = byte(44);
    packet[7] = byte(64);
    packet[8] = byte(0x20);
    packet[9] = byte(1);
    packet[10] = byte(0x0d);
    packet[11] = byte(0xb8);
    packet[23] = byte(1);
    packet[24] = byte(0x20);
    packet[25] = byte(1);
    packet[26] = byte(0x0d);
    packet[27] = byte(0xb8);
    packet[39] = byte(2);
    packet[40] = byte(6);
    const auto offsetUnits = static_cast<std::uint16_t>(offsetBytes / 8U);
    const auto offsetAndMore = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(offsetUnits << 3U) | (moreFragments ? 1U : 0U));
    put16(packet, 42, offsetAndMore);
    put16(packet, 44, static_cast<std::uint16_t>(identification >> 16U));
    put16(packet, 46, static_cast<std::uint16_t>(identification & 0xffffU));
    std::ranges::copy(payload, packet.begin() + 48);
    return packet;
}

std::array<std::byte, 24> firstPayload() {
    return {
        byte(0x9c), byte(0x40), byte(0x01), byte(0xbb), // TCP ports 40000 -> 443.
        byte(0x01), byte(0x02), byte(0x03), byte(0x04),
        byte(0x05), byte(0x06), byte(0x07), byte(0x08),
        byte(0x50), byte(0x00), byte(0x00), byte(0x00), // 20-byte TCP header.
        byte(0x0d), byte(0x0e), byte(0x0f), byte(0x10),
        byte(0x11), byte(0x12), byte(0x13), byte(0x14),
    };
}

std::array<std::byte, 8> secondPayload() {
    return {byte(0x21), byte(0x22), byte(0x23), byte(0x24),
            byte(0x25), byte(0x26), byte(0x27), byte(0x28)};
}

std::array<std::byte, 8> conflictingPayload() {
    return {byte(0xe1), byte(0xe2), byte(0xe3), byte(0xe4),
            byte(0xe5), byte(0xe6), byte(0xe7), byte(0xe8)};
}

FragmentSteeringConfig config(const std::size_t maxDatagrams = 8U) {
    return FragmentSteeringConfig{
        .maxDatagrams = maxDatagrams,
        .maxFragmentsPerDatagram = 4,
        .maxPacketBytes = 128,
        .timeoutTicks = 10,
    };
}

FragmentReassemblyResult submit(FragmentSteering &steering,
                                const std::vector<std::byte> &packet,
                                const std::uint64_t now) {
    return steering.submit(packet, static_cast<std::uint32_t>(packet.size()), now);
}

TEST(FragmentSteeringTest, IPv4SameKeyCoLocatesAndCapturesInitialFlowOwner) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config());
    const auto first = firstPayload();
    const auto second = secondPayload();
    const auto firstPacket = ipv4Fragment(0x4242, 0, true, first);
    const auto secondPacket = ipv4Fragment(0x4242, 24, false, second);

    const auto buffered = submit(steering, firstPacket, 1);
    const auto complete = submit(steering, secondPacket, 2);

    EXPECT_EQ(buffered.status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(complete.status, FragmentSubmitStatus::Reassembled);
    ASSERT_TRUE(complete.owner.has_value());
    EXPECT_EQ(complete.owner->flowKey.ipProtocol, 6);
    EXPECT_EQ(complete.owner->flowKey.portA, 40000);
    EXPECT_EQ(complete.owner->flowKey.portB, 443);
    EXPECT_EQ(complete.owner->finalOwner,
              steering.selector().ownerFor(complete.owner->flowKey));
    EXPECT_FALSE(complete.correctiveHandoffConsumed());
    ASSERT_EQ(complete.packet.size(), 20U + first.size() + second.size());
    EXPECT_EQ(complete.packet[6], byte(0));
    EXPECT_TRUE(std::ranges::equal(
        std::span<const std::byte>{complete.packet}.subspan(20),
        std::array{first[0], first[1], first[2], first[3], first[4], first[5], first[6],
                   first[7], first[8], first[9], first[10], first[11], first[12], first[13],
                   first[14], first[15], first[16], first[17], first[18], first[19], first[20],
                   first[21], first[22], first[23], second[0], second[1], second[2], second[3],
                   second[4], second[5], second[6], second[7]}));
}

TEST(FragmentSteeringTest, IPv6SameKeyCoLocatesButDifferentIdentificationCannotJoin) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config(1));
    const auto first = firstPayload();
    const auto second = secondPayload();
    const auto initial = ipv6Fragment(0x11223344, 0, true, first);
    const auto otherInitial = ipv6Fragment(0x55667788, 0, true, first);
    const auto final = ipv6Fragment(0x11223344, 24, false, second);

    EXPECT_EQ(submit(steering, initial, 1).status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(submit(steering, otherInitial, 2).status, FragmentSubmitStatus::Capacity);
    const auto complete = submit(steering, final, 3);

    EXPECT_EQ(complete.status, FragmentSubmitStatus::Reassembled);
    ASSERT_TRUE(complete.owner.has_value());
    EXPECT_EQ(complete.owner->flowKey.family, AddressFamily::Ipv6);
    EXPECT_EQ(complete.packet[6], byte(6)); // Fragment header removed.
    EXPECT_EQ(steering.counters().capacityDrops, 1U);
}

TEST(FragmentSteeringTest, NonInitialFragmentNeverFabricatesPortsOrFlowOwner) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config());
    const auto nonInitial = ipv4Fragment(0x5151, 24, false, secondPayload());

    const auto outcome = submit(steering, nonInitial, 1);

    EXPECT_EQ(outcome.status, FragmentSubmitStatus::Buffered);
    EXPECT_FALSE(outcome.owner.has_value());
}

TEST(FragmentSteeringTest, OutOfOrderCompletionUsesInitialOwnerWithoutCorrection) {
    FragmentSteering steering(WorkerLayout{2, 0x55aa}, config());
    const auto first = firstPayload();
    const auto second = secondPayload();
    const auto firstPacket = ipv4Fragment(0x6161, 0, true, first);
    const auto secondPacket = ipv4Fragment(0x6161, 24, false, second);

    const auto outOfOrder = submit(steering, secondPacket, 1);
    const auto complete = submit(steering, firstPacket, 2);

    EXPECT_EQ(outOfOrder.status, FragmentSubmitStatus::Buffered);
    EXPECT_FALSE(outOfOrder.owner.has_value());
    EXPECT_EQ(complete.status, FragmentSubmitStatus::Reassembled);
    EXPECT_TRUE(complete.owner.has_value());
    EXPECT_FALSE(complete.correctiveHandoffConsumed());
    EXPECT_EQ(steering.counters().reassembledPackets, 1U);
}

TEST(FragmentSteeringTest, IdenticalDuplicateIsIdempotentWhileDatagramIsActive) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config());
    const auto first = firstPayload();
    const auto firstPacket = ipv4Fragment(0x7171, 0, true, first);
    const auto finalPacket = ipv4Fragment(0x7171, 24, false, secondPayload());

    EXPECT_EQ(submit(steering, firstPacket, 1).status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(submit(steering, firstPacket, 2).status, FragmentSubmitStatus::Duplicate);
    EXPECT_EQ(submit(steering, finalPacket, 3).status, FragmentSubmitStatus::Reassembled);
    EXPECT_EQ(steering.counters().duplicatePackets, 1U);
    EXPECT_EQ(steering.counters().reassembledPackets, 1U);
}

TEST(FragmentSteeringTest, ConflictingOverlapDropsDatagramAndClearsItsState) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config());
    const auto firstPacket = ipv4Fragment(0x8181, 0, true, firstPayload());
    const auto overlapPacket = ipv4Fragment(0x8181, 16, true, conflictingPayload());
    const auto finalPacket = ipv4Fragment(0x8181, 24, false, secondPayload());

    EXPECT_EQ(submit(steering, firstPacket, 1).status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(submit(steering, overlapPacket, 2).status, FragmentSubmitStatus::Conflict);
    EXPECT_EQ(steering.counters().conflictPackets, 1U);
    EXPECT_EQ(steering.activeDatagrams(), 0U);
    EXPECT_EQ(submit(steering, finalPacket, 3).status, FragmentSubmitStatus::Buffered);
}

TEST(FragmentSteeringTest, MalformedFragmentsAreRejectedDeterministically) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config());
    const std::array<std::byte, 7> shortMorePayload{
        byte(0x31), byte(0x32), byte(0x33), byte(0x34),
        byte(0x35), byte(0x36), byte(0x37),
    };
    const auto malformedIpv4 = ipv4Fragment(0x9191, 0, true, shortMorePayload);
    auto malformedIpv6 = ipv6Fragment(0xa1a1a1a1, 0, true, firstPayload());
    malformedIpv6[41] = byte(1); // Reserved Fragment-header byte must be zero.

    EXPECT_EQ(submit(steering, malformedIpv4, 1).status, FragmentSubmitStatus::Malformed);
    EXPECT_EQ(submit(steering, malformedIpv6, 2).status, FragmentSubmitStatus::Malformed);
    EXPECT_EQ(steering.counters().malformedPackets, 2U);
}

TEST(FragmentSteeringTest, FragmentCountAndCapacityRemainBounded) {
    FragmentSteering steering(
        WorkerLayout{2, 0x1234},
        FragmentSteeringConfig{
            .maxDatagrams = 8,
            .maxFragmentsPerDatagram = 1,
            .maxPacketBytes = 128,
            .timeoutTicks = 10,
        });
    const auto firstPacket = ipv4Fragment(0xb1b1, 0, true, firstPayload());
    const auto finalPacket = ipv4Fragment(0xb1b1, 24, false, secondPayload());

    EXPECT_EQ(submit(steering, firstPacket, 1).status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(submit(steering, finalPacket, 2).status, FragmentSubmitStatus::Capacity);
    EXPECT_EQ(steering.counters().capacityDrops, 1U);
    EXPECT_EQ(steering.activeDatagrams(), 0U);
}

TEST(FragmentSteeringTest, TimeoutReleasesStateAndAllowsNextDatagram) {
    FragmentSteering steering(WorkerLayout{2, 0x1234}, config(1));
    const auto firstPacket = ipv4Fragment(0xc1c1, 0, true, firstPayload());
    const auto otherPacket = ipv4Fragment(0xd2d2, 0, true, firstPayload());

    EXPECT_EQ(submit(steering, firstPacket, 10).status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(submit(steering, otherPacket, 11).status, FragmentSubmitStatus::Capacity);
    EXPECT_EQ(steering.expire(20), 1U);
    EXPECT_EQ(steering.counters().timeoutDatagrams, 1U);
    EXPECT_EQ(submit(steering, otherPacket, 21).status, FragmentSubmitStatus::Buffered);
    EXPECT_EQ(steering.activeDatagrams(), 1U);
}

} // namespace
