/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowTelemetryAbi.hpp>
#include <FlowTelemetryRing.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

TEST(FlowTelemetryAbi, LayoutConstantsMatchSpecBaseline) {
    EXPECT_EQ(FlowTelemetryAbi::kSlotBytes, 1024u);
    EXPECT_EQ(FlowTelemetryAbi::kRingDataBytes, 16ull * 1024ull * 1024ull);
    EXPECT_EQ(FlowTelemetryAbi::kSlotCount, 16384u);
    EXPECT_EQ(FlowTelemetryAbi::kSlotHeaderBytes, 24u);
    EXPECT_EQ(FlowTelemetryAbi::kMaxPayloadBytes, 1000u);
}

TEST(FlowTelemetryAbi, LittleEndianHelpersRoundtrip) {
    std::array<std::byte, 32> buf{};
    FlowTelemetryAbi::writeU16Le(buf, 0, 0x1234u);
    FlowTelemetryAbi::writeU32Le(buf, 2, 0xA1B2C3D4u);
    FlowTelemetryAbi::writeU64Le(buf, 8, 0x1122334455667788ull);

    EXPECT_EQ(static_cast<std::uint8_t>(buf[0]), 0x34u);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[1]), 0x12u);

    EXPECT_EQ(static_cast<std::uint8_t>(buf[2]), 0xD4u);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[3]), 0xC3u);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[4]), 0xB2u);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[5]), 0xA1u);

    EXPECT_EQ(FlowTelemetryAbi::readU16Le(buf, 0), 0x1234u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(buf, 2), 0xA1B2C3D4u);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(buf, 8), 0x1122334455667788ull);
}

TEST(FlowTelemetryRing, ProducerWritesAndCommitsOneSlot) {
    FlowTelemetryRing ring;
    FlowTelemetryRing::Config cfg{};
    cfg.slotBytes = 128;
    cfg.slotCount = 4;
    std::vector<std::byte> storage(static_cast<size_t>(cfg.slotBytes) * cfg.slotCount);
    ASSERT_TRUE(ring.init(storage, cfg));

    const std::array<std::byte, 4> payload{std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}};
    const auto res = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, payload);
    ASSERT_TRUE(res.wrote);
    EXPECT_EQ(res.dropReason, FlowTelemetryRing::DropReason::None);
    EXPECT_EQ(res.ticket, 0ull);

    const auto slot = ring.slotBytesForTicket(res.ticket);
    ASSERT_EQ(slot.size(), cfg.slotBytes);

    const std::uint32_t state = FlowTelemetryAbi::readU32Le(slot, FlowTelemetryAbi::kSlotOffsetState);
    EXPECT_EQ(state, static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed));

    const std::uint16_t recordType =
        FlowTelemetryAbi::readU16Le(slot, FlowTelemetryAbi::kSlotOffsetRecordType);
    EXPECT_EQ(recordType, static_cast<std::uint16_t>(FlowTelemetryAbi::RecordType::Flow));

    const std::uint64_t ticket = FlowTelemetryAbi::readU64Le(slot, FlowTelemetryAbi::kSlotOffsetTicket);
    EXPECT_EQ(ticket, 0ull);

    const std::uint32_t payloadSize =
        FlowTelemetryAbi::readU32Le(slot, FlowTelemetryAbi::kSlotOffsetPayloadSize);
    EXPECT_EQ(payloadSize, 4u);

    EXPECT_EQ(slot[FlowTelemetryAbi::kSlotHeaderBytes + 0], std::byte{0xAA});
    EXPECT_EQ(slot[FlowTelemetryAbi::kSlotHeaderBytes + 1], std::byte{0xBB});
    EXPECT_EQ(slot[FlowTelemetryAbi::kSlotHeaderBytes + 2], std::byte{0xCC});
    EXPECT_EQ(slot[FlowTelemetryAbi::kSlotHeaderBytes + 3], std::byte{0xDD});
}

TEST(FlowTelemetryRing, OverwritesOldCommittedSlot) {
    FlowTelemetryRing ring;
    FlowTelemetryRing::Config cfg{};
    cfg.slotBytes = 128;
    cfg.slotCount = 1;
    std::vector<std::byte> storage(static_cast<size_t>(cfg.slotBytes) * cfg.slotCount);
    ASSERT_TRUE(ring.init(storage, cfg));

    const std::array<std::byte, 1> p0{std::byte{0x01}};
    const std::array<std::byte, 1> p1{std::byte{0x02}};

    const auto r0 = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, p0);
    ASSERT_TRUE(r0.wrote);
    EXPECT_EQ(r0.ticket, 0ull);

    const auto r1 = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, p1);
    ASSERT_TRUE(r1.wrote);
    EXPECT_EQ(r1.ticket, 1ull);

    const auto slot = ring.slotBytesForTicket(/*ticket=*/0);
    const std::uint64_t ticket = FlowTelemetryAbi::readU64Le(slot, FlowTelemetryAbi::kSlotOffsetTicket);
    EXPECT_EQ(ticket, 1ull) << "slot should have been overwritten with latest committed ticket";

    const std::uint32_t payloadSize =
        FlowTelemetryAbi::readU32Le(slot, FlowTelemetryAbi::kSlotOffsetPayloadSize);
    EXPECT_EQ(payloadSize, 1u);
    EXPECT_EQ(slot[FlowTelemetryAbi::kSlotHeaderBytes], std::byte{0x02});
}

TEST(FlowTelemetryRing, DropsWhenTargetSlotIsWriting) {
    FlowTelemetryRing ring;
    FlowTelemetryRing::Config cfg{};
    cfg.slotBytes = 128;
    cfg.slotCount = 1;
    std::vector<std::byte> storage(static_cast<size_t>(cfg.slotBytes) * cfg.slotCount);
    ASSERT_TRUE(ring.init(storage, cfg));

    // Force WRITING state using atomic semantics.
    auto slot = ring.slotBytesForTicket(0);
    auto *statePtr = std::launder(reinterpret_cast<std::uint32_t *>(
        slot.data() + FlowTelemetryAbi::kSlotOffsetState));
    std::atomic_ref<std::uint32_t>(*statePtr).store(
        static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Writing),
        std::memory_order_release);

    const std::array<std::byte, 1> payload{std::byte{0xFF}};
    const auto res = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, payload);
    EXPECT_FALSE(res.wrote);
    EXPECT_EQ(res.dropReason, FlowTelemetryRing::DropReason::SlotBusy);
}

TEST(FlowTelemetryRing, DropsRecordThatDoesNotFitInOneSlot) {
    FlowTelemetryRing ring;
    FlowTelemetryRing::Config cfg{};
    cfg.slotBytes = 64;
    cfg.slotCount = 2;
    std::vector<std::byte> storage(static_cast<size_t>(cfg.slotBytes) * cfg.slotCount);
    ASSERT_TRUE(ring.init(storage, cfg));

    // slotBytes=64 with headerBytes=24 => maxPayload=40.
    std::vector<std::byte> payload(41, std::byte{0xAB});
    const auto res = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, payload);
    EXPECT_FALSE(res.wrote);
    EXPECT_EQ(res.dropReason, FlowTelemetryRing::DropReason::RecordTooLarge);
}

TEST(FlowTelemetryRing, ConsumerCanDetectTicketGap) {
    FlowTelemetryRing ring;
    FlowTelemetryRing::Config cfg{};
    cfg.slotBytes = 128;
    cfg.slotCount = 1;
    std::vector<std::byte> storage(static_cast<size_t>(cfg.slotBytes) * cfg.slotCount);
    ASSERT_TRUE(ring.init(storage, cfg));

    const std::array<std::byte, 1> payload{std::byte{0xAA}};
    ASSERT_TRUE(ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, payload).wrote); // ticket 0
    ASSERT_TRUE(ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, payload).wrote); // ticket 1 overwrites slot

    // Consumer expects ticket 0, but slot contains ticket 1 => gap.
    const std::uint64_t expected = 0;
    const auto slot = ring.slotBytesForTicket(expected);
    const std::uint64_t seen = FlowTelemetryAbi::readU64Le(slot, FlowTelemetryAbi::kSlotOffsetTicket);
    ASSERT_GT(seen, expected);
}

TEST(FlowTelemetryRing, PerFlowRecordSeqIncrementsOnlyOnSuccessfulWrite) {
    FlowTelemetryRing ring;
    FlowTelemetryRing::Config cfg{};
    cfg.slotBytes = 64;
    cfg.slotCount = 1;
    std::vector<std::byte> storage(static_cast<size_t>(cfg.slotBytes) * cfg.slotCount);
    ASSERT_TRUE(ring.init(storage, cfg));

    std::uint64_t recordSeq = 0;
    const auto onAttempt = [&](const bool wrote) {
        if (wrote) {
            recordSeq += 1;
        }
    };

    {
        const std::array<std::byte, 1> okPayload{std::byte{0x01}};
        const auto r0 = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, okPayload);
        onAttempt(r0.wrote);
        EXPECT_TRUE(r0.wrote);
        EXPECT_EQ(recordSeq, 1ull);
    }

    {
        // Oversize drop must not advance per-flow recordSeq.
        std::vector<std::byte> big(1000, std::byte{0xEE});
        const auto r1 = ring.tryWrite(FlowTelemetryAbi::RecordType::Flow, big);
        onAttempt(r1.wrote);
        EXPECT_FALSE(r1.wrote);
        EXPECT_EQ(r1.dropReason, FlowTelemetryRing::DropReason::RecordTooLarge);
        EXPECT_EQ(recordSeq, 1ull);
    }
}
