/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePacketLeaseAdapter.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace {

using namespace SnortDatapath::Nfqueue;

struct VerdictIntent final {
    std::uint32_t packetId = 0;
    NfqueuePacketLeaseVerdict verdict = NfqueuePacketLeaseVerdict::Drop;
};

NfqueuePacketLeaseAdapter makeAdapter(
    std::vector<VerdictIntent> &intents, const std::size_t pendingCapacity = 4U,
    const std::uint32_t laneGeneration = 7U, const std::uint32_t queueNumber = 52U,
    const std::chrono::steady_clock::duration timeout = std::chrono::seconds(10)) {
    return NfqueuePacketLeaseAdapter(
        NfqueuePacketLeaseAdapterConfig{
            .pendingCapacity = pendingCapacity,
            .laneGeneration = laneGeneration,
            .queueNumber = queueNumber,
            .completionTimeout = timeout,
        },
        [&intents](const std::uint32_t packetId,
                   const NfqueuePacketLeaseVerdict verdict) {
            intents.push_back(VerdictIntent{.packetId = packetId, .verdict = verdict});
            return true;
        });
}

NfqueuePacketLeaseIdentity identityOf(
    const NfqueuePacketLeaseAdmission &admission) {
    EXPECT_TRUE(admission.identity.has_value());
    return admission.identity.value_or(NfqueuePacketLeaseIdentity{});
}

TEST(NfqueuePacketLeaseAdapterTest, SuccessAndDuplicateCompletionEmitOneVerdict) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents);
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto admission = adapter.admit(1001, now);
    const auto packet = identityOf(admission);

    EXPECT_EQ(admission.status, NfqueuePacketLeaseAdmissionStatus::Retained);
    EXPECT_FALSE(admission.verdictSent);
    EXPECT_EQ(adapter.complete(packet, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(adapter.complete(packet, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Duplicate);
    EXPECT_EQ(adapter.pending(), 0U);

    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].packetId, 1001U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Accept);
    const auto &counters = adapter.counters();
    EXPECT_EQ(counters.retained, 1U);
    EXPECT_EQ(counters.accepted, 1U);
    EXPECT_EQ(counters.duplicateCompletions, 1U);
    EXPECT_EQ(counters.verdictSendFailures, 0U);
}

TEST(NfqueuePacketLeaseAdapterTest, StaleGenerationCannotCompleteAReusedPacketId) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 4, 8, 53);
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto oldAdmission = adapter.admit(1002, now);
    const auto oldIdentity = identityOf(oldAdmission);

    auto staleIdentity = oldIdentity;
    ++staleIdentity.generation;
    EXPECT_EQ(adapter.complete(staleIdentity, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Stale);
    EXPECT_EQ(adapter.pending(), 1U);
    EXPECT_EQ(adapter.complete(oldIdentity, NfqueuePacketLeaseTerminalReason::Dropped),
              NfqueuePacketLeaseCompletionStatus::Completed);

    const auto nextAdmission = adapter.admit(1002, now + std::chrono::milliseconds(1));
    const auto nextIdentity = identityOf(nextAdmission);
    EXPECT_NE(nextIdentity.generation, oldIdentity.generation);
    EXPECT_EQ(adapter.complete(nextIdentity, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Completed);

    const auto &counters = adapter.counters();
    EXPECT_EQ(counters.staleCompletions, 1U);
    EXPECT_EQ(counters.dropped, 1U);
    EXPECT_EQ(counters.accepted, 1U);
    EXPECT_EQ(intents.size(), 2U);
}

TEST(NfqueuePacketLeaseAdapterTest, DeadlineDropsExactlyOnceAndLateCompletionIsDuplicate) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 4, 11, 54, std::chrono::milliseconds(10));
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto admission = adapter.admit(1003, now);
    const auto packet = identityOf(admission);

    EXPECT_EQ(adapter.expire(now + std::chrono::milliseconds(9)), 0U);
    EXPECT_EQ(adapter.expire(now + std::chrono::milliseconds(10)), 1U);
    EXPECT_EQ(adapter.pending(), 0U);
    EXPECT_EQ(adapter.complete(packet, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Duplicate);

    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    const auto &counters = adapter.counters();
    EXPECT_EQ(counters.timeout, 1U);
    EXPECT_EQ(counters.duplicateCompletions, 1U);
    EXPECT_EQ(counters.verdictSendFailures, 0U);
}

TEST(NfqueuePacketLeaseAdapterTest, ShutdownDrainsAllRetainedLeasesAsDrops) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 4, 12, 55, std::chrono::seconds(100));
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto first = identityOf(adapter.admit(1004, now));
    const auto second = identityOf(adapter.admit(1005, now + std::chrono::milliseconds(1)));

    EXPECT_EQ(adapter.shutdown(), 2U);
    EXPECT_TRUE(adapter.isClosed());
    EXPECT_EQ(adapter.pending(), 0U);
    EXPECT_EQ(adapter.complete(first, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Duplicate);
    EXPECT_EQ(adapter.complete(second, NfqueuePacketLeaseTerminalReason::Dropped),
              NfqueuePacketLeaseCompletionStatus::Duplicate);
    EXPECT_EQ(adapter.shutdown(), 0U);

    const auto closed = adapter.admit(1006, now + std::chrono::milliseconds(2));
    EXPECT_EQ(closed.status, NfqueuePacketLeaseAdmissionStatus::Closed);
    EXPECT_FALSE(closed.identity.has_value());
    EXPECT_FALSE(closed.verdictSent);
    ASSERT_EQ(intents.size(), 2U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(intents[1].verdict, NfqueuePacketLeaseVerdict::Drop);
    const auto &counters = adapter.counters();
    EXPECT_EQ(counters.shutdown, 2U);
    EXPECT_EQ(counters.closedAdmissions, 1U);
    EXPECT_EQ(counters.duplicateCompletions, 2U);
}

TEST(NfqueuePacketLeaseAdapterTest, CapacityFailOpenIsBoundedAndHighWatermarkIsExact) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 2, 13, 56, std::chrono::seconds(100));
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto first = identityOf(adapter.admit(1007, now));
    const auto second = identityOf(adapter.admit(1008, now + std::chrono::milliseconds(1)));
    const auto rejected = adapter.admit(1009, now + std::chrono::milliseconds(2));

    EXPECT_EQ(rejected.status, NfqueuePacketLeaseAdmissionStatus::CapacityFailOpen);
    ASSERT_TRUE(rejected.identity.has_value());
    EXPECT_TRUE(rejected.verdictSent);
    EXPECT_EQ(adapter.pending(), 2U);
    EXPECT_EQ(adapter.highWatermark(), 2U);
    EXPECT_EQ(adapter.counters().capacity, 1U);
    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].packetId, 1009U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Accept);

    EXPECT_EQ(adapter.complete(first, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Completed);
    const auto admitted = identityOf(adapter.admit(1009, now + std::chrono::milliseconds(3)));
    EXPECT_EQ(adapter.complete(second, NfqueuePacketLeaseTerminalReason::Dropped),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(adapter.complete(admitted, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(adapter.pending(), 0U);
    EXPECT_EQ(adapter.highWatermark(), 2U);

    const auto &counters = adapter.counters();
    EXPECT_EQ(counters.accepted, 2U);
    EXPECT_EQ(counters.dropped, 1U);
    EXPECT_EQ(counters.capacity, 1U);
    EXPECT_EQ(intents.size(), 4U);
}

TEST(NfqueuePacketLeaseAdapterTest, HighWatermarkAndTerminalAccountingRemainExactlyOnce) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 3, 14, 57, std::chrono::milliseconds(10));
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto first = identityOf(adapter.admit(1010, now));
    const auto second = identityOf(adapter.admit(1011, now + std::chrono::milliseconds(1)));
    const auto third = identityOf(adapter.admit(1012, now + std::chrono::milliseconds(2)));

    EXPECT_EQ(adapter.highWatermark(), 3U);
    EXPECT_EQ(adapter.complete(first, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(adapter.complete(second, NfqueuePacketLeaseTerminalReason::Dropped),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(adapter.expire(now + std::chrono::milliseconds(12)), 1U);
    EXPECT_EQ(adapter.complete(third, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Duplicate);
    EXPECT_EQ(adapter.complete(first, NfqueuePacketLeaseTerminalReason::Dropped),
              NfqueuePacketLeaseCompletionStatus::Duplicate);

    const auto &counters = adapter.counters();
    EXPECT_EQ(adapter.highWatermark(), 3U);
    EXPECT_EQ(counters.accepted, 1U);
    EXPECT_EQ(counters.dropped, 1U);
    EXPECT_EQ(counters.timeout, 1U);
    EXPECT_EQ(counters.duplicateCompletions, 2U);
    EXPECT_EQ(intents.size(), 3U);
}

TEST(NfqueuePacketLeaseAdapterTest, LaneAndQueueIdentityRejectWrongCompletions) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 4, 15, 58);
    const auto now = NfqueuePacketLeaseAdapter::TimePoint{};
    const auto packet = identityOf(adapter.admit(1013, now));

    auto wrongGeneration = packet;
    ++wrongGeneration.generation;
    EXPECT_EQ(adapter.complete(wrongGeneration, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Stale);

    auto wrongQueue = packet;
    ++wrongQueue.queueNumber;
    EXPECT_EQ(adapter.complete(wrongQueue, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Missing);

    auto wrongPacket = packet;
    ++wrongPacket.packetId;
    EXPECT_EQ(adapter.complete(wrongPacket, NfqueuePacketLeaseTerminalReason::Accepted),
              NfqueuePacketLeaseCompletionStatus::Missing);
    EXPECT_EQ(adapter.pending(), 1U);
    EXPECT_EQ(adapter.counters().staleCompletions, 1U);
    EXPECT_EQ(adapter.counters().missingCompletions, 2U);
    EXPECT_EQ(adapter.complete(packet, NfqueuePacketLeaseTerminalReason::Dropped),
              NfqueuePacketLeaseCompletionStatus::Completed);
    EXPECT_EQ(intents.size(), 1U);
}

} // namespace
