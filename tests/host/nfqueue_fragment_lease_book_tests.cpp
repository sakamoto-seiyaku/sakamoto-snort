/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueFragmentLeaseBook.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using namespace SnortDatapath;
using namespace SnortDatapath::Nfqueue;

struct VerdictIntent final {
    std::uint32_t packetId = 0;
    NfqueuePacketLeaseVerdict verdict = NfqueuePacketLeaseVerdict::Drop;
};

NfqueuePacketLeaseAdapter makeAdapter(std::vector<VerdictIntent> &intents,
                                      const std::uint32_t queueNumber) {
    return NfqueuePacketLeaseAdapter(
        NfqueuePacketLeaseAdapterConfig{
            .pendingCapacity = 8,
            .laneGeneration = 17,
            .queueNumber = queueNumber,
            .completionTimeout = std::chrono::seconds(30),
        },
        [&intents](const std::uint32_t packetId,
                   const NfqueuePacketLeaseVerdict verdict) {
            intents.push_back(VerdictIntent{.packetId = packetId, .verdict = verdict});
            return true;
        });
}

NfqueuePacketLeaseIdentity admit(NfqueuePacketLeaseAdapter &adapter,
                                 const std::uint32_t packetId) {
    const auto admission = adapter.admit(
        packetId, NfqueuePacketLeaseAdapter::TimePoint{});
    EXPECT_EQ(admission.status, NfqueuePacketLeaseAdmissionStatus::Retained);
    EXPECT_TRUE(admission.identity.has_value());
    return admission.identity.value_or(NfqueuePacketLeaseIdentity{});
}

Flow::FragmentKey key(const std::uint32_t identification) {
    return {
        .family = Flow::AddressFamily::Ipv4,
        .source = Flow::IpAddress::v4({10, 0, 0, 1}),
        .destination = Flow::IpAddress::v4({192, 0, 2, 1}),
        .ipProtocol = 6,
        .identification = identification,
    };
}

TEST(NfqueueFragmentLeaseBookTest, CompletesMultipleLeasesExactlyOnce) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 31);
    NfqueueFragmentLeaseCompletionMailbox mailbox(4);
    NfqueueFragmentLeaseBook book(2, 3);
    const auto first = admit(adapter, 1001);
    const auto second = admit(adapter, 1002);
    const auto datagram = key(700);

    EXPECT_TRUE(book.retain(datagram, first, mailbox, 10));
    EXPECT_TRUE(book.retain(datagram, first, mailbox, 10));
    EXPECT_TRUE(book.retain(datagram, second, mailbox, 11));
    EXPECT_EQ(book.datagrams(), 1U);
    EXPECT_EQ(book.leases(), 2U);
    EXPECT_EQ(book.complete(datagram, NfqueuePacketLeaseTerminalReason::Accepted), 2U);
    EXPECT_EQ(book.complete(datagram, NfqueuePacketLeaseTerminalReason::Accepted), 0U);
    EXPECT_EQ(book.datagrams(), 0U);
    EXPECT_EQ(mailbox.size(), 2U);

    EXPECT_EQ(mailbox.drain(adapter), 2U);
    EXPECT_EQ(mailbox.drain(adapter), 0U);
    ASSERT_EQ(intents.size(), 2U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Accept);
    EXPECT_EQ(intents[1].verdict, NfqueuePacketLeaseVerdict::Accept);
    EXPECT_EQ(adapter.pending(), 0U);
}

TEST(NfqueueFragmentLeaseBookTest, PostsToEachOriginalMailbox) {
    std::vector<VerdictIntent> firstIntents;
    std::vector<VerdictIntent> secondIntents;
    auto firstAdapter = makeAdapter(firstIntents, 32);
    auto secondAdapter = makeAdapter(secondIntents, 33);
    NfqueueFragmentLeaseCompletionMailbox firstMailbox(2);
    NfqueueFragmentLeaseCompletionMailbox secondMailbox(2);
    NfqueueFragmentLeaseBook book(2, 3);
    const auto datagram = key(701);

    EXPECT_TRUE(book.retain(datagram, admit(firstAdapter, 1003), firstMailbox, 1));
    EXPECT_TRUE(book.retain(datagram, admit(secondAdapter, 1004), secondMailbox, 2));
    EXPECT_EQ(book.complete(datagram, NfqueuePacketLeaseTerminalReason::Dropped), 2U);
    EXPECT_EQ(firstMailbox.drain(firstAdapter), 1U);
    EXPECT_EQ(secondMailbox.drain(secondAdapter), 1U);
    ASSERT_EQ(firstIntents.size(), 1U);
    ASSERT_EQ(secondIntents.size(), 1U);
    EXPECT_EQ(firstIntents[0].packetId, 1003U);
    EXPECT_EQ(secondIntents[0].packetId, 1004U);
    EXPECT_EQ(firstIntents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(secondIntents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
}

TEST(NfqueueFragmentLeaseBookTest, ExpirePostsTimeoutAndClearsGroup) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 34);
    NfqueueFragmentLeaseCompletionMailbox mailbox(2);
    NfqueueFragmentLeaseBook book(2, 2);
    const auto datagram = key(702);

    EXPECT_TRUE(book.retain(datagram, admit(adapter, 1005), mailbox, 100));
    EXPECT_EQ(book.expire(109, 10), 0U);
    EXPECT_EQ(book.expire(110, 10), 1U);
    EXPECT_EQ(book.expire(120, 10), 0U);
    EXPECT_EQ(book.datagrams(), 0U);
    EXPECT_EQ(mailbox.drain(adapter), 1U);
    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].verdict, NfqueuePacketLeaseVerdict::Drop);
    EXPECT_EQ(adapter.counters().timeout, 1U);
}

TEST(NfqueueFragmentLeaseBookTest, DetachRemovesReferencesBeforeMailboxDestruction) {
    std::vector<VerdictIntent> keptIntents;
    std::vector<VerdictIntent> detachedIntents;
    auto keptAdapter = makeAdapter(keptIntents, 35);
    auto detachedAdapter = makeAdapter(detachedIntents, 36);
    NfqueueFragmentLeaseCompletionMailbox keptMailbox(2);
    NfqueueFragmentLeaseCompletionMailbox detachedMailbox(2);
    NfqueueFragmentLeaseBook book(2, 3);
    const auto datagram = key(703);

    EXPECT_TRUE(book.retain(datagram, admit(keptAdapter, 1006), keptMailbox, 1));
    EXPECT_TRUE(book.retain(datagram, admit(detachedAdapter, 1007), detachedMailbox, 1));
    EXPECT_EQ(book.detach(detachedMailbox), 1U);
    EXPECT_EQ(book.leases(), 1U);
    EXPECT_EQ(book.complete(datagram, NfqueuePacketLeaseTerminalReason::Accepted), 1U);
    EXPECT_EQ(keptMailbox.drain(keptAdapter), 1U);
    EXPECT_EQ(detachedMailbox.drain(detachedAdapter), 0U);
    ASSERT_EQ(keptIntents.size(), 1U);
    EXPECT_TRUE(detachedIntents.empty());
    EXPECT_EQ(detachedAdapter.pending(), 1U);
}

TEST(NfqueueFragmentLeaseBookTest, EnforcesDistinctGroupLeaseAndMailboxCapacities) {
    std::vector<VerdictIntent> intents;
    auto adapter = makeAdapter(intents, 37);
    NfqueueFragmentLeaseCompletionMailbox mailbox(1);
    NfqueueFragmentLeaseBook book(1, 2);
    const auto firstKey = key(704);
    const auto secondKey = key(705);
    const auto first = admit(adapter, 1008);
    const auto second = admit(adapter, 1009);
    const auto third = admit(adapter, 1010);

    EXPECT_EQ(book.groupCapacity(), 1U);
    EXPECT_EQ(book.leaseCapacity(), 2U);
    EXPECT_TRUE(book.retain(firstKey, first, mailbox, 1));
    EXPECT_FALSE(book.retain(firstKey, second, mailbox, 2));
    EXPECT_FALSE(book.retain(firstKey, third, mailbox, 3));
    EXPECT_FALSE(book.retain(secondKey, third, mailbox, 3));
    EXPECT_EQ(book.complete(firstKey, NfqueuePacketLeaseTerminalReason::Accepted), 1U);
    EXPECT_EQ(mailbox.size(), 1U);
    EXPECT_EQ(mailbox.dropped(), 0U);
    EXPECT_EQ(mailbox.drain(adapter), 1U);
    ASSERT_EQ(intents.size(), 1U);
    EXPECT_EQ(intents[0].packetId, 1008U);
}

} // namespace
