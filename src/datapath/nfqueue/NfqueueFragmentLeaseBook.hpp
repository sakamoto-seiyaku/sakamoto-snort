/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FragmentSteering.hpp>
#include <NfqueuePacketLeaseAdapter.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace SnortDatapath::Nfqueue {

/**
 * Thread-safe, bounded handoff queue for returning a lease completion to its
 * owning NFQUEUE lane.  `post` may run on a worker thread; `drain` must run on
 * the lane that owns the supplied adapter.
 */
class NfqueueFragmentLeaseCompletionMailbox final {
public:
    explicit NfqueueFragmentLeaseCompletionMailbox(std::size_t capacity);

    NfqueueFragmentLeaseCompletionMailbox(
        const NfqueueFragmentLeaseCompletionMailbox &) = delete;
    NfqueueFragmentLeaseCompletionMailbox &operator=(
        const NfqueueFragmentLeaseCompletionMailbox &) = delete;
    NfqueueFragmentLeaseCompletionMailbox(
        NfqueueFragmentLeaseCompletionMailbox &&) = delete;
    NfqueueFragmentLeaseCompletionMailbox &operator=(
        NfqueueFragmentLeaseCompletionMailbox &&) = delete;

    /** Queue one terminal completion. Returns false when the ring is full. */
    [[nodiscard]] bool post(const NfqueuePacketLeaseIdentity &identity,
                            NfqueuePacketLeaseTerminalReason reason) noexcept;

    /** Reserve one future terminal entry for a retained fragment lease. */
    [[nodiscard]] bool reserve() noexcept;

    /** Consume a reservation and enqueue its terminal completion. */
    [[nodiscard]] bool postReserved(
        const NfqueuePacketLeaseIdentity &identity,
        NfqueuePacketLeaseTerminalReason reason) noexcept;

    /** Release a reservation when its lease is detached before terminalization. */
    void releaseReservation() noexcept;

    /**
     * Complete every currently available entry through the owning lane's
     * adapter.  This is deliberately the only method that invokes
     * NfqueuePacketLeaseAdapter::complete.
     */
    [[nodiscard]] std::size_t drain(NfqueuePacketLeaseAdapter &adapter) noexcept;

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::size_t capacity() const noexcept { return entries_.size(); }
    [[nodiscard]] std::size_t dropped() const noexcept;
    [[nodiscard]] std::size_t reservations() const noexcept;

private:
    struct Completion final {
        NfqueuePacketLeaseIdentity identity;
        NfqueuePacketLeaseTerminalReason reason =
            NfqueuePacketLeaseTerminalReason::Dropped;
    };

    mutable std::mutex mutex_;
    std::vector<Completion> entries_;
    std::size_t head_ = 0;
    std::size_t tail_ = 0;
    std::size_t size_ = 0;
    std::size_t reserved_ = 0;
    std::size_t dropped_ = 0;
};

/** Runtime-fixed bounds for fragment-to-NFQUEUE lease associations. */
struct NfqueueFragmentLeaseBookConfig final {
    std::size_t maxDatagrams = 64;
    std::size_t maxLeasesPerDatagram = 32;
};

/**
 * Lane-confined, fixed-capacity associations from an in-flight fragment
 * datagram to the packet leases that must receive its terminal outcome.
 *
 * The caller serializes all methods.  A mailbox must be detached before its
 * destruction; `detach` removes its non-owning references so the book cannot
 * post through a stale mailbox pointer.  Constructor-time vectors provide all
 * storage used by retain, complete, expire and detach.
 */
class NfqueueFragmentLeaseBook final {
public:
    explicit NfqueueFragmentLeaseBook(NfqueueFragmentLeaseBookConfig config = {});
    NfqueueFragmentLeaseBook(std::size_t maxDatagrams,
                             std::size_t maxLeasesPerDatagram);

    NfqueueFragmentLeaseBook(const NfqueueFragmentLeaseBook &) = delete;
    NfqueueFragmentLeaseBook &operator=(const NfqueueFragmentLeaseBook &) = delete;
    NfqueueFragmentLeaseBook(NfqueueFragmentLeaseBook &&) = delete;
    NfqueueFragmentLeaseBook &operator=(NfqueueFragmentLeaseBook &&) = delete;

    /**
     * Retain one lease for a fragment datagram.  A duplicate identity in the
     * same datagram is retained only once, preserving one terminal post.
     * Returns false if either the group or per-group lease capacity is full.
     */
    [[nodiscard]] bool retain(
        const Flow::FragmentKey &key, const NfqueuePacketLeaseIdentity &identity,
        NfqueueFragmentLeaseCompletionMailbox &mailbox, std::uint64_t now) noexcept;

    /** Post a terminal outcome for every lease of key, then remove its group. */
    [[nodiscard]] std::size_t complete(
        const Flow::FragmentKey &key,
        NfqueuePacketLeaseTerminalReason reason) noexcept;

    /** Expire timed-out groups with Timeout, returning leases terminalized. */
    [[nodiscard]] std::size_t expire(std::uint64_t now,
                                     std::uint64_t timeoutTicks) noexcept;

    /** Remove every reference to mailbox and return the number removed. */
    [[nodiscard]] std::size_t detach(
        NfqueueFragmentLeaseCompletionMailbox &mailbox) noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return activeDatagrams_; }
    [[nodiscard]] std::size_t datagrams() const noexcept { return activeDatagrams_; }
    [[nodiscard]] std::size_t leases() const noexcept { return activeLeases_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return groups_.size(); }
    [[nodiscard]] std::size_t maxDatagrams() const noexcept { return groups_.size(); }
    [[nodiscard]] std::size_t maxLeasesPerDatagram() const noexcept {
        return config_.maxLeasesPerDatagram;
    }
    [[nodiscard]] std::size_t groupCapacity() const noexcept { return groups_.size(); }
    [[nodiscard]] std::size_t leaseCapacity() const noexcept {
        return config_.maxLeasesPerDatagram;
    }

private:
    struct Lease final {
        NfqueuePacketLeaseIdentity identity;
        NfqueueFragmentLeaseCompletionMailbox *mailbox = nullptr;
    };

    struct Group final {
        Flow::FragmentKey key;
        std::uint64_t lastSeen = 0;
        std::vector<Lease> leases;
        std::size_t leaseCount = 0;
        bool active = false;
    };

    NfqueueFragmentLeaseBookConfig config_;
    std::vector<Group> groups_;
    std::size_t activeDatagrams_ = 0;
    std::size_t activeLeases_ = 0;

    [[nodiscard]] std::size_t findGroup(const Flow::FragmentKey &key) const noexcept;
    [[nodiscard]] std::size_t findFreeGroup() const noexcept;
    [[nodiscard]] static bool timedOut(std::uint64_t now, std::uint64_t lastSeen,
                                       std::uint64_t timeoutTicks) noexcept;
    void resetGroup(Group &group) noexcept;
    [[nodiscard]] std::size_t terminalize(
        Group &group, NfqueuePacketLeaseTerminalReason reason) noexcept;
};

} // namespace SnortDatapath::Nfqueue
