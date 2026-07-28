/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueFragmentLeaseBook.hpp>

#include <stdexcept>
#include <utility>

namespace SnortDatapath::Nfqueue {
namespace {

constexpr auto kNoGroup = static_cast<std::size_t>(-1);

NfqueueFragmentLeaseBookConfig validateConfig(
    const NfqueueFragmentLeaseBookConfig config) {
    if (config.maxDatagrams == 0 || config.maxLeasesPerDatagram == 0) {
        throw std::invalid_argument(
            "NFQUEUE fragment lease book capacities must be non-zero");
    }
    return config;
}

} // namespace

NfqueueFragmentLeaseCompletionMailbox::NfqueueFragmentLeaseCompletionMailbox(
    const std::size_t capacity)
    : entries_(capacity) {
    if (capacity == 0) {
        throw std::invalid_argument("NFQUEUE fragment mailbox requires capacity");
    }
}

bool NfqueueFragmentLeaseCompletionMailbox::post(
    const NfqueuePacketLeaseIdentity &identity,
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    const std::lock_guard lock(mutex_);
    if (size_ + reserved_ >= entries_.size()) {
        ++dropped_;
        return false;
    }

    entries_[tail_] = Completion{.identity = identity, .reason = reason};
    tail_ = (tail_ + 1) % entries_.size();
    ++size_;
    return true;
}

bool NfqueueFragmentLeaseCompletionMailbox::reserve() noexcept {
    const std::lock_guard lock(mutex_);
    if (size_ + reserved_ >= entries_.size()) {
        return false;
    }
    ++reserved_;
    return true;
}

bool NfqueueFragmentLeaseCompletionMailbox::postReserved(
    const NfqueuePacketLeaseIdentity &identity,
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    const std::lock_guard lock(mutex_);
    if (reserved_ == 0 || size_ == entries_.size()) {
        ++dropped_;
        return false;
    }
    --reserved_;
    entries_[tail_] = Completion{.identity = identity, .reason = reason};
    tail_ = (tail_ + 1) % entries_.size();
    ++size_;
    return true;
}

void NfqueueFragmentLeaseCompletionMailbox::releaseReservation() noexcept {
    const std::lock_guard lock(mutex_);
    if (reserved_ > 0) {
        --reserved_;
    }
}

std::size_t NfqueueFragmentLeaseCompletionMailbox::drain(
    NfqueuePacketLeaseAdapter &adapter) noexcept {
    std::size_t drained = 0;
    for (;;) {
        Completion completion;
        {
            const std::lock_guard lock(mutex_);
            if (size_ == 0) {
                break;
            }
            completion = entries_[head_];
            head_ = (head_ + 1) % entries_.size();
            --size_;
        }
        static_cast<void>(adapter.complete(completion.identity, completion.reason));
        ++drained;
    }
    return drained;
}

std::size_t NfqueueFragmentLeaseCompletionMailbox::size() const noexcept {
    const std::lock_guard lock(mutex_);
    return size_;
}

std::size_t NfqueueFragmentLeaseCompletionMailbox::dropped() const noexcept {
    const std::lock_guard lock(mutex_);
    return dropped_;
}

std::size_t NfqueueFragmentLeaseCompletionMailbox::reservations() const noexcept {
    const std::lock_guard lock(mutex_);
    return reserved_;
}

NfqueueFragmentLeaseBook::NfqueueFragmentLeaseBook(
    const NfqueueFragmentLeaseBookConfig config)
    : config_(validateConfig(config)), groups_(config_.maxDatagrams) {
    for (auto &group : groups_) {
        group.leases.resize(config_.maxLeasesPerDatagram);
    }
}

NfqueueFragmentLeaseBook::NfqueueFragmentLeaseBook(
    const std::size_t maxDatagrams, const std::size_t maxLeasesPerDatagram)
    : NfqueueFragmentLeaseBook(NfqueueFragmentLeaseBookConfig{
          .maxDatagrams = maxDatagrams,
          .maxLeasesPerDatagram = maxLeasesPerDatagram,
      }) {}

std::size_t NfqueueFragmentLeaseBook::findGroup(
    const Flow::FragmentKey &key) const noexcept {
    for (std::size_t index = 0; index < groups_.size(); ++index) {
        if (groups_[index].active && groups_[index].key == key) {
            return index;
        }
    }
    return kNoGroup;
}

std::size_t NfqueueFragmentLeaseBook::findFreeGroup() const noexcept {
    for (std::size_t index = 0; index < groups_.size(); ++index) {
        if (!groups_[index].active) {
            return index;
        }
    }
    return kNoGroup;
}

bool NfqueueFragmentLeaseBook::timedOut(const std::uint64_t now,
                                        const std::uint64_t lastSeen,
                                        const std::uint64_t timeoutTicks) noexcept {
    return now >= lastSeen && now - lastSeen >= timeoutTicks;
}

bool NfqueueFragmentLeaseBook::retain(
    const Flow::FragmentKey &key, const NfqueuePacketLeaseIdentity &identity,
    NfqueueFragmentLeaseCompletionMailbox &mailbox, const std::uint64_t now) noexcept {
    auto groupIndex = findGroup(key);
    if (groupIndex == kNoGroup) {
        groupIndex = findFreeGroup();
        if (groupIndex == kNoGroup) {
            return false;
        }
        auto &group = groups_[groupIndex];
        group.active = true;
        group.key = key;
        group.lastSeen = now;
        group.leaseCount = 0;
        ++activeDatagrams_;
    }

    auto &group = groups_[groupIndex];
    group.lastSeen = now;
    for (std::size_t index = 0; index < group.leaseCount; ++index) {
        if (group.leases[index].identity == identity) {
            return true;
        }
    }
    if (group.leaseCount == group.leases.size()) {
        return false;
    }

    if (!mailbox.reserve()) {
        if (group.leaseCount == 0) {
            resetGroup(group);
        }
        return false;
    }

    group.leases[group.leaseCount] = Lease{.identity = identity, .mailbox = &mailbox};
    ++group.leaseCount;
    ++activeLeases_;
    return true;
}

void NfqueueFragmentLeaseBook::resetGroup(Group &group) noexcept {
    if (group.active) {
        group.active = false;
        if (activeDatagrams_ > 0) {
            --activeDatagrams_;
        }
    }
    if (activeLeases_ >= group.leaseCount) {
        activeLeases_ -= group.leaseCount;
    } else {
        activeLeases_ = 0;
    }
    group.leaseCount = 0;
    group.lastSeen = 0;
}

std::size_t NfqueueFragmentLeaseBook::terminalize(
    Group &group, const NfqueuePacketLeaseTerminalReason reason) noexcept {
    const auto terminalized = group.leaseCount;
    for (std::size_t index = 0; index < group.leaseCount; ++index) {
        static_cast<void>(group.leases[index].mailbox->postReserved(
            group.leases[index].identity, reason));
    }
    resetGroup(group);
    return terminalized;
}

std::size_t NfqueueFragmentLeaseBook::complete(
    const Flow::FragmentKey &key,
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    const auto groupIndex = findGroup(key);
    if (groupIndex == kNoGroup) {
        return 0;
    }
    return terminalize(groups_[groupIndex], reason);
}

std::size_t NfqueueFragmentLeaseBook::expire(
    const std::uint64_t now, const std::uint64_t timeoutTicks) noexcept {
    std::size_t terminalized = 0;
    for (auto &group : groups_) {
        if (!group.active || !timedOut(now, group.lastSeen, timeoutTicks)) {
            continue;
        }
        terminalized += terminalize(group, NfqueuePacketLeaseTerminalReason::Timeout);
    }
    return terminalized;
}

std::size_t NfqueueFragmentLeaseBook::detach(
    NfqueueFragmentLeaseCompletionMailbox &mailbox) noexcept {
    std::size_t detached = 0;
    for (auto &group : groups_) {
        if (!group.active) {
            continue;
        }

        auto retained = std::size_t{0};
        for (std::size_t index = 0; index < group.leaseCount; ++index) {
            if (group.leases[index].mailbox == &mailbox) {
                mailbox.releaseReservation();
                ++detached;
                continue;
            }
            group.leases[retained] = group.leases[index];
            ++retained;
        }
        if (retained == 0) {
            resetGroup(group);
            continue;
        }
        if (activeLeases_ >= group.leaseCount - retained) {
            activeLeases_ -= group.leaseCount - retained;
        } else {
            activeLeases_ = 0;
        }
        group.leaseCount = retained;
    }
    return detached;
}

} // namespace SnortDatapath::Nfqueue
