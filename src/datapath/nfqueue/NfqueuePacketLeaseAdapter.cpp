/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePacketLeaseAdapter.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace SnortDatapath::Nfqueue {
namespace {

NfqueuePacketLeaseAdapterConfig validateConfig(NfqueuePacketLeaseAdapterConfig config) {
    if (config.pendingCapacity == 0) {
        throw std::invalid_argument("NFQUEUE lease adapter requires pending capacity");
    }
    if (config.completionHistoryCapacity == 0) {
        config.completionHistoryCapacity = config.pendingCapacity;
    }
    if (config.laneGeneration == 0) {
        throw std::invalid_argument("NFQUEUE lease adapter requires lane generation");
    }
    if (config.completionTimeout < NfqueuePacketLeaseAdapter::Clock::duration::zero()) {
        throw std::invalid_argument("NFQUEUE lease adapter requires non-negative timeout");
    }
    return config;
}

bool samePacketContext(const NfqueuePacketLeaseIdentity &left,
                       const NfqueuePacketLeaseIdentity &right) noexcept {
    return left.laneGeneration == right.laneGeneration
        && left.queueNumber == right.queueNumber && left.packetId == right.packetId;
}

using TerminalCounter = std::uint64_t NfqueuePacketLeaseCounters::*;

struct TerminalPolicy final {
    NfqueuePacketLeaseVerdict verdict;
    TerminalCounter counter;
};

constexpr std::array<TerminalPolicy, 6> kTerminalPolicies{
    TerminalPolicy{
        .verdict = NfqueuePacketLeaseVerdict::Accept,
        .counter = &NfqueuePacketLeaseCounters::accepted,
    },
    TerminalPolicy{
        .verdict = NfqueuePacketLeaseVerdict::Drop,
        .counter = &NfqueuePacketLeaseCounters::dropped,
    },
    TerminalPolicy{
        .verdict = NfqueuePacketLeaseVerdict::Accept,
        .counter = &NfqueuePacketLeaseCounters::failOpen,
    },
    TerminalPolicy{
        .verdict = NfqueuePacketLeaseVerdict::Drop,
        .counter = &NfqueuePacketLeaseCounters::timeout,
    },
    TerminalPolicy{
        .verdict = NfqueuePacketLeaseVerdict::Drop,
        .counter = &NfqueuePacketLeaseCounters::shutdown,
    },
    TerminalPolicy{
        .verdict = NfqueuePacketLeaseVerdict::Accept,
        .counter = &NfqueuePacketLeaseCounters::capacity,
    },
};

const TerminalPolicy *terminalPolicyFor(
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    const auto index = static_cast<std::size_t>(reason);
    if (index >= kTerminalPolicies.size()) {
        return nullptr;
    }
    return &kTerminalPolicies[index];
}

bool validTerminalReason(const NfqueuePacketLeaseTerminalReason reason) noexcept {
    return terminalPolicyFor(reason) != nullptr;
}

} // namespace

NfqueuePacketLeaseAdapter::NfqueuePacketLeaseAdapter(
    NfqueuePacketLeaseAdapterConfig config, NfqueuePacketLeaseVerdictSink &sink)
    : config_(validateConfig(std::move(config))), sink_(std::ref(sink)),
      pendingEntries_(config_.pendingCapacity),
      terminalHistory_(config_.completionHistoryCapacity) {}

NfqueuePacketLeaseAdapter::NfqueuePacketLeaseAdapter(
    NfqueuePacketLeaseAdapterConfig config, NfqueuePacketLeaseVerdictCallback callback)
    : config_(validateConfig(std::move(config))), callback_(std::move(callback)),
      pendingEntries_(config_.pendingCapacity),
      terminalHistory_(config_.completionHistoryCapacity) {
    if (!callback_) {
        throw std::invalid_argument("NFQUEUE lease adapter requires a verdict callback");
    }
}

NfqueuePacketLeaseAdapter::~NfqueuePacketLeaseAdapter() {
    (void)shutdown();
}

NfqueuePacketLeaseIdentity NfqueuePacketLeaseAdapter::makeIdentity(
    const std::uint32_t packetId) noexcept {
    auto generation = nextGeneration_;
    do {
        nextGeneration_ = generation == std::numeric_limits<std::uint64_t>::max()
            ? 1
            : generation + 1;
        const NfqueuePacketLeaseIdentity candidate{
            .laneGeneration = config_.laneGeneration,
            .queueNumber = config_.queueNumber,
            .packetId = packetId,
            .generation = generation,
        };
        const bool activeCollision = std::any_of(
            pendingEntries_.begin(), pendingEntries_.end(),
            [&candidate](const PendingEntry &entry) {
                return entry.active && entry.identity == candidate;
            });
        if (!activeCollision && !identityInHistory(candidate)) {
            return candidate;
        }
        generation = nextGeneration_;
    } while (generation != 0);

    return NfqueuePacketLeaseIdentity{
        .laneGeneration = config_.laneGeneration,
        .queueNumber = config_.queueNumber,
        .packetId = packetId,
        .generation = 1,
    };
}

bool NfqueuePacketLeaseAdapter::identityInHistory(
    const NfqueuePacketLeaseIdentity &identity) const noexcept {
    for (std::size_t index = 0; index < historySize_; ++index) {
        if (terminalHistory_[index].valid && terminalHistory_[index].identity == identity) {
            return true;
        }
    }
    return false;
}

std::size_t NfqueuePacketLeaseAdapter::activeIndexForPacket(
    const std::uint32_t packetId) const noexcept {
    for (std::size_t index = 0; index < pendingEntries_.size(); ++index) {
        if (pendingEntries_[index].active && pendingEntries_[index].identity.packetId == packetId) {
            return index;
        }
    }
    return pendingEntries_.size();
}

std::optional<std::size_t> NfqueuePacketLeaseAdapter::activeIndexForIdentity(
    const NfqueuePacketLeaseIdentity &identity) const noexcept {
    for (std::size_t index = 0; index < pendingEntries_.size(); ++index) {
        if (pendingEntries_[index].active && pendingEntries_[index].identity == identity) {
            return index;
        }
    }
    return std::nullopt;
}

bool NfqueuePacketLeaseAdapter::sendVerdict(
    const std::uint32_t packetId, const NfqueuePacketLeaseVerdict verdict) noexcept {
    try {
        const bool sent = sink_.has_value()
            ? sink_->get().sendVerdict(packetId, verdict)
            : callback_(packetId, verdict);
        if (!sent) {
            ++counters_.verdictSendFailures;
        }
        return sent;
    } catch (...) {
        ++counters_.verdictSendFailures;
        return false;
    }
}

void NfqueuePacketLeaseAdapter::rememberTerminal(
    const NfqueuePacketLeaseIdentity &identity,
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    terminalHistory_[historyCursor_] = TerminalRecord{
        .identity = identity,
        .reason = reason,
        .valid = true,
    };
    historyCursor_ = (historyCursor_ + 1) % terminalHistory_.size();
    if (historySize_ < terminalHistory_.size()) {
        ++historySize_;
    }
    counters_.completionHighWatermark = std::max(
        counters_.completionHighWatermark, historySize_);
}

void NfqueuePacketLeaseAdapter::countTerminal(
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    if (const auto *policy = terminalPolicyFor(reason); policy != nullptr) {
        ++(counters_.*(policy->counter));
    }
}

bool NfqueuePacketLeaseAdapter::recordTerminal(
    const NfqueuePacketLeaseIdentity &identity,
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    const auto *policy = terminalPolicyFor(reason);
    if (policy == nullptr) {
        return false;
    }
    rememberTerminal(identity, reason);
    countTerminal(reason);
    return sendVerdict(identity.packetId, policy->verdict);
}

bool NfqueuePacketLeaseAdapter::terminalize(
    const std::size_t index, const NfqueuePacketLeaseTerminalReason reason) noexcept {
    auto &entry = pendingEntries_[index];
    const auto identity = entry.identity;
    const bool verdictSent = recordTerminal(identity, reason);
    entry.active = false;
    if (pending_ > 0) {
        --pending_;
    }
    if (!verdictSent) {
        ++counters_.completionFaults;
        ++counters_.completionVerdictSendFailures;
    }
    return verdictSent;
}

NfqueuePacketLeaseAdmission NfqueuePacketLeaseAdapter::failOpenForCapacity(
    const NfqueuePacketLeaseIdentity &identity) noexcept {
    ++counters_.capacityAdmissions;
    const bool verdictSent = recordTerminal(
        identity, NfqueuePacketLeaseTerminalReason::Capacity);
    if (!verdictSent) {
        ++counters_.admissionVerdictSendFailures;
    }
    return NfqueuePacketLeaseAdmission{
        .status = NfqueuePacketLeaseAdmissionStatus::CapacityFailOpen,
        .identity = identity,
        .verdictSent = verdictSent,
    };
}

NfqueuePacketLeaseAdmission NfqueuePacketLeaseAdapter::admit(
    const std::uint32_t packetId) noexcept {
    return admit(packetId, Clock::now());
}

NfqueuePacketLeaseAdmission NfqueuePacketLeaseAdapter::admit(
    const std::uint32_t packetId, const TimePoint now) noexcept {
    if (closed_) {
        ++counters_.closedAdmissions;
        return NfqueuePacketLeaseAdmission{
            .status = NfqueuePacketLeaseAdmissionStatus::Closed,
            .identity = std::nullopt,
            .verdictSent = false,
        };
    }

    if (activeIndexForPacket(packetId) != pendingEntries_.size()) {
        ++counters_.duplicateAdmissions;
        return NfqueuePacketLeaseAdmission{
            .status = NfqueuePacketLeaseAdmissionStatus::DuplicatePacketId,
            .identity = std::nullopt,
            .verdictSent = false,
        };
    }

    const auto identity = makeIdentity(packetId);
    const auto freeEntry = std::find_if(
        pendingEntries_.begin(), pendingEntries_.end(),
        [](const PendingEntry &entry) { return !entry.active; });
    if (pending_ >= config_.pendingCapacity || freeEntry == pendingEntries_.end()) {
        return failOpenForCapacity(identity);
    }

    freeEntry->identity = identity;
    freeEntry->deadline = now + config_.completionTimeout;
    freeEntry->active = true;
    ++pending_;
    ++counters_.retained;
    counters_.highWatermark = std::max(counters_.highWatermark, pending_);
    return NfqueuePacketLeaseAdmission{
        .status = NfqueuePacketLeaseAdmissionStatus::Retained,
        .identity = identity,
        .verdictSent = false,
    };
}

NfqueuePacketLeaseCompletionStatus NfqueuePacketLeaseAdapter::complete(
    const NfqueuePacketLeaseIdentity &identity,
    const NfqueuePacketLeaseTerminalReason reason) noexcept {
    if (!validTerminalReason(reason)) {
        ++counters_.invalidCompletions;
        return NfqueuePacketLeaseCompletionStatus::InvalidOutcome;
    }

    if (const auto index = activeIndexForIdentity(identity); index.has_value()) {
        return terminalize(*index, reason)
            ? NfqueuePacketLeaseCompletionStatus::Completed
            : NfqueuePacketLeaseCompletionStatus::VerdictSendFailure;
    }

    const auto activeIndex = activeIndexForPacket(identity.packetId);
    if (activeIndex != pendingEntries_.size()) {
        const auto &active = pendingEntries_[activeIndex].identity;
        if (samePacketContext(active, identity)) {
            ++counters_.staleCompletions;
            return NfqueuePacketLeaseCompletionStatus::Stale;
        }
    }
    if (identityInHistory(identity)) {
        ++counters_.duplicateCompletions;
        return NfqueuePacketLeaseCompletionStatus::Duplicate;
    }
    ++counters_.missingCompletions;
    return NfqueuePacketLeaseCompletionStatus::Missing;
}

NfqueuePacketLeaseCompletionStatus NfqueuePacketLeaseAdapter::complete(
    const NfqueuePacketLeaseIdentity &identity,
    const Flow::PacketLeaseOutcome outcome) noexcept {
    switch (outcome) {
    case Flow::PacketLeaseOutcome::Accepted:
        return complete(identity, NfqueuePacketLeaseTerminalReason::Accepted);
    case Flow::PacketLeaseOutcome::Dropped:
        return complete(identity, NfqueuePacketLeaseTerminalReason::Dropped);
    case Flow::PacketLeaseOutcome::Open:
        ++counters_.invalidCompletions;
        return NfqueuePacketLeaseCompletionStatus::InvalidOutcome;
    }
    ++counters_.invalidCompletions;
    return NfqueuePacketLeaseCompletionStatus::InvalidOutcome;
}

std::size_t NfqueuePacketLeaseAdapter::expire(const TimePoint now) noexcept {
    if (closed_) {
        return 0;
    }
    std::size_t expired = 0;
    for (std::size_t index = 0; index < pendingEntries_.size(); ++index) {
        if (pendingEntries_[index].active && pendingEntries_[index].deadline <= now) {
            (void)terminalize(index, NfqueuePacketLeaseTerminalReason::Timeout);
            ++expired;
        }
    }
    return expired;
}

std::size_t NfqueuePacketLeaseAdapter::shutdown() noexcept {
    if (closed_) {
        return 0;
    }
    closed_ = true;
    std::size_t drained = 0;
    for (std::size_t index = 0; index < pendingEntries_.size(); ++index) {
        if (pendingEntries_[index].active) {
            (void)terminalize(index, NfqueuePacketLeaseTerminalReason::Shutdown);
            ++drained;
        }
    }
    return drained;
}

} // namespace SnortDatapath::Nfqueue
