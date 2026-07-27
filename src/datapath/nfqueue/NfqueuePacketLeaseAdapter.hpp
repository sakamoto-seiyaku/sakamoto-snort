/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace SnortDatapath::Nfqueue {

/** The semantic reason for the one terminal outcome of an NFQUEUE packet. */
enum class NfqueuePacketLeaseTerminalReason : std::uint8_t {
    Accepted,
    Dropped,
    FailOpen,
    Timeout,
    Shutdown,
    Capacity,
};

/** The platform-neutral intent passed to the original queue completion lane. */
enum class NfqueuePacketLeaseVerdict : std::uint8_t {
    Drop = 0,
    Accept = 1,
};

/**
 * A packet ID is only meaningful within one queue instance.  The lane and
 * lease generations make an asynchronous completion safe across queue
 * recreation and packet-ID reuse.
 */
struct NfqueuePacketLeaseIdentity {
    std::uint32_t laneGeneration = 0;
    std::uint32_t queueNumber = 0;
    std::uint32_t packetId = 0;
    std::uint64_t generation = 0;

    friend bool operator==(const NfqueuePacketLeaseIdentity &,
                           const NfqueuePacketLeaseIdentity &) = default;
};

/** Pure C++ sink implemented by the owning NFQUEUE completion lane. */
class NfqueuePacketLeaseVerdictSink {
public:
    virtual ~NfqueuePacketLeaseVerdictSink() = default;

    /** Return false when the verdict intent could not be handed to the lane. */
    virtual bool sendVerdict(std::uint32_t packetId,
                             NfqueuePacketLeaseVerdict verdict) = 0;
};

using NfqueuePacketLeaseVerdictCallback =
    std::function<bool(std::uint32_t, NfqueuePacketLeaseVerdict)>;

enum class NfqueuePacketLeaseAdmissionStatus : std::uint8_t {
    Retained,
    CapacityFailOpen,
    DuplicatePacketId,
    Closed,
};

struct NfqueuePacketLeaseAdmission {
    NfqueuePacketLeaseAdmissionStatus status = NfqueuePacketLeaseAdmissionStatus::Closed;
    std::optional<NfqueuePacketLeaseIdentity> identity;
    bool verdictSent = false;
};

enum class NfqueuePacketLeaseCompletionStatus : std::uint8_t {
    Completed,
    Duplicate,
    Stale,
    Missing,
    InvalidOutcome,
    /** The lease is terminal, but the one verdict send attempt failed. */
    VerdictSendFailure,
};

struct NfqueuePacketLeaseCounters {
    std::uint64_t retained = 0;
    std::uint64_t accepted = 0;
    std::uint64_t dropped = 0;
    std::uint64_t failOpen = 0;
    std::uint64_t timeout = 0;
    std::uint64_t shutdown = 0;
    std::uint64_t capacity = 0;
    std::uint64_t duplicateCompletions = 0;
    std::uint64_t staleCompletions = 0;
    std::uint64_t missingCompletions = 0;
    std::uint64_t invalidCompletions = 0;
    std::uint64_t duplicateAdmissions = 0;
    std::uint64_t closedAdmissions = 0;
    /** Capacity rejects that were fail-opened without retaining a lease. */
    std::uint64_t capacityAdmissions = 0;
    /** Aggregate count across capacity and retained-lease terminal paths. */
    std::uint64_t verdictSendFailures = 0;
    /** Send failures while emitting a capacity fail-open verdict. */
    std::uint64_t admissionVerdictSendFailures = 0;
    /** Retained leases terminalized without a delivered verdict intent. */
    std::uint64_t completionFaults = 0;
    /** Subset of completionFaults caused by the verdict sink returning/failing. */
    std::uint64_t completionVerdictSendFailures = 0;
    std::size_t highWatermark = 0;
    std::size_t completionHighWatermark = 0;
};

struct NfqueuePacketLeaseAdapterConfig {
    std::size_t pendingCapacity = 64;
    std::uint32_t laneGeneration = 1;
    std::uint32_t queueNumber = 0;
    std::chrono::steady_clock::duration completionTimeout = std::chrono::seconds(5);
    /** Zero means the fixed completion history mirrors pendingCapacity. */
    std::size_t completionHistoryCapacity = 0;
};

/**
 * Lane-confined, fixed-capacity registry for asynchronous NFQUEUE packet
 * leases.
 *
 * The adapter owns no queue/socket handle and has no internal lock.  One
 * ingress/completion lane must serialize admit, complete, expire and
 * shutdown.  All vectors are sized by the constructor; terminal operations
 * do not allocate.  The sink must outlive this adapter because shutdown is
 * RAII-drained in the destructor.
 *
 * A terminal operation records the outcome and releases the pending slot
 * before returning.  It emits at most one verdict intent.  A sink failure is
 * counted and is not retried: a successful netlink write cannot be promoted
 * to end-to-end kernel acknowledgement, so retrying here would risk a
 * duplicate verdict.
 */
class NfqueuePacketLeaseAdapter final {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    NfqueuePacketLeaseAdapter(NfqueuePacketLeaseAdapterConfig config,
                              NfqueuePacketLeaseVerdictSink &sink);
    NfqueuePacketLeaseAdapter(NfqueuePacketLeaseAdapterConfig config,
                              NfqueuePacketLeaseVerdictCallback callback);
    ~NfqueuePacketLeaseAdapter();

    NfqueuePacketLeaseAdapter(const NfqueuePacketLeaseAdapter &) = delete;
    NfqueuePacketLeaseAdapter &operator=(const NfqueuePacketLeaseAdapter &) = delete;
    NfqueuePacketLeaseAdapter(NfqueuePacketLeaseAdapter &&) = delete;
    NfqueuePacketLeaseAdapter &operator=(NfqueuePacketLeaseAdapter &&) = delete;

    /** Admit a packet using the adapter's monotonic clock. */
    [[nodiscard]] NfqueuePacketLeaseAdmission admit(std::uint32_t packetId) noexcept;

    /**
     * Admit with an injected time point, allowing deterministic deadline
     * tests and a single lane clock source.
     */
    [[nodiscard]] NfqueuePacketLeaseAdmission admit(std::uint32_t packetId,
                                                    TimePoint now) noexcept;

    /** Complete one retained identity, or suppress an invalid/stale repeat. */
    [[nodiscard]] NfqueuePacketLeaseCompletionStatus complete(
        const NfqueuePacketLeaseIdentity &identity,
        NfqueuePacketLeaseTerminalReason reason) noexcept;

    /** Convenience bridge for the shared Flow::PacketLease terminal vocabulary. */
    [[nodiscard]] NfqueuePacketLeaseCompletionStatus complete(
        const NfqueuePacketLeaseIdentity &identity,
        Flow::PacketLeaseOutcome outcome) noexcept;

    /** Complete every deadline-expired lease with a DROP timeout outcome. */
    [[nodiscard]] std::size_t expire(TimePoint now) noexcept;

    /**
     * Stop admission, complete every remaining lease with DROP/shutdown, and
     * return the number drained.  Repeated calls are no-ops.
     */
    [[nodiscard]] std::size_t shutdown() noexcept;

    [[nodiscard]] bool isClosed() const noexcept { return closed_; }
    [[nodiscard]] std::size_t pending() const noexcept { return pending_; }
    [[nodiscard]] std::size_t pendingCapacity() const noexcept {
        return config_.pendingCapacity;
    }
    /** Capacity of the fixed terminal-completion history buffer. */
    [[nodiscard]] std::size_t completionCapacity() const noexcept {
        return config_.completionHistoryCapacity;
    }
    /** The pending registry is the bounded ingress buffer for this adapter. */
    [[nodiscard]] std::size_t bufferCapacity() const noexcept {
        return config_.pendingCapacity;
    }
    [[nodiscard]] std::size_t highWatermark() const noexcept {
        return counters_.highWatermark;
    }
    [[nodiscard]] std::size_t pendingHighWatermark() const noexcept {
        return counters_.highWatermark;
    }
    [[nodiscard]] std::size_t completionHighWatermark() const noexcept {
        return counters_.completionHighWatermark;
    }
    [[nodiscard]] std::size_t bufferHighWatermark() const noexcept {
        return counters_.highWatermark;
    }
    [[nodiscard]] std::size_t completionRecords() const noexcept {
        return historySize_;
    }
    [[nodiscard]] const NfqueuePacketLeaseCounters &counters() const noexcept {
        return counters_;
    }

private:
    struct PendingEntry {
        NfqueuePacketLeaseIdentity identity;
        TimePoint deadline{};
        bool active = false;
    };

    struct TerminalRecord {
        NfqueuePacketLeaseIdentity identity;
        NfqueuePacketLeaseTerminalReason reason = NfqueuePacketLeaseTerminalReason::Dropped;
        bool valid = false;
    };

    NfqueuePacketLeaseAdapterConfig config_;
    std::optional<std::reference_wrapper<NfqueuePacketLeaseVerdictSink>> sink_;
    NfqueuePacketLeaseVerdictCallback callback_;
    std::vector<PendingEntry> pendingEntries_;
    std::vector<TerminalRecord> terminalHistory_;
    std::uint64_t nextGeneration_ = 1;
    std::size_t pending_ = 0;
    std::size_t historySize_ = 0;
    std::size_t historyCursor_ = 0;
    bool closed_ = false;
    NfqueuePacketLeaseCounters counters_;

    [[nodiscard]] NfqueuePacketLeaseIdentity makeIdentity(std::uint32_t packetId) noexcept;
    [[nodiscard]] bool identityInHistory(
        const NfqueuePacketLeaseIdentity &identity) const noexcept;
    [[nodiscard]] std::size_t activeIndexForPacket(std::uint32_t packetId) const noexcept;
    [[nodiscard]] std::optional<std::size_t> activeIndexForIdentity(
        const NfqueuePacketLeaseIdentity &identity) const noexcept;
    [[nodiscard]] bool sendVerdict(std::uint32_t packetId,
                                   NfqueuePacketLeaseVerdict verdict) noexcept;
    [[nodiscard]] NfqueuePacketLeaseAdmission failOpenForCapacity(
        const NfqueuePacketLeaseIdentity &identity) noexcept;
    [[nodiscard]] bool recordTerminal(const NfqueuePacketLeaseIdentity &identity,
                                      NfqueuePacketLeaseTerminalReason reason) noexcept;
    void rememberTerminal(const NfqueuePacketLeaseIdentity &identity,
                          NfqueuePacketLeaseTerminalReason reason) noexcept;
    void countTerminal(NfqueuePacketLeaseTerminalReason reason) noexcept;
    [[nodiscard]] bool terminalize(std::size_t index,
                                   NfqueuePacketLeaseTerminalReason reason) noexcept;
};

} // namespace SnortDatapath::Nfqueue
