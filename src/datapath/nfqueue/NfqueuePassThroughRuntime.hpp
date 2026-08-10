/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueHookPlan.hpp>
#include <NfqueueFragmentLeaseBook.hpp>
#include <NfqueuePacketLeaseAdapter.hpp>
#include <NfqueueTopology.hpp>
#include <PacketPolicy.hpp>
#include <RuntimeControl.hpp>
#include <FlowGraphFragmentIngress.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace SnortDatapath::Nfqueue {

enum class NfqueueAddressFamily : std::uint8_t {
    Ipv4 = 0,
    Ipv6 = 1,
};

struct PassThroughListenerPlan {
    NfqueueAddressFamily family = NfqueueAddressFamily::Ipv4;
    std::uint32_t queue = 0;

    friend bool operator==(const PassThroughListenerPlan &, const PassThroughListenerPlan &) =
        default;
};

struct NfqueueFlowAdapterConfig {
    std::uint32_t workerCount = 2;
    std::uint64_t hashSeed = 0;
    std::size_t queueCapacity = 64;
    std::uint32_t copyPrefixBytes = 512;
    const Policy::PacketPolicySnapshot *packetPolicy = nullptr;
    Flow::FragmentSteeringConfig fragmentSteering;
    std::size_t fragmentLeaseCapacityPerDatagram = 64;
};

/** Origin lane for a retained fragment packet lease. */
struct NfqueueFragmentLeaseContext final {
    std::optional<NfqueuePacketLeaseIdentity> identity;
    NfqueueFragmentLeaseCompletionMailbox *mailbox = nullptr;
    bool *routed = nullptr;

    [[nodiscard]] bool valid() const noexcept {
        return identity.has_value() && mailbox != nullptr;
    }

    void markRouted() const noexcept {
        if (routed != nullptr) {
            *routed = true;
        }
    }
};

struct NfqueuePacketMetadata final {
    std::uint32_t linuxUid = 0;
    std::uint32_t inputInterfaceIndex = 0;
    std::uint32_t outputInterfaceIndex = 0;
    std::uint32_t networkContext = 0;
};

struct DualStackPassThroughRuntimeConfig {
    std::string inputChain = "sucre-snort_INPUT";
    std::string outputChain = "sucre-snort_OUTPUT";
    NfqueueTopology topology = NfqueueTopology::SplitInOut;
    std::uint32_t firstQueue = 0;
    std::uint32_t queuesPerFamily = 4;
    NfqueueFlowAdapterConfig flowAdapter;
};

enum class NfqueueFlowAdapterResult : std::uint8_t {
    FlowAccepted,
    FlowDropped,
    FailOpenParse,
    FailOpenCapacity,
    FailOpenOwnerFault,
    FragmentBuffered,
    FragmentDuplicate,
    FragmentTimeout,
    FragmentMalformed,
    FragmentConflict,
    FragmentCapacity,
};

struct NfqueueFlowAdapterCounters {
    std::uint64_t packetsSeen = 0;
    std::uint64_t normalizedPackets = 0;
    std::uint64_t acceptedPackets = 0;
    std::uint64_t droppedPackets = 0;
    std::uint64_t parsePassThroughPackets = 0;
    std::uint64_t fragmentPassThroughPackets = 0;
    std::uint64_t capacityPassThroughPackets = 0;
    std::uint64_t ownerFaultPassThroughPackets = 0;
    std::uint64_t verdictSendFailures = 0;
    std::uint64_t directPackets = 0;
    std::uint64_t parseDrops = 0;
    std::uint64_t capacityDrops = 0;
    std::uint64_t normalWorkerHandoffs = 0;
    std::uint64_t ownerGuardPasses = 0;
    std::uint64_t ownerGuardMismatches = 0;
    std::uint64_t correctiveHandoffs = 0;
    std::uint64_t secondMismatchDrops = 0;
    std::uint64_t fragmentBufferedPackets = 0;
    std::uint64_t fragmentDuplicatePackets = 0;
    std::uint64_t fragmentReassembledPackets = 0;
    std::uint64_t fragmentMalformedPackets = 0;
    std::uint64_t fragmentConflictPackets = 0;
    std::uint64_t fragmentTimeoutPackets = 0;
    std::uint64_t fragmentCapacityPackets = 0;
    std::uint64_t fragmentOwnerMetadataPackets = 0;
};

[[nodiscard]] inline NfqueuePacketLeaseTerminalReason terminalReasonFor(
    const NfqueueFlowAdapterResult result) noexcept {
    switch (result) {
    case NfqueueFlowAdapterResult::FlowAccepted:
        return NfqueuePacketLeaseTerminalReason::Accepted;
    case NfqueueFlowAdapterResult::FlowDropped:
        return NfqueuePacketLeaseTerminalReason::Dropped;
    case NfqueueFlowAdapterResult::FailOpenParse:
    case NfqueueFlowAdapterResult::FailOpenCapacity:
    case NfqueueFlowAdapterResult::FailOpenOwnerFault:
    case NfqueueFlowAdapterResult::FragmentBuffered:
    case NfqueueFlowAdapterResult::FragmentDuplicate:
    case NfqueueFlowAdapterResult::FragmentTimeout:
    case NfqueueFlowAdapterResult::FragmentMalformed:
    case NfqueueFlowAdapterResult::FragmentConflict:
    case NfqueueFlowAdapterResult::FragmentCapacity:
        return NfqueuePacketLeaseTerminalReason::FailOpen;
    }
    return NfqueuePacketLeaseTerminalReason::FailOpen;
}

struct NfqueueRuntimeFaultSnapshot final {
    std::uint64_t listenerOpenFailures = 0;
    std::uint64_t listenerBindFailures = 0;
    std::uint64_t queueConfigFailures = 0;
    std::uint64_t packetParseFailures = 0;
    std::uint64_t missingPacketHeaders = 0;
    std::uint64_t receiveFailures = 0;
    std::uint64_t callbackFailures = 0;
};

/** Runtime I/O faults are kept separate from policy and flow-gate counters. */
class NfqueueRuntimeFaultCounters final {
public:
    void recordListenerOpenFailure() noexcept { ++listenerOpenFailures_; }
    void recordListenerBindFailure() noexcept { ++listenerBindFailures_; }
    void recordQueueConfigFailure() noexcept { ++queueConfigFailures_; }
    void recordPacketParseFailure() noexcept { ++packetParseFailures_; }
    void recordMissingPacketHeader() noexcept { ++missingPacketHeaders_; }
    void recordReceiveFailure() noexcept { ++receiveFailures_; }
    void recordCallbackFailure() noexcept { ++callbackFailures_; }

    [[nodiscard]] NfqueueRuntimeFaultSnapshot snapshot() const noexcept {
        return {
            .listenerOpenFailures = listenerOpenFailures_.load(std::memory_order_relaxed),
            .listenerBindFailures = listenerBindFailures_.load(std::memory_order_relaxed),
            .queueConfigFailures = queueConfigFailures_.load(std::memory_order_relaxed),
            .packetParseFailures = packetParseFailures_.load(std::memory_order_relaxed),
            .missingPacketHeaders = missingPacketHeaders_.load(std::memory_order_relaxed),
            .receiveFailures = receiveFailures_.load(std::memory_order_relaxed),
            .callbackFailures = callbackFailures_.load(std::memory_order_relaxed),
        };
    }

private:
    std::atomic<std::uint64_t> listenerOpenFailures_{0};
    std::atomic<std::uint64_t> listenerBindFailures_{0};
    std::atomic<std::uint64_t> queueConfigFailures_{0};
    std::atomic<std::uint64_t> packetParseFailures_{0};
    std::atomic<std::uint64_t> missingPacketHeaders_{0};
    std::atomic<std::uint64_t> receiveFailures_{0};
    std::atomic<std::uint64_t> callbackFailures_{0};
};

/**
 * Root/NFQUEUE's synchronous graph-injection gate.
 *
 * Payload bytes are normalized, directly queued to the selected owner,
 * guarded, completed, and only then does the caller emit the ACCEPT verdict.
 * The mutex keeps descriptor handles valid while multiple NFQUEUE listeners
 * share this first production gate.
 */
class NfqueueFlowAdapter final {
public:
    explicit NfqueueFlowAdapter(NfqueueFlowAdapterConfig config = {});
    ~NfqueueFlowAdapter() = default;

    NfqueueFlowAdapter(const NfqueueFlowAdapter &) = delete;
    NfqueueFlowAdapter &operator=(const NfqueueFlowAdapter &) = delete;
    NfqueueFlowAdapter(NfqueueFlowAdapter &&) = delete;
    NfqueueFlowAdapter &operator=(NfqueueFlowAdapter &&) = delete;

    [[nodiscard]] NfqueueFlowAdapterResult process(
        std::uint32_t captureQueue, std::uint8_t hook,
        std::span<const std::uint8_t> payload,
        std::uint32_t originalLengthHint = 0,
        NfqueuePacketMetadata metadata = {},
        NfqueueFragmentLeaseContext leaseContext = {}) noexcept;
    /** Expire with one shared monotonic clock; non-zero is a deterministic test advance. */
    void expireFragments(std::uint64_t testAdvanceMilliseconds = 0) noexcept;
    void detachFragmentLeaseMailbox(
        NfqueueFragmentLeaseCompletionMailbox &mailbox) noexcept;
    void recordVerdictSendFailure() noexcept;

    [[nodiscard]] NfqueueFlowAdapterCounters counters() const noexcept;
    [[nodiscard]] std::uint32_t copyPrefixBytes() const noexcept {
        return config_.copyPrefixBytes;
    }
    [[nodiscard]] std::size_t queueCapacity() const noexcept {
        return config_.queueCapacity;
    }
    [[nodiscard]] std::size_t fragmentLeaseMailboxCapacity() const noexcept {
        return config_.fragmentSteering.maxDatagrams
            * config_.fragmentLeaseCapacityPerDatagram;
    }

private:
    NfqueueFlowAdapterConfig config_;
    Flow::FlowSteeringRuntime steering_;
    Flow::FlowGraphFragmentIngress graphIngress_;
    NfqueueFragmentLeaseBook fragmentLeaseBook_;
    std::chrono::steady_clock::time_point fragmentEpoch_ =
        std::chrono::steady_clock::now();
    std::uint64_t fragmentTick_ = 0;
    mutable std::mutex mutex_;
    NfqueueFlowAdapterCounters counters_;

    [[nodiscard]] std::uint64_t monotonicFragmentNow() noexcept;
};

struct DualStackPassThroughRuntimePlan {
    DualStackHookPlanConfig hookPlan;
    std::vector<PassThroughListenerPlan> listeners;
};

class PassThroughWorkerGroup {
public:
    PassThroughWorkerGroup() = default;
    ~PassThroughWorkerGroup() { join(); }

    PassThroughWorkerGroup(const PassThroughWorkerGroup &) = delete;
    PassThroughWorkerGroup &operator=(const PassThroughWorkerGroup &) = delete;
    PassThroughWorkerGroup(PassThroughWorkerGroup &&) = delete;
    PassThroughWorkerGroup &operator=(PassThroughWorkerGroup &&) = delete;

    template <typename Worker> void start(Worker &&worker) {
        workers_.emplace_back(std::forward<Worker>(worker));
    }

    void join() {
        for (auto &worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
    }

    [[nodiscard]] std::size_t workerCount() const noexcept { return workers_.size(); }

private:
    std::vector<std::thread> workers_;
};

[[nodiscard]] inline DualStackPassThroughRuntimePlan makeDualStackPassThroughRuntimePlan(
    const DualStackPassThroughRuntimeConfig &config) {
    DualStackPassThroughRuntimePlan plan{
        .hookPlan = {.inputChain = config.inputChain,
                     .outputChain = config.outputChain,
                     .topology = config.topology,
                     .ipv4FirstQueue = config.firstQueue,
                     .ipv6FirstQueue = config.firstQueue + config.queuesPerFamily,
                     .queuesPerFamily = config.queuesPerFamily},
        .listeners = {},
    };

    plan.listeners.reserve(config.queuesPerFamily * 2);
    for (std::uint32_t i = 0; i < config.queuesPerFamily; ++i) {
        plan.listeners.push_back(PassThroughListenerPlan{
            .family = NfqueueAddressFamily::Ipv4,
            .queue = config.firstQueue + i,
        });
    }
    for (std::uint32_t i = 0; i < config.queuesPerFamily; ++i) {
        plan.listeners.push_back(PassThroughListenerPlan{
            .family = NfqueueAddressFamily::Ipv6,
            .queue = config.firstQueue + config.queuesPerFamily + i,
        });
    }
    return plan;
}

class DualStackPassThroughRuntime final : public SnortRuntime::BaseRuntimeControl {
public:
    explicit DualStackPassThroughRuntime(DualStackPassThroughRuntimeConfig config = {});
    ~DualStackPassThroughRuntime();

    [[nodiscard]] bool start();
    [[nodiscard]] bool nfqueuePassThroughReady() const noexcept override;
    [[nodiscard]] bool resetBaseRuntime() noexcept override;
    [[nodiscard]] bool packetPolicyControlReady() const noexcept override;
    [[nodiscard]] Policy::PacketPolicySnapshotStatus
    packetPolicyStatus() const noexcept override;
    [[nodiscard]] Policy::PacketPolicyDecision evaluatePacketPolicy(
        const Flow::PacketFacts &facts) const noexcept override;
    [[nodiscard]] bool applyPacketPolicy(
        std::vector<Policy::PacketPolicySubjectView> subjects,
        std::uint64_t revision) noexcept override;
    [[nodiscard]] bool nfqueueRuntimeCountersReady() const noexcept override {
        return true;
    }
    [[nodiscard]] SnortRuntime::NfqueueRuntimeCounters
    nfqueueRuntimeCounters() const noexcept override {
        const auto counters = flowAdapterCounters();
        return {
            .packetsSeen = counters.packetsSeen,
            .acceptedPackets = counters.acceptedPackets,
            .droppedPackets = counters.droppedPackets,
            .parsePassThroughPackets = counters.parsePassThroughPackets,
            .capacityPassThroughPackets = counters.capacityPassThroughPackets,
            .ownerFaultPassThroughPackets = counters.ownerFaultPassThroughPackets,
            .verdictSendFailures = counters.verdictSendFailures,
            .fragmentBufferedPackets = counters.fragmentBufferedPackets,
            .fragmentReassembledPackets = counters.fragmentReassembledPackets,
        };
    }
    [[nodiscard]] NfqueueFlowAdapterCounters flowAdapterCounters() const noexcept {
        return flowAdapter_.counters();
    }
    [[nodiscard]] NfqueueRuntimeFaultSnapshot runtimeFaultCounters() const noexcept {
        return runtimeFaults_.snapshot();
    }

private:
    DualStackPassThroughRuntimeConfig config_;
    Policy::RuntimePacketPolicySnapshot packetPolicy_;
    NfqueueFlowAdapter flowAdapter_;
    PassThroughWorkerGroup workers_;
    NfqueueRuntimeFaultCounters runtimeFaults_;
    std::atomic_bool ready_{false};
};

struct Ipv4PassThroughRuntimeConfig {
    std::string inputChain = "sucre-snort_INPUT";
    std::string outputChain = "sucre-snort_OUTPUT";
    NfqueueTopology topology = NfqueueTopology::SplitInOut;
    std::uint32_t firstQueue = 0;
    std::uint32_t queueCount = 4;
    NfqueueFlowAdapterConfig flowAdapter;
};

class Ipv4PassThroughRuntime {
public:
    explicit Ipv4PassThroughRuntime(Ipv4PassThroughRuntimeConfig config = {});
    ~Ipv4PassThroughRuntime();

    [[nodiscard]] bool start();
    [[nodiscard]] NfqueueFlowAdapterCounters flowAdapterCounters() const noexcept {
        return flowAdapter_.counters();
    }
    [[nodiscard]] NfqueueRuntimeFaultSnapshot runtimeFaultCounters() const noexcept {
        return runtimeFaults_.snapshot();
    }

private:
    Ipv4PassThroughRuntimeConfig config_;
    NfqueueFlowAdapter flowAdapter_;
    PassThroughWorkerGroup workers_;
    NfqueueRuntimeFaultCounters runtimeFaults_;
};

} // namespace SnortDatapath::Nfqueue
