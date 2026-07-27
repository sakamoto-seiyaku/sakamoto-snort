/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueHookPlan.hpp>
#include <NfqueueTopology.hpp>
#include <RuntimeControl.hpp>
#include <FlowSteering.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
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
    FailOpenParse,
    FailOpenCapacity,
    FailOpenOwnerFault,
};

struct NfqueueFlowAdapterCounters {
    std::uint64_t packetsSeen = 0;
    std::uint64_t normalizedPackets = 0;
    std::uint64_t acceptedPackets = 0;
    std::uint64_t parsePassThroughPackets = 0;
    std::uint64_t fragmentPassThroughPackets = 0;
    std::uint64_t capacityPassThroughPackets = 0;
    std::uint64_t ownerFaultPassThroughPackets = 0;
    std::uint64_t verdictSendFailures = 0;
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
        std::uint32_t originalLengthHint = 0) noexcept;
    void recordVerdictSendFailure() noexcept;

    [[nodiscard]] NfqueueFlowAdapterCounters counters() const noexcept;
    [[nodiscard]] std::uint32_t copyPrefixBytes() const noexcept {
        return config_.copyPrefixBytes;
    }
    [[nodiscard]] std::size_t queueCapacity() const noexcept {
        return config_.queueCapacity;
    }

private:
    NfqueueFlowAdapterConfig config_;
    Flow::FlowSteeringRuntime steering_;
    mutable std::mutex mutex_;
    NfqueueFlowAdapterCounters counters_;
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
    [[nodiscard]] NfqueueFlowAdapterCounters flowAdapterCounters() const noexcept {
        return flowAdapter_.counters();
    }

private:
    DualStackPassThroughRuntimeConfig config_;
    NfqueueFlowAdapter flowAdapter_;
    PassThroughWorkerGroup workers_;
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

private:
    Ipv4PassThroughRuntimeConfig config_;
    NfqueueFlowAdapter flowAdapter_;
    PassThroughWorkerGroup workers_;
};

} // namespace SnortDatapath::Nfqueue
