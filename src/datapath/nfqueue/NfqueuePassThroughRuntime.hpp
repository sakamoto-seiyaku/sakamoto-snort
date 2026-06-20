/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueHookPlan.hpp>
#include <NfqueueTopology.hpp>

#include <cstddef>
#include <cstdint>
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

struct DualStackPassThroughRuntimeConfig {
    std::string inputChain = "sucre-snort_INPUT";
    std::string outputChain = "sucre-snort_OUTPUT";
    NfqueueTopology topology = NfqueueTopology::SplitInOut;
    std::uint32_t firstQueue = 0;
    std::uint32_t queuesPerFamily = 4;
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

class DualStackPassThroughRuntime {
public:
    explicit DualStackPassThroughRuntime(DualStackPassThroughRuntimeConfig config = {});
    ~DualStackPassThroughRuntime();

    [[nodiscard]] bool start();

private:
    DualStackPassThroughRuntimeConfig config_;
    PassThroughWorkerGroup workers_;
};

struct Ipv4PassThroughRuntimeConfig {
    std::string inputChain = "sucre-snort_INPUT";
    std::string outputChain = "sucre-snort_OUTPUT";
    NfqueueTopology topology = NfqueueTopology::SplitInOut;
    std::uint32_t firstQueue = 0;
    std::uint32_t queueCount = 4;
};

class Ipv4PassThroughRuntime {
public:
    explicit Ipv4PassThroughRuntime(Ipv4PassThroughRuntimeConfig config = {});
    ~Ipv4PassThroughRuntime();

    [[nodiscard]] bool start();

private:
    Ipv4PassThroughRuntimeConfig config_;
    PassThroughWorkerGroup workers_;
};

} // namespace SnortDatapath::Nfqueue
