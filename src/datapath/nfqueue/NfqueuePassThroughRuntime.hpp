/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueHookPlan.hpp>
#include <NfqueueTopology.hpp>

#include <cstdint>
#include <string>
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

    [[nodiscard]] bool start();

private:
    DualStackPassThroughRuntimeConfig config_;
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

    [[nodiscard]] bool start();

private:
    Ipv4PassThroughRuntimeConfig config_;
};

} // namespace SnortDatapath::Nfqueue
