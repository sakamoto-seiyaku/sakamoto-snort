/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueTopology.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace SnortDatapath::Nfqueue {

struct IptablesCommand {
    std::string executable;
    std::vector<std::string> args;

    friend bool operator==(const IptablesCommand &, const IptablesCommand &) = default;
};

struct HookPlan {
    std::vector<IptablesCommand> commands;
};

struct HookPlanConfig {
    std::string inputChain;
    std::string outputChain;
    NfqueueQueuePlan queuePlan;
};

struct DualStackHookPlanConfig {
    std::string inputChain;
    std::string outputChain;
    NfqueueTopology topology = NfqueueTopology::SplitInOut;
    std::uint32_t ipv4FirstQueue = 0;
    std::uint32_t ipv6FirstQueue = 0;
    std::uint32_t queuesPerFamily = 0;
};

[[nodiscard]] HookPlan makeIpv4PassThroughHookPlan(const HookPlanConfig &config);
[[nodiscard]] HookPlan makeDualStackPassThroughHookPlan(const DualStackHookPlanConfig &config);

} // namespace SnortDatapath::Nfqueue
