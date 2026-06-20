/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueTopology.hpp>

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

[[nodiscard]] HookPlan makeIpv4PassThroughHookPlan(const HookPlanConfig &config);

} // namespace SnortDatapath::Nfqueue
