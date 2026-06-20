/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueHookPlan.hpp>

namespace SnortDatapath::Nfqueue {

class HookCommandExecutor {
public:
    virtual ~HookCommandExecutor() = default;

    virtual bool execute(const IptablesCommand &command) = 0;
};

[[nodiscard]] bool installIpv4PassThroughHooks(const HookPlanConfig &config,
                                               HookCommandExecutor &executor);
[[nodiscard]] bool installDualStackPassThroughHooks(const DualStackHookPlanConfig &config,
                                                    HookCommandExecutor &executor);

} // namespace SnortDatapath::Nfqueue
