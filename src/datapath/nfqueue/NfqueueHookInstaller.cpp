/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookInstaller.hpp>

namespace SnortDatapath::Nfqueue {

namespace {

bool executePlan(const HookPlan &plan, HookCommandExecutor &executor) {
    bool ok = true;
    for (const auto &command : plan.commands) {
        ok = executor.execute(command) && ok;
    }
    return ok;
}

} // namespace

bool installIpv4PassThroughHooks(const HookPlanConfig &config, HookCommandExecutor &executor) {
    return executePlan(makeIpv4PassThroughHookPlan(config), executor);
}

bool installDualStackPassThroughHooks(const DualStackHookPlanConfig &config,
                                      HookCommandExecutor &executor) {
    return executePlan(makeDualStackPassThroughHookPlan(config), executor);
}

} // namespace SnortDatapath::Nfqueue
