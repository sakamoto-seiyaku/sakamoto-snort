/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookInstaller.hpp>

namespace SnortDatapath::Nfqueue {

namespace {

bool isIdempotentSetupOrCleanup(const IptablesCommand &command) {
    return command.args.size() >= 2 && (command.args[1] == "-N" || command.args[1] == "-D");
}

bool executePlan(const HookPlan &plan, HookCommandExecutor &executor) {
    bool ok = true;
    for (const auto &command : plan.commands) {
        const bool commandOk = executor.execute(command);
        if (!commandOk && !isIdempotentSetupOrCleanup(command)) {
            ok = false;
        }
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
