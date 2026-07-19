/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookInstaller.hpp>

namespace SnortDatapath::Nfqueue {

namespace {

bool isIdempotentInstallFailure(const IptablesCommand &command) {
    return command.args.size() >= 2 && (command.args[1] == "-N" || command.args[1] == "-D");
}

bool isIdempotentCleanupFailure(const IptablesCommand &command) {
    return command.args.size() >= 2 && (command.args[1] == "-D" || command.args[1] == "-F" ||
                                        command.args[1] == "-X");
}

bool executeInstallPlan(const HookPlan &plan, HookCommandExecutor &executor) {
    bool ok = true;
    for (const auto &command : plan.commands) {
        const bool commandOk = executor.execute(command);
        if (!commandOk && !isIdempotentInstallFailure(command)) {
            ok = false;
        }
    }
    return ok;
}

bool executeCleanupPlan(const HookPlan &plan, HookCommandExecutor &executor) {
    bool ok = true;
    for (const auto &command : plan.commands) {
        const bool commandOk = executor.execute(command);
        if (!commandOk && !isIdempotentCleanupFailure(command)) {
            ok = false;
        }
    }
    return ok;
}

} // namespace

bool installIpv4PassThroughHooks(const HookPlanConfig &config, HookCommandExecutor &executor) {
    return executeInstallPlan(makeIpv4PassThroughHookPlan(config), executor);
}

bool installDualStackPassThroughHooks(const DualStackHookPlanConfig &config,
                                      HookCommandExecutor &executor) {
    return executeInstallPlan(makeDualStackPassThroughHookPlan(config), executor);
}

bool removeIpv4PassThroughHooks(const HookCleanupPlanConfig &config,
                                HookCommandExecutor &executor) {
    return executeCleanupPlan(makeIpv4PassThroughHookCleanupPlan(config), executor);
}

bool removeDualStackPassThroughHooks(const HookCleanupPlanConfig &config,
                                     HookCommandExecutor &executor) {
    return executeCleanupPlan(makeDualStackPassThroughHookCleanupPlan(config), executor);
}

} // namespace SnortDatapath::Nfqueue
