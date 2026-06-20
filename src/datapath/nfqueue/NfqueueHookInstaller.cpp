/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookInstaller.hpp>

namespace SnortDatapath::Nfqueue {

bool installIpv4PassThroughHooks(const HookPlanConfig &config, HookCommandExecutor &executor) {
    bool ok = true;
    const auto plan = makeIpv4PassThroughHookPlan(config);
    for (const auto &command : plan.commands) {
        ok = executor.execute(command) && ok;
    }
    return ok;
}

} // namespace SnortDatapath::Nfqueue
