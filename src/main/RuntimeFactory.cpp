/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeFactory.hpp>

#include <NfqueuePassThroughRuntime.hpp>

#include <memory>

namespace SnortRuntime {

RuntimeFactoryResult createStartedRuntime(const RuntimeProfileSelection selection) {
    RuntimeFactoryResult result{
        .plan = planRuntimeFactory(selection),
        .runtime = nullptr,
    };
    if (!result.plan.launchable) {
        return result;
    }

    if (result.plan.action == RuntimeFactoryAction::CreateRootNfqueue) {
        auto runtime = std::make_unique<SnortDatapath::Nfqueue::DualStackPassThroughRuntime>();
        (void)runtime->start();
        result.runtime = std::move(runtime);
    }
    return result;
}

} // namespace SnortRuntime
