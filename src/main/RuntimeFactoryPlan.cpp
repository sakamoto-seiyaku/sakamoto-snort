/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeFactoryPlan.hpp>

namespace SnortRuntime {

RuntimeFactoryPlan planRuntimeFactory(const RuntimeProfileSelection selection) noexcept {
    if (!selection.ok) {
        return RuntimeFactoryPlan{
            .action = RuntimeFactoryAction::RejectProfile,
            .launchable = false,
            .exitCode = 2,
            .errorCode = selection.errorCode,
            .adapterName = {},
        };
    }

    if (selection.profile == RuntimeProfile::Vpn) {
        return RuntimeFactoryPlan{
            .action = RuntimeFactoryAction::RejectVpnUnavailable,
            .launchable = false,
            .exitCode = 3,
            .errorCode = "vpn_adapter_unavailable",
            .adapterName = "vpn-tun-hev",
        };
    }

    return RuntimeFactoryPlan{
        .action = RuntimeFactoryAction::CreateRootNfqueue,
        .launchable = true,
        .exitCode = 0,
        .errorCode = {},
        .adapterName = "root-nfqueue",
    };
}

} // namespace SnortRuntime
