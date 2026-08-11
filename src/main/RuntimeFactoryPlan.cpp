/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeFactoryPlan.hpp>

namespace SnortRuntime {

RuntimeFactoryPlan planRuntimeFactory(const RuntimeProfileSelection selection) noexcept {
    return planRuntimeFactory(selection, {});
}

RuntimeFactoryPlan planRuntimeFactory(const RuntimeProfileSelection selection,
                                      const std::string_view vpnTunFdSource) noexcept {
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
        (void)vpnTunFdSource;
        return RuntimeFactoryPlan{
            .action = RuntimeFactoryAction::CreateVpnTunFdHandoff,
            .launchable = true,
            .exitCode = 0,
            .errorCode = {},
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
