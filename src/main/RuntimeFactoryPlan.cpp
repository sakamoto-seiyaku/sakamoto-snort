/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeFactoryPlan.hpp>

namespace SnortRuntime {

RuntimeFactoryPlan planRuntimeFactory(const RuntimeProfileSelection selection) noexcept {
    return planRuntimeFactory(selection, RuntimeFactoryOptions{});
}

RuntimeFactoryPlan planRuntimeFactory(const RuntimeProfileSelection selection,
                                      const std::string_view vpnTunFdSource) noexcept {
    return planRuntimeFactory(
        selection,
        RuntimeFactoryOptions{.vpnTunFdSource = vpnTunFdSource});
}

RuntimeFactoryPlan planRuntimeFactory(const RuntimeProfileSelection selection,
                                      const RuntimeFactoryOptions options) noexcept {
    if (!selection.ok) {
        return RuntimeFactoryPlan{
            .action = RuntimeFactoryAction::RejectProfile,
            .launchable = false,
            .exitCode = 2,
            .errorCode = selection.errorCode,
            .adapterName = {},
            .vpnFlowStackBackend = VpnFlowStackRuntimeBackend::None,
            .usingCompatibilityFallback = false,
        };
    }

    if (selection.profile == RuntimeProfile::Vpn) {
        if (options.preferredVpnFlowStackBackend
                == VpnFlowStackRuntimeBackend::HevLwipFacade
            && options.vpnHevLwipDriverAvailable) {
            return RuntimeFactoryPlan{
                .action = RuntimeFactoryAction::CreateVpnTunHevLwip,
                .launchable = true,
                .exitCode = 0,
                .errorCode = {},
                .adapterName = "vpn-tun-hev-lwip",
                .vpnFlowStackBackend =
                    VpnFlowStackRuntimeBackend::HevLwipFacade,
                .usingCompatibilityFallback = false,
            };
        }

        (void)options.vpnTunFdSource;
        return RuntimeFactoryPlan{
            .action = RuntimeFactoryAction::CreateVpnTunFdHandoff,
            .launchable = true,
            .exitCode = 0,
            .errorCode = {},
            .adapterName = "vpn-tun-fd-compat",
            .vpnFlowStackBackend = VpnFlowStackRuntimeBackend::FdCompatibility,
            .usingCompatibilityFallback =
                options.preferredVpnFlowStackBackend
                == VpnFlowStackRuntimeBackend::HevLwipFacade,
        };
    }

    return RuntimeFactoryPlan{
        .action = RuntimeFactoryAction::CreateRootNfqueue,
        .launchable = true,
        .exitCode = 0,
        .errorCode = {},
        .adapterName = "root-nfqueue",
        .vpnFlowStackBackend = VpnFlowStackRuntimeBackend::None,
        .usingCompatibilityFallback = false,
    };
}

} // namespace SnortRuntime
