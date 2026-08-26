/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeFactory.hpp>

#include <NfqueuePassThroughRuntime.hpp>
#include <VpnHevLwipFlowStack.hpp>
#include <VpnTunFdRuntime.hpp>

#include <memory>
#include <string_view>

namespace SnortRuntime {

RuntimeFactoryResult createStartedRuntime(const RuntimeProfileSelection selection) {
    return createStartedRuntime(selection, RuntimeFactoryStartOptions{});
}

RuntimeFactoryResult createStartedRuntime(const RuntimeProfileSelection selection,
                                          const char *const vpnTunFdSource) {
    return createStartedRuntime(
        selection,
        RuntimeFactoryStartOptions{
            .vpnTunFdSource = vpnTunFdSource == nullptr
                ? std::string_view{}
                : std::string_view{vpnTunFdSource},
        });
}

RuntimeFactoryResult createStartedRuntime(
    const RuntimeProfileSelection selection,
    const RuntimeFactoryStartOptions options) {
    RuntimeFactoryResult result{
        .plan = planRuntimeFactory(
            selection,
            RuntimeFactoryOptions{
                .vpnTunFdSource = options.vpnTunFdSource,
                .preferredVpnFlowStackBackend =
                    options.preferredVpnFlowStackBackend,
                .vpnHevLwipDriverAvailable =
                    options.vpnHevLwipDriver != nullptr,
            }),
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
    if (result.plan.action == RuntimeFactoryAction::CreateVpnTunFdHandoff
        || result.plan.action == RuntimeFactoryAction::CreateVpnTunHevLwip) {
        int tunFd = -1;
        if (!options.vpnTunFdSource.empty()) {
            tunFd = SnortDatapath::Tun::openVpnTunFdSource(
                options.vpnTunFdSource);
        }
        if (!options.vpnTunFdSource.empty() && tunFd < 0) {
            result.plan.launchable = false;
            result.plan.exitCode = 3;
            result.plan.errorCode = "vpn_tun_fd_open_failed";
            return result;
        }

        std::unique_ptr<SnortDatapath::Tun::VpnTunFdRuntime> runtime;
        if (result.plan.action == RuntimeFactoryAction::CreateVpnTunHevLwip) {
            if (options.vpnHevLwipDriver == nullptr) {
                result.plan.launchable = false;
                result.plan.exitCode = 4;
                result.plan.errorCode = "vpn_hev_lwip_driver_unavailable";
                return result;
            }
            auto flowStack =
                std::make_unique<SnortDatapath::Tun::VpnHevLwipFlowStackBoundary>(
                    SnortDatapath::Tun::VpnHevLwipFlowStackConfig{
                        .ownerCount = 2,
                        .generation = 0,
                        .maxPacketBytes = 1500,
                    },
                    *options.vpnHevLwipDriver);
            runtime = std::make_unique<SnortDatapath::Tun::VpnTunFdRuntime>(
                tunFd,
                true,
                SnortDatapath::Tun::VpnTunFlowStackRuntimeConfig{
                    .flowStack = std::move(flowStack),
                    .adapterName = "vpn-tun-hev-lwip",
                    .transportFdHandoffReady = false,
                    .requiresTransportFdForDrain = false,
                    .flowStackReadyWithoutTransport = true,
                });
        } else {
            runtime =
                std::make_unique<SnortDatapath::Tun::VpnTunFdRuntime>(tunFd, true);
        }
        (void)runtime->start();
        result.runtime = std::move(runtime);
    }
    return result;
}

} // namespace SnortRuntime
