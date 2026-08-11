/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeFactory.hpp>

#include <NfqueuePassThroughRuntime.hpp>
#include <VpnTunFdRuntime.hpp>

#include <memory>
#include <string_view>

namespace SnortRuntime {

RuntimeFactoryResult createStartedRuntime(const RuntimeProfileSelection selection) {
    return createStartedRuntime(selection, nullptr);
}

RuntimeFactoryResult createStartedRuntime(const RuntimeProfileSelection selection,
                                          const char *const vpnTunFdSource) {
    const std::string_view source =
        vpnTunFdSource == nullptr ? std::string_view{} : std::string_view{vpnTunFdSource};
    RuntimeFactoryResult result{
        .plan = planRuntimeFactory(selection, source),
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
    if (result.plan.action == RuntimeFactoryAction::CreateVpnTunFdHandoff) {
        int tunFd = -1;
        if (!source.empty()) {
            tunFd = SnortDatapath::Tun::openVpnTunFdSource(source);
        }
        if (!source.empty() && tunFd < 0) {
            result.plan.launchable = false;
            result.plan.exitCode = 3;
            result.plan.errorCode = "vpn_tun_fd_open_failed";
            return result;
        }
        auto runtime =
            std::make_unique<SnortDatapath::Tun::VpnTunFdRuntime>(tunFd, true);
        (void)runtime->start();
        result.runtime = std::move(runtime);
    }
    return result;
}

} // namespace SnortRuntime
