/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <DaemonRuntime.hpp>
#include <RuntimeFactory.hpp>
#include <RuntimeProfile.hpp>

#include <cstdlib>
#include <iostream>
#include <string_view>

int main() {
    SnortRuntime::installSignalHandlers();
    if (!SnortRuntime::installParentDeathGuard()) {
        return 1;
    }

    const auto selectedProfile =
        SnortRuntime::runtimeProfileFromEnv(std::getenv("SAKAMOTO_RUNTIME_PROFILE"));
    const auto selectedVpnFlowStackBackend =
        SnortRuntime::vpnFlowStackRuntimeBackendFromEnv(
            std::getenv("SAKAMOTO_VPN_FLOW_STACK_BACKEND"));
    if (!selectedVpnFlowStackBackend.ok) {
        std::cerr << "runtime profile rejected: "
                  << selectedVpnFlowStackBackend.errorCode << '\n';
        return 2;
    }
    const char *const vpnTunFdSourceEnv =
        std::getenv("SAKAMOTO_VPN_TUN_FD_SOURCE");
    auto runtime = SnortRuntime::createStartedRuntime(
        selectedProfile,
        SnortRuntime::RuntimeFactoryStartOptions{
            .vpnTunFdSource = vpnTunFdSourceEnv == nullptr
                ? std::string_view{}
                : std::string_view{vpnTunFdSourceEnv},
            .preferredVpnFlowStackBackend =
                selectedVpnFlowStackBackend.backend,
        });
    if (!runtime.plan.launchable) {
        std::cerr << "runtime profile rejected: " << runtime.plan.errorCode << '\n';
        return runtime.plan.exitCode;
    }
    if (!runtime.runtime) {
        std::cerr << "runtime profile rejected: runtime_factory_empty\n";
        return 4;
    }

    SnortControlVNext::ControlServer server(*runtime.runtime);
    const int result = server.run();
    SnortRuntime::joinParentDeathMonitor();
    return result;
}
