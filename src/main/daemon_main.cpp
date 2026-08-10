/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <DaemonRuntime.hpp>
#include <NfqueuePassThroughRuntime.hpp>
#include <RuntimeProfile.hpp>

#include <cstdlib>
#include <iostream>

int main() {
    SnortRuntime::installSignalHandlers();
    if (!SnortRuntime::installParentDeathGuard()) {
        return 1;
    }

    const auto profile =
        SnortRuntime::runtimeProfileFromEnv(std::getenv("SAKAMOTO_RUNTIME_PROFILE"));
    if (!profile.ok) {
        std::cerr << "runtime profile rejected: " << profile.errorCode << '\n';
        return 2;
    }
    if (profile.profile == SnortRuntime::RuntimeProfile::Vpn) {
        std::cerr << "runtime profile vpn rejected: vpn_adapter_unavailable\n";
        return 3;
    }

    SnortDatapath::Nfqueue::DualStackPassThroughRuntime datapath;
    (void)datapath.start();

    SnortControlVNext::ControlServer server(datapath);
    const int result = server.run();
    SnortRuntime::joinParentDeathMonitor();
    return result;
}
