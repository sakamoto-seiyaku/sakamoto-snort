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

int main() {
    SnortRuntime::installSignalHandlers();
    if (!SnortRuntime::installParentDeathGuard()) {
        return 1;
    }

    const auto selectedProfile =
        SnortRuntime::runtimeProfileFromEnv(std::getenv("SAKAMOTO_RUNTIME_PROFILE"));
    auto runtime = SnortRuntime::createStartedRuntime(selectedProfile);
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
