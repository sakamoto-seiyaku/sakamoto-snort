/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <DaemonRuntime.hpp>
#include <NfqueuePassThroughRuntime.hpp>

int main() {
    SnortRuntime::installSignalHandlers();
    if (!SnortRuntime::installParentDeathGuard()) {
        return 1;
    }

    SnortDatapath::Nfqueue::DualStackPassThroughRuntime datapath;
    (void)datapath.start();

    SnortControlVNext::ControlServer server(datapath);
    const int result = server.run();
    SnortRuntime::joinParentDeathMonitor();
    return result;
}
