/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <DaemonRuntime.hpp>

int main() {
    SnortRuntime::installSignalHandlers();

    SnortControlVNext::ControlServer server;
    return server.run();
}
