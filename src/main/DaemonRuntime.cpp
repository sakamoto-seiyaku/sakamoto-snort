/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <DaemonRuntime.hpp>

#include <atomic>
#include <csignal>

namespace {

std::atomic_bool g_shutdownRequested{false};

void handleShutdownSignal(int) {
    SnortRuntime::requestShutdown();
}

} // namespace

namespace SnortRuntime {

void installSignalHandlers() {
    struct sigaction action {};
    action.sa_handler = handleShutdownSignal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
}

void requestShutdown() noexcept {
    g_shutdownRequested.store(true, std::memory_order_relaxed);
}

bool shutdownRequested() noexcept {
    return g_shutdownRequested.load(std::memory_order_relaxed);
}

} // namespace SnortRuntime
