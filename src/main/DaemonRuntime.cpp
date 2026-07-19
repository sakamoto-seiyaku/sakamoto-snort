/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <DaemonRuntime.hpp>

#include <sys/prctl.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <exception>
#include <iostream>
#include <thread>

namespace {

std::atomic_bool g_shutdownRequested{false};
std::thread g_parentDeathMonitor;

void monitorParentDeath(const pid_t expectedParent) {
    while (!SnortRuntime::shutdownRequested()) {
        if (::getppid() != expectedParent) {
            constexpr char kParentMonitorLog[] = "parent monitor detected reparenting\n";
            (void)::write(STDERR_FILENO, kParentMonitorLog, sizeof(kParentMonitorLog) - 1);
            SnortRuntime::requestShutdown();
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void handleShutdownSignal(int) {
    constexpr char kShutdownSignalLog[] = "shutdown signal received\n";
    (void)::write(STDERR_FILENO, kShutdownSignalLog, sizeof(kShutdownSignalLog) - 1);
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

bool installParentDeathGuard() noexcept {
    const pid_t expectedParent = ::getppid();
    if (::prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
        std::cerr << "parent death guard install failed: " << std::strerror(errno) << "\n";
        return false;
    }

    const pid_t actualParent = ::getppid();
    if (actualParent != expectedParent) {
        std::cerr << "parent death guard race: expected parent " << expectedParent
                  << ", actual parent " << actualParent << "\n";
        ::raise(SIGTERM);
        return false;
    }

    try {
        g_parentDeathMonitor = std::thread(monitorParentDeath, actualParent);
    } catch (const std::exception &error) {
        std::cerr << "parent monitor install failed: " << error.what() << "\n";
        return false;
    }

    std::cerr << "parent death guard installed parent_pid=" << actualParent << "\n";
    return true;
}

void joinParentDeathMonitor() noexcept {
    requestShutdown();
    if (g_parentDeathMonitor.joinable()) {
        g_parentDeathMonitor.join();
    }
}

void requestShutdown() noexcept {
    g_shutdownRequested.store(true, std::memory_order_relaxed);
}

bool shutdownRequested() noexcept {
    return g_shutdownRequested.load(std::memory_order_relaxed);
}

} // namespace SnortRuntime
