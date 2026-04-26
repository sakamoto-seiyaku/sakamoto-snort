/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <pthread.h>
#include <thread>
#include <utility>

std::shared_mutex mutexListeners;
std::mutex mutexControlMutations;

namespace {

std::atomic<std::uint64_t> g_snortResetEpoch{0};
std::mutex g_shutdownMutex;
std::condition_variable g_shutdownCv;
bool g_shutdownRequested = false;
std::once_flag g_signalWaiterOnce;

std::atomic<std::uint32_t> g_activeControlSessions{0};
std::atomic<std::uint32_t> g_activeDnsSessions{0};

constexpr std::uint32_t kControlSessionBudget = 128;
constexpr std::uint32_t kDnsSessionBudget = 256;

void makeTerminationSignalSet(sigset_t &set) {
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
}

std::atomic<std::uint32_t> &activeCounter(const SnortSessionBudgetKind kind) noexcept {
    return kind == SnortSessionBudgetKind::Control ? g_activeControlSessions : g_activeDnsSessions;
}

std::uint32_t budgetLimit(const SnortSessionBudgetKind kind) noexcept {
    return kind == SnortSessionBudgetKind::Control ? kControlSessionBudget : kDnsSessionBudget;
}

}

std::uint64_t snortResetEpoch() noexcept {
    return g_snortResetEpoch.load(std::memory_order_acquire);
}

bool snortResetEpochIsStable(const std::uint64_t epoch) noexcept { return (epoch & 1ULL) == 0; }

bool snortResetEpochStillCurrent(const std::uint64_t epoch) noexcept {
    return snortResetEpochIsStable(epoch) &&
           g_snortResetEpoch.load(std::memory_order_acquire) == epoch;
}

void snortBeginResetEpoch() noexcept { g_snortResetEpoch.fetch_add(1, std::memory_order_acq_rel); }

void snortEndResetEpoch() noexcept { g_snortResetEpoch.fetch_add(1, std::memory_order_release); }

void snortConfigureProcessSignals() {
    sigset_t set;
    makeTerminationSignalSet(set);
    if (pthread_sigmask(SIG_BLOCK, &set, nullptr) != 0) {
        LOG(ERROR) << "failed to block termination signals";
    }
    std::signal(SIGPIPE, SIG_IGN);
}

void snortStartSignalWaiter() {
    std::call_once(g_signalWaiterOnce, [] {
        std::thread([] {
            sigset_t set;
            makeTerminationSignalSet(set);
            int signal = 0;
            while (sigwait(&set, &signal) == 0) {
                if (signal == SIGINT || signal == SIGTERM) {
                    snortRequestShutdown();
                    return;
                }
            }
        }).detach();
    });
}

void snortRequestShutdown() {
    {
        const std::lock_guard lock(g_shutdownMutex);
        g_shutdownRequested = true;
    }
    g_shutdownCv.notify_all();
}

bool snortShutdownRequested() {
    const std::lock_guard lock(g_shutdownMutex);
    return g_shutdownRequested;
}

bool snortWaitForShutdownFor(const std::chrono::milliseconds timeout) {
    std::unique_lock lock(g_shutdownMutex);
    return g_shutdownCv.wait_for(lock, timeout, [] { return g_shutdownRequested; });
}

void snortResetShutdownForTests() {
    {
        const std::lock_guard lock(g_shutdownMutex);
        g_shutdownRequested = false;
    }
    g_shutdownCv.notify_all();
}

SnortSessionBudgetToken::SnortSessionBudgetToken(const SnortSessionBudgetKind kind,
                                                 const bool active) noexcept
    : _kind(kind), _active(active) {}

SnortSessionBudgetToken::~SnortSessionBudgetToken() { release(); }

SnortSessionBudgetToken::SnortSessionBudgetToken(SnortSessionBudgetToken &&other) noexcept
    : _kind(other._kind), _active(std::exchange(other._active, false)) {}

SnortSessionBudgetToken &
SnortSessionBudgetToken::operator=(SnortSessionBudgetToken &&other) noexcept {
    if (this != &other) {
        release();
        _kind = other._kind;
        _active = std::exchange(other._active, false);
    }
    return *this;
}

void SnortSessionBudgetToken::release() noexcept {
    if (!_active) {
        return;
    }
    activeCounter(_kind).fetch_sub(1, std::memory_order_release);
    _active = false;
}

SnortSessionBudgetToken snortTryAcquireSessionBudget(const SnortSessionBudgetKind kind) noexcept {
    auto &counter = activeCounter(kind);
    const std::uint32_t limit = budgetLimit(kind);
    std::uint32_t current = counter.load(std::memory_order_relaxed);
    while (current < limit) {
        if (counter.compare_exchange_weak(current, current + 1, std::memory_order_acq_rel,
                                          std::memory_order_relaxed)) {
            return SnortSessionBudgetToken(kind, true);
        }
    }
    return SnortSessionBudgetToken(kind, false);
}

std::uint32_t snortSessionBudgetLimit(const SnortSessionBudgetKind kind) noexcept {
    return budgetLimit(kind);
}

std::uint32_t snortActiveSessions(const SnortSessionBudgetKind kind) noexcept {
    return activeCounter(kind).load(std::memory_order_acquire);
}

void snortResetSessionBudgetsForTests() noexcept {
    g_activeControlSessions.store(0, std::memory_order_release);
    g_activeDnsSessions.store(0, std::memory_order_release);
}
