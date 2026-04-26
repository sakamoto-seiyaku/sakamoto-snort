/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <atomic>

std::shared_mutex mutexListeners;

namespace {

std::atomic<std::uint64_t> g_snortResetEpoch{0};

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
