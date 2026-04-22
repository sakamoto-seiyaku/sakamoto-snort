/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>

struct TrafficCounts {
    std::uint64_t allow = 0;
    std::uint64_t block = 0;
};

inline constexpr std::array<std::string_view, 5> kTrafficMetricKeys = {
    "dns",
    "rxp",
    "rxb",
    "txp",
    "txb",
};

struct TrafficSnapshot {
    std::array<TrafficCounts, kTrafficMetricKeys.size()> dims{};
};

// Fixed-dimension per-app traffic counters (always-on, relaxed atomics).
class TrafficCounters {
public:
    TrafficCounters() { reset(); }

    TrafficCounters(const TrafficCounters &) = delete;
    TrafficCounters &operator=(const TrafficCounters &) = delete;

    void observeDns(const bool blocked) noexcept {
        constexpr size_t idx = 0; // dns
        if (blocked) {
            _block[idx].fetch_add(1, std::memory_order_relaxed);
        } else {
            _allow[idx].fetch_add(1, std::memory_order_relaxed);
        }
    }

    void observePacket(const bool input, const bool accepted, const std::uint64_t bytes) noexcept {
        const size_t pktIdx = input ? 1 : 3;   // rxp/txp
        const size_t bytesIdx = input ? 2 : 4; // rxb/txb

        auto *bucket = accepted ? &_allow : &_block;
        (*bucket)[pktIdx].fetch_add(1, std::memory_order_relaxed);
        (*bucket)[bytesIdx].fetch_add(bytes, std::memory_order_relaxed);
    }

    void reset() noexcept {
        for (size_t i = 0; i < kTrafficMetricKeys.size(); ++i) {
            _allow[i].store(0, std::memory_order_relaxed);
            _block[i].store(0, std::memory_order_relaxed);
        }
    }

    TrafficSnapshot snapshot() const noexcept {
        TrafficSnapshot snap{};
        for (size_t i = 0; i < kTrafficMetricKeys.size(); ++i) {
            snap.dims[i].allow = _allow[i].load(std::memory_order_relaxed);
            snap.dims[i].block = _block[i].load(std::memory_order_relaxed);
        }
        return snap;
    }

private:
    std::array<std::atomic<std::uint64_t>, kTrafficMetricKeys.size()> _allow{};
    std::array<std::atomic<std::uint64_t>, kTrafficMetricKeys.size()> _block{};
};
