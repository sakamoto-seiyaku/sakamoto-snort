/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <optional>

// Hot-path helper for amortized per-UID IPRULES gating.
//
// Packed as: [rulesEpoch:56 | caps:8]
// Epoch is sourced from the pinned IpRulesEngine snapshot (coherent).
struct IpRulesCapsCache {
    std::atomic<std::uint64_t> packed{0};

    // Returns std::nullopt if cache is stale for the provided rulesEpoch.
    std::optional<bool> usesCtIfFresh(const std::uint64_t rulesEpoch) const noexcept {
        static constexpr std::uint64_t kUsesCt = 1u;
        const std::uint64_t v = packed.load(std::memory_order_relaxed);
        const std::uint64_t cachedEpoch = v >> 8;
        if (cachedEpoch != rulesEpoch) {
            return std::nullopt;
        }
        return (v & kUsesCt) != 0;
    }

    void setUsesCt(const std::uint64_t rulesEpoch, const bool usesCt) noexcept {
        static constexpr std::uint64_t kUsesCt = 1u;
        const std::uint64_t caps = usesCt ? kUsesCt : 0u;
        packed.store((rulesEpoch << 8) | caps, std::memory_order_relaxed);
    }
};

