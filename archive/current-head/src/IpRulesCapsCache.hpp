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
    // Low 8 bits are a family-discriminated mask:
    // - bit0: ipv4 uses ct
    // - bit1: ipv6 uses ct
    std::optional<std::uint8_t> usesCtMaskIfFresh(const std::uint64_t rulesEpoch) const noexcept {
        const std::uint64_t v = packed.load(std::memory_order_relaxed);
        const std::uint64_t cachedEpoch = v >> 8;
        if (cachedEpoch != rulesEpoch) {
            return std::nullopt;
        }
        return static_cast<std::uint8_t>(v & 0xFFu);
    }

    void setUsesCtMask(const std::uint64_t rulesEpoch, const std::uint8_t mask) noexcept {
        packed.store((rulesEpoch << 8) | static_cast<std::uint64_t>(mask), std::memory_order_relaxed);
    }
};
