/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

enum class NfqueueTopology : std::uint8_t {
    SplitInOut = 0,
    SharedFlowPool = 1,
};

enum class NfqueuePacketDirection : std::uint8_t {
    Input = 0,
    Output = 1,
};

struct NfqueueRange {
    std::uint32_t first = 0;
    std::uint32_t count = 0;

    friend constexpr bool operator==(const NfqueueRange &, const NfqueueRange &) = default;
};

struct NfqueueQueuePlan {
    NfqueueRange input;
    NfqueueRange output;
    NfqueueRange listeners;
};

inline constexpr std::string_view kNfqueueTopologySplitInOut = "split-in-out";
inline constexpr std::string_view kNfqueueTopologySharedFlowPool = "shared-flow-pool";
inline constexpr std::uint8_t kNfqueueHookPreRouting = 0;
inline constexpr std::uint8_t kNfqueueHookLocalIn = 1;
inline constexpr std::uint8_t kNfqueueHookForward = 2;
inline constexpr std::uint8_t kNfqueueHookLocalOut = 3;
inline constexpr std::uint8_t kNfqueueHookPostRouting = 4;

[[nodiscard]] constexpr NfqueueTopology defaultNfqueueTopology() noexcept {
    return NfqueueTopology::SplitInOut;
}

[[nodiscard]] constexpr std::string_view nfqueueTopologyToString(
    const NfqueueTopology topology) noexcept {
    switch (topology) {
    case NfqueueTopology::SplitInOut:
        return kNfqueueTopologySplitInOut;
    case NfqueueTopology::SharedFlowPool:
        return kNfqueueTopologySharedFlowPool;
    }
    return kNfqueueTopologySplitInOut;
}

[[nodiscard]] constexpr std::optional<NfqueueTopology> parseNfqueueTopology(
    const std::string_view value) noexcept {
    if (value == kNfqueueTopologySplitInOut) {
        return NfqueueTopology::SplitInOut;
    }
    if (value == kNfqueueTopologySharedFlowPool) {
        return NfqueueTopology::SharedFlowPool;
    }
    return std::nullopt;
}

[[nodiscard]] constexpr NfqueueQueuePlan makeNfqueueQueuePlan(
    const NfqueueTopology topology, const std::uint32_t firstQueue,
    const std::uint32_t queueCount) noexcept {
    if (topology == NfqueueTopology::SharedFlowPool) {
        return NfqueueQueuePlan{
            .input = {.first = firstQueue, .count = queueCount},
            .output = {.first = firstQueue, .count = queueCount},
            .listeners = {.first = firstQueue, .count = queueCount},
        };
    }

    const std::uint32_t inputCount = queueCount / 2;
    const std::uint32_t outputCount = queueCount - inputCount;
    return NfqueueQueuePlan{
        .input = {.first = firstQueue, .count = inputCount},
        .output = {.first = firstQueue + inputCount, .count = outputCount},
        .listeners = {.first = firstQueue, .count = queueCount},
    };
}

[[nodiscard]] constexpr std::optional<NfqueuePacketDirection> nfqueueHookToDirection(
    const std::uint8_t hook) noexcept {
    switch (hook) {
    case kNfqueueHookLocalIn:
        return NfqueuePacketDirection::Input;
    case kNfqueueHookLocalOut:
        return NfqueuePacketDirection::Output;
    default:
        return std::nullopt;
    }
}

[[nodiscard]] constexpr bool nfqueueDirectionIsInput(
    const NfqueuePacketDirection direction) noexcept {
    return direction == NfqueuePacketDirection::Input;
}
