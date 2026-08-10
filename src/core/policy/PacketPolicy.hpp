/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>

#include <cstdint>

namespace SnortDatapath::Policy {

enum class PacketPolicyVerdict : std::uint8_t {
    PASS_NEXT,
    DROP,
};

enum class PacketPolicyStage : std::uint8_t {
    None,
    NetworkGate,
    L4,
};

struct PacketPolicyDecision {
    PacketPolicyVerdict verdict = PacketPolicyVerdict::PASS_NEXT;
    PacketPolicyStage stage = PacketPolicyStage::None;
    std::uint32_t reasonId = 0;
    std::uint64_t ruleId = 0;
    std::uint64_t revision = 0;

    [[nodiscard]] static PacketPolicyDecision passNext() noexcept;
    [[nodiscard]] static PacketPolicyDecision drop(
        std::uint32_t reasonId = 0, std::uint64_t ruleId = 0,
        std::uint64_t revision = 0,
        PacketPolicyStage stage = PacketPolicyStage::L4) noexcept;
};

class PacketPolicySnapshot {
public:
    PacketPolicySnapshot() = default;
    PacketPolicySnapshot(const PacketPolicySnapshot &) = delete;
    PacketPolicySnapshot &operator=(const PacketPolicySnapshot &) = delete;
    virtual ~PacketPolicySnapshot() = default;

    [[nodiscard]] virtual PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept = 0;
};

class EmptyPacketPolicySnapshot final : public PacketPolicySnapshot {
public:
    [[nodiscard]] PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept override;
};

[[nodiscard]] const PacketPolicySnapshot &emptyPacketPolicySnapshot() noexcept;

} // namespace SnortDatapath::Policy
