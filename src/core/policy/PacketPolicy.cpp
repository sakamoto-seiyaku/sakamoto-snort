/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <PacketPolicy.hpp>

namespace SnortDatapath::Policy {

PacketPolicyDecision PacketPolicyDecision::passNext() noexcept {
    return PacketPolicyDecision{};
}

PacketPolicyDecision PacketPolicyDecision::drop(
    const std::uint32_t reasonId, const std::uint64_t ruleId,
    const std::uint64_t revision, const PacketPolicyStage stage) noexcept {
    return PacketPolicyDecision{
        .verdict = PacketPolicyVerdict::DROP,
        .stage = stage,
        .reasonId = reasonId,
        .ruleId = ruleId,
        .revision = revision,
    };
}

PacketPolicyDecision EmptyPacketPolicySnapshot::evaluate(
    const Flow::PacketFacts &facts) const noexcept {
    static_cast<void>(facts);
    return PacketPolicyDecision::passNext();
}

const PacketPolicySnapshot &emptyPacketPolicySnapshot() noexcept {
    static const EmptyPacketPolicySnapshot snapshot;
    return snapshot;
}

} // namespace SnortDatapath::Policy
