/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <PacketPolicy.hpp>
#include <FlowSteering.hpp>

#include <cstdint>
#include <vector>

namespace SnortRuntime {

class BaseRuntimeControl {
public:
    virtual ~BaseRuntimeControl() = default;

    [[nodiscard]] virtual bool nfqueuePassThroughReady() const noexcept = 0;
    [[nodiscard]] virtual bool resetBaseRuntime() noexcept = 0;
    [[nodiscard]] virtual bool packetPolicyControlReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual SnortDatapath::Policy::PacketPolicySnapshotStatus
    packetPolicyStatus() const noexcept {
        return {};
    }
    [[nodiscard]] virtual SnortDatapath::Policy::PacketPolicyDecision
    evaluatePacketPolicy(const SnortDatapath::Flow::PacketFacts &facts) const noexcept {
        static_cast<void>(facts);
        return SnortDatapath::Policy::PacketPolicyDecision::passNext();
    }
    [[nodiscard]] virtual bool applyPacketPolicy(
        std::vector<SnortDatapath::Policy::PacketPolicySubjectView> subjects,
        std::uint64_t revision) noexcept {
        static_cast<void>(subjects);
        static_cast<void>(revision);
        return false;
    }
};

} // namespace SnortRuntime
