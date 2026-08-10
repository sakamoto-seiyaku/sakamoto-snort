/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>
#include <PacketPolicy.hpp>

#include <cstddef>
#include <cstdint>

namespace SnortDatapath::Flow {

enum class GraphInjectionResult : std::uint8_t {
    Accepted,
    ParseDrop,
    CapacityDrop,
    PolicyDrop,
    OwnerFaultDrop,
};

struct GraphInjectionCounters {
    std::uint64_t injectedPackets = 0;
    std::uint64_t acceptedPackets = 0;
    std::uint64_t parseDrops = 0;
    std::uint64_t capacityDrops = 0;
    std::uint64_t policyDrops = 0;
    std::uint64_t correctiveHandoffs = 0;
    std::uint64_t ownerFaultDrops = 0;
};

/**
 * Small adapter-neutral graph gate. A VPP graph node or an Android capture
 * adapter can feed normalized PacketSubmissions here; the gate performs the
 * direct owner enqueue, owner guard, corrective handoff, and completion in
 * one bounded transaction.
 *
 * The gate is lane-confined and does not add a second lock around the
 * runtime. Callers sharing it must serialize inject(); the NFQUEUE adapter
 * owns that serialization for its listener set.
 */
class FlowGraphInjectionGate final {
public:
    explicit FlowGraphInjectionGate(
        FlowSteeringRuntime &runtime,
        const Policy::PacketPolicySnapshot &policy =
            Policy::emptyPacketPolicySnapshot()) noexcept
        : runtime_(runtime), policy_(policy) {}

    [[nodiscard]] GraphInjectionResult inject(
        PacketSubmission &submission, std::uint32_t currentWorker) noexcept;

    [[nodiscard]] const GraphInjectionCounters &counters() const noexcept {
        return counters_;
    }

private:
    FlowSteeringRuntime &runtime_;
    const Policy::PacketPolicySnapshot &policy_;
    GraphInjectionCounters counters_;
};

} // namespace SnortDatapath::Flow
