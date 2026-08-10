/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <PacketPolicy.hpp>
#include <FlowSteering.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace SnortRuntime {

struct NfqueueRuntimeCounters {
    std::uint64_t packetsSeen = 0;
    std::uint64_t acceptedPackets = 0;
    std::uint64_t droppedPackets = 0;
    std::uint64_t parsePassThroughPackets = 0;
    std::uint64_t capacityPassThroughPackets = 0;
    std::uint64_t ownerFaultPassThroughPackets = 0;
    std::uint64_t verdictSendFailures = 0;
    std::uint64_t fragmentBufferedPackets = 0;
    std::uint64_t fragmentReassembledPackets = 0;
    std::uint64_t uidMetadataPresentPackets = 0;
    std::uint64_t uidMetadataMissingPackets = 0;
    std::uint32_t lastObservedLinuxUid = 0;
    std::uint32_t lastObservedNetworkContext = 0;
    std::uint32_t lastObservedHook = 0;
    std::uint32_t lastObservedInputInterfaceIndex = 0;
    std::uint32_t lastObservedOutputInterfaceIndex = 0;
    std::string lastObservedResult = "none";
};

class BaseRuntimeControl {
public:
    virtual ~BaseRuntimeControl() = default;

    [[nodiscard]] virtual bool nfqueuePassThroughReady() const noexcept = 0;
    [[nodiscard]] virtual bool resetBaseRuntime() noexcept = 0;
    [[nodiscard]] virtual bool packetPolicyControlReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual bool nfqueueRuntimeCountersReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual NfqueueRuntimeCounters nfqueueRuntimeCounters() const noexcept {
        return {};
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
