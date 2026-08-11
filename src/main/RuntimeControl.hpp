/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <PacketPolicy.hpp>
#include <FlowSteering.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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
    std::uint64_t queueCapacity = 0;
    std::uint64_t queueHighWatermark = 0;
    std::uint64_t queueCompletionCapacity = 0;
    std::uint64_t queueCompletionHighWatermark = 0;
    std::uint64_t flowTableEntries = 0;
    std::uint64_t flowTableCapacity = 0;
    std::uint64_t flowTableHighWatermark = 0;
    std::uint64_t flowTableCapacityMisses = 0;
    std::uint64_t uidMetadataPresentPackets = 0;
    std::uint64_t uidMetadataMissingPackets = 0;
    SnortDatapath::Policy::PacketPolicyDropActivityCounters policyDropActivity;
    SnortDatapath::Flow::FlowEntryActivityCounters allowedFlowActivity;
    std::uint32_t lastObservedLinuxUid = 0;
    bool lastObservedUidKnown = false;
    std::uint32_t lastObservedNetworkContext = 0;
    std::uint32_t lastObservedHook = 0;
    std::uint32_t lastObservedInputInterfaceIndex = 0;
    std::uint32_t lastObservedOutputInterfaceIndex = 0;
    std::string lastObservedResult = "none";
};

struct VpnTunRuntimeCounters {
    std::uint64_t packetsSeen = 0;
    std::uint64_t normalizedPackets = 0;
    std::uint64_t forwardedPackets = 0;
    std::uint64_t droppedPackets = 0;
    std::uint64_t parsePolicyBypassPackets = 0;
    std::uint64_t capacityPolicyBypassPackets = 0;
    std::uint64_t ownerFaultRuntimeDrops = 0;
    std::uint64_t fragmentBufferedPackets = 0;
    std::uint64_t fragmentReassembledPackets = 0;
    std::uint64_t uidAttributionHitPackets = 0;
    std::uint64_t uidUnknownFallbackPackets = 0;
    std::uint64_t outboundPackets = 0;
    std::uint64_t transportReturnPackets = 0;
    std::uint64_t transportSucceededPackets = 0;
    std::uint64_t transportFailedPackets = 0;
    std::uint64_t transportUnsupportedPackets = 0;
    std::uint64_t directPackets = 0;
    std::uint64_t flowTableEntries = 0;
    std::uint64_t flowTableCapacity = 0;
    std::uint64_t flowTableHighWatermark = 0;
    std::uint64_t flowTableCapacityMisses = 0;
    std::uint64_t ownerGuardPasses = 0;
    std::uint64_t ownerGuardMismatches = 0;
    std::uint64_t attributionUpdates = 0;
    std::uint64_t attributionMisses = 0;
    std::uint64_t attributionResolutions = 0;
    SnortDatapath::Policy::PacketPolicyDropActivityCounters policyDropActivity;
    SnortDatapath::Flow::FlowEntryActivityCounters allowedFlowActivity;
    std::uint32_t lastObservedLinuxUid = 0;
    bool lastObservedUidKnown = false;
    std::uint32_t lastObservedNetworkContext = 0;
    std::uint32_t lastObservedInterfaceIndex = 0;
    std::string lastObservedDirection = "outbound";
    std::string lastObservedResult = "none";
};

struct VpnTunFdAttachResult {
    bool ok = false;
    std::string errorCode;
    std::string errorMessage;

    [[nodiscard]] static VpnTunFdAttachResult accepted() {
        return VpnTunFdAttachResult{.ok = true, .errorCode = {}, .errorMessage = {}};
    }

    [[nodiscard]] static VpnTunFdAttachResult error(std::string code, std::string message) {
        return VpnTunFdAttachResult{
            .ok = false,
            .errorCode = std::move(code),
            .errorMessage = std::move(message),
        };
    }
};

class BaseRuntimeControl {
public:
    virtual ~BaseRuntimeControl() = default;

    [[nodiscard]] virtual bool nfqueuePassThroughReady() const noexcept = 0;
    [[nodiscard]] virtual bool packetAdapterReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual std::string_view packetAdapterName() const noexcept {
        return {};
    }
    [[nodiscard]] virtual bool vpnTunFdHandoffReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual bool vpnTunTransportFdHandoffReady() const noexcept {
        return false;
    }
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
    [[nodiscard]] virtual bool vpnTunRuntimeCountersReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual bool vpnTunAttributionControlReady() const noexcept {
        return false;
    }
    [[nodiscard]] virtual VpnTunRuntimeCounters vpnTunRuntimeCounters() const noexcept {
        return {};
    }
    [[nodiscard]] virtual std::optional<SnortDatapath::Flow::FlowAttributionObservation>
    applyResolvedVpnTunAttribution(const SnortDatapath::Flow::PacketFacts &facts,
                                   std::uint32_t linuxUid,
                                   bool uidKnown) noexcept {
        static_cast<void>(facts);
        static_cast<void>(linuxUid);
        static_cast<void>(uidKnown);
        return std::nullopt;
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
    [[nodiscard]] virtual VpnTunFdAttachResult attachVpnTunFd(
        int tunFd, bool enableIpv6) noexcept {
        static_cast<void>(tunFd);
        static_cast<void>(enableIpv6);
        return VpnTunFdAttachResult::error("VPN_TUN_ATTACH_UNSUPPORTED",
                                           "VPN TUN fd handoff is unavailable");
    }
    [[nodiscard]] virtual VpnTunFdAttachResult attachVpnTransportFd(
        int transportFd) noexcept {
        static_cast<void>(transportFd);
        return VpnTunFdAttachResult::error(
            "VPN_TRANSPORT_ATTACH_UNSUPPORTED",
            "VPN transport fd handoff is unavailable");
    }
};

} // namespace SnortRuntime
