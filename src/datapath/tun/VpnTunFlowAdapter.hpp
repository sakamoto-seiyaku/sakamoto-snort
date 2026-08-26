/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowGraphFragmentIngress.hpp>
#include <PacketPolicy.hpp>
#include <VpnFlowStackBoundary.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>

namespace SnortDatapath::Tun {

enum class VpnTunPacketDirection : std::uint8_t {
    Outbound,
    TransportReturn,
};

enum class VpnTunTransportOutcome : std::uint8_t {
    Succeeded,
    Failed,
    Unsupported,
};

enum class VpnTunFlowAdapterResult : std::uint8_t {
    FlowForwarded,
    FlowDropped,
    PolicyBypassedParse,
    PolicyBypassedCapacity,
    RuntimeDroppedOwnerFault,
    FragmentBuffered,
    FragmentDuplicate,
    FragmentTimeout,
    FragmentMalformed,
    FragmentConflict,
    FragmentCapacity,
};

[[nodiscard]] const char *vpnTunFlowAdapterResultName(
    VpnTunFlowAdapterResult result) noexcept;

struct VpnTunPacketMetadata final {
    std::uint32_t linuxUid = 0;
    std::uint32_t networkContext = 0;
    std::uint32_t interfaceIndex = 0;
    bool uidKnown = false;
};

struct VpnTunFlowAdapterConfig final {
    std::uint32_t workerCount = 2;
    std::uint64_t hashSeed = 0;
    std::size_t queueCapacity = 64;
    std::uint32_t maxL3Bytes = Flow::FlowGraphIngressConfig::kDefaultMaxL3Bytes;
    const Policy::PacketPolicySnapshot *packetPolicy = nullptr;
    Protocol::LpiRecognitionProvider *lpiProvider = nullptr;
    Flow::FragmentSteeringConfig fragmentSteering;
};

struct VpnTunFlowAdapterCounters final {
    std::uint64_t packetsSeen = 0;
    std::uint64_t normalizedPackets = 0;
    std::uint64_t forwardedPackets = 0;
    std::uint64_t droppedPackets = 0;
    std::uint64_t parsePolicyBypassPackets = 0;
    std::uint64_t capacityPolicyBypassPackets = 0;
    std::uint64_t ownerFaultRuntimeDrops = 0;
    std::uint64_t fragmentBufferedPackets = 0;
    std::uint64_t fragmentDuplicatePackets = 0;
    std::uint64_t fragmentTimeoutPackets = 0;
    std::uint64_t fragmentMalformedPackets = 0;
    std::uint64_t fragmentConflictPackets = 0;
    std::uint64_t fragmentCapacityPackets = 0;
    std::uint64_t fragmentReassembledPackets = 0;
    std::uint64_t fragmentOwnerMetadataPackets = 0;
    std::uint64_t flowTableEntries = 0;
    std::uint64_t flowTableCapacity = 0;
    std::uint64_t flowTableHighWatermark = 0;
    std::uint64_t flowTableCapacityMisses = 0;
    std::uint64_t uidAttributionHitPackets = 0;
    std::uint64_t uidUnknownFallbackPackets = 0;
    std::uint64_t outboundPackets = 0;
    std::uint64_t transportReturnPackets = 0;
    std::uint64_t transportSucceededPackets = 0;
    std::uint64_t transportFailedPackets = 0;
    std::uint64_t transportUnsupportedPackets = 0;
    std::uint64_t directPackets = 0;
    std::uint64_t ownerGuardPasses = 0;
    std::uint64_t ownerGuardMismatches = 0;
    std::uint64_t correctiveHandoffs = 0;
    std::uint64_t secondMismatchDrops = 0;
    std::uint64_t attributionUpdates = 0;
    std::uint64_t attributionMisses = 0;
    std::uint64_t attributionResolutions = 0;
    Protocol::LpiProviderStatus lpiProvider;
    Policy::PacketPolicyDropActivityCounters policyDropActivity;
    Flow::FlowEntryActivityCounters allowedFlowActivity;
    std::uint32_t lastObservedLinuxUid = 0;
    std::uint32_t lastObservedNetworkContext = 0;
    std::uint32_t lastObservedInterfaceIndex = 0;
    bool lastObservedUidKnown = false;
    VpnTunPacketDirection lastObservedDirection = VpnTunPacketDirection::Outbound;
    std::string lastObservedResult = "none";
};

struct VpnTunAcceptedPacketHandoff final {
    Flow::PacketFacts facts;
    std::uint32_t canonicalOwner = 0;
    std::uint64_t policyRevision = 0;
    VpnFlowStackPacketProvenance provenance =
        VpnFlowStackPacketProvenance::TunOrigin;
};

/**
 * VPN/TUN's shared graph ingress seam.
 *
 * The adapter consumes complete L3 TUN packets plus explicit application
 * attribution metadata. Parsing, canonical owner selection, and Gate/L4 policy
 * evaluation stay inside the shared FlowGraph pipeline used by Root/NFQUEUE.
 * VPN transport success/failure is recorded separately from policy verdicts.
 */
class VpnTunFlowAdapter final {
public:
    explicit VpnTunFlowAdapter(VpnTunFlowAdapterConfig config = {});
    ~VpnTunFlowAdapter() = default;

    VpnTunFlowAdapter(const VpnTunFlowAdapter &) = delete;
    VpnTunFlowAdapter &operator=(const VpnTunFlowAdapter &) = delete;
    VpnTunFlowAdapter(VpnTunFlowAdapter &&) = delete;
    VpnTunFlowAdapter &operator=(VpnTunFlowAdapter &&) = delete;

    [[nodiscard]] VpnTunFlowAdapterResult process(
        VpnTunPacketDirection direction,
        std::span<const std::uint8_t> l3Packet,
        std::uint32_t originalLengthHint = 0,
        VpnTunPacketMetadata metadata = {}) noexcept;
    void expireFragments(std::uint64_t testAdvanceMilliseconds = 0) noexcept;
    void recordTransportOutcome(VpnTunTransportOutcome outcome) noexcept;
    [[nodiscard]] std::optional<Flow::FlowAttributionObservation>
    applyResolvedAttribution(const Flow::PacketFacts &facts,
                             std::uint32_t linuxUid,
                             bool uidKnown = true) noexcept;
    [[nodiscard]] std::optional<VpnTunAcceptedPacketHandoff>
    lastAcceptedPacketHandoff() const noexcept;

    [[nodiscard]] VpnTunFlowAdapterCounters counters() const noexcept;
    [[nodiscard]] std::uint32_t maxL3Bytes() const noexcept {
        return config_.maxL3Bytes;
    }
    [[nodiscard]] std::size_t queueCapacity() const noexcept {
        return config_.queueCapacity;
    }

private:
    VpnTunFlowAdapterConfig config_;
    Flow::FlowSteeringRuntime steering_;
    Flow::FlowGraphFragmentIngress graphIngress_;
    std::chrono::steady_clock::time_point fragmentEpoch_ =
        std::chrono::steady_clock::now();
    std::uint64_t fragmentTick_ = 0;
    mutable std::mutex mutex_;
    VpnTunFlowAdapterCounters counters_;
    std::optional<VpnTunAcceptedPacketHandoff> lastAcceptedPacketHandoff_;

    [[nodiscard]] std::uint64_t monotonicFragmentNow() noexcept;
};

} // namespace SnortDatapath::Tun
