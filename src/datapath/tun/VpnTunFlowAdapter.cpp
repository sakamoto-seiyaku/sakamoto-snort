/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnTunFlowAdapter.hpp>

#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace {

SnortDatapath::Tun::VpnTunFlowAdapterConfig validateConfig(
    SnortDatapath::Tun::VpnTunFlowAdapterConfig config) {
    if (config.maxL3Bytes == 0
        || config.maxL3Bytes > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("VPN/TUN flow adapter requires a valid L3 byte limit");
    }
    return config;
}

[[nodiscard]] SnortDatapath::Tun::VpnTunFlowAdapterResult adapterResultFor(
    const SnortDatapath::Flow::FlowGraphIngressStatus status) noexcept {
    using GraphStatus = SnortDatapath::Flow::FlowGraphIngressStatus;
    using AdapterResult = SnortDatapath::Tun::VpnTunFlowAdapterResult;
    switch (status) {
    case GraphStatus::Accepted:
        return AdapterResult::FlowForwarded;
    case GraphStatus::PolicyDrop:
        return AdapterResult::FlowDropped;
    case GraphStatus::ParseFailOpen:
        return AdapterResult::PolicyBypassedParse;
    case GraphStatus::CapacityFailOpen:
        return AdapterResult::PolicyBypassedCapacity;
    case GraphStatus::OwnerFaultFailOpen:
        return AdapterResult::RuntimeDroppedOwnerFault;
    case GraphStatus::FragmentBuffered:
        return AdapterResult::FragmentBuffered;
    case GraphStatus::FragmentDuplicate:
        return AdapterResult::FragmentDuplicate;
    case GraphStatus::FragmentTimeout:
        return AdapterResult::FragmentTimeout;
    case GraphStatus::FragmentMalformed:
        return AdapterResult::FragmentMalformed;
    case GraphStatus::FragmentConflict:
        return AdapterResult::FragmentConflict;
    case GraphStatus::FragmentCapacity:
        return AdapterResult::FragmentCapacity;
    }
    return AdapterResult::RuntimeDroppedOwnerFault;
}

[[nodiscard]] SnortDatapath::Flow::DevicePacketDirection graphDirectionFor(
    const SnortDatapath::Tun::VpnTunPacketDirection direction) noexcept {
    using TunDirection = SnortDatapath::Tun::VpnTunPacketDirection;
    return direction == TunDirection::TransportReturn
        ? SnortDatapath::Flow::DevicePacketDirection::Input
        : SnortDatapath::Flow::DevicePacketDirection::Output;
}

[[nodiscard]] SnortDatapath::Tun::VpnFlowStackPacketProvenance
flowStackProvenanceFor(
    const SnortDatapath::Tun::VpnTunPacketDirection direction) noexcept {
    return direction == SnortDatapath::Tun::VpnTunPacketDirection::TransportReturn
        ? SnortDatapath::Tun::VpnFlowStackPacketProvenance::FlowStackOrigin
        : SnortDatapath::Tun::VpnFlowStackPacketProvenance::TunOrigin;
}

} // namespace

namespace SnortDatapath::Tun {

const char *vpnTunFlowAdapterResultName(
    const VpnTunFlowAdapterResult result) noexcept {
    switch (result) {
    case VpnTunFlowAdapterResult::FlowForwarded:
        return "FlowForwarded";
    case VpnTunFlowAdapterResult::FlowDropped:
        return "FlowDropped";
    case VpnTunFlowAdapterResult::PolicyBypassedParse:
        return "PolicyBypassedParse";
    case VpnTunFlowAdapterResult::PolicyBypassedCapacity:
        return "PolicyBypassedCapacity";
    case VpnTunFlowAdapterResult::RuntimeDroppedOwnerFault:
        return "RuntimeDroppedOwnerFault";
    case VpnTunFlowAdapterResult::FragmentBuffered:
        return "FragmentBuffered";
    case VpnTunFlowAdapterResult::FragmentDuplicate:
        return "FragmentDuplicate";
    case VpnTunFlowAdapterResult::FragmentTimeout:
        return "FragmentTimeout";
    case VpnTunFlowAdapterResult::FragmentMalformed:
        return "FragmentMalformed";
    case VpnTunFlowAdapterResult::FragmentConflict:
        return "FragmentConflict";
    case VpnTunFlowAdapterResult::FragmentCapacity:
        return "FragmentCapacity";
    }
    return "Unknown";
}

VpnTunFlowAdapter::VpnTunFlowAdapter(VpnTunFlowAdapterConfig config)
    : config_(validateConfig(std::move(config))),
      steering_(Flow::WorkerLayout(config_.workerCount, config_.hashSeed), config_.queueCapacity),
      graphIngress_(steering_,
                    config_.packetPolicy == nullptr
                        ? Policy::emptyPacketPolicySnapshot()
                        : *config_.packetPolicy,
                    Flow::FlowGraphIngressConfig{.maxL3Bytes = config_.maxL3Bytes},
                    config_.fragmentSteering,
                    config_.lpiProvider) {}

VpnTunFlowAdapterResult VpnTunFlowAdapter::process(
    const VpnTunPacketDirection direction,
    const std::span<const std::uint8_t> l3Packet,
    const std::uint32_t originalLengthHint,
    const VpnTunPacketMetadata metadata) noexcept {
    std::lock_guard lock(mutex_);
    lastAcceptedPacketHandoff_.reset();
    ++counters_.packetsSeen;
    if (direction == VpnTunPacketDirection::TransportReturn) {
        ++counters_.transportReturnPackets;
    } else {
        ++counters_.outboundPackets;
    }
    if (metadata.uidKnown) {
        ++counters_.uidAttributionHitPackets;
    } else {
        ++counters_.uidUnknownFallbackPackets;
    }
    counters_.lastObservedLinuxUid = metadata.linuxUid;
    counters_.lastObservedUidKnown = metadata.uidKnown;
    counters_.lastObservedNetworkContext = metadata.networkContext;
    counters_.lastObservedInterfaceIndex = metadata.interfaceIndex;
    counters_.lastObservedDirection = direction;

    const auto fragmentTick = monotonicFragmentNow();
    static_cast<void>(graphIngress_.expireFragments(fragmentTick));
    const auto originalLength = originalLengthHint == 0
        ? static_cast<std::uint32_t>(l3Packet.size())
        : originalLengthHint;

    ++counters_.normalizedPackets;
    const auto graphResult = graphIngress_.processL3Packet(
        std::as_bytes(l3Packet),
        Flow::FlowGraphIngressMetadata{
            .direction = graphDirectionFor(direction),
            .originalLength = originalLength,
            .domain = Flow::FlowDomain{
                .adapter = Flow::AdapterKind::VpnTun,
                .linuxUid = metadata.linuxUid,
                .uidKnown = metadata.uidKnown,
                .captureQueue = 0,
                .networkContext = metadata.networkContext,
                .runtimeProfile = 1,
                .interfaceIndex = metadata.interfaceIndex,
            },
        },
        fragmentTick);
    const auto adapterResult = adapterResultFor(graphResult.status);

    switch (graphResult.status) {
    case Flow::FlowGraphIngressStatus::Accepted:
        ++counters_.forwardedPackets;
        if (graphResult.acceptedFacts.has_value()
            && graphResult.flowEntryObservation.has_value()) {
            counters_.allowedFlowActivity.record(
                *graphResult.acceptedFacts,
                *graphResult.flowEntryObservation);
        }
        if (graphResult.acceptedFacts.has_value()
            && graphResult.acceptedOwner.has_value()) {
            lastAcceptedPacketHandoff_ = VpnTunAcceptedPacketHandoff{
                .facts = *graphResult.acceptedFacts,
                .canonicalOwner = *graphResult.acceptedOwner,
                .policyRevision = graphResult.flowEntryObservation.has_value()
                    ? graphResult.flowEntryObservation->policyRevision
                    : 0,
                .provenance = flowStackProvenanceFor(direction),
            };
        }
        break;
    case Flow::FlowGraphIngressStatus::PolicyDrop:
        ++counters_.droppedPackets;
        if (graphResult.policyDecision.has_value()) {
            const auto &dropFacts = graphResult.policyDropFacts.has_value()
                ? *graphResult.policyDropFacts
                : Flow::PacketFacts{};
            const auto linuxUid = graphResult.policyDropFacts.has_value()
                ? dropFacts.domain.linuxUid
                : metadata.linuxUid;
            const auto uidKnown = graphResult.policyDropFacts.has_value()
                ? dropFacts.domain.uidKnown
                : metadata.uidKnown;
            const auto networkContext = graphResult.policyDropFacts.has_value()
                ? dropFacts.domain.networkContext
                : metadata.networkContext;
            counters_.policyDropActivity.record(
                *graphResult.policyDecision,
                dropFacts,
                linuxUid,
                uidKnown,
                networkContext);
        }
        break;
    case Flow::FlowGraphIngressStatus::ParseFailOpen:
        ++counters_.parsePolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::CapacityFailOpen:
        ++counters_.capacityPolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::OwnerFaultFailOpen:
        ++counters_.ownerFaultRuntimeDrops;
        break;
    case Flow::FlowGraphIngressStatus::FragmentBuffered:
        ++counters_.fragmentBufferedPackets;
        ++counters_.parsePolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentDuplicate:
        ++counters_.fragmentDuplicatePackets;
        ++counters_.parsePolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentTimeout:
        ++counters_.fragmentTimeoutPackets;
        ++counters_.parsePolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentMalformed:
        ++counters_.fragmentMalformedPackets;
        ++counters_.parsePolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentConflict:
        ++counters_.fragmentConflictPackets;
        ++counters_.parsePolicyBypassPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentCapacity:
        ++counters_.fragmentCapacityPackets;
        ++counters_.capacityPolicyBypassPackets;
        break;
    }
    if (graphResult.fragmentReassembled) {
        ++counters_.fragmentReassembledPackets;
    }
    if (graphResult.fragmentOwnerMetadata) {
        ++counters_.fragmentOwnerMetadataPackets;
    }
    counters_.lastObservedResult = vpnTunFlowAdapterResultName(adapterResult);
    return adapterResult;
}

std::optional<VpnTunAcceptedPacketHandoff>
VpnTunFlowAdapter::lastAcceptedPacketHandoff() const noexcept {
    std::lock_guard lock(mutex_);
    return lastAcceptedPacketHandoff_;
}

void VpnTunFlowAdapter::recordTransportOutcome(
    const VpnTunTransportOutcome outcome) noexcept {
    std::lock_guard lock(mutex_);
    switch (outcome) {
    case VpnTunTransportOutcome::Succeeded:
        ++counters_.transportSucceededPackets;
        break;
    case VpnTunTransportOutcome::Failed:
        ++counters_.transportFailedPackets;
        break;
    case VpnTunTransportOutcome::Unsupported:
        ++counters_.transportUnsupportedPackets;
        break;
    }
}

std::optional<Flow::FlowAttributionObservation>
VpnTunFlowAdapter::applyResolvedAttribution(
    const Flow::PacketFacts &facts,
    const std::uint32_t linuxUid,
    const bool uidKnown) noexcept {
    std::lock_guard lock(mutex_);
    return steering_.flowTable().applyResolvedAttribution(facts, linuxUid, uidKnown);
}

std::uint64_t VpnTunFlowAdapter::monotonicFragmentNow() noexcept {
    const auto elapsed = std::chrono::steady_clock::now() - fragmentEpoch_;
    const auto wallMilliseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    if (wallMilliseconds > fragmentTick_) {
        fragmentTick_ = wallMilliseconds;
    }
    return fragmentTick_;
}

void VpnTunFlowAdapter::expireFragments(
    const std::uint64_t testAdvanceMilliseconds) noexcept {
    std::lock_guard lock(mutex_);
    static_cast<void>(monotonicFragmentNow());
    if (testAdvanceMilliseconds
        >= std::numeric_limits<std::uint64_t>::max() - fragmentTick_) {
        fragmentTick_ = std::numeric_limits<std::uint64_t>::max();
    } else {
        fragmentTick_ += testAdvanceMilliseconds;
    }
    static_cast<void>(graphIngress_.expireFragments(fragmentTick_));
}

VpnTunFlowAdapterCounters VpnTunFlowAdapter::counters() const noexcept {
    std::lock_guard lock(mutex_);
    auto result = counters_;
    const auto &distributionCounters = steering_.distribution().counters();
    const auto &guardCounters = steering_.ownerGuard().counters();
    const auto &flowTable = steering_.flowTable();
    result.directPackets = distributionCounters.directPackets;
    result.ownerGuardPasses = guardCounters.localPass;
    result.ownerGuardMismatches = guardCounters.mismatches;
    result.correctiveHandoffs = guardCounters.correctiveHandoffs;
    result.secondMismatchDrops = guardCounters.secondMismatchDrops;
    const auto &flowCounters = flowTable.counters();
    result.attributionUpdates = flowCounters.attributionUpdates;
    result.attributionMisses = flowCounters.attributionMisses;
    result.attributionResolutions = flowCounters.attributionResolutions;
    result.flowTableEntries = flowTable.size();
    result.flowTableCapacity = flowTable.capacity();
    result.flowTableHighWatermark = flowCounters.highWatermark;
    result.flowTableCapacityMisses = flowCounters.capacityMisses;
    result.lpiProvider = graphIngress_.lpiProviderStatus();
    return result;
}

} // namespace SnortDatapath::Tun
