/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnHevLwipFlowStack.hpp>

namespace SnortDatapath::Tun {
namespace {

[[nodiscard]] VpnFlowStackAdmissionStatus flowStackStatusFor(
    const VpnHevLwipAdmissionStatus status) noexcept {
    switch (status) {
    case VpnHevLwipAdmissionStatus::Enqueued:
        return VpnFlowStackAdmissionStatus::Accepted;
    case VpnHevLwipAdmissionStatus::CapacityDrop:
        return VpnFlowStackAdmissionStatus::DroppedCapacity;
    case VpnHevLwipAdmissionStatus::UnsupportedProtocol:
        return VpnFlowStackAdmissionStatus::UnsupportedProtocol;
    case VpnHevLwipAdmissionStatus::OwnerFault:
        return VpnFlowStackAdmissionStatus::OwnerFault;
    case VpnHevLwipAdmissionStatus::StaleGeneration:
        return VpnFlowStackAdmissionStatus::StaleGeneration;
    case VpnHevLwipAdmissionStatus::TransportUnavailable:
        return VpnFlowStackAdmissionStatus::TransportUnavailable;
    case VpnHevLwipAdmissionStatus::TransportFailed:
        return VpnFlowStackAdmissionStatus::TransportFailed;
    }
    return VpnFlowStackAdmissionStatus::OwnerFault;
}

[[nodiscard]] bool directEgressSupported(
    const Flow::PacketFacts &facts) noexcept {
    return facts.parseStatus == Flow::ParseStatus::Ready
        && facts.portsAvailable
        && (facts.ipProtocol == 6 || facts.ipProtocol == 17);
}

} // namespace

VpnHevLwipFlowStackBoundary::VpnHevLwipFlowStackBoundary(
    const VpnHevLwipFlowStackConfig config,
    VpnHevLwipDriver &driver) noexcept
    : ownerCount_(config.ownerCount == 0 ? 1U : config.ownerCount),
      generation_(config.generation),
      maxPacketBytes_(config.maxPacketBytes == 0 ? 1500U
                                                 : config.maxPacketBytes),
      driver_(driver) {}

VpnFlowStackAdmissionResult VpnHevLwipFlowStackBoundary::admitPacket(
    const VpnFlowStackAdmissionRequest &request,
    const std::span<const std::byte> l3Packet) noexcept {
    if (request.provenance != VpnFlowStackPacketProvenance::TunOrigin) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::LoopRejected,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    if (!ownerExists(request.canonicalOwner)) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::OwnerFault,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    if (request.generation != generation_) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::StaleGeneration,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    if (!directEgressSupported(request.facts)) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::UnsupportedProtocol,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    if (l3Packet.empty() || l3Packet.size() > maxPacketBytes_) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::DroppedCapacity,
            .canonicalOwner = request.canonicalOwner,
        };
    }

    const auto driverResult = driver_.enqueueTunPacket(
        VpnHevLwipPacketContext{
            .facts = request.facts,
            .canonicalOwner = request.canonicalOwner,
            .generation = request.generation,
            .policyRevision = request.policyRevision,
        },
        l3Packet);
    return VpnFlowStackAdmissionResult{
        .status = flowStackStatusFor(driverResult.status),
        .canonicalOwner = request.canonicalOwner,
    };
}

VpnFlowStackReturnResult VpnHevLwipFlowStackBoundary::receiveReturnPacket(
    const std::span<std::byte> packetBuffer) noexcept {
    if (packetBuffer.empty()) {
        return VpnFlowStackReturnResult{
            .status = VpnFlowStackReturnStatus::PacketTooLarge,
            .bytes = 0,
        };
    }
    return driver_.receiveReturnPacket(packetBuffer);
}

VpnFlowStackDriveStatus VpnHevLwipFlowStackBoundary::driveOwner(
    const std::uint32_t owner,
    const VpnFlowStackDriveBudget budget) noexcept {
    if (!ownerExists(owner)) {
        return VpnFlowStackDriveStatus::Fault;
    }
    return driver_.driveOwner(owner, budget);
}

VpnFlowStackDriveStatus VpnHevLwipFlowStackBoundary::finishOwnerIfReady(
    const std::uint32_t owner) noexcept {
    if (!ownerExists(owner)) {
        return VpnFlowStackDriveStatus::Fault;
    }
    return driver_.finishOwnerIfReady(owner);
}

VpnFlowStackWakeStatus VpnHevLwipFlowStackBoundary::enqueueOwnerWake(
    const VpnFlowStackDeferredWork &work) noexcept {
    if (!ownerExists(work.currentWorker) || !ownerExists(work.targetOwner)) {
        return VpnFlowStackWakeStatus::Fault;
    }
    if (work.generation != generation_) {
        return VpnFlowStackWakeStatus::StaleGeneration;
    }
    return driver_.enqueueWake(work);
}

void VpnHevLwipFlowStackBoundary::setGeneration(
    const std::uint64_t generation) noexcept {
    generation_ = generation;
    driver_.resetGeneration(generation_);
}

std::uint64_t VpnHevLwipFlowStackBoundary::generation() const noexcept {
    return generation_;
}

bool VpnHevLwipFlowStackBoundary::ownerExists(
    const std::uint32_t owner) const noexcept {
    return owner < ownerCount_;
}

} // namespace SnortDatapath::Tun
