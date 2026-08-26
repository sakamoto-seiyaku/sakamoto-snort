/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace SnortDatapath::Tun {

enum class VpnFlowStackPacketProvenance : std::uint8_t {
    TunOrigin,
    FlowStackOrigin,
};

enum class VpnFlowStackAdmissionStatus : std::uint8_t {
    Accepted,
    DroppedCapacity,
    UnsupportedProtocol,
    OwnerFault,
    StaleGeneration,
};

enum class VpnFlowStackDeferredReason : std::uint8_t {
    PacketAdmission,
    SameOwnerRearm,
    FdWake,
    TimerWake,
    TeardownDrain,
};

enum class VpnFlowStackDriveStatus : std::uint8_t {
    NotRequested,
    Idle,
    MadeProgress,
    Completed,
    Fault,
};

enum class VpnFlowStackWakeStatus : std::uint8_t {
    NotRequested,
    Enqueued,
    CapacityDrop,
    StaleGeneration,
    Fault,
};

enum class VpnFlowStackServiceAction : std::uint8_t {
    LocalDrive,
    CrossOwnerWake,
};

struct VpnFlowStackDriveBudget final {
    std::uint32_t maxPackets = 1;
    std::uint32_t maxCallbacks = 1;
    std::uint32_t maxReturnPackets = 1;
};

struct VpnFlowStackAdmissionRequest final {
    Flow::PacketFacts facts;
    std::uint32_t canonicalOwner = 0;
    std::uint64_t generation = 0;
    std::uint64_t policyRevision = 0;
    VpnFlowStackPacketProvenance provenance =
        VpnFlowStackPacketProvenance::TunOrigin;
};

struct VpnFlowStackAdmissionResult final {
    VpnFlowStackAdmissionStatus status = VpnFlowStackAdmissionStatus::Accepted;
    std::uint32_t canonicalOwner = 0;

    [[nodiscard]] bool accepted() const noexcept {
        return status == VpnFlowStackAdmissionStatus::Accepted;
    }
};

struct VpnFlowStackDeferredWork final {
    std::uint32_t currentWorker = 0;
    std::uint32_t targetOwner = 0;
    std::uint64_t generation = 0;
    VpnFlowStackDeferredReason reason =
        VpnFlowStackDeferredReason::PacketAdmission;
};

struct VpnFlowStackServiceResult final {
    VpnFlowStackServiceAction action = VpnFlowStackServiceAction::LocalDrive;
    std::uint32_t targetOwner = 0;
    VpnFlowStackDriveStatus driveStatus =
        VpnFlowStackDriveStatus::NotRequested;
    VpnFlowStackDriveStatus finishStatus =
        VpnFlowStackDriveStatus::NotRequested;
    VpnFlowStackWakeStatus wakeStatus =
        VpnFlowStackWakeStatus::NotRequested;

    [[nodiscard]] bool droveLocally() const noexcept {
        return action == VpnFlowStackServiceAction::LocalDrive;
    }

    [[nodiscard]] bool queuedCrossOwner() const noexcept {
        return action == VpnFlowStackServiceAction::CrossOwnerWake
            && wakeStatus == VpnFlowStackWakeStatus::Enqueued;
    }
};

/**
 * Deep seam for Android VPN post-policy Direct Egress.
 *
 * Callers provide canonical owner/provenance and accepted packet facts.  The
 * implementation owns HEV/lwIP/session/socket/pbuf details behind this
 * Interface.  The packet byte span passed to admitPacket() is borrowed only
 * for that call; an implementation that retains payload must materialize its
 * own bounded storage before returning.
 */
class VpnFlowStackBoundary {
public:
    virtual ~VpnFlowStackBoundary() = default;

    [[nodiscard]] virtual VpnFlowStackAdmissionResult admitPacket(
        const VpnFlowStackAdmissionRequest &request,
        std::span<const std::byte> l3Packet) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackDriveStatus driveOwner(
        std::uint32_t owner, VpnFlowStackDriveBudget budget) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackDriveStatus finishOwnerIfReady(
        std::uint32_t owner) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackWakeStatus enqueueOwnerWake(
        const VpnFlowStackDeferredWork &work) noexcept = 0;
};

/**
 * S244 invariant: a deferred work item targeting the current owner is driven
 * locally for one bounded quantum and must not be self-enqueued through the
 * cross-owner wake path.  Only true cross-owner work is enqueued.
 */
[[nodiscard]] VpnFlowStackServiceResult serviceDeferredFlowStackWork(
    VpnFlowStackBoundary &boundary,
    const VpnFlowStackDeferredWork &work,
    VpnFlowStackDriveBudget budget) noexcept;

} // namespace SnortDatapath::Tun
