/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnFlowStackBoundary.hpp>

#include <poll.h>
#include <unistd.h>

namespace SnortDatapath::Tun {
namespace {

[[nodiscard]] bool writePacket(
    const int fd, const std::span<const std::byte> packet) noexcept {
    if (fd < 0 || packet.empty()) {
        return false;
    }
    pollfd pollTarget{
        .fd = fd,
        .events = POLLOUT | POLLERR | POLLHUP,
        .revents = 0,
    };
    const int pollResult = ::poll(&pollTarget, 1, 0);
    if (pollResult <= 0 || (pollTarget.revents & POLLOUT) == 0
        || (pollTarget.revents & (POLLERR | POLLHUP)) != 0) {
        return false;
    }
    const ssize_t written = ::write(fd, packet.data(), packet.size());
    return written == static_cast<ssize_t>(packet.size());
}

} // namespace

VpnFdFlowStackBoundary::VpnFdFlowStackBoundary(int &transportFd) noexcept
    : transportFd_(&transportFd) {}

VpnFlowStackAdmissionResult VpnFdFlowStackBoundary::admitPacket(
    const VpnFlowStackAdmissionRequest &request,
    const std::span<const std::byte> l3Packet) noexcept {
    if (request.provenance != VpnFlowStackPacketProvenance::TunOrigin) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::LoopRejected,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    if (transportFd_ == nullptr || *transportFd_ < 0) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::TransportUnavailable,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    if (!writePacket(*transportFd_, l3Packet)) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::TransportFailed,
            .canonicalOwner = request.canonicalOwner,
        };
    }
    return VpnFlowStackAdmissionResult{
        .status = VpnFlowStackAdmissionStatus::Accepted,
        .canonicalOwner = request.canonicalOwner,
    };
}

VpnFlowStackDriveStatus VpnFdFlowStackBoundary::driveOwner(
    const std::uint32_t, const VpnFlowStackDriveBudget) noexcept {
    return VpnFlowStackDriveStatus::Idle;
}

VpnFlowStackDriveStatus VpnFdFlowStackBoundary::finishOwnerIfReady(
    const std::uint32_t) noexcept {
    return VpnFlowStackDriveStatus::Idle;
}

VpnFlowStackWakeStatus VpnFdFlowStackBoundary::enqueueOwnerWake(
    const VpnFlowStackDeferredWork &) noexcept {
    return VpnFlowStackWakeStatus::Fault;
}

VpnFlowStackServiceResult serviceDeferredFlowStackWork(
    VpnFlowStackBoundary &boundary,
    const VpnFlowStackDeferredWork &work,
    const VpnFlowStackDriveBudget budget) noexcept {
    if (work.currentWorker == work.targetOwner) {
        const auto driveStatus = boundary.driveOwner(work.targetOwner, budget);
        const auto finishStatus = boundary.finishOwnerIfReady(work.targetOwner);
        return VpnFlowStackServiceResult{
            .action = VpnFlowStackServiceAction::LocalDrive,
            .targetOwner = work.targetOwner,
            .driveStatus = driveStatus,
            .finishStatus = finishStatus,
            .wakeStatus = VpnFlowStackWakeStatus::NotRequested,
        };
    }

    return VpnFlowStackServiceResult{
        .action = VpnFlowStackServiceAction::CrossOwnerWake,
        .targetOwner = work.targetOwner,
        .driveStatus = VpnFlowStackDriveStatus::NotRequested,
        .finishStatus = VpnFlowStackDriveStatus::NotRequested,
        .wakeStatus = boundary.enqueueOwnerWake(work),
    };
}

} // namespace SnortDatapath::Tun
