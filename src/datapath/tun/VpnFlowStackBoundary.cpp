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

[[nodiscard]] VpnFlowStackReturnResult readPacket(
    const int fd, const std::span<std::byte> packetBuffer) noexcept {
    if (fd < 0) {
        return {
            .status = VpnFlowStackReturnStatus::TransportUnavailable,
            .bytes = 0,
        };
    }
    if (packetBuffer.empty()) {
        return {
            .status = VpnFlowStackReturnStatus::PacketTooLarge,
            .bytes = 0,
        };
    }

    pollfd target{
        .fd = fd,
        .events = POLLIN | POLLERR | POLLHUP,
        .revents = 0,
    };
    const int pollResult = ::poll(&target, 1, 0);
    if (pollResult < 0) {
        return {
            .status = VpnFlowStackReturnStatus::TransportFailed,
            .bytes = 0,
        };
    }
    if (pollResult == 0) {
        return {
            .status = VpnFlowStackReturnStatus::NoPacket,
            .bytes = 0,
        };
    }
    if ((target.revents & POLLERR) != 0) {
        return {
            .status = VpnFlowStackReturnStatus::TransportFailed,
            .bytes = 0,
        };
    }
    if ((target.revents & POLLIN) == 0) {
        return {
            .status = (target.revents & POLLHUP) != 0
                ? VpnFlowStackReturnStatus::Eof
                : VpnFlowStackReturnStatus::NoPacket,
            .bytes = 0,
        };
    }

    const ssize_t bytes = ::read(fd, packetBuffer.data(), packetBuffer.size());
    if (bytes < 0) {
        return {
            .status = VpnFlowStackReturnStatus::TransportFailed,
            .bytes = 0,
        };
    }
    if (bytes == 0) {
        return {
            .status = VpnFlowStackReturnStatus::Eof,
            .bytes = 0,
        };
    }
    return {
        .status = VpnFlowStackReturnStatus::Packet,
        .bytes = static_cast<std::size_t>(bytes),
    };
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

VpnFlowStackReturnResult VpnFdFlowStackBoundary::receiveReturnPacket(
    const std::span<std::byte> packetBuffer) noexcept {
    if (transportFd_ == nullptr) {
        return {
            .status = VpnFlowStackReturnStatus::TransportUnavailable,
            .bytes = 0,
        };
    }
    return readPacket(*transportFd_, packetBuffer);
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
