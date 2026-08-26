/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnFlowStackBoundary.hpp>

#include <algorithm>
#include <poll.h>
#include <utility>
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

VpnOwnerLocalFlowStackBoundary::VpnOwnerLocalFlowStackBoundary(
    VpnOwnerLocalFlowStackConfig config)
    : generation_(config.generation),
      maxPacketsPerOwner_(config.maxPacketsPerOwner),
      maxPacketBytes_(config.maxPacketBytes),
      maxReturnPackets_(config.maxReturnPackets),
      maxWakeDepthPerOwner_(config.maxWakeDepthPerOwner),
      owners_(config.ownerCount == 0 ? 1U : config.ownerCount) {}

VpnFlowStackAdmissionResult VpnOwnerLocalFlowStackBoundary::admitPacket(
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
    if (request.facts.parseStatus != Flow::ParseStatus::Ready
        || (request.facts.ipProtocol != 6 && request.facts.ipProtocol != 17)
        || !request.facts.portsAvailable) {
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

    auto &owner = owners_[request.canonicalOwner];
    if (owner.admittedPackets.size() >= maxPacketsPerOwner_) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::DroppedCapacity,
            .canonicalOwner = request.canonicalOwner,
        };
    }

    try {
        owner.admittedPackets.emplace_back(l3Packet.begin(), l3Packet.end());
    } catch (...) {
        return VpnFlowStackAdmissionResult{
            .status = VpnFlowStackAdmissionStatus::DroppedCapacity,
            .canonicalOwner = request.canonicalOwner,
        };
    }

    return VpnFlowStackAdmissionResult{
        .status = VpnFlowStackAdmissionStatus::Accepted,
        .canonicalOwner = request.canonicalOwner,
    };
}

VpnFlowStackReturnResult VpnOwnerLocalFlowStackBoundary::receiveReturnPacket(
    const std::span<std::byte> packetBuffer) noexcept {
    if (returnPackets_.empty()) {
        return VpnFlowStackReturnResult{
            .status = VpnFlowStackReturnStatus::NoPacket,
            .bytes = 0,
        };
    }

    const auto &packet = returnPackets_.front();
    if (packet.empty() || packet.size() > packetBuffer.size()) {
        return VpnFlowStackReturnResult{
            .status = VpnFlowStackReturnStatus::PacketTooLarge,
            .bytes = 0,
        };
    }

    std::copy(packet.begin(), packet.end(), packetBuffer.begin());
    const auto bytes = packet.size();
    returnPackets_.pop_front();
    return VpnFlowStackReturnResult{
        .status = VpnFlowStackReturnStatus::Packet,
        .bytes = bytes,
    };
}

VpnFlowStackDriveStatus VpnOwnerLocalFlowStackBoundary::driveOwner(
    const std::uint32_t owner,
    const VpnFlowStackDriveBudget budget) noexcept {
    if (!ownerExists(owner)) {
        return VpnFlowStackDriveStatus::Fault;
    }
    if (budget.maxPackets == 0 || budget.maxReturnPackets == 0) {
        return VpnFlowStackDriveStatus::Idle;
    }

    auto &shard = owners_[owner];
    std::uint32_t moved = 0;
    const std::uint32_t limit =
        std::min(budget.maxPackets, budget.maxReturnPackets);
    while (moved < limit && !shard.admittedPackets.empty()) {
        if (returnPackets_.size() >= maxReturnPackets_) {
            return moved == 0 ? VpnFlowStackDriveStatus::Fault
                              : VpnFlowStackDriveStatus::MadeProgress;
        }

        auto packet = std::move(shard.admittedPackets.front());
        shard.admittedPackets.pop_front();
        try {
            returnPackets_.push_back(std::move(packet));
        } catch (...) {
            return moved == 0 ? VpnFlowStackDriveStatus::Fault
                              : VpnFlowStackDriveStatus::MadeProgress;
        }
        ++moved;
    }

    if (moved == 0) {
        return VpnFlowStackDriveStatus::Idle;
    }
    return VpnFlowStackDriveStatus::MadeProgress;
}

VpnFlowStackDriveStatus VpnOwnerLocalFlowStackBoundary::finishOwnerIfReady(
    const std::uint32_t owner) noexcept {
    if (!ownerExists(owner)) {
        return VpnFlowStackDriveStatus::Fault;
    }
    return owners_[owner].admittedPackets.empty()
        ? VpnFlowStackDriveStatus::Completed
        : VpnFlowStackDriveStatus::MadeProgress;
}

VpnFlowStackWakeStatus VpnOwnerLocalFlowStackBoundary::enqueueOwnerWake(
    const VpnFlowStackDeferredWork &work) noexcept {
    if (!ownerExists(work.targetOwner) || !ownerExists(work.currentWorker)) {
        return VpnFlowStackWakeStatus::Fault;
    }
    if (work.generation != generation_) {
        return VpnFlowStackWakeStatus::StaleGeneration;
    }

    auto &owner = owners_[work.targetOwner];
    if (owner.wakes.size() >= maxWakeDepthPerOwner_) {
        return VpnFlowStackWakeStatus::CapacityDrop;
    }
    try {
        owner.wakes.push_back(work);
    } catch (...) {
        return VpnFlowStackWakeStatus::Fault;
    }
    return VpnFlowStackWakeStatus::Enqueued;
}

void VpnOwnerLocalFlowStackBoundary::setGeneration(
    const std::uint64_t generation) noexcept {
    generation_ = generation;
    clearQueuedWork();
}

std::uint64_t VpnOwnerLocalFlowStackBoundary::generation() const noexcept {
    return generation_;
}

std::size_t VpnOwnerLocalFlowStackBoundary::pendingPackets(
    const std::uint32_t owner) const noexcept {
    if (!ownerExists(owner)) {
        return 0;
    }
    return owners_[owner].admittedPackets.size();
}

std::size_t VpnOwnerLocalFlowStackBoundary::pendingReturnPackets()
    const noexcept {
    return returnPackets_.size();
}

std::size_t VpnOwnerLocalFlowStackBoundary::queuedWakes(
    const std::uint32_t owner) const noexcept {
    if (!ownerExists(owner)) {
        return 0;
    }
    return owners_[owner].wakes.size();
}

bool VpnOwnerLocalFlowStackBoundary::ownerExists(
    const std::uint32_t owner) const noexcept {
    return owner < owners_.size();
}

void VpnOwnerLocalFlowStackBoundary::clearQueuedWork() noexcept {
    for (auto &owner : owners_) {
        owner.admittedPackets.clear();
        owner.wakes.clear();
    }
    returnPackets_.clear();
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
