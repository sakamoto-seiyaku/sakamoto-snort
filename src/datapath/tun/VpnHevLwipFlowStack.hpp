/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <VpnFlowStackBoundary.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace SnortDatapath::Tun {

enum class VpnHevLwipAdmissionStatus : std::uint8_t {
    Enqueued,
    CapacityDrop,
    UnsupportedProtocol,
    OwnerFault,
    StaleGeneration,
    TransportUnavailable,
    TransportFailed,
};

struct VpnHevLwipPacketContext final {
    Flow::PacketFacts facts;
    std::uint32_t canonicalOwner = 0;
    std::uint64_t generation = 0;
    std::uint64_t policyRevision = 0;
};

struct VpnHevLwipAdmissionResult final {
    VpnHevLwipAdmissionStatus status =
        VpnHevLwipAdmissionStatus::TransportFailed;
};

/**
 * Internal HEV/lwIP driver slot behind the VPN Flow Stack Interface.
 *
 * Production code will satisfy this slot with the pinned Sakamoto HEV Fork /
 * lwIP implementation.  Tests can satisfy it with a fake without forcing
 * callers or VpnTunFdRuntime to learn HEV PCB/session/protected-socket details.
 */
class VpnHevLwipDriver {
public:
    virtual ~VpnHevLwipDriver() = default;

    [[nodiscard]] virtual VpnHevLwipAdmissionResult enqueueTunPacket(
        const VpnHevLwipPacketContext &context,
        std::span<const std::byte> l3Packet) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackReturnResult receiveReturnPacket(
        std::span<std::byte> packetBuffer) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackDriveStatus driveOwner(
        std::uint32_t owner, VpnFlowStackDriveBudget budget) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackDriveStatus finishOwnerIfReady(
        std::uint32_t owner) noexcept = 0;

    [[nodiscard]] virtual VpnFlowStackWakeStatus enqueueWake(
        const VpnFlowStackDeferredWork &work) noexcept = 0;

    virtual void resetGeneration(std::uint64_t generation) noexcept = 0;
};

struct VpnHevLwipFlowStackConfig final {
    std::uint32_t ownerCount = 1;
    std::uint64_t generation = 1;
    std::size_t maxPacketBytes = 1500;
};

/**
 * Product facade for the Android VPN HEV/lwIP Direct Egress implementation.
 *
 * The facade owns the product-facing invariants: TUN-origin admission,
 * canonical owner range, generation checks, TCP/UDP direct-egress eligibility,
 * and bounded packet size.  HEV/lwIP-specific session and socket work remains
 * inside the injected driver.
 */
class VpnHevLwipFlowStackBoundary final : public VpnFlowStackBoundary {
public:
    VpnHevLwipFlowStackBoundary(
        VpnHevLwipFlowStackConfig config,
        VpnHevLwipDriver &driver) noexcept;

    VpnHevLwipFlowStackBoundary(const VpnHevLwipFlowStackBoundary &) = delete;
    VpnHevLwipFlowStackBoundary &operator=(
        const VpnHevLwipFlowStackBoundary &) = delete;
    VpnHevLwipFlowStackBoundary(VpnHevLwipFlowStackBoundary &&) = delete;
    VpnHevLwipFlowStackBoundary &operator=(
        VpnHevLwipFlowStackBoundary &&) = delete;

    [[nodiscard]] VpnFlowStackAdmissionResult admitPacket(
        const VpnFlowStackAdmissionRequest &request,
        std::span<const std::byte> l3Packet) noexcept override;

    [[nodiscard]] VpnFlowStackReturnResult receiveReturnPacket(
        std::span<std::byte> packetBuffer) noexcept override;

    [[nodiscard]] VpnFlowStackDriveStatus driveOwner(
        std::uint32_t owner, VpnFlowStackDriveBudget budget) noexcept override;

    [[nodiscard]] VpnFlowStackDriveStatus finishOwnerIfReady(
        std::uint32_t owner) noexcept override;

    [[nodiscard]] VpnFlowStackWakeStatus enqueueOwnerWake(
        const VpnFlowStackDeferredWork &work) noexcept override;

    void setGeneration(std::uint64_t generation) noexcept;

    [[nodiscard]] std::uint64_t generation() const noexcept;

private:
    [[nodiscard]] bool ownerExists(std::uint32_t owner) const noexcept;

    std::uint32_t ownerCount_ = 1;
    std::uint64_t generation_ = 1;
    std::size_t maxPacketBytes_ = 1500;
    VpnHevLwipDriver &driver_;
};

} // namespace SnortDatapath::Tun
