/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <VpnTunFlowAdapter.hpp>
#include <RuntimeControl.hpp>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace SnortDatapath::Tun {

struct VpnTunDrainResult final {
    std::uint64_t packetsRead = 0;
    std::uint64_t forwardedToTransport = 0;
    std::uint64_t forwardedWithoutTransport = 0;
    std::uint64_t returnedToTun = 0;
    std::uint64_t policyDropped = 0;
    std::uint64_t policyBypassedWithoutTransport = 0;
    std::uint64_t runtimeDropped = 0;
    std::uint64_t writeFailures = 0;
    std::uint64_t readErrors = 0;
    int lastErrno = 0;
    bool eof = false;
};

[[nodiscard]] inline std::string_view vpnTunPacketDirectionName(
    const VpnTunPacketDirection direction) noexcept {
    return direction == VpnTunPacketDirection::TransportReturn
        ? std::string_view{"transport-return"}
        : std::string_view{"outbound"};
}

[[nodiscard]] inline int openVpnTunFdSource(const std::string_view source) noexcept {
    if (source.empty()) {
        return -1;
    }
    const std::string path{source};
    return ::open(path.c_str(), O_RDWR | O_CLOEXEC);
}

class VpnTunFdRuntime final : public SnortRuntime::BaseRuntimeControl {
public:
    explicit VpnTunFdRuntime(const int tunFd)
        : tunFd_(tunFd),
          flowAdapter_(VpnTunFlowAdapterConfig{.packetPolicy = &packetPolicy_}) {}

    ~VpnTunFdRuntime() override {
        if (tunFd_ >= 0) {
            ::close(tunFd_);
        }
        if (transportFd_ >= 0) {
            ::close(transportFd_);
        }
    }

    VpnTunFdRuntime(const VpnTunFdRuntime &) = delete;
    VpnTunFdRuntime &operator=(const VpnTunFdRuntime &) = delete;
    VpnTunFdRuntime(VpnTunFdRuntime &&) = delete;
    VpnTunFdRuntime &operator=(VpnTunFdRuntime &&) = delete;

    [[nodiscard]] bool start() const noexcept {
        return tunFd_ >= 0;
    }

    [[nodiscard]] bool nfqueuePassThroughReady() const noexcept override {
        return false;
    }

    [[nodiscard]] bool packetAdapterReady() const noexcept override {
        return false;
    }

    [[nodiscard]] std::string_view packetAdapterName() const noexcept override {
        return "vpn-tun-hev";
    }

    [[nodiscard]] bool vpnTunFdHandoffReady() const noexcept override {
        return tunFd_ >= 0;
    }

    [[nodiscard]] bool vpnTunTransportFdHandoffReady() const noexcept override {
        return tunFd_ >= 0;
    }

    [[nodiscard]] bool packetPolicyControlReady() const noexcept override {
        return true;
    }

    [[nodiscard]] bool vpnTunRuntimeCountersReady() const noexcept override {
        return true;
    }

    [[nodiscard]] SnortRuntime::VpnTunRuntimeCounters
    vpnTunRuntimeCounters() const noexcept override {
        const auto counters = flowAdapterCounters();
        return {
            .packetsSeen = counters.packetsSeen,
            .normalizedPackets = counters.normalizedPackets,
            .forwardedPackets = counters.forwardedPackets,
            .droppedPackets = counters.droppedPackets,
            .parsePolicyBypassPackets = counters.parsePolicyBypassPackets,
            .capacityPolicyBypassPackets = counters.capacityPolicyBypassPackets,
            .ownerFaultRuntimeDrops = counters.ownerFaultRuntimeDrops,
            .fragmentBufferedPackets = counters.fragmentBufferedPackets,
            .fragmentReassembledPackets = counters.fragmentReassembledPackets,
            .uidAttributionHitPackets = counters.uidAttributionHitPackets,
            .uidUnknownFallbackPackets = counters.uidUnknownFallbackPackets,
            .outboundPackets = counters.outboundPackets,
            .transportReturnPackets = counters.transportReturnPackets,
            .transportSucceededPackets = counters.transportSucceededPackets,
            .transportFailedPackets = counters.transportFailedPackets,
            .transportUnsupportedPackets = counters.transportUnsupportedPackets,
            .directPackets = counters.directPackets,
            .ownerGuardPasses = counters.ownerGuardPasses,
            .ownerGuardMismatches = counters.ownerGuardMismatches,
            .lastObservedLinuxUid = counters.lastObservedLinuxUid,
            .lastObservedUidKnown = counters.lastObservedUidKnown,
            .lastObservedNetworkContext = counters.lastObservedNetworkContext,
            .lastObservedInterfaceIndex = counters.lastObservedInterfaceIndex,
            .lastObservedDirection = std::string{
                vpnTunPacketDirectionName(counters.lastObservedDirection)},
            .lastObservedResult = counters.lastObservedResult,
        };
    }

    [[nodiscard]] Policy::PacketPolicySnapshotStatus
    packetPolicyStatus() const noexcept override {
        return packetPolicy_.status();
    }

    [[nodiscard]] Policy::PacketPolicyDecision evaluatePacketPolicy(
        const Flow::PacketFacts &facts) const noexcept override {
        return packetPolicy_.evaluate(facts);
    }

    [[nodiscard]] bool applyPacketPolicy(
        std::vector<Policy::PacketPolicySubjectView> subjects,
        const std::uint64_t revision) noexcept override {
        try {
            packetPolicy_.apply(std::move(subjects), revision);
            return true;
        } catch (const std::exception &e) {
            std::cerr << "VPN/TUN packet policy apply failed: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "VPN/TUN packet policy apply failed: unknown exception\n";
        }
        return false;
    }

    [[nodiscard]] bool resetBaseRuntime() noexcept override {
        return tunFd_ >= 0;
    }

    [[nodiscard]] SnortRuntime::VpnTunFdAttachResult attachVpnTransportFd(
        const int transportFd) noexcept override {
        if (transportFd < 0) {
            return SnortRuntime::VpnTunFdAttachResult::error(
                "VPN_TRANSPORT_ATTACH_INVALID_FD", "VPN transport fd is invalid");
        }
        if (transportFd_ >= 0) {
            ::close(transportFd_);
        }
        transportFd_ = transportFd;
        return SnortRuntime::VpnTunFdAttachResult::accepted();
    }

    /**
     * Bounded single-lane TUN ingress drain.
     *
     * The product runtime does not call this from start() yet because the HEV
     * transport owner is not integrated. This method is the native seam that
     * later loop code will use: one readable TUN packet is read as complete L3
     * bytes, normalized through the shared VPN/TUN flow adapter, and then
     * classified as policy drop or not-yet-transported.
     */
    [[nodiscard]] VpnTunDrainResult drainTunPackets(
        std::size_t maxPackets,
        VpnTunPacketMetadata metadata = {},
        VpnTunPacketDirection direction = VpnTunPacketDirection::Outbound) noexcept {
        VpnTunDrainResult result;
        if (tunFd_ < 0) {
            result.readErrors = 1;
            result.lastErrno = EBADF;
            return result;
        }

        std::array<std::uint8_t, kMaxTunPacketBytes> packet{};
        for (std::size_t packetIndex = 0; packetIndex < maxPackets; ++packetIndex) {
            pollfd fd{
                .fd = tunFd_,
                .events = POLLIN | POLLERR | POLLHUP,
                .revents = 0,
            };
            const int pollResult = ::poll(&fd, 1, 0);
            if (pollResult < 0) {
                if (errno == EINTR) {
                    continue;
                }
                ++result.readErrors;
                result.lastErrno = errno;
                break;
            }
            if (pollResult == 0) {
                break;
            }
            if ((fd.revents & POLLERR) != 0) {
                ++result.readErrors;
                result.lastErrno = EIO;
                break;
            }
            if ((fd.revents & POLLIN) == 0) {
                if ((fd.revents & POLLHUP) != 0) {
                    result.eof = true;
                }
                break;
            }

            const ssize_t bytes = ::read(tunFd_, packet.data(), packet.size());
            if (bytes < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                ++result.readErrors;
                result.lastErrno = errno;
                break;
            }
            if (bytes == 0) {
                result.eof = true;
                break;
            }

            ++result.packetsRead;
            const auto adapterResult = flowAdapter_.process(
                direction,
                std::span<const std::uint8_t>{
                    packet.data(), static_cast<std::size_t>(bytes)},
                static_cast<std::uint32_t>(bytes),
                metadata);
            switch (adapterResult) {
            case VpnTunFlowAdapterResult::FlowForwarded:
                if (writePacketToTransport(
                        std::span<const std::uint8_t>{
                            packet.data(), static_cast<std::size_t>(bytes)})) {
                    ++result.forwardedToTransport;
                    flowAdapter_.recordTransportOutcome(VpnTunTransportOutcome::Succeeded);
                } else {
                    if (transportFd_ < 0) {
                        ++result.forwardedWithoutTransport;
                        flowAdapter_.recordTransportOutcome(VpnTunTransportOutcome::Unsupported);
                    } else {
                        ++result.writeFailures;
                        result.lastErrno = result.lastErrno == 0 ? EIO : result.lastErrno;
                        flowAdapter_.recordTransportOutcome(VpnTunTransportOutcome::Failed);
                    }
                }
                break;
            case VpnTunFlowAdapterResult::FlowDropped:
                ++result.policyDropped;
                break;
            case VpnTunFlowAdapterResult::RuntimeDroppedOwnerFault:
                ++result.runtimeDropped;
                break;
            case VpnTunFlowAdapterResult::PolicyBypassedParse:
            case VpnTunFlowAdapterResult::PolicyBypassedCapacity:
            case VpnTunFlowAdapterResult::FragmentBuffered:
            case VpnTunFlowAdapterResult::FragmentDuplicate:
            case VpnTunFlowAdapterResult::FragmentTimeout:
            case VpnTunFlowAdapterResult::FragmentMalformed:
            case VpnTunFlowAdapterResult::FragmentConflict:
            case VpnTunFlowAdapterResult::FragmentCapacity:
                ++result.policyBypassedWithoutTransport;
                flowAdapter_.recordTransportOutcome(VpnTunTransportOutcome::Unsupported);
                break;
            }
        }
        return result;
    }

    [[nodiscard]] VpnTunDrainResult drainTransportReturnPackets(
        std::size_t maxPackets,
        VpnTunPacketMetadata metadata = {}) noexcept {
        VpnTunDrainResult result;
        if (transportFd_ < 0 || tunFd_ < 0) {
            result.readErrors = 1;
            result.lastErrno = transportFd_ < 0 ? ENOTCONN : EBADF;
            return result;
        }

        std::array<std::uint8_t, kMaxTunPacketBytes> packet{};
        for (std::size_t packetIndex = 0; packetIndex < maxPackets; ++packetIndex) {
            pollfd fd{
                .fd = transportFd_,
                .events = POLLIN | POLLERR | POLLHUP,
                .revents = 0,
            };
            const int pollResult = ::poll(&fd, 1, 0);
            if (pollResult < 0) {
                if (errno == EINTR) {
                    continue;
                }
                ++result.readErrors;
                result.lastErrno = errno;
                break;
            }
            if (pollResult == 0) {
                break;
            }
            if ((fd.revents & POLLERR) != 0) {
                ++result.readErrors;
                result.lastErrno = EIO;
                break;
            }
            if ((fd.revents & POLLIN) == 0) {
                if ((fd.revents & POLLHUP) != 0) {
                    result.eof = true;
                }
                break;
            }

            const ssize_t bytes = ::read(transportFd_, packet.data(), packet.size());
            if (bytes < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                ++result.readErrors;
                result.lastErrno = errno;
                break;
            }
            if (bytes == 0) {
                result.eof = true;
                break;
            }

            ++result.packetsRead;
            const auto adapterResult = flowAdapter_.process(
                VpnTunPacketDirection::TransportReturn,
                std::span<const std::uint8_t>{
                    packet.data(), static_cast<std::size_t>(bytes)},
                static_cast<std::uint32_t>(bytes),
                metadata);
            if (adapterResult == VpnTunFlowAdapterResult::FlowDropped) {
                ++result.policyDropped;
                continue;
            }
            if (adapterResult == VpnTunFlowAdapterResult::RuntimeDroppedOwnerFault) {
                ++result.runtimeDropped;
                continue;
            }
            if (adapterResult != VpnTunFlowAdapterResult::FlowForwarded) {
                ++result.policyBypassedWithoutTransport;
            }
            if (writePacketToTun(std::span<const std::uint8_t>{
                    packet.data(), static_cast<std::size_t>(bytes)})) {
                ++result.returnedToTun;
                flowAdapter_.recordTransportOutcome(VpnTunTransportOutcome::Succeeded);
            } else {
                ++result.writeFailures;
                result.lastErrno = result.lastErrno == 0 ? EIO : result.lastErrno;
                flowAdapter_.recordTransportOutcome(VpnTunTransportOutcome::Failed);
            }
        }
        return result;
    }

    [[nodiscard]] SnortRuntime::VpnTunFdAttachResult attachVpnTunFd(
        const int tunFd, const bool enableIpv6) noexcept override {
        if (tunFd < 0) {
            return SnortRuntime::VpnTunFdAttachResult::error(
                "VPN_TUN_ATTACH_INVALID_FD", "VPN TUN fd is invalid");
        }
        if (tunFd_ >= 0) {
            ::close(tunFd_);
        }
        tunFd_ = tunFd;
        ipv6Enabled_ = enableIpv6;
        return SnortRuntime::VpnTunFdAttachResult::accepted();
    }

    [[nodiscard]] VpnTunFlowAdapterCounters flowAdapterCounters() const noexcept {
        return flowAdapter_.counters();
    }

private:
    static constexpr std::size_t kMaxTunPacketBytes = 65536;

    [[nodiscard]] bool writePacketToTransport(
        const std::span<const std::uint8_t> packet) noexcept {
        return transportFd_ >= 0 && writePacket(transportFd_, packet);
    }

    [[nodiscard]] bool writePacketToTun(
        const std::span<const std::uint8_t> packet) noexcept {
        return tunFd_ >= 0 && writePacket(tunFd_, packet);
    }

    [[nodiscard]] static bool writePacket(
        const int fd, const std::span<const std::uint8_t> packet) noexcept {
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

    int tunFd_ = -1;
    int transportFd_ = -1;
    bool ipv6Enabled_ = false;
    Policy::RuntimePacketPolicySnapshot packetPolicy_;
    VpnTunFlowAdapter flowAdapter_;
};

} // namespace SnortDatapath::Tun
