/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <VpnTunFlowAdapter.hpp>
#include <RuntimeControl.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace SnortDatapath::Tun {

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

    [[nodiscard]] bool packetPolicyControlReady() const noexcept override {
        return true;
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
    int tunFd_ = -1;
    bool ipv6Enabled_ = false;
    Policy::RuntimePacketPolicySnapshot packetPolicy_;
    VpnTunFlowAdapter flowAdapter_;
};

} // namespace SnortDatapath::Tun
