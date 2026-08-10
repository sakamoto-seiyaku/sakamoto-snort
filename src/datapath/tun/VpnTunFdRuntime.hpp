/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <RuntimeControl.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <utility>

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
    explicit VpnTunFdRuntime(const int tunFd) noexcept : tunFd_(tunFd) {}

    ~VpnTunFdRuntime() override {
        if (tunFd_ >= 0) {
            ::close(tunFd_);
        }
    }

    VpnTunFdRuntime(const VpnTunFdRuntime &) = delete;
    VpnTunFdRuntime &operator=(const VpnTunFdRuntime &) = delete;

    VpnTunFdRuntime(VpnTunFdRuntime &&other) noexcept
        : tunFd_(std::exchange(other.tunFd_, -1)) {}

    VpnTunFdRuntime &operator=(VpnTunFdRuntime &&other) noexcept {
        if (this != &other) {
            if (tunFd_ >= 0) {
                ::close(tunFd_);
            }
            tunFd_ = std::exchange(other.tunFd_, -1);
        }
        return *this;
    }

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

private:
    int tunFd_ = -1;
    bool ipv6Enabled_ = false;
};

} // namespace SnortDatapath::Tun
