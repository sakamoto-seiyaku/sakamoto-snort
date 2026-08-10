/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowGraphIngress.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace SnortDatapath::Flow {

struct PacketCaptureAdapterConfig final {
    static constexpr std::uint32_t kDefaultMaxPrefixLength = 512;

    std::uint32_t maxPrefixLength = kDefaultMaxPrefixLength;
};

/**
 * Compatibility wrapper for the graph-owned ingress parser.
 *
 * New datapath code should call FlowGraphIngressParser directly with complete
 * L3 bytes and normalized platform metadata. This wrapper exists for older
 * host vectors that still exercise the historical PacketCaptureAdapter name.
 */
class PacketCaptureAdapter final {
public:
    explicit PacketCaptureAdapter(
        AdapterKind adapter, PacketCaptureAdapterConfig config = {}) noexcept;

    [[nodiscard]] PacketFacts normalize(
        std::span<const std::byte> packetPrefix, std::uint32_t originalLength,
        DevicePacketDirection direction, FlowDomain domain) const noexcept;

    [[nodiscard]] AdapterKind adapterKind() const noexcept { return adapter_; }
    [[nodiscard]] std::uint32_t maxPrefixLength() const noexcept {
        return maxPrefixLength_;
    }

private:
    AdapterKind adapter_;
    std::uint32_t maxPrefixLength_;
    FlowGraphIngressParser parser_;
};

} // namespace SnortDatapath::Flow
