/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace SnortDatapath::Flow {

struct FlowGraphIngressConfig final {
    static constexpr std::uint32_t kDefaultMaxL3Bytes = 512;

    std::uint32_t maxL3Bytes = kDefaultMaxL3Bytes;
};

struct FlowGraphIngressMetadata final {
    DevicePacketDirection direction = DevicePacketDirection::Input;
    std::uint32_t originalLength = 0;
    FlowDomain domain;
};

/**
 * Graph-owned ingress parser for complete L3 packet bytes.
 *
 * Platform adapters supply bytes plus normalized platform metadata. The parser
 * constructs shared PacketFacts before owner selection, policy, or completion.
 * This keeps parser ownership with the shared graph seam rather than with any
 * Root/NFQUEUE or VPN/TUN capture adapter.
 */
class FlowGraphIngressParser final {
public:
    explicit FlowGraphIngressParser(FlowGraphIngressConfig config = {}) noexcept;

    [[nodiscard]] PacketFacts parseL3Packet(
        std::span<const std::byte> l3Packet,
        FlowGraphIngressMetadata metadata) const noexcept;

    [[nodiscard]] std::uint32_t maxL3Bytes() const noexcept {
        return maxL3Bytes_;
    }

private:
    std::uint32_t maxL3Bytes_;
};

[[nodiscard]] PacketFacts parseIngressPacketFacts(
    std::span<const std::byte> l3Packet,
    FlowGraphIngressMetadata metadata,
    FlowGraphIngressConfig config = {}) noexcept;

} // namespace SnortDatapath::Flow
