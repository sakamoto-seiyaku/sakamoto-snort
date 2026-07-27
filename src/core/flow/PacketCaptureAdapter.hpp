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

struct PacketCaptureAdapterConfig final {
    static constexpr std::uint32_t kDefaultMaxPrefixLength = 512;

    std::uint32_t maxPrefixLength = kDefaultMaxPrefixLength;
};

/**
 * Converts an IPv4/IPv6 L3 prefix from one capture adapter into shared facts.
 *
 * The adapter never owns the packet bytes. It only retains the configured
 * adapter identity and reads the supplied bounded span during normalization.
 * Fragment reassembly and IPv6 extension-header traversal are deliberately
 * outside this slice.
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
};

} // namespace SnortDatapath::Flow
