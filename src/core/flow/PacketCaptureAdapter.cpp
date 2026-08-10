/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <PacketCaptureAdapter.hpp>

namespace SnortDatapath::Flow {

PacketCaptureAdapter::PacketCaptureAdapter(
    const AdapterKind adapter, const PacketCaptureAdapterConfig config) noexcept
    : adapter_(adapter),
      maxPrefixLength_(config.maxPrefixLength),
      parser_(FlowGraphIngressConfig{.maxL3Bytes = config.maxPrefixLength}) {}

PacketFacts PacketCaptureAdapter::normalize(
    const std::span<const std::byte> packetPrefix, const std::uint32_t originalLength,
    const DevicePacketDirection direction, FlowDomain domain) const noexcept {
    domain.adapter = adapter_;
    return parser_.parseL3Packet(
        packetPrefix,
        FlowGraphIngressMetadata{
            .direction = direction,
            .originalLength = originalLength,
            .domain = domain,
        });
}

} // namespace SnortDatapath::Flow
