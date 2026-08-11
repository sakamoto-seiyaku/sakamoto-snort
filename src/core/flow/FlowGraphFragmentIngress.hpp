/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowGraphIngress.hpp>
#include <FlowGraphInjection.hpp>
#include <FragmentSteering.hpp>
#include <core/protocol/LpiRecognitionProvider.hpp>

#include <cstdint>
#include <optional>
#include <span>

namespace SnortDatapath::Flow {

enum class FlowGraphIngressStatus : std::uint8_t {
    Accepted,
    PolicyDrop,
    ParseFailOpen,
    CapacityFailOpen,
    OwnerFaultFailOpen,
    FragmentBuffered,
    FragmentDuplicate,
    FragmentTimeout,
    FragmentMalformed,
    FragmentConflict,
    FragmentCapacity,
};

struct FlowGraphIngressResult final {
    FlowGraphIngressStatus status = FlowGraphIngressStatus::ParseFailOpen;
    std::optional<FragmentKey> datagramKey;
    bool fragmentReassembled = false;
    bool fragmentOwnerMetadata = false;
    std::optional<Policy::PacketPolicyDecision> policyDecision;
    std::optional<PacketFacts> policyDropFacts;
    std::optional<PacketFacts> acceptedFacts;
    std::optional<FlowEntryObservation> flowEntryObservation;
    std::optional<Protocol::LpiPipelineOutcome> lpiRecognition;
};

/**
 * Graph-owned L3 ingress pipeline.
 *
 * Packet capture Adapters supply complete L3 bytes plus graph ingress metadata.
 * This Module owns shared parsing, fragment steering/reassembly, final-owner
 * selection, policy evaluation, and graph injection. Adapter callers see only a
 * graph-level terminal/fragment status and optional datagram identity for
 * platform completion routing.
 */
class FlowGraphFragmentIngress final {
public:
    FlowGraphFragmentIngress(
        FlowSteeringRuntime &runtime,
        const Policy::PacketPolicySnapshot &policy =
            Policy::emptyPacketPolicySnapshot(),
        FlowGraphIngressConfig ingressConfig = {},
        FragmentSteeringConfig fragmentConfig = {},
        Protocol::LpiRecognitionProvider *lpiProvider = nullptr);

    [[nodiscard]] FlowGraphIngressResult processL3Packet(
        std::span<const std::byte> l3Packet,
        FlowGraphIngressMetadata metadata,
        std::uint64_t fragmentNow) noexcept;

    /** Expire graph-owned fragment state using the caller's lane clock. */
    [[nodiscard]] std::size_t expireFragments(std::uint64_t fragmentNow) noexcept;
    [[nodiscard]] Protocol::LpiProviderStatus lpiProviderStatus() const noexcept {
        return lpiPipeline_.status();
    }

private:
    FlowGraphIngressParser parser_;
    FragmentSteering fragments_;
    FlowGraphInjectionGate injectionGate_;
    Protocol::LpiRecognitionPipeline lpiPipeline_;

    [[nodiscard]] FlowGraphIngressResult injectFacts(
        std::span<const std::byte> l3Packet,
        PacketFacts facts) noexcept;
    [[nodiscard]] FlowGraphIngressResult processReassembled(
        const FragmentReassemblyResult &fragment,
        FlowGraphIngressMetadata metadata) noexcept;
};

} // namespace SnortDatapath::Flow
