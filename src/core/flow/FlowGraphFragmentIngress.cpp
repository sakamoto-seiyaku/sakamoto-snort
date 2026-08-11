/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphFragmentIngress.hpp>

#include <utility>

namespace SnortDatapath::Flow {
namespace {

[[nodiscard]] FlowGraphIngressStatus statusFor(
    const GraphInjectionResult result) noexcept {
    switch (result) {
    case GraphInjectionResult::Accepted:
        return FlowGraphIngressStatus::Accepted;
    case GraphInjectionResult::PolicyDrop:
        return FlowGraphIngressStatus::PolicyDrop;
    case GraphInjectionResult::ParseDrop:
        return FlowGraphIngressStatus::ParseFailOpen;
    case GraphInjectionResult::CapacityDrop:
        return FlowGraphIngressStatus::CapacityFailOpen;
    case GraphInjectionResult::OwnerFaultDrop:
        return FlowGraphIngressStatus::OwnerFaultFailOpen;
    }
    return FlowGraphIngressStatus::OwnerFaultFailOpen;
}

} // namespace

FlowGraphFragmentIngress::FlowGraphFragmentIngress(
    FlowSteeringRuntime &runtime,
    const Policy::PacketPolicySnapshot &policy,
    const FlowGraphIngressConfig ingressConfig,
    const FragmentSteeringConfig fragmentConfig)
    : parser_(ingressConfig),
      fragments_(runtime.distribution().selector(), fragmentConfig),
      injectionGate_(runtime, policy) {}

FlowGraphIngressResult FlowGraphFragmentIngress::injectFacts(
    PacketFacts facts) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        return {.status = FlowGraphIngressStatus::ParseFailOpen};
    }

    const auto owner = fragments_.selector().ownerFor(*key);
    PacketSubmission submission{.facts = std::move(facts)};
    const auto result = injectionGate_.inject(submission, owner);
    return {
        .status = statusFor(result),
        .policyDecision = result == GraphInjectionResult::PolicyDrop
            ? injectionGate_.lastPolicyDropDecision()
            : std::optional<Policy::PacketPolicyDecision>{},
        .acceptedFacts = result == GraphInjectionResult::Accepted
            ? injectionGate_.lastAcceptedFacts()
            : std::optional<PacketFacts>{},
        .flowEntryObservation = result == GraphInjectionResult::Accepted
            ? injectionGate_.lastFlowEntryObservation()
            : std::optional<FlowEntryObservation>{},
    };
}

FlowGraphIngressResult FlowGraphFragmentIngress::processReassembled(
    const FragmentReassemblyResult &fragment,
    const FlowGraphIngressMetadata metadata) noexcept {
    auto reassembledFacts = parser_.parseL3Packet(
        std::span<const std::byte>{fragment.packet},
        FlowGraphIngressMetadata{
            .direction = metadata.direction,
            .originalLength = static_cast<std::uint32_t>(fragment.packet.size()),
            .domain = metadata.domain,
        });

    const auto key = CanonicalFlowKey::from(reassembledFacts);
    if (!key.has_value()) {
        return {
            .status = FlowGraphIngressStatus::FragmentMalformed,
            .datagramKey = fragment.datagramKey,
            .fragmentReassembled = true,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    }

    auto owner = fragments_.selector().ownerFor(*key);
    if (fragment.owner.has_value()) {
        if (fragment.owner->flowKey != *key || fragment.owner->finalOwner != owner) {
            return {
                .status = FlowGraphIngressStatus::FragmentConflict,
                .datagramKey = fragment.datagramKey,
                .fragmentReassembled = true,
                .fragmentOwnerMetadata = true,
            };
        }
        owner = fragment.owner->finalOwner;
    }

    PacketSubmission submission{.facts = std::move(reassembledFacts)};
    const auto result = injectionGate_.inject(submission, owner);
    return {
        .status = statusFor(result),
        .datagramKey = fragment.datagramKey,
        .fragmentReassembled = true,
        .fragmentOwnerMetadata = fragment.owner.has_value(),
        .policyDecision = result == GraphInjectionResult::PolicyDrop
            ? injectionGate_.lastPolicyDropDecision()
            : std::optional<Policy::PacketPolicyDecision>{},
        .acceptedFacts = result == GraphInjectionResult::Accepted
            ? injectionGate_.lastAcceptedFacts()
            : std::optional<PacketFacts>{},
        .flowEntryObservation = result == GraphInjectionResult::Accepted
            ? injectionGate_.lastFlowEntryObservation()
            : std::optional<FlowEntryObservation>{},
    };
}

FlowGraphIngressResult FlowGraphFragmentIngress::processL3Packet(
    const std::span<const std::byte> l3Packet,
    const FlowGraphIngressMetadata metadata,
    const std::uint64_t fragmentNow) noexcept {
    const auto facts = parser_.parseL3Packet(l3Packet, metadata);
    if (!facts.fragmented) {
        static_cast<void>(fragments_.expire(fragmentNow));
        return injectFacts(facts);
    }

    FragmentReassemblyResult fragment{};
    try {
        fragment = fragments_.submit(l3Packet, metadata.originalLength, fragmentNow);
    } catch (...) {
        return {.status = FlowGraphIngressStatus::FragmentCapacity};
    }

    switch (fragment.status) {
    case FragmentSubmitStatus::Buffered:
        return {
            .status = FlowGraphIngressStatus::FragmentBuffered,
            .datagramKey = fragment.datagramKey,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    case FragmentSubmitStatus::Duplicate:
        return {
            .status = FlowGraphIngressStatus::FragmentDuplicate,
            .datagramKey = fragment.datagramKey,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    case FragmentSubmitStatus::Timeout:
        return {
            .status = FlowGraphIngressStatus::FragmentTimeout,
            .datagramKey = fragment.datagramKey,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    case FragmentSubmitStatus::Malformed:
        return {
            .status = FlowGraphIngressStatus::FragmentMalformed,
            .datagramKey = fragment.datagramKey,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    case FragmentSubmitStatus::Conflict:
        return {
            .status = FlowGraphIngressStatus::FragmentConflict,
            .datagramKey = fragment.datagramKey,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    case FragmentSubmitStatus::Capacity:
        return {
            .status = FlowGraphIngressStatus::FragmentCapacity,
            .datagramKey = fragment.datagramKey,
            .fragmentOwnerMetadata = fragment.owner.has_value(),
        };
    case FragmentSubmitStatus::Reassembled:
        return processReassembled(fragment, metadata);
    case FragmentSubmitStatus::NotFragment:
        break;
    }

    return injectFacts(facts);
}

std::size_t FlowGraphFragmentIngress::expireFragments(
    const std::uint64_t fragmentNow) noexcept {
    return fragments_.expire(fragmentNow);
}

} // namespace SnortDatapath::Flow
