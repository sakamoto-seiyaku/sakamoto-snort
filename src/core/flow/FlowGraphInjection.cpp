/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowGraphInjection.hpp>

namespace SnortDatapath::Flow {
namespace {

bool isPolicyDrop(const Policy::PacketPolicyDecision &decision) noexcept {
    return decision.verdict == Policy::PacketPolicyVerdict::DROP;
}

} // namespace

GraphInjectionResult FlowGraphInjectionGate::inject(
    PacketSubmission &submission,
    const std::uint32_t currentWorker) noexcept {
    ++counters_.injectedPackets;
    lastPolicyDropDecision_.reset();
    lastFlowEntryObservation_.reset();
    const auto key = CanonicalFlowKey::from(submission.facts);
    if (!key.has_value()) {
        (void)submission.lease.drop();
        ++counters_.parseDrops;
        return GraphInjectionResult::ParseDrop;
    }

    auto &distribution = runtime_.distribution();
    const auto owner = distribution.selector().ownerFor(*key);
    if (distribution.submit(std::span<PacketSubmission>(&submission, 1)) != 1) {
        ++counters_.capacityDrops;
        return GraphInjectionResult::CapacityDrop;
    }

    const auto descriptorId = distribution.dequeue(owner);
    const auto *descriptor = descriptorId.has_value()
        ? distribution.descriptor(*descriptorId)
        : nullptr;
    const auto descriptorKey = descriptor == nullptr
        ? std::optional<CanonicalFlowKey>{}
        : CanonicalFlowKey::from(descriptor->facts);
    if (!descriptorId.has_value() || descriptor == nullptr || !descriptorKey.has_value()
        || distribution.selector().ownerFor(*descriptorKey) != owner) {
        if (descriptorId.has_value() && descriptor != nullptr) {
            (void)distribution.complete(*descriptorId, PacketLeaseOutcome::Dropped);
        }
        ++counters_.ownerFaultDrops;
        return GraphInjectionResult::OwnerFaultDrop;
    }

    const auto decision = distribution.checkOwner(
        *descriptorId, currentWorker, runtime_.ownerGuard());
    if (decision == OwnerGuardDecision::Local) {
        const auto policyDecision = policy_.evaluate(descriptor->facts);
        (void)runtime_.flowTable().reconcilePolicyRevision(
            descriptor->facts, policyDecision.revision);
        if (isPolicyDrop(policyDecision)) {
            if (distribution.complete(*descriptorId, PacketLeaseOutcome::Dropped)) {
                lastPolicyDropDecision_ = policyDecision;
                ++counters_.policyDrops;
                return GraphInjectionResult::PolicyDrop;
            }
        } else {
            const auto acceptedFacts = descriptor->facts;
            if (distribution.complete(*descriptorId, PacketLeaseOutcome::Accepted)) {
                lastFlowEntryObservation_ = runtime_.flowTable().observeAccepted(
                    acceptedFacts, policyDecision.revision);
                ++counters_.acceptedPackets;
                return GraphInjectionResult::Accepted;
            }
        }
    }

    if (decision == OwnerGuardDecision::CorrectiveHandoff) {
        ++counters_.correctiveHandoffs;
        if (distribution.requeueCorrective(*descriptorId, owner)) {
            const auto retryId = distribution.dequeue(owner);
            if (retryId.has_value() && distribution.checkOwner(
                    *retryId, owner, runtime_.ownerGuard()) == OwnerGuardDecision::Local) {
                const auto *retryDescriptor = distribution.descriptor(*retryId);
                const auto policyDecision = retryDescriptor == nullptr
                    ? Policy::PacketPolicyDecision::passNext()
                    : policy_.evaluate(retryDescriptor->facts);
                if (retryDescriptor != nullptr) {
                    (void)runtime_.flowTable().reconcilePolicyRevision(
                        retryDescriptor->facts, policyDecision.revision);
                }
                if (retryDescriptor != nullptr && isPolicyDrop(policyDecision)) {
                    if (distribution.complete(*retryId, PacketLeaseOutcome::Dropped)) {
                        lastPolicyDropDecision_ = policyDecision;
                        ++counters_.policyDrops;
                        return GraphInjectionResult::PolicyDrop;
                    }
                } else if (retryDescriptor != nullptr) {
                    const auto acceptedFacts = retryDescriptor->facts;
                    if (distribution.complete(*retryId, PacketLeaseOutcome::Accepted)) {
                        lastFlowEntryObservation_ =
                            runtime_.flowTable().observeAccepted(
                                acceptedFacts, policyDecision.revision);
                        ++counters_.acceptedPackets;
                        return GraphInjectionResult::Accepted;
                    }
                }
            }
            if (retryId.has_value() && distribution.descriptor(*retryId) != nullptr) {
                (void)distribution.complete(*retryId, PacketLeaseOutcome::Dropped);
            }
        }
    }

    if (distribution.descriptor(*descriptorId) != nullptr) {
        (void)distribution.complete(*descriptorId, PacketLeaseOutcome::Dropped);
    }
    ++counters_.ownerFaultDrops;
    return GraphInjectionResult::OwnerFaultDrop;
}

} // namespace SnortDatapath::Flow
