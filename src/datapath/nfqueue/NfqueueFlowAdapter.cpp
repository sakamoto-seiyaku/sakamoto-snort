/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

#include <PacketCaptureAdapter.hpp>

#include <array>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace {

SnortDatapath::Nfqueue::NfqueueFlowAdapterConfig validateConfig(
    SnortDatapath::Nfqueue::NfqueueFlowAdapterConfig config) {
    if (config.copyPrefixBytes == 0
        || config.copyPrefixBytes > static_cast<std::uint32_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("NFQUEUE flow adapter requires a valid copy prefix");
    }
    return config;
}

} // namespace

namespace SnortDatapath::Nfqueue {

NfqueueFlowAdapter::NfqueueFlowAdapter(NfqueueFlowAdapterConfig config)
    : config_(validateConfig(std::move(config))),
      steering_(Flow::WorkerLayout(config_.workerCount, config_.hashSeed), config_.queueCapacity) {}

NfqueueFlowAdapterResult NfqueueFlowAdapter::process(
    const std::uint32_t captureQueue, const std::uint8_t hook,
    const std::span<const std::uint8_t> payload,
    const std::uint32_t originalLengthHint) noexcept {
    std::lock_guard lock(mutex_);
    ++counters_.packetsSeen;

    const auto hookDirection = nfqueueHookToDirection(hook);
    const auto direction = hookDirection.has_value() && nfqueueDirectionIsInput(*hookDirection)
        ? Flow::DevicePacketDirection::Input
        : Flow::DevicePacketDirection::Output;
    const Flow::FlowDomain domain{
        .adapter = Flow::AdapterKind::RootNfqueue,
        .linuxUid = 0,
        .captureQueue = captureQueue,
        .networkContext = 0,
        .runtimeProfile = 0,
    };
    const auto originalLength = originalLengthHint == 0
        ? static_cast<std::uint32_t>(payload.size())
        : originalLengthHint;
    const Flow::PacketCaptureAdapter captureAdapter(
        Flow::AdapterKind::RootNfqueue,
        Flow::PacketCaptureAdapterConfig{.maxPrefixLength = config_.copyPrefixBytes});
    auto facts = captureAdapter.normalize(std::as_bytes(payload), originalLength, direction, domain);
    if (!hookDirection.has_value()) {
        facts.parseStatus = Flow::ParseStatus::Malformed;
    }

    ++counters_.normalizedPackets;
    const auto key = Flow::CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.parsePassThroughPackets;
        if (facts.fragmented) {
            ++counters_.fragmentPassThroughPackets;
        }
        return NfqueueFlowAdapterResult::FailOpenParse;
    }

    auto &distribution = steering_.distribution();
    const auto owner = distribution.selector().ownerFor(*key);
    std::array<Flow::PacketSubmission, 1> submissions{
        Flow::PacketSubmission{.facts = std::move(facts)}};
    if (distribution.submit(std::span<Flow::PacketSubmission>{submissions}) != 1) {
        ++counters_.capacityPassThroughPackets;
        return NfqueueFlowAdapterResult::FailOpenCapacity;
    }

    const auto descriptorId = distribution.dequeue(owner);
    auto *descriptor = descriptorId.has_value() ? distribution.descriptor(*descriptorId) : nullptr;
    if (descriptor == nullptr) {
        ++counters_.ownerFaultPassThroughPackets;
        return NfqueueFlowAdapterResult::FailOpenOwnerFault;
    }

    const auto decision = steering_.ownerGuard().check(owner, descriptor->facts,
                                                       descriptor->lease);
    if (decision == Flow::OwnerGuardDecision::Local
        && distribution.complete(*descriptorId, Flow::PacketLeaseOutcome::Accepted)) {
        ++counters_.acceptedPackets;
        return NfqueueFlowAdapterResult::FlowAccepted;
    }

    if (decision == Flow::OwnerGuardDecision::CorrectiveHandoff
        && distribution.requeueCorrective(*descriptorId, owner)) {
        const auto retryId = distribution.dequeue(owner);
        auto *retryDescriptor = retryId.has_value() ? distribution.descriptor(*retryId) : nullptr;
        if (retryDescriptor != nullptr
            && steering_.ownerGuard().check(owner, retryDescriptor->facts,
                                             retryDescriptor->lease) == Flow::OwnerGuardDecision::Local
            && distribution.complete(*retryId, Flow::PacketLeaseOutcome::Accepted)) {
            ++counters_.acceptedPackets;
            return NfqueueFlowAdapterResult::FlowAccepted;
        }
        if (retryId.has_value()) {
            if (auto *faultDescriptor = distribution.descriptor(*retryId);
                faultDescriptor != nullptr) {
                if (!faultDescriptor->lease.isTerminal()) {
                    (void)faultDescriptor->lease.drop();
                }
                (void)distribution.complete(*retryId, Flow::PacketLeaseOutcome::Dropped);
            }
        }
    }

    // The owner guard owns a fault's terminal DROP state. The distribution
    // releases the descriptor while the external NFQUEUE verdict stays
    // fail-open for the packet capture adapter.
    if (auto *faultDescriptor = distribution.descriptor(*descriptorId);
        faultDescriptor != nullptr) {
        if (!faultDescriptor->lease.isTerminal()) {
            (void)faultDescriptor->lease.drop();
        }
        (void)distribution.complete(*descriptorId, Flow::PacketLeaseOutcome::Dropped);
    }
    ++counters_.ownerFaultPassThroughPackets;
    return NfqueueFlowAdapterResult::FailOpenOwnerFault;
}

void NfqueueFlowAdapter::recordVerdictSendFailure() noexcept {
    std::lock_guard lock(mutex_);
    ++counters_.verdictSendFailures;
}

NfqueueFlowAdapterCounters NfqueueFlowAdapter::counters() const noexcept {
    std::lock_guard lock(mutex_);
    return counters_;
}

} // namespace SnortDatapath::Nfqueue
