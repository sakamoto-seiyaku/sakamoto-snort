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
      steering_(Flow::WorkerLayout(config_.workerCount, config_.hashSeed), config_.queueCapacity),
      graphGate_(steering_) {}

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
    const auto graphResult = graphGate_.inject(submissions[0], owner);
    if (graphResult == Flow::GraphInjectionResult::CapacityDrop) {
        ++counters_.capacityPassThroughPackets;
        return NfqueueFlowAdapterResult::FailOpenCapacity;
    }
    if (graphResult == Flow::GraphInjectionResult::Accepted) {
        ++counters_.acceptedPackets;
        return NfqueueFlowAdapterResult::FlowAccepted;
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
    auto result = counters_;
    const auto &distributionCounters = steering_.distribution().counters();
    const auto &guardCounters = steering_.ownerGuard().counters();
    result.directPackets = distributionCounters.directPackets;
    result.parseDrops = distributionCounters.parseDrops;
    result.capacityDrops = distributionCounters.capacityDrops;
    result.normalWorkerHandoffs = distributionCounters.normalWorkerHandoffs;
    result.ownerGuardPasses = guardCounters.localPass;
    result.ownerGuardMismatches = guardCounters.mismatches;
    result.correctiveHandoffs = guardCounters.correctiveHandoffs;
    result.secondMismatchDrops = guardCounters.secondMismatchDrops;
    return result;
}

} // namespace SnortDatapath::Nfqueue
