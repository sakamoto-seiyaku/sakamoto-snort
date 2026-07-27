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
      graphGate_(steering_),
      fragmentSteering_(steering_.distribution().selector(), config_.fragmentSteering) {}

NfqueueFlowAdapterResult NfqueueFlowAdapter::process(
    const std::uint32_t captureQueue, const std::uint8_t hook,
    const std::span<const std::uint8_t> payload,
    const std::uint32_t originalLengthHint) noexcept {
    std::lock_guard lock(mutex_);
    ++counters_.packetsSeen;

    if (fragmentTick_ != std::numeric_limits<std::uint64_t>::max()) {
        ++fragmentTick_;
    }
    const auto fragmentTick = fragmentTick_;

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
    if (!hookDirection.has_value()) {
        static_cast<void>(fragmentSteering_.expire(fragmentTick));
        ++counters_.parsePassThroughPackets;
        return NfqueueFlowAdapterResult::FailOpenParse;
    }

    const auto injectFacts = [this](Flow::PacketFacts graphFacts,
                                    const std::uint32_t owner) noexcept {
        std::array<Flow::PacketSubmission, 1> submissions{
            Flow::PacketSubmission{.facts = std::move(graphFacts)}};
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
    };

    if (facts.fragmented) {
        Flow::FragmentReassemblyResult fragment{};
        try {
            fragment = fragmentSteering_.submit(
                std::as_bytes(payload), originalLength, fragmentTick);
        } catch (...) {
            ++counters_.fragmentCapacityPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.capacityPassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentCapacity;
        }
        switch (fragment.status) {
        case Flow::FragmentSubmitStatus::Buffered:
            ++counters_.fragmentBufferedPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentBuffered;
        case Flow::FragmentSubmitStatus::Duplicate:
            ++counters_.fragmentDuplicatePackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentDuplicate;
        case Flow::FragmentSubmitStatus::Timeout:
            ++counters_.fragmentTimeoutPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentTimeout;
        case Flow::FragmentSubmitStatus::Malformed:
            ++counters_.fragmentMalformedPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentMalformed;
        case Flow::FragmentSubmitStatus::Conflict:
            ++counters_.fragmentConflictPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentConflict;
        case Flow::FragmentSubmitStatus::Capacity:
            ++counters_.fragmentCapacityPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.capacityPassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentCapacity;
        case Flow::FragmentSubmitStatus::Reassembled:
            break;
        case Flow::FragmentSubmitStatus::NotFragment:
            break;
        }

        if (fragment.status == Flow::FragmentSubmitStatus::Reassembled) {
            ++counters_.fragmentReassembledPackets;
            if (fragment.owner.has_value()) {
                ++counters_.fragmentOwnerMetadataPackets;
            }

            auto reassembledFacts = captureAdapter.normalize(
                std::span<const std::byte>{fragment.packet},
                static_cast<std::uint32_t>(fragment.packet.size()), direction, domain);
            const auto key = Flow::CanonicalFlowKey::from(reassembledFacts);
            if (!key.has_value()) {
                ++counters_.fragmentMalformedPackets;
                ++counters_.fragmentPassThroughPackets;
                ++counters_.parsePassThroughPackets;
                return NfqueueFlowAdapterResult::FragmentMalformed;
            }

            auto owner = steering_.distribution().selector().ownerFor(*key);
            if (fragment.owner.has_value()) {
                if (fragment.owner->flowKey != *key
                    || fragment.owner->finalOwner != owner) {
                    ++counters_.fragmentConflictPackets;
                    ++counters_.fragmentPassThroughPackets;
                    ++counters_.parsePassThroughPackets;
                    return NfqueueFlowAdapterResult::FragmentConflict;
                }
                owner = fragment.owner->finalOwner;
            }
            return injectFacts(std::move(reassembledFacts), owner);
        }
    }

    static_cast<void>(fragmentSteering_.expire(fragmentTick));

    const auto key = Flow::CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.parsePassThroughPackets;
        return NfqueueFlowAdapterResult::FailOpenParse;
    }

    const auto owner = steering_.distribution().selector().ownerFor(*key);
    return injectFacts(std::move(facts), owner);
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
