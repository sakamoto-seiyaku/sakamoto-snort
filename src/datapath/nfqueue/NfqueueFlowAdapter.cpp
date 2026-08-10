/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

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
    if (config.fragmentLeaseCapacityPerDatagram == 0) {
        throw std::invalid_argument(
            "NFQUEUE flow adapter requires fragment lease capacity");
    }
    return config;
}

} // namespace

namespace SnortDatapath::Nfqueue {

NfqueueFlowAdapter::NfqueueFlowAdapter(NfqueueFlowAdapterConfig config)
    : config_(validateConfig(std::move(config))),
      steering_(Flow::WorkerLayout(config_.workerCount, config_.hashSeed), config_.queueCapacity),
      graphGate_(steering_, config_.packetPolicy == nullptr
          ? Policy::emptyPacketPolicySnapshot()
          : *config_.packetPolicy),
      ingressParser_(Flow::FlowGraphIngressConfig{.maxL3Bytes = config_.copyPrefixBytes}),
      fragmentSteering_(steering_.distribution().selector(), config_.fragmentSteering),
      fragmentLeaseBook_(config_.fragmentSteering.maxDatagrams,
                         config_.fragmentLeaseCapacityPerDatagram) {}

NfqueueFlowAdapterResult NfqueueFlowAdapter::process(
    const std::uint32_t captureQueue, const std::uint8_t hook,
    const std::span<const std::uint8_t> payload,
    const std::uint32_t originalLengthHint,
    const NfqueuePacketMetadata metadata,
    NfqueueFragmentLeaseContext leaseContext) noexcept {
    std::lock_guard lock(mutex_);
    ++counters_.packetsSeen;

    const auto fragmentTick = monotonicFragmentNow();
    static_cast<void>(fragmentLeaseBook_.expire(
        fragmentTick, config_.fragmentSteering.timeoutTicks));

    const auto hookDirection = nfqueueHookToDirection(hook);
    const auto direction = hookDirection.has_value() && nfqueueDirectionIsInput(*hookDirection)
        ? Flow::DevicePacketDirection::Input
        : Flow::DevicePacketDirection::Output;
    const Flow::FlowDomain domain{
        .adapter = Flow::AdapterKind::RootNfqueue,
        .linuxUid = metadata.linuxUid,
        .captureQueue = captureQueue,
        .networkContext = metadata.networkContext,
        .runtimeProfile = 0,
        .interfaceIndex = hookDirection.has_value()
            && nfqueueDirectionIsInput(*hookDirection)
            ? metadata.inputInterfaceIndex
            : metadata.outputInterfaceIndex,
    };
    const auto originalLength = originalLengthHint == 0
        ? static_cast<std::uint32_t>(payload.size())
        : originalLengthHint;
    auto facts = ingressParser_.parseL3Packet(
        std::as_bytes(payload),
        Flow::FlowGraphIngressMetadata{
            .direction = direction,
            .originalLength = originalLength,
            .domain = domain,
        });
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
        switch (graphResult) {
        case Flow::GraphInjectionResult::Accepted:
            ++counters_.acceptedPackets;
            return NfqueueFlowAdapterResult::FlowAccepted;
        case Flow::GraphInjectionResult::PolicyDrop:
            ++counters_.droppedPackets;
            return NfqueueFlowAdapterResult::FlowDropped;
        case Flow::GraphInjectionResult::ParseDrop:
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FailOpenParse;
        case Flow::GraphInjectionResult::CapacityDrop:
            ++counters_.capacityPassThroughPackets;
            return NfqueueFlowAdapterResult::FailOpenCapacity;
        case Flow::GraphInjectionResult::OwnerFaultDrop:
            ++counters_.ownerFaultPassThroughPackets;
            return NfqueueFlowAdapterResult::FailOpenOwnerFault;
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
            if (fragment.datagramKey.has_value() && leaseContext.valid()) {
                if (fragmentLeaseBook_.retain(
                        *fragment.datagramKey, *leaseContext.identity,
                        *leaseContext.mailbox, fragmentTick)) {
                    leaseContext.markRouted();
                } else if (leaseContext.mailbox->post(
                               *leaseContext.identity,
                               NfqueuePacketLeaseTerminalReason::FailOpen)) {
                    leaseContext.markRouted();
                }
            }
            ++counters_.fragmentBufferedPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentBuffered;
        case Flow::FragmentSubmitStatus::Duplicate:
            if (fragment.datagramKey.has_value() && leaseContext.valid()) {
                if (fragmentLeaseBook_.retain(
                        *fragment.datagramKey, *leaseContext.identity,
                        *leaseContext.mailbox, fragmentTick)) {
                    leaseContext.markRouted();
                } else if (leaseContext.mailbox->post(
                               *leaseContext.identity,
                               NfqueuePacketLeaseTerminalReason::FailOpen)) {
                    leaseContext.markRouted();
                }
            }
            ++counters_.fragmentDuplicatePackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentDuplicate;
        case Flow::FragmentSubmitStatus::Timeout:
            if (fragment.datagramKey.has_value()) {
                static_cast<void>(fragmentLeaseBook_.complete(
                    *fragment.datagramKey,
                    NfqueuePacketLeaseTerminalReason::FailOpen));
            }
            ++counters_.fragmentTimeoutPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentTimeout;
        case Flow::FragmentSubmitStatus::Malformed:
            if (fragment.datagramKey.has_value()) {
                static_cast<void>(fragmentLeaseBook_.complete(
                    *fragment.datagramKey,
                    NfqueuePacketLeaseTerminalReason::FailOpen));
            }
            ++counters_.fragmentMalformedPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentMalformed;
        case Flow::FragmentSubmitStatus::Conflict:
            if (fragment.datagramKey.has_value()) {
                static_cast<void>(fragmentLeaseBook_.complete(
                    *fragment.datagramKey,
                    NfqueuePacketLeaseTerminalReason::FailOpen));
            }
            ++counters_.fragmentConflictPackets;
            ++counters_.fragmentPassThroughPackets;
            ++counters_.parsePassThroughPackets;
            return NfqueueFlowAdapterResult::FragmentConflict;
        case Flow::FragmentSubmitStatus::Capacity:
            if (fragment.datagramKey.has_value()) {
                static_cast<void>(fragmentLeaseBook_.complete(
                    *fragment.datagramKey,
                    NfqueuePacketLeaseTerminalReason::FailOpen));
            }
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

            auto reassembledFacts = ingressParser_.parseL3Packet(
                std::span<const std::byte>{fragment.packet},
                Flow::FlowGraphIngressMetadata{
                    .direction = direction,
                    .originalLength = static_cast<std::uint32_t>(fragment.packet.size()),
                    .domain = domain,
                });
            const auto key = Flow::CanonicalFlowKey::from(reassembledFacts);
            if (!key.has_value()) {
                if (fragment.datagramKey.has_value()) {
                    static_cast<void>(fragmentLeaseBook_.complete(
                        *fragment.datagramKey,
                        NfqueuePacketLeaseTerminalReason::FailOpen));
                }
                ++counters_.fragmentMalformedPackets;
                ++counters_.fragmentPassThroughPackets;
                ++counters_.parsePassThroughPackets;
                return NfqueueFlowAdapterResult::FragmentMalformed;
            }

            auto owner = steering_.distribution().selector().ownerFor(*key);
            if (fragment.owner.has_value()) {
                if (fragment.owner->flowKey != *key
                    || fragment.owner->finalOwner != owner) {
                    if (fragment.datagramKey.has_value()) {
                        static_cast<void>(fragmentLeaseBook_.complete(
                            *fragment.datagramKey,
                            NfqueuePacketLeaseTerminalReason::FailOpen));
                    }
                    ++counters_.fragmentConflictPackets;
                    ++counters_.fragmentPassThroughPackets;
                    ++counters_.parsePassThroughPackets;
                    return NfqueueFlowAdapterResult::FragmentConflict;
                }
                owner = fragment.owner->finalOwner;
            }
            const auto graphResult = injectFacts(std::move(reassembledFacts), owner);
            if (fragment.datagramKey.has_value()) {
                static_cast<void>(fragmentLeaseBook_.complete(
                    *fragment.datagramKey, terminalReasonFor(graphResult)));
            }
            return graphResult;
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

std::uint64_t NfqueueFlowAdapter::monotonicFragmentNow() noexcept {
    const auto elapsed = std::chrono::steady_clock::now() - fragmentEpoch_;
    const auto wallMilliseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    if (wallMilliseconds > fragmentTick_) {
        fragmentTick_ = wallMilliseconds;
    }
    return fragmentTick_;
}

void NfqueueFlowAdapter::expireFragments(
    const std::uint64_t testAdvanceMilliseconds) noexcept {
    std::lock_guard lock(mutex_);
    static_cast<void>(monotonicFragmentNow());
    if (testAdvanceMilliseconds
        >= std::numeric_limits<std::uint64_t>::max() - fragmentTick_) {
        fragmentTick_ = std::numeric_limits<std::uint64_t>::max();
    } else {
        fragmentTick_ += testAdvanceMilliseconds;
    }
    static_cast<void>(fragmentLeaseBook_.expire(
        fragmentTick_, config_.fragmentSteering.timeoutTicks));
    static_cast<void>(fragmentSteering_.expire(fragmentTick_));
}

void NfqueueFlowAdapter::detachFragmentLeaseMailbox(
    NfqueueFragmentLeaseCompletionMailbox &mailbox) noexcept {
    std::lock_guard lock(mutex_);
    static_cast<void>(fragmentLeaseBook_.detach(mailbox));
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
