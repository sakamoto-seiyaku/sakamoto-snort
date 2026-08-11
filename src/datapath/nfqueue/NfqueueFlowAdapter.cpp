/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThroughRuntime.hpp>

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

[[nodiscard]] SnortDatapath::Nfqueue::NfqueueFlowAdapterResult adapterResultFor(
    const SnortDatapath::Flow::FlowGraphIngressStatus status) noexcept {
    using GraphStatus = SnortDatapath::Flow::FlowGraphIngressStatus;
    using AdapterResult = SnortDatapath::Nfqueue::NfqueueFlowAdapterResult;
    switch (status) {
    case GraphStatus::Accepted:
        return AdapterResult::FlowAccepted;
    case GraphStatus::PolicyDrop:
        return AdapterResult::FlowDropped;
    case GraphStatus::ParseFailOpen:
        return AdapterResult::FailOpenParse;
    case GraphStatus::CapacityFailOpen:
        return AdapterResult::FailOpenCapacity;
    case GraphStatus::OwnerFaultFailOpen:
        return AdapterResult::FailOpenOwnerFault;
    case GraphStatus::FragmentBuffered:
        return AdapterResult::FragmentBuffered;
    case GraphStatus::FragmentDuplicate:
        return AdapterResult::FragmentDuplicate;
    case GraphStatus::FragmentTimeout:
        return AdapterResult::FragmentTimeout;
    case GraphStatus::FragmentMalformed:
        return AdapterResult::FragmentMalformed;
    case GraphStatus::FragmentConflict:
        return AdapterResult::FragmentConflict;
    case GraphStatus::FragmentCapacity:
        return AdapterResult::FragmentCapacity;
    }
    return AdapterResult::FailOpenOwnerFault;
}

} // namespace

namespace SnortDatapath::Nfqueue {

NfqueueFlowAdapter::NfqueueFlowAdapter(NfqueueFlowAdapterConfig config)
    : config_(validateConfig(std::move(config))),
      steering_(Flow::WorkerLayout(config_.workerCount, config_.hashSeed), config_.queueCapacity),
      graphIngress_(steering_,
                    config_.packetPolicy == nullptr
                        ? Policy::emptyPacketPolicySnapshot()
                        : *config_.packetPolicy,
                    Flow::FlowGraphIngressConfig{.maxL3Bytes = config_.copyPrefixBytes},
                    config_.fragmentSteering,
                    config_.lpiProvider),
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
    if (metadata.uidMetadataPresent) {
        ++counters_.uidMetadataPresentPackets;
    } else {
        ++counters_.uidMetadataMissingPackets;
    }
    counters_.lastObservedLinuxUid = metadata.linuxUid;
    counters_.lastObservedUidKnown = metadata.uidMetadataPresent;
    counters_.lastObservedNetworkContext = metadata.networkContext;
    counters_.lastObservedHook = hook;
    counters_.lastObservedInputInterfaceIndex = metadata.inputInterfaceIndex;
    counters_.lastObservedOutputInterfaceIndex = metadata.outputInterfaceIndex;

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
        .uidKnown = metadata.uidMetadataPresent,
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

    ++counters_.normalizedPackets;
    if (!hookDirection.has_value()) {
        static_cast<void>(graphIngress_.expireFragments(fragmentTick));
        ++counters_.parsePassThroughPackets;
        counters_.lastObservedResult = nfqueueFlowAdapterResultName(
            NfqueueFlowAdapterResult::FailOpenParse);
        return NfqueueFlowAdapterResult::FailOpenParse;
    }

    const auto graphResult = graphIngress_.processL3Packet(
        std::as_bytes(payload),
        Flow::FlowGraphIngressMetadata{
            .direction = direction,
            .originalLength = originalLength,
            .domain = domain,
        },
        fragmentTick);
    const auto adapterResult = adapterResultFor(graphResult.status);

    switch (graphResult.status) {
    case Flow::FlowGraphIngressStatus::Accepted:
        ++counters_.acceptedPackets;
        if (graphResult.acceptedFacts.has_value()
            && graphResult.flowEntryObservation.has_value()) {
            counters_.allowedFlowActivity.record(
                *graphResult.acceptedFacts,
                *graphResult.flowEntryObservation);
        }
        break;
    case Flow::FlowGraphIngressStatus::PolicyDrop:
        ++counters_.droppedPackets;
        if (graphResult.policyDecision.has_value()) {
            const auto &dropFacts = graphResult.policyDropFacts.has_value()
                ? *graphResult.policyDropFacts
                : Flow::PacketFacts{};
            const auto linuxUid = graphResult.policyDropFacts.has_value()
                ? dropFacts.domain.linuxUid
                : metadata.linuxUid;
            const auto uidKnown = graphResult.policyDropFacts.has_value()
                ? dropFacts.domain.uidKnown
                : metadata.uidMetadataPresent;
            const auto networkContext = graphResult.policyDropFacts.has_value()
                ? dropFacts.domain.networkContext
                : metadata.networkContext;
            counters_.policyDropActivity.record(
                *graphResult.policyDecision,
                linuxUid,
                uidKnown,
                networkContext);
        }
        break;
    case Flow::FlowGraphIngressStatus::ParseFailOpen:
        ++counters_.parsePassThroughPackets;
        break;
    case Flow::FlowGraphIngressStatus::CapacityFailOpen:
        ++counters_.capacityPassThroughPackets;
        break;
    case Flow::FlowGraphIngressStatus::OwnerFaultFailOpen:
        ++counters_.ownerFaultPassThroughPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentBuffered:
        if (graphResult.datagramKey.has_value() && leaseContext.valid()) {
            if (fragmentLeaseBook_.retain(
                    *graphResult.datagramKey, *leaseContext.identity,
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
        break;
    case Flow::FlowGraphIngressStatus::FragmentDuplicate:
        if (graphResult.datagramKey.has_value() && leaseContext.valid()) {
            if (fragmentLeaseBook_.retain(
                    *graphResult.datagramKey, *leaseContext.identity,
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
        break;
    case Flow::FlowGraphIngressStatus::FragmentTimeout:
        if (graphResult.datagramKey.has_value()) {
            static_cast<void>(fragmentLeaseBook_.complete(
                *graphResult.datagramKey,
                NfqueuePacketLeaseTerminalReason::FailOpen));
        }
        ++counters_.fragmentTimeoutPackets;
        ++counters_.fragmentPassThroughPackets;
        ++counters_.parsePassThroughPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentMalformed:
        if (graphResult.datagramKey.has_value()) {
            static_cast<void>(fragmentLeaseBook_.complete(
                *graphResult.datagramKey,
                NfqueuePacketLeaseTerminalReason::FailOpen));
        }
        ++counters_.fragmentMalformedPackets;
        ++counters_.fragmentPassThroughPackets;
        ++counters_.parsePassThroughPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentConflict:
        if (graphResult.datagramKey.has_value()) {
            static_cast<void>(fragmentLeaseBook_.complete(
                *graphResult.datagramKey,
                NfqueuePacketLeaseTerminalReason::FailOpen));
        }
        ++counters_.fragmentConflictPackets;
        ++counters_.fragmentPassThroughPackets;
        ++counters_.parsePassThroughPackets;
        break;
    case Flow::FlowGraphIngressStatus::FragmentCapacity:
        if (graphResult.datagramKey.has_value()) {
            static_cast<void>(fragmentLeaseBook_.complete(
                *graphResult.datagramKey,
                NfqueuePacketLeaseTerminalReason::FailOpen));
        }
        ++counters_.fragmentCapacityPackets;
        ++counters_.fragmentPassThroughPackets;
        ++counters_.capacityPassThroughPackets;
        break;
    }

    if (graphResult.datagramKey.has_value()
        && (graphResult.status == Flow::FlowGraphIngressStatus::Accepted
            || graphResult.status == Flow::FlowGraphIngressStatus::PolicyDrop
            || graphResult.status == Flow::FlowGraphIngressStatus::ParseFailOpen
            || graphResult.status == Flow::FlowGraphIngressStatus::CapacityFailOpen
            || graphResult.status == Flow::FlowGraphIngressStatus::OwnerFaultFailOpen)) {
        static_cast<void>(fragmentLeaseBook_.complete(
            *graphResult.datagramKey, terminalReasonFor(adapterResult)));
    }
    if (graphResult.fragmentReassembled) {
        ++counters_.fragmentReassembledPackets;
    }
    if (graphResult.fragmentOwnerMetadata) {
        ++counters_.fragmentOwnerMetadataPackets;
    }
    counters_.lastObservedResult = nfqueueFlowAdapterResultName(adapterResult);
    return adapterResult;
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
    static_cast<void>(graphIngress_.expireFragments(fragmentTick_));
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
    const auto &flowTable = steering_.flowTable();
    const auto &flowCounters = flowTable.counters();
    result.directPackets = distributionCounters.directPackets;
    result.parseDrops = distributionCounters.parseDrops;
    result.capacityDrops = distributionCounters.capacityDrops;
    result.normalWorkerHandoffs = distributionCounters.normalWorkerHandoffs;
    result.ownerGuardPasses = guardCounters.localPass;
    result.ownerGuardMismatches = guardCounters.mismatches;
    result.correctiveHandoffs = guardCounters.correctiveHandoffs;
    result.secondMismatchDrops = guardCounters.secondMismatchDrops;
    result.flowTableEntries = flowTable.size();
    result.flowTableCapacity = flowTable.capacity();
    result.flowTableHighWatermark = flowCounters.highWatermark;
    result.flowTableCapacityMisses = flowCounters.capacityMisses;
    result.lpiProvider = graphIngress_.lpiProviderStatus();
    return result;
}

} // namespace SnortDatapath::Nfqueue
