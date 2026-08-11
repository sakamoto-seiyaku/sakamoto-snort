/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowSteering.hpp>

#include <algorithm>
#include <limits>

namespace SnortDatapath::Flow {
namespace {

constexpr std::uint8_t kTcpProtocol = 6;
constexpr std::uint8_t kUdpProtocol = 17;
constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;
constexpr std::uint64_t kDescriptorSlotMask = 0xffffffffULL;

bool addressLess(const IpAddress &left, const IpAddress &right) noexcept {
    if (left.family != right.family) {
        return static_cast<std::uint8_t>(left.family)
            < static_cast<std::uint8_t>(right.family);
    }
    return std::lexicographical_compare(
        left.bytes.begin(), left.bytes.end(), right.bytes.begin(), right.bytes.end());
}

void hashByte(std::uint64_t &hash, const std::uint8_t value) noexcept {
    hash ^= value;
    hash *= kFnvPrime;
}

void hashAddress(std::uint64_t &hash, const IpAddress &address) noexcept {
    hashByte(hash, static_cast<std::uint8_t>(address.family));
    for (const auto value : address.bytes) {
        hashByte(hash, value);
    }
}

void hashU16(std::uint64_t &hash, const std::uint16_t value) noexcept {
    hashByte(hash, static_cast<std::uint8_t>(value >> 8U));
    hashByte(hash, static_cast<std::uint8_t>(value & 0xffU));
}

bool packetMatchesOrigin(const FlowEntry &entry, const PacketFacts &facts) noexcept {
    return facts.source == entry.originSource
        && facts.destination == entry.originDestination
        && facts.sourcePort == entry.originSourcePort
        && facts.destinationPort == entry.originDestinationPort;
}

bool hasMappedResult(const LpiRecognitionState &state,
                     const sucre::protocol::ApplicationProtocolId protocolId) noexcept {
    return std::any_of(
        state.mappedResults.begin(), state.mappedResults.end(),
        [protocolId](const LpiRecognitionResult &result) noexcept {
            return result.protocolId == protocolId;
        });
}

PacketDescriptorSlot descriptorSlot(const PacketDescriptorId id) noexcept {
    return static_cast<PacketDescriptorSlot>(id & kDescriptorSlotMask);
}

std::uint32_t descriptorGeneration(const PacketDescriptorId id) noexcept {
    return static_cast<std::uint32_t>(id >> 32U);
}

PacketDescriptorId makeDescriptorId(const PacketDescriptorSlot slot,
                                    const std::uint32_t generation) noexcept {
    return (static_cast<PacketDescriptorId>(generation) << 32U) | slot;
}

void compactQueue(std::vector<PacketDescriptorId> &ids, std::size_t &head) noexcept {
    if (head == 0) {
        return;
    }
    if (head == ids.size()) {
        ids.clear();
        head = 0;
        return;
    }
    std::move(ids.begin() + static_cast<std::ptrdiff_t>(head), ids.end(), ids.begin());
    ids.resize(ids.size() - head);
    head = 0;
}

} // namespace

IpAddress IpAddress::v4(const std::array<std::uint8_t, 4> value) noexcept {
    IpAddress result;
    result.family = AddressFamily::Ipv4;
    std::copy(value.begin(), value.end(), result.bytes.begin());
    return result;
}

IpAddress IpAddress::v6(const std::array<std::uint8_t, 16> value) noexcept {
    IpAddress result;
    result.family = AddressFamily::Ipv6;
    result.bytes = value;
    return result;
}

bool PacketFacts::isCanonicalizable() const noexcept {
    return source.family == destination.family
        && (source.family == AddressFamily::Ipv4 || source.family == AddressFamily::Ipv6)
        && (ipProtocol == kTcpProtocol || ipProtocol == kUdpProtocol)
        && portsAvailable && !fragmented && parseStatus == ParseStatus::Ready
        && originalLength > 0 && boundedPrefixLength > 0
        && boundedPrefixLength <= originalLength;
}

bool PacketFacts::hasTransportPayload() const noexcept {
    return isCanonicalizable()
        && transportPayloadLength > 0
        && transportPayloadOffset < boundedPrefixLength
        && transportPayloadLength <= boundedPrefixLength - transportPayloadOffset;
}

std::optional<CanonicalFlowKey> CanonicalFlowKey::from(const PacketFacts &facts) noexcept {
    if (!facts.isCanonicalizable()) {
        return std::nullopt;
    }

    CanonicalFlowKey key{
        .family = facts.source.family,
        .ipProtocol = facts.ipProtocol,
        .endpointA = facts.source,
        .endpointB = facts.destination,
        .portA = facts.sourcePort,
        .portB = facts.destinationPort,
    };
    if (addressLess(key.endpointB, key.endpointA)
        || (key.endpointA == key.endpointB && key.portB < key.portA)) {
        std::swap(key.endpointA, key.endpointB);
        std::swap(key.portA, key.portB);
    }
    return key;
}

WorkerLayout::WorkerLayout(const std::uint32_t count, const std::uint64_t seed)
    : workerCount_(count), hashSeed_(seed) {
    if (workerCount_ == 0) {
        throw std::invalid_argument("WorkerLayout requires at least one worker");
    }
}

OwnerSelector::OwnerSelector(WorkerLayout layout) : layout_(layout) {
    if (layout_.workerCount() == 0) {
        throw std::invalid_argument("OwnerSelector requires at least one worker");
    }
}

std::uint32_t OwnerSelector::ownerFor(const CanonicalFlowKey &key) const noexcept {
    std::uint64_t hash = kFnvOffset ^ layout_.hashSeed();
    hashByte(hash, key.ipProtocol);
    hashAddress(hash, key.endpointA);
    hashAddress(hash, key.endpointB);
    hashU16(hash, key.portA);
    hashU16(hash, key.portB);
    return static_cast<std::uint32_t>(hash % layout_.workerCount());
}

bool PacketLease::accept() noexcept {
    if (isTerminal()) {
        ++duplicateTerminalAttempts_;
        return false;
    }
    outcome_ = PacketLeaseOutcome::Accepted;
    return true;
}

PacketLease::PacketLease(PacketLease &&other) noexcept
    : outcome_(other.outcome_), corrections_(other.corrections_),
      duplicateTerminalAttempts_(other.duplicateTerminalAttempts_) {
    other.outcome_ = PacketLeaseOutcome::Dropped;
    other.corrections_ = 0;
    other.duplicateTerminalAttempts_ = 0;
}

PacketLease &PacketLease::operator=(PacketLease &&other) noexcept {
    if (this != &other) {
        outcome_ = other.outcome_;
        corrections_ = other.corrections_;
        duplicateTerminalAttempts_ = other.duplicateTerminalAttempts_;
        other.outcome_ = PacketLeaseOutcome::Dropped;
        other.corrections_ = 0;
        other.duplicateTerminalAttempts_ = 0;
    }
    return *this;
}

bool PacketLease::drop() noexcept {
    if (isTerminal()) {
        ++duplicateTerminalAttempts_;
        return false;
    }
    outcome_ = PacketLeaseOutcome::Dropped;
    return true;
}

bool PacketLease::requestCorrectiveHandoff() noexcept {
    if (isTerminal() || corrections_ != 0) {
        return false;
    }
    corrections_ = 1;
    return true;
}

namespace {

std::size_t checkedDescriptorCount(const WorkerLayout &layout, const std::size_t queueCapacity) {
    if (queueCapacity == 0) {
        throw std::invalid_argument("PrimarySoftwareDistribution requires queue capacity");
    }
    if (queueCapacity > std::numeric_limits<std::size_t>::max() / layout.workerCount()) {
        throw std::length_error("PrimarySoftwareDistribution descriptor pool is too large");
    }
    const auto count = queueCapacity * layout.workerCount();
    if (count > std::numeric_limits<PacketDescriptorSlot>::max()) {
        throw std::length_error("PrimarySoftwareDistribution descriptor id space is exhausted");
    }
    return count;
}

} // namespace

PrimarySoftwareDistribution::PrimarySoftwareDistribution(
    WorkerLayout layout, const std::size_t queueCapacity)
    : selector_(layout), queueCapacity_(queueCapacity),
      descriptors_(checkedDescriptorCount(layout, queueCapacity_)),
      freeDescriptors_(), queues_(layout.workerCount()),
      activeDescriptors_(descriptors_.size(), false),
      queuedDescriptors_(descriptors_.size(), false),
      descriptorGenerations_(descriptors_.size(), 0) {
    freeDescriptors_.reserve(descriptors_.size());
    for (std::size_t index = descriptors_.size(); index > 0; --index) {
        freeDescriptors_.push_back(static_cast<PacketDescriptorSlot>(index - 1));
    }
    for (auto &queue : queues_) {
        queue.ids.reserve(queueCapacity_);
    }
}

bool PrimarySoftwareDistribution::enqueue(const PacketFacts &facts, PacketLease *lease) noexcept {
    if (lease != nullptr && lease->isTerminal()) {
        ++counters_.alreadyTerminalPackets;
        return false;
    }
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        if (lease != nullptr) {
            (void)lease->drop();
        }
        ++counters_.parseDrops;
        return false;
    }
    const auto owner = selector_.ownerFor(*key);
    auto &target = queues_[owner];
    compactQueue(target.ids, target.head);
    if (target.ids.size() >= queueCapacity_ || freeDescriptors_.empty()) {
        if (lease != nullptr) {
            (void)lease->drop();
        }
        ++counters_.capacityDrops;
        return false;
    }
    const auto slot = freeDescriptors_.back();
    freeDescriptors_.pop_back();
    auto generation = descriptorGenerations_[slot] + 1U;
    if (generation == 0) {
        generation = 1;
    }
    descriptorGenerations_[slot] = generation;
    const auto descriptorId = makeDescriptorId(slot, generation);
    auto &descriptor = descriptors_[slot];
    PacketLease descriptorLease;
    if (lease != nullptr) {
        descriptorLease = std::move(*lease);
    }
    descriptor = PacketDescriptor{
        .facts = facts,
        .lease = std::move(descriptorLease),
        .targetWorker = owner,
    };
    activeDescriptors_[slot] = true;
    queuedDescriptors_[slot] = true;
    target.ids.push_back(descriptorId);
    ++counters_.directPackets;
    return true;
}

std::size_t PrimarySoftwareDistribution::submit(
    const std::span<PacketSubmission> packets) noexcept {
    std::size_t queued = 0;
    for (auto &packet : packets) {
        if (enqueue(packet.facts, &packet.lease)) {
            ++queued;
        }
    }
    return queued;
}

std::size_t PrimarySoftwareDistribution::submit(
    const std::span<const PacketFacts> packets) noexcept {
    std::size_t queued = 0;
    for (const auto &facts : packets) {
        if (enqueue(facts, nullptr)) {
            ++queued;
        }
    }
    return queued;
}

std::size_t PrimarySoftwareDistribution::queueDepth(const std::uint32_t worker) const noexcept {
    if (worker >= queues_.size()) {
        return 0;
    }
    const auto &queue = queues_[worker];
    return queue.ids.size() - queue.head;
}

std::optional<PacketDescriptorId> PrimarySoftwareDistribution::dequeue(
    const std::uint32_t worker) noexcept {
    if (worker >= queues_.size()) {
        return std::nullopt;
    }
    auto &queue = queues_[worker];
    if (queue.head == queue.ids.size()) {
        queue.ids.clear();
        queue.head = 0;
        return std::nullopt;
    }
    const auto descriptorId = queue.ids[queue.head++];
    queuedDescriptors_[descriptorSlot(descriptorId)] = false;
    return descriptorId;
}

const PacketDescriptor *PrimarySoftwareDistribution::descriptor(
    const PacketDescriptorId id) noexcept {
    const auto slot = descriptorSlot(id);
    if (slot >= descriptors_.size() || descriptorGeneration(id) == 0
        || descriptorGenerations_[slot] != descriptorGeneration(id) || !activeDescriptors_[slot]) {
        return nullptr;
    }
    return &descriptors_[slot];
}

const PacketDescriptor *PrimarySoftwareDistribution::descriptor(
    const PacketDescriptorId id) const noexcept {
    const auto slot = descriptorSlot(id);
    if (slot >= descriptors_.size() || descriptorGeneration(id) == 0
        || descriptorGenerations_[slot] != descriptorGeneration(id) || !activeDescriptors_[slot]) {
        return nullptr;
    }
    return &descriptors_[slot];
}

bool PrimarySoftwareDistribution::complete(
    const PacketDescriptorId id, const PacketLeaseOutcome outcome) noexcept {
    auto *entry = descriptor(id);
    if (entry == nullptr) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    const auto slot = descriptorSlot(id);
    if (queuedDescriptors_[slot]) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    const bool alreadyCompleted = outcome != PacketLeaseOutcome::Open
        && entry->lease.outcome() == outcome;
    const bool completed = alreadyCompleted || (outcome == PacketLeaseOutcome::Accepted
        ? descriptors_[slot].lease.accept() : outcome == PacketLeaseOutcome::Dropped
        ? descriptors_[slot].lease.drop() : false);
    if (!completed) {
        return false;
    }
    activeDescriptors_[slot] = false;
    queuedDescriptors_[slot] = false;
    freeDescriptors_.push_back(slot);
    return true;
}

bool PrimarySoftwareDistribution::requestCorrectiveHandoff(
    const PacketDescriptorId id) noexcept {
    const auto *entry = descriptor(id);
    const auto slot = descriptorSlot(id);
    if (entry == nullptr || queuedDescriptors_[slot] || entry->lease.isTerminal()) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    if (!descriptors_[slot].lease.requestCorrectiveHandoff()) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    return true;
}

void PrimarySoftwareDistribution::releaseDropped(const PacketDescriptorSlot slot) noexcept {
    auto &entry = descriptors_[slot];
    if (entry.lease.drop()) {
        activeDescriptors_[slot] = false;
        queuedDescriptors_[slot] = false;
        freeDescriptors_.push_back(slot);
    }
}

bool PrimarySoftwareDistribution::requeueCorrective(
    const PacketDescriptorId id, const std::uint32_t targetWorker) noexcept {
    const auto *entry = descriptor(id);
    const auto slot = descriptorSlot(id);
    if (entry == nullptr || targetWorker >= queues_.size()
        || entry->lease.correctionCount() != 1 || queuedDescriptors_[slot]
        || entry->lease.isTerminal()) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    const auto key = CanonicalFlowKey::from(entry->facts);
    if (!key.has_value() || selector_.ownerFor(*key) != targetWorker) {
        ++counters_.staleDescriptorHandles;
        releaseDropped(slot);
        return false;
    }
    auto &target = queues_[targetWorker];
    compactQueue(target.ids, target.head);
    if (target.ids.size() >= queueCapacity_) {
        ++counters_.capacityDrops;
        releaseDropped(slot);
        return false;
    }
    descriptors_[slot].targetWorker = targetWorker;
    queuedDescriptors_[slot] = true;
    target.ids.push_back(id);
    return true;
}

OwnerGuard::OwnerGuard(WorkerLayout layout) : selector_(layout) {}

OwnerGuard::OwnerGuard(const OwnerSelector &selector) : selector_(selector) {}

OwnerGuardDecision OwnerGuard::check(
    const std::uint32_t currentWorker, const PacketFacts &facts,
    PacketLease &lease) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        (void)lease.drop();
        return OwnerGuardDecision::Drop;
    }
    const auto expectedWorker = selector_.ownerFor(*key);
    if (currentWorker == expectedWorker) {
        ++counters_.localPass;
        return OwnerGuardDecision::Local;
    }

    ++counters_.mismatches;
    if (lease.requestCorrectiveHandoff()) {
        ++counters_.correctiveHandoffs;
        return OwnerGuardDecision::CorrectiveHandoff;
    }

    ++counters_.secondMismatchDrops;
    (void)lease.drop();
    return OwnerGuardDecision::Drop;
}

OwnerGuardDecision PrimarySoftwareDistribution::checkOwner(
    const PacketDescriptorId id, const std::uint32_t currentWorker,
    OwnerGuard &guard) noexcept {
    const auto *entry = descriptor(id);
    const auto slot = descriptorSlot(id);
    if (entry == nullptr || queuedDescriptors_[slot]) {
        ++counters_.staleDescriptorHandles;
        return OwnerGuardDecision::Drop;
    }
    return guard.check(currentWorker, entry->facts, descriptors_[slot].lease);
}

BoundedFlowTable::BoundedFlowTable(const std::size_t capacity)
    : capacity_(capacity) {
    entries_.reserve(capacity_);
}

const FlowEntry *BoundedFlowTable::find(const CanonicalFlowKey &key) const noexcept {
    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == key; });
    return found == entries_.end() ? nullptr : &*found;
}

std::optional<FlowEntryRevisionObservation> BoundedFlowTable::reconcilePolicyRevision(
    const PacketFacts &facts, const std::uint64_t policyRevision) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.nonCanonicalPackets;
        return std::nullopt;
    }

    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == *key; });
    if (found == entries_.end()) {
        return FlowEntryRevisionObservation{
            .found = false,
            .decisionStateCleared = false,
            .previousPolicyRevision = 0,
            .currentPolicyRevision = policyRevision,
        };
    }

    const auto previousPolicyRevision = found->policyRevision;
    auto cleared = false;
    if (found->decisionStateValid && previousPolicyRevision != policyRevision) {
        found->decisionStateValid = false;
        found->policyRevision = policyRevision;
        ++found->decisionStateClears;
        ++counters_.decisionStateClears;
        cleared = true;
    }
    return FlowEntryRevisionObservation{
        .found = true,
        .decisionStateCleared = cleared,
        .previousPolicyRevision = previousPolicyRevision,
        .currentPolicyRevision = policyRevision,
    };
}

std::optional<FlowAttributionObservation> BoundedFlowTable::applyResolvedAttribution(
    const PacketFacts &facts, const std::uint32_t linuxUid,
    const bool uidKnown) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.nonCanonicalPackets;
        return std::nullopt;
    }

    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == *key; });
    if (found == entries_.end()) {
        ++counters_.attributionMisses;
        return FlowAttributionObservation{
            .found = false,
            .updated = false,
            .previousLinuxUid = 0,
            .previousUidKnown = false,
            .currentLinuxUid = linuxUid,
            .currentUidKnown = uidKnown,
            .attributionUpdates = 0,
        };
    }

    const auto previousLinuxUid = found->linuxUid;
    const auto previousUidKnown = found->uidKnown;
    const auto updated = previousLinuxUid != linuxUid || previousUidKnown != uidKnown;
    if (updated) {
        found->linuxUid = linuxUid;
        found->uidKnown = uidKnown;
        ++found->attributionUpdates;
        ++counters_.attributionUpdates;
    }
    return FlowAttributionObservation{
        .found = true,
        .updated = updated,
        .previousLinuxUid = previousLinuxUid,
        .previousUidKnown = previousUidKnown,
        .currentLinuxUid = found->linuxUid,
        .currentUidKnown = found->uidKnown,
        .attributionUpdates = found->attributionUpdates,
    };
}

PacketFacts BoundedFlowTable::factsWithResolvedAttribution(
    const PacketFacts &facts) noexcept {
    if (facts.domain.uidKnown) {
        return facts;
    }

    auto resolved = facts;
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.nonCanonicalPackets;
        return resolved;
    }

    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == *key; });
    if (found == entries_.end() || !found->uidKnown) {
        return resolved;
    }

    resolved.domain.linuxUid = found->linuxUid;
    resolved.domain.uidKnown = true;
    ++counters_.attributionResolutions;
    return resolved;
}

std::optional<LpiRecognitionUpdate> BoundedFlowTable::recordLpiRecognition(
    const PacketFacts &facts,
    const bool payloadBearing,
    const std::optional<sucre::protocol::ApplicationProtocolId> mappedResult,
    const bool providerResultPresent,
    const bool detectorDone,
    const bool budgetExhausted) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.nonCanonicalPackets;
        return std::nullopt;
    }

    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == *key; });
    if (found == entries_.end()) {
        ++counters_.lpiFlowMisses;
        return LpiRecognitionUpdate{
            .found = false,
        };
    }

    auto &state = found->lpiRecognition;
    const auto direction = packetMatchesOrigin(*found, facts)
        ? FlowRelativeDirection::Orig
        : FlowRelativeDirection::Reply;

    if (state.terminal()) {
        ++counters_.lpiTerminalSkips;
        return LpiRecognitionUpdate{
            .found = true,
            .payloadSubmitted = false,
            .mappedResultAppended = false,
            .duplicateMappedResult = false,
            .unmappedResult = false,
            .terminalSkip = true,
            .terminalState = state.terminalState,
            .direction = direction,
            .payloadPacketSequence = state.payloadPacketsSubmitted,
            .mappedResultCount = state.mappedResults.size(),
            .latestExactResult = state.latestExactResult(),
        };
    }

    auto payloadSubmitted = false;
    auto appended = false;
    auto duplicate = false;
    auto unmapped = false;
    if (payloadBearing) {
        ++state.payloadPacketsSubmitted;
        ++counters_.lpiPayloadPackets;
        payloadSubmitted = true;
        if (mappedResult.has_value()) {
            state.latestExactProtocolId = *mappedResult;
            if (hasMappedResult(state, *mappedResult)) {
                duplicate = true;
                ++counters_.lpiDuplicateMappedResults;
            } else if (state.mappedResults.size() < LpiRecognitionState::kMaxMappedResults) {
                state.mappedResults.push_back(LpiRecognitionResult{
                    .protocolId = *mappedResult,
                    .firstPayloadPacketSequence = state.payloadPacketsSubmitted,
                    .direction = direction,
                });
                appended = true;
                ++counters_.lpiMappedResults;
            } else {
                ++counters_.lpiResultCapacityMisses;
            }
        } else if (providerResultPresent) {
            unmapped = true;
            ++counters_.lpiUnmappedResults;
        }
    }

    const auto internalBudgetExhausted =
        payloadSubmitted
        && state.payloadPacketsSubmitted >= LpiRecognitionState::kMaxPayloadPackets
        && !detectorDone;
    if (budgetExhausted || internalBudgetExhausted) {
        state.terminalState = LpiRecognitionTerminalState::Exhausted;
    } else if (detectorDone) {
        state.terminalState = LpiRecognitionTerminalState::Done;
    }

    return LpiRecognitionUpdate{
        .found = true,
        .payloadSubmitted = payloadSubmitted,
        .mappedResultAppended = appended,
        .duplicateMappedResult = duplicate,
        .unmappedResult = unmapped,
        .terminalSkip = false,
        .terminalState = state.terminalState,
        .direction = direction,
        .payloadPacketSequence = state.payloadPacketsSubmitted,
        .mappedResultCount = state.mappedResults.size(),
        .latestExactResult = state.latestExactResult(),
    };
}

std::optional<LpiRecognitionState> BoundedFlowTable::lpiRecognitionStateFor(
    const PacketFacts &facts) const noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        return std::nullopt;
    }

    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == *key; });
    if (found == entries_.end()) {
        return std::nullopt;
    }
    return found->lpiRecognition;
}

std::optional<FlowEntryObservation> BoundedFlowTable::observeAccepted(
    const PacketFacts &facts, const std::uint64_t policyRevision) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.nonCanonicalPackets;
        return std::nullopt;
    }

    const auto found = std::find_if(
        entries_.begin(), entries_.end(),
        [&key](const FlowEntry &entry) noexcept { return entry.key == *key; });
    if (found != entries_.end()) {
        const auto decisionStateCleared =
            !found->decisionStateValid && found->policyRevision == policyRevision
            && found->decisionStateClears > 0;
        const auto attributionUpdated = facts.domain.uidKnown
            && (found->linuxUid != facts.domain.linuxUid || !found->uidKnown);
        if (attributionUpdated) {
            found->linuxUid = facts.domain.linuxUid;
            found->uidKnown = true;
            ++found->attributionUpdates;
            ++counters_.attributionUpdates;
        }
        found->decisionStateValid = true;
        found->policyRevision = policyRevision;
        found->packets += 1U;
        found->bytes += facts.originalLength;
        ++counters_.updates;
        return FlowEntryObservation{
            .relativeDirection = packetMatchesOrigin(*found, facts)
                ? FlowRelativeDirection::Orig
                : FlowRelativeDirection::Reply,
            .flowOriginDir = found->flowOriginDir,
            .created = false,
            .linuxUid = found->linuxUid,
            .uidKnown = found->uidKnown,
            .attributionUpdated = attributionUpdated,
            .decisionStateValid = found->decisionStateValid,
            .decisionStateCleared = decisionStateCleared,
            .policyRevision = found->policyRevision,
            .packets = found->packets,
            .bytes = found->bytes,
            .lpiRecognition = found->lpiRecognition,
        };
    }

    if (entries_.size() >= capacity_) {
        ++counters_.capacityMisses;
        return std::nullopt;
    }

    auto &entry = entries_.emplace_back(FlowEntry{
        .key = *key,
        .originSource = facts.source,
        .originDestination = facts.destination,
        .originSourcePort = facts.sourcePort,
        .originDestinationPort = facts.destinationPort,
        .flowOriginDir = facts.deviceDirection,
        .linuxUid = facts.domain.linuxUid,
        .uidKnown = facts.domain.uidKnown,
        .attributionUpdates = 0,
        .decisionStateValid = true,
        .policyRevision = policyRevision,
        .decisionStateClears = 0,
        .packets = 1U,
        .bytes = facts.originalLength,
    });
    ++counters_.creates;
    counters_.highWatermark = std::max(counters_.highWatermark, entries_.size());
    return FlowEntryObservation{
        .relativeDirection = FlowRelativeDirection::Orig,
        .flowOriginDir = entry.flowOriginDir,
        .created = true,
        .linuxUid = entry.linuxUid,
        .uidKnown = entry.uidKnown,
        .attributionUpdated = false,
        .decisionStateValid = entry.decisionStateValid,
        .decisionStateCleared = false,
        .policyRevision = entry.policyRevision,
        .packets = entry.packets,
        .bytes = entry.bytes,
        .lpiRecognition = entry.lpiRecognition,
    };
}

FlowSteeringRuntime::FlowSteeringRuntime(
    WorkerLayout layout, const std::size_t queueCapacity,
    const std::size_t flowCapacity)
    : distribution_(layout, queueCapacity), guard_(distribution_.selector()),
      flowTable_(flowCapacity == 0 ? queueCapacity : flowCapacity) {}

} // namespace SnortDatapath::Flow
