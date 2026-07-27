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
    if (count > std::numeric_limits<PacketDescriptorId>::max()) {
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
      queuedDescriptors_(descriptors_.size(), false) {
    freeDescriptors_.reserve(descriptors_.size());
    for (std::size_t index = descriptors_.size(); index > 0; --index) {
        freeDescriptors_.push_back(static_cast<PacketDescriptorId>(index - 1));
    }
    for (auto &queue : queues_) {
        queue.ids.reserve(queueCapacity_);
    }
}

std::size_t PrimarySoftwareDistribution::submit(
    const std::span<const PacketFacts> packets) noexcept {
    std::size_t queued = 0;
    for (const auto &facts : packets) {
        const auto key = CanonicalFlowKey::from(facts);
        if (!key.has_value()) {
            ++counters_.parseDrops;
            continue;
        }
        const auto owner = selector_.ownerFor(*key);
        auto &target = queues_[owner];
        if (target.ids.size() - target.head >= queueCapacity_ || freeDescriptors_.empty()) {
            ++counters_.capacityDrops;
            continue;
        }
        const auto descriptorId = freeDescriptors_.back();
        freeDescriptors_.pop_back();
        auto &descriptor = descriptors_[descriptorId];
        descriptor = PacketDescriptor{
            .facts = facts,
            .lease = {},
            .targetWorker = owner,
        };
        activeDescriptors_[descriptorId] = true;
        queuedDescriptors_[descriptorId] = true;
        target.ids.push_back(descriptorId);
        ++counters_.directPackets;
        ++queued;
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
    queuedDescriptors_[descriptorId] = false;
    return descriptorId;
}

PacketDescriptor *PrimarySoftwareDistribution::descriptor(const PacketDescriptorId id) noexcept {
    if (id >= descriptors_.size() || !activeDescriptors_[id]) {
        return nullptr;
    }
    return &descriptors_[id];
}

const PacketDescriptor *PrimarySoftwareDistribution::descriptor(
    const PacketDescriptorId id) const noexcept {
    if (id >= descriptors_.size() || !activeDescriptors_[id]) {
        return nullptr;
    }
    return &descriptors_[id];
}

bool PrimarySoftwareDistribution::complete(
    const PacketDescriptorId id, const PacketLeaseOutcome outcome) noexcept {
    auto *entry = descriptor(id);
    if (entry == nullptr) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    if (queuedDescriptors_[id]) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    const bool completed = outcome == PacketLeaseOutcome::Accepted
        ? entry->lease.accept() : outcome == PacketLeaseOutcome::Dropped
        ? entry->lease.drop() : false;
    if (!completed) {
        return false;
    }
    activeDescriptors_[id] = false;
    queuedDescriptors_[id] = false;
    freeDescriptors_.push_back(id);
    return true;
}

bool PrimarySoftwareDistribution::requeueCorrective(
    const PacketDescriptorId id, const std::uint32_t targetWorker) noexcept {
    auto *entry = descriptor(id);
    if (entry == nullptr || targetWorker >= queues_.size()
        || entry->lease.correctionCount() != 1 || queuedDescriptors_[id]
        || entry->lease.isTerminal()) {
        ++counters_.staleDescriptorHandles;
        return false;
    }
    auto &target = queues_[targetWorker];
    if (target.ids.size() - target.head >= queueCapacity_) {
        ++counters_.capacityDrops;
        if (entry->lease.drop()) {
            activeDescriptors_[id] = false;
            queuedDescriptors_[id] = false;
            freeDescriptors_.push_back(id);
        }
        return false;
    }
    entry->targetWorker = targetWorker;
    queuedDescriptors_[id] = true;
    target.ids.push_back(id);
    return true;
}

OwnerGuard::OwnerGuard(WorkerLayout layout) : selector_(layout) {}

OwnerGuardDecision OwnerGuard::check(
    const std::uint32_t currentWorker, const PacketFacts &facts,
    PacketLease &lease) noexcept {
    const auto key = CanonicalFlowKey::from(facts);
    if (!key.has_value()) {
        ++counters_.mismatches;
        (void)lease.drop();
        ++counters_.secondMismatchDrops;
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

} // namespace SnortDatapath::Flow
