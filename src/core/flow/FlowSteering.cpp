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
    std::copy(value.begin(), value.end(), result.bytes.end() - value.size());
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
        && originalLength > 0 && boundedPrefixLength <= originalLength;
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
    : workerCount(count), hashSeed(seed) {
    if (workerCount == 0) {
        throw std::invalid_argument("WorkerLayout requires at least one worker");
    }
}

OwnerSelector::OwnerSelector(WorkerLayout layout) : layout_(layout) {
    if (layout_.workerCount == 0) {
        throw std::invalid_argument("OwnerSelector requires at least one worker");
    }
}

std::uint32_t OwnerSelector::ownerFor(const CanonicalFlowKey &key) const noexcept {
    std::uint64_t hash = kFnvOffset ^ layout_.hashSeed;
    hashByte(hash, key.ipProtocol);
    hashAddress(hash, key.endpointA);
    hashAddress(hash, key.endpointB);
    hashU16(hash, key.portA);
    hashU16(hash, key.portB);
    return static_cast<std::uint32_t>(hash % layout_.workerCount);
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

PrimarySoftwareDistribution::PrimarySoftwareDistribution(
    WorkerLayout layout, const std::size_t queueCapacity)
    : selector_(layout), queueCapacity_(queueCapacity), queues_(layout.workerCount) {}

std::size_t PrimarySoftwareDistribution::submit(
    const std::span<PacketEnvelope> packets) noexcept {
    std::size_t queued = 0;
    for (auto &packet : packets) {
        if (packet.lease.isTerminal()) {
            ++counters_.terminalDrops;
            continue;
        }
        const auto key = CanonicalFlowKey::from(packet.facts);
        if (!key.has_value()) {
            (void)packet.lease.drop();
            ++counters_.parseDrops;
            continue;
        }
        const auto owner = selector_.ownerFor(*key);
        packet.targetWorker = owner;
        auto &target = queues_[owner];
        if (target.size() >= queueCapacity_) {
            (void)packet.lease.drop();
            ++counters_.capacityDrops;
            continue;
        }
        target.push_back(&packet);
        ++counters_.directPackets;
        ++queued;
    }
    return queued;
}

std::size_t PrimarySoftwareDistribution::queueDepth(const std::uint32_t worker) const noexcept {
    if (worker >= queues_.size()) {
        return 0;
    }
    return queues_[worker].size();
}

const std::vector<PacketEnvelope *> &PrimarySoftwareDistribution::queue(
    const std::uint32_t worker) const noexcept {
    static const std::vector<PacketEnvelope *> empty;
    if (worker >= queues_.size()) {
        return empty;
    }
    return queues_[worker];
}

OwnerGuardDecision OwnerGuard::check(
    const std::uint32_t currentWorker, const std::uint32_t expectedWorker,
    PacketLease &lease) noexcept {
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
