/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

namespace SnortDatapath::Flow {

enum class AdapterKind : std::uint8_t {
    RootNfqueue,
    VpnTun,
};

enum class AddressFamily : std::uint8_t {
    Ipv4,
    Ipv6,
};

enum class DevicePacketDirection : std::uint8_t {
    Input,
    Output,
};

enum class ParseStatus : std::uint8_t {
    Ready,
    UnsupportedProtocol,
    Fragment,
    Malformed,
};

struct IpAddress {
    AddressFamily family = AddressFamily::Ipv4;
    std::array<std::uint8_t, 16> bytes{};

    static IpAddress v4(std::array<std::uint8_t, 4> value) noexcept;
    static IpAddress v6(std::array<std::uint8_t, 16> value) noexcept;

    friend bool operator==(const IpAddress &, const IpAddress &) = default;
};

/** Adapter facts are shared by Root/NFQUEUE and VPN/TUN. */
struct FlowDomain {
    AdapterKind adapter = AdapterKind::RootNfqueue;
    std::uint32_t linuxUid = 0;
    bool uidKnown = false;
    std::uint32_t captureQueue = 0;
    std::uint32_t networkContext = 0;
    std::uint32_t runtimeProfile = 0;
    std::uint32_t interfaceIndex = 0;
};

struct PacketFacts {
    IpAddress source;
    IpAddress destination;
    std::uint8_t ipProtocol = 0;
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;
    bool portsAvailable = false;
    bool fragmented = false;
    ParseStatus parseStatus = ParseStatus::Malformed;
    DevicePacketDirection deviceDirection = DevicePacketDirection::Input;
    std::uint32_t originalLength = 0;
    std::uint32_t boundedPrefixLength = 0;
    FlowDomain domain;

    [[nodiscard]] bool isCanonicalizable() const noexcept;
};

/** Direction-independent key for a non-fragmented TCP/UDP flow. */
struct CanonicalFlowKey {
    AddressFamily family = AddressFamily::Ipv4;
    std::uint8_t ipProtocol = 0;
    IpAddress endpointA;
    IpAddress endpointB;
    std::uint16_t portA = 0;
    std::uint16_t portB = 0;

    [[nodiscard]] static std::optional<CanonicalFlowKey> from(
        const PacketFacts &facts) noexcept;

    friend bool operator==(const CanonicalFlowKey &, const CanonicalFlowKey &) = default;
};

class WorkerLayout final {
public:
    WorkerLayout() = default;
    WorkerLayout(std::uint32_t count, std::uint64_t seed);

    [[nodiscard]] std::uint32_t workerCount() const noexcept { return workerCount_; }
    [[nodiscard]] std::uint64_t hashSeed() const noexcept { return hashSeed_; }

private:
    std::uint32_t workerCount_ = 1;
    std::uint64_t hashSeed_ = 0;
};

class OwnerSelector final {
public:
    explicit OwnerSelector(WorkerLayout layout);

    [[nodiscard]] std::uint32_t ownerFor(const CanonicalFlowKey &key) const noexcept;
    [[nodiscard]] const WorkerLayout &layout() const noexcept { return layout_; }

private:
    WorkerLayout layout_;
};

enum class PacketLeaseOutcome : std::uint8_t {
    Open,
    Accepted,
    Dropped,
};

enum class OwnerGuardDecision : std::uint8_t;
class OwnerGuard;

/** One adapter packet may acquire exactly one terminal outcome. */
class PacketLease final {
public:
    PacketLease() = default;
    PacketLease(const PacketLease &) = delete;
    PacketLease &operator=(const PacketLease &) = delete;
    PacketLease(PacketLease &&other) noexcept;
    PacketLease &operator=(PacketLease &&other) noexcept;

    [[nodiscard]] bool accept() noexcept;
    [[nodiscard]] bool drop() noexcept;
    [[nodiscard]] bool requestCorrectiveHandoff() noexcept;

    [[nodiscard]] PacketLeaseOutcome outcome() const noexcept { return outcome_; }
    [[nodiscard]] std::uint8_t correctionCount() const noexcept { return corrections_; }
    [[nodiscard]] std::uint32_t duplicateTerminalAttempts() const noexcept {
        return duplicateTerminalAttempts_;
    }
    [[nodiscard]] bool isTerminal() const noexcept {
        return outcome_ != PacketLeaseOutcome::Open;
    }

private:
    PacketLeaseOutcome outcome_ = PacketLeaseOutcome::Open;
    std::uint8_t corrections_ = 0;
    std::uint32_t duplicateTerminalAttempts_ = 0;
};

using PacketDescriptorSlot = std::uint32_t;
using PacketDescriptorId = std::uint64_t;

struct PacketSubmission {
    PacketFacts facts;
    PacketLease lease;
};

struct PacketDescriptor {
    PacketFacts facts;
    PacketLease lease;
    std::uint32_t targetWorker = std::numeric_limits<std::uint32_t>::max();
};

struct DistributionCounters {
    std::uint64_t directPackets = 0;
    std::uint64_t parseDrops = 0;
    std::uint64_t capacityDrops = 0;
    std::uint64_t alreadyTerminalPackets = 0;
    std::uint64_t staleDescriptorHandles = 0;
    std::uint64_t normalWorkerHandoffs = 0;
};

/**
 * Primary distribution model. Queues are fixed at runtime construction and
 * packets are placed directly into their calculated worker queue.
 *
 * The object is lane-confined rather than internally synchronized. An
 * adapter that shares one instance across ingress threads must serialize the
 * complete dequeue/guard/completion transaction, as the NFQUEUE adapter does.
 */
class PrimarySoftwareDistribution final {
public:
    PrimarySoftwareDistribution(WorkerLayout layout, std::size_t queueCapacity);

    [[nodiscard]] std::size_t submit(std::span<PacketSubmission> packets) noexcept;
    [[nodiscard]] std::size_t submit(std::span<const PacketFacts> packets) noexcept;
    [[nodiscard]] std::size_t queueDepth(std::uint32_t worker) const noexcept;
    [[nodiscard]] std::optional<PacketDescriptorId> dequeue(
        std::uint32_t worker) noexcept;
    [[nodiscard]] const PacketDescriptor *descriptor(PacketDescriptorId id) noexcept;
    [[nodiscard]] const PacketDescriptor *descriptor(PacketDescriptorId id) const noexcept;
    [[nodiscard]] bool requestCorrectiveHandoff(PacketDescriptorId id) noexcept;
    [[nodiscard]] OwnerGuardDecision checkOwner(PacketDescriptorId id,
                                                 std::uint32_t currentWorker,
                                                 OwnerGuard &guard) noexcept;
    [[nodiscard]] bool complete(PacketDescriptorId id, PacketLeaseOutcome outcome) noexcept;
    [[nodiscard]] bool requeueCorrective(PacketDescriptorId id,
                                          std::uint32_t targetWorker) noexcept;
    [[nodiscard]] const DistributionCounters &counters() const noexcept { return counters_; }
    [[nodiscard]] const OwnerSelector &selector() const noexcept { return selector_; }

private:
    struct WorkerQueue {
        std::vector<PacketDescriptorId> ids;
        std::size_t head = 0;
    };

    OwnerSelector selector_;
    std::size_t queueCapacity_ = 0;
    std::vector<PacketDescriptor> descriptors_;
    std::vector<PacketDescriptorSlot> freeDescriptors_;
    std::vector<WorkerQueue> queues_;
    std::vector<bool> activeDescriptors_;
    std::vector<bool> queuedDescriptors_;
    std::vector<std::uint32_t> descriptorGenerations_;
    DistributionCounters counters_;

    bool enqueue(const PacketFacts &facts, PacketLease *lease) noexcept;
    void releaseDropped(PacketDescriptorSlot slot) noexcept;
};

enum class OwnerGuardDecision : std::uint8_t {
    Local,
    CorrectiveHandoff,
    Drop,
};

struct OwnerGuardCounters {
    std::uint64_t localPass = 0;
    std::uint64_t mismatches = 0;
    std::uint64_t correctiveHandoffs = 0;
    std::uint64_t secondMismatchDrops = 0;
};

class OwnerGuard final {
public:
    explicit OwnerGuard(WorkerLayout layout);
    explicit OwnerGuard(const OwnerSelector &selector);

    [[nodiscard]] OwnerGuardDecision check(
        std::uint32_t currentWorker, const PacketFacts &facts,
        PacketLease &lease) noexcept;
    [[nodiscard]] const OwnerGuardCounters &counters() const noexcept { return counters_; }

private:
    OwnerSelector selector_;
    OwnerGuardCounters counters_;
};

enum class FlowRelativeDirection : std::uint8_t {
    Orig,
    Reply,
};

struct FlowEntry {
    CanonicalFlowKey key;
    IpAddress originSource;
    IpAddress originDestination;
    std::uint16_t originSourcePort = 0;
    std::uint16_t originDestinationPort = 0;
    DevicePacketDirection flowOriginDir = DevicePacketDirection::Input;
    bool decisionStateValid = false;
    std::uint64_t policyRevision = 0;
    std::uint64_t decisionStateClears = 0;
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
};

struct FlowEntryObservation {
    FlowRelativeDirection relativeDirection = FlowRelativeDirection::Orig;
    DevicePacketDirection flowOriginDir = DevicePacketDirection::Input;
    bool created = false;
    bool decisionStateValid = false;
    bool decisionStateCleared = false;
    std::uint64_t policyRevision = 0;
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
};

struct FlowEntryRevisionObservation {
    bool found = false;
    bool decisionStateCleared = false;
    std::uint64_t previousPolicyRevision = 0;
    std::uint64_t currentPolicyRevision = 0;
};

struct BoundedFlowTableCounters {
    std::uint64_t creates = 0;
    std::uint64_t updates = 0;
    std::uint64_t capacityMisses = 0;
    std::uint64_t nonCanonicalPackets = 0;
    std::uint64_t decisionStateClears = 0;
};

class BoundedFlowTable final {
public:
    explicit BoundedFlowTable(std::size_t capacity);

    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] const BoundedFlowTableCounters &counters() const noexcept {
        return counters_;
    }
    [[nodiscard]] std::optional<FlowEntryRevisionObservation> reconcilePolicyRevision(
        const PacketFacts &facts, std::uint64_t policyRevision) noexcept;
    [[nodiscard]] std::optional<FlowEntryObservation> observeAccepted(
        const PacketFacts &facts, std::uint64_t policyRevision = 0) noexcept;
    [[nodiscard]] const FlowEntry *find(const CanonicalFlowKey &key) const noexcept;

private:
    std::size_t capacity_ = 0;
    std::vector<FlowEntry> entries_;
    BoundedFlowTableCounters counters_;
};

/** Pragmatic shared seam used by both normalized packet-capture adapters. */
class FlowSteeringRuntime final {
public:
    FlowSteeringRuntime(WorkerLayout layout, std::size_t queueCapacity,
                        std::size_t flowCapacity = 0);

    [[nodiscard]] PrimarySoftwareDistribution &distribution() noexcept { return distribution_; }
    [[nodiscard]] const PrimarySoftwareDistribution &distribution() const noexcept {
        return distribution_;
    }
    [[nodiscard]] OwnerGuard &ownerGuard() noexcept { return guard_; }
    [[nodiscard]] const OwnerGuard &ownerGuard() const noexcept { return guard_; }
    [[nodiscard]] BoundedFlowTable &flowTable() noexcept { return flowTable_; }
    [[nodiscard]] const BoundedFlowTable &flowTable() const noexcept { return flowTable_; }

private:
    PrimarySoftwareDistribution distribution_;
    OwnerGuard guard_;
    BoundedFlowTable flowTable_;
};

} // namespace SnortDatapath::Flow
