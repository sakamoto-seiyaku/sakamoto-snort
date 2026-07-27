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
    std::uint32_t captureQueue = 0;
    std::uint32_t networkContext = 0;
    std::uint32_t runtimeProfile = 0;
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

struct WorkerLayout {
    std::uint32_t workerCount = 1;
    std::uint64_t hashSeed = 0;

    WorkerLayout() = default;
    WorkerLayout(std::uint32_t count, std::uint64_t seed);
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

/** One adapter packet may acquire exactly one terminal outcome. */
class PacketLease final {
public:
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

struct PacketEnvelope {
    PacketFacts facts;
    PacketLease lease;
    std::uint32_t targetWorker = std::numeric_limits<std::uint32_t>::max();
};

struct DistributionCounters {
    std::uint64_t directPackets = 0;
    std::uint64_t parseDrops = 0;
    std::uint64_t capacityDrops = 0;
    std::uint64_t terminalDrops = 0;
    std::uint64_t normalWorkerHandoffs = 0;
};

/**
 * Primary distribution model. Queues are fixed at runtime construction and
 * packets are placed directly into their calculated worker queue.
 */
class PrimarySoftwareDistribution final {
public:
    PrimarySoftwareDistribution(WorkerLayout layout, std::size_t queueCapacity);

    [[nodiscard]] std::size_t submit(std::span<PacketEnvelope> packets) noexcept;
    [[nodiscard]] std::size_t queueDepth(std::uint32_t worker) const noexcept;
    [[nodiscard]] const std::vector<PacketEnvelope *> &queue(
        std::uint32_t worker) const noexcept;
    [[nodiscard]] const DistributionCounters &counters() const noexcept { return counters_; }
    [[nodiscard]] const OwnerSelector &selector() const noexcept { return selector_; }

private:
    OwnerSelector selector_;
    std::size_t queueCapacity_ = 0;
    std::vector<std::vector<PacketEnvelope *>> queues_;
    DistributionCounters counters_;
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
    [[nodiscard]] OwnerGuardDecision check(
        std::uint32_t currentWorker, std::uint32_t expectedWorker,
        PacketLease &lease) noexcept;
    [[nodiscard]] const OwnerGuardCounters &counters() const noexcept { return counters_; }

private:
    OwnerGuardCounters counters_;
};

} // namespace SnortDatapath::Flow
