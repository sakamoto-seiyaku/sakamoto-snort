/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace SnortDatapath::Policy {

enum class PacketPolicyVerdict : std::uint8_t {
    PASS_NEXT,
    DROP,
};

enum class PacketPolicyStage : std::uint8_t {
    None,
    NetworkGate,
    L4,
};

enum class L4RuleAction : std::uint8_t {
    Allow,
    Drop,
};

struct PacketPolicyDecision {
    PacketPolicyVerdict verdict = PacketPolicyVerdict::PASS_NEXT;
    PacketPolicyStage stage = PacketPolicyStage::None;
    std::uint32_t reasonId = 0;
    std::uint64_t ruleId = 0;
    std::uint64_t revision = 0;

    [[nodiscard]] static PacketPolicyDecision passNext() noexcept;
    [[nodiscard]] static PacketPolicyDecision drop(
        std::uint32_t reasonId = 0, std::uint64_t ruleId = 0,
        std::uint64_t revision = 0,
        PacketPolicyStage stage = PacketPolicyStage::L4) noexcept;
};

struct NetworkGateView {
    std::uint64_t blockedNetworkContextBits = 0;
    std::vector<std::uint32_t> blockedNetworkContexts;
    std::uint32_t reasonId = 0;
    std::uint64_t ruleId = 0;

    [[nodiscard]] bool blocks(std::uint32_t networkContext) const noexcept;
};

struct PortRange {
    std::uint16_t first = 0;
    std::uint16_t last = 0;

    [[nodiscard]] static PortRange exact(std::uint16_t port) noexcept;
    [[nodiscard]] static PortRange inclusive(
        std::uint16_t first, std::uint16_t last) noexcept;
    [[nodiscard]] bool contains(std::uint16_t port) const noexcept;
};

struct L4RuleMatch {
    std::optional<Flow::AddressFamily> family;
    std::optional<Flow::DevicePacketDirection> direction;
    std::optional<std::uint8_t> ipProtocol;
    std::uint64_t networkContextBits = 0;
    std::vector<std::uint32_t> networkContexts;
    std::optional<PortRange> sourcePorts;
    std::optional<PortRange> destinationPorts;

    [[nodiscard]] bool matches(const Flow::PacketFacts &facts) const noexcept;
};

struct L4Rule {
    std::uint64_t ruleId = 0;
    std::uint32_t reasonId = 0;
    std::int32_t priority = 0;
    std::uint32_t order = 0;
    L4RuleAction action = L4RuleAction::Drop;
    L4RuleMatch match;
};

struct PacketPolicySubjectView {
    std::uint32_t linuxUid = 0;
    NetworkGateView networkGate;
    std::vector<L4Rule> l4Rules;
};

struct PacketPolicySnapshotStatus {
    std::uint64_t revision = 0;
    std::size_t subjectCount = 0;
    std::size_t networkGateRuleCount = 0;
    std::size_t l4RuleCount = 0;

    [[nodiscard]] std::size_t ruleCount() const noexcept {
        return networkGateRuleCount + l4RuleCount;
    }
};

class PacketPolicySnapshot {
public:
    PacketPolicySnapshot() = default;
    PacketPolicySnapshot(const PacketPolicySnapshot &) = delete;
    PacketPolicySnapshot &operator=(const PacketPolicySnapshot &) = delete;
    virtual ~PacketPolicySnapshot() = default;

    [[nodiscard]] virtual PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept = 0;
};

class EmptyPacketPolicySnapshot final : public PacketPolicySnapshot {
public:
    [[nodiscard]] PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept override;
};

class StatelessPacketPolicySnapshot final : public PacketPolicySnapshot {
public:
    explicit StatelessPacketPolicySnapshot(
        std::vector<PacketPolicySubjectView> subjects,
        std::uint64_t revision = 0);

    [[nodiscard]] PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept override;
    [[nodiscard]] std::uint64_t revision() const noexcept { return revision_; }
    [[nodiscard]] std::size_t subjectCount() const noexcept {
        return subjects_.size();
    }
    [[nodiscard]] PacketPolicySnapshotStatus status() const noexcept;

private:
    std::vector<PacketPolicySubjectView> subjects_;
    std::uint64_t revision_ = 0;
    std::size_t networkGateRuleCount_ = 0;
    std::size_t l4RuleCount_ = 0;
};

class RuntimePacketPolicySnapshot final : public PacketPolicySnapshot {
public:
    RuntimePacketPolicySnapshot();

    [[nodiscard]] PacketPolicyDecision evaluate(
        const Flow::PacketFacts &facts) const noexcept override;
    void apply(std::vector<PacketPolicySubjectView> subjects,
               std::uint64_t revision);
    [[nodiscard]] PacketPolicySnapshotStatus status() const noexcept;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<const StatelessPacketPolicySnapshot> active_;
};

[[nodiscard]] const PacketPolicySnapshot &emptyPacketPolicySnapshot() noexcept;

} // namespace SnortDatapath::Policy
