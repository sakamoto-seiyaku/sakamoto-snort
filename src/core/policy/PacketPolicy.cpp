/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <PacketPolicy.hpp>

#include <algorithm>
#include <memory>
#include <utility>

namespace SnortDatapath::Policy {
namespace {

bool contextMatches(const std::uint64_t bits,
                    const std::vector<std::uint32_t> &contexts,
                    const std::uint32_t networkContext) noexcept {
    const auto bitMatches = networkContext < 64U
        && (bits & (1ULL << networkContext)) != 0;
    return bitMatches
        || std::find(contexts.begin(), contexts.end(), networkContext) != contexts.end();
}

bool ruleRankLess(const L4Rule &left, const L4Rule &right) noexcept {
    if (left.priority != right.priority) {
        return left.priority < right.priority;
    }
    if (left.order != right.order) {
        return left.order < right.order;
    }
    return left.ruleId < right.ruleId;
}

bool networkGateConfigured(const NetworkGateView &gate) noexcept {
    return gate.blockedNetworkContextBits != 0 || !gate.blockedNetworkContexts.empty();
}

} // namespace

PacketPolicyDecision PacketPolicyDecision::passNext() noexcept {
    return PacketPolicyDecision{};
}

PacketPolicyDecision PacketPolicyDecision::drop(
    const std::uint32_t reasonId, const std::uint64_t ruleId,
    const std::uint64_t revision, const PacketPolicyStage stage) noexcept {
    return PacketPolicyDecision{
        .verdict = PacketPolicyVerdict::DROP,
        .stage = stage,
        .reasonId = reasonId,
        .ruleId = ruleId,
        .revision = revision,
    };
}

bool NetworkGateView::blocks(const std::uint32_t networkContext) const noexcept {
    return contextMatches(
        blockedNetworkContextBits, blockedNetworkContexts, networkContext);
}

PortRange PortRange::exact(const std::uint16_t port) noexcept {
    return PortRange{.first = port, .last = port};
}

PortRange PortRange::inclusive(
    const std::uint16_t first, const std::uint16_t last) noexcept {
    return PortRange{.first = first, .last = last};
}

bool PortRange::contains(const std::uint16_t port) const noexcept {
    return first <= last && first <= port && port <= last;
}

bool L4RuleMatch::matches(const Flow::PacketFacts &facts) const noexcept {
    if (family.has_value()
        && (facts.source.family != *family || facts.destination.family != *family)) {
        return false;
    }
    if (direction.has_value() && facts.deviceDirection != *direction) {
        return false;
    }
    if (ipProtocol.has_value() && facts.ipProtocol != *ipProtocol) {
        return false;
    }
    if ((networkContextBits != 0 || !networkContexts.empty())
        && !contextMatches(networkContextBits, networkContexts,
                           facts.domain.networkContext)) {
        return false;
    }
    if (sourcePorts.has_value() || destinationPorts.has_value()) {
        if (!facts.portsAvailable) {
            return false;
        }
        if (sourcePorts.has_value() && !sourcePorts->contains(facts.sourcePort)) {
            return false;
        }
        if (destinationPorts.has_value()
            && !destinationPorts->contains(facts.destinationPort)) {
            return false;
        }
    }
    return true;
}

PacketPolicyDecision EmptyPacketPolicySnapshot::evaluate(
    const Flow::PacketFacts &facts) const noexcept {
    static_cast<void>(facts);
    return PacketPolicyDecision::passNext();
}

StatelessPacketPolicySnapshot::StatelessPacketPolicySnapshot(
    std::vector<PacketPolicySubjectView> subjects,
    const std::uint64_t revision)
    : subjects_(std::move(subjects)), revision_(revision) {
    for (auto &subject : subjects_) {
        if (networkGateConfigured(subject.networkGate)) {
            ++networkGateRuleCount_;
        }
        l4RuleCount_ += subject.l4Rules.size();
        std::stable_sort(
            subject.l4Rules.begin(), subject.l4Rules.end(), ruleRankLess);
    }
}

PacketPolicyDecision StatelessPacketPolicySnapshot::evaluate(
    const Flow::PacketFacts &facts) const noexcept {
    const auto subject = std::find_if(
        subjects_.begin(), subjects_.end(),
        [&facts](const PacketPolicySubjectView &candidate) noexcept {
            return candidate.linuxUid == facts.domain.linuxUid;
        });
    if (subject == subjects_.end()) {
        return PacketPolicyDecision::passNext();
    }

    if (subject->networkGate.blocks(facts.domain.networkContext)) {
        return PacketPolicyDecision::drop(
            subject->networkGate.reasonId, subject->networkGate.ruleId,
            revision_, PacketPolicyStage::NetworkGate);
    }

    for (const auto &rule : subject->l4Rules) {
        if (!rule.match.matches(facts)) {
            continue;
        }
        if (rule.action == L4RuleAction::Drop) {
            return PacketPolicyDecision::drop(
                rule.reasonId, rule.ruleId, revision_, PacketPolicyStage::L4);
        }
        return PacketPolicyDecision::passNext();
    }

    return PacketPolicyDecision::passNext();
}

PacketPolicySnapshotStatus StatelessPacketPolicySnapshot::status() const noexcept {
    return PacketPolicySnapshotStatus{
        .revision = revision_,
        .subjectCount = subjects_.size(),
        .networkGateRuleCount = networkGateRuleCount_,
        .l4RuleCount = l4RuleCount_,
    };
}

RuntimePacketPolicySnapshot::RuntimePacketPolicySnapshot()
    : active_(std::make_shared<StatelessPacketPolicySnapshot>(
          std::vector<PacketPolicySubjectView>{}, 0)) {}

PacketPolicyDecision RuntimePacketPolicySnapshot::evaluate(
    const Flow::PacketFacts &facts) const noexcept {
    std::shared_ptr<const StatelessPacketPolicySnapshot> active;
    {
        std::lock_guard lock(mutex_);
        active = active_;
    }
    return active->evaluate(facts);
}

void RuntimePacketPolicySnapshot::apply(
    std::vector<PacketPolicySubjectView> subjects,
    const std::uint64_t revision) {
    auto next = std::make_shared<StatelessPacketPolicySnapshot>(
        std::move(subjects), revision);
    std::lock_guard lock(mutex_);
    active_ = std::move(next);
}

PacketPolicySnapshotStatus RuntimePacketPolicySnapshot::status() const noexcept {
    std::shared_ptr<const StatelessPacketPolicySnapshot> active;
    {
        std::lock_guard lock(mutex_);
        active = active_;
    }
    return active->status();
}

const PacketPolicySnapshot &emptyPacketPolicySnapshot() noexcept {
    static const EmptyPacketPolicySnapshot snapshot;
    return snapshot;
}

} // namespace SnortDatapath::Policy
