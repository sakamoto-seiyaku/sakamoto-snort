/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <DomainPolicySources.hpp>
#include <PacketReasons.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ControlVNextStreamExplain {

inline constexpr std::size_t maxExplainCandidatesPerStage = 64;

inline constexpr std::string_view kDnsKind = "dns-policy";
inline constexpr std::string_view kPktKind = "packet-verdict";

inline constexpr std::string_view kDnsStageAppAllowList = "app.custom.allowList";
inline constexpr std::string_view kDnsStageAppBlockList = "app.custom.blockList";
inline constexpr std::string_view kDnsStageAppAllowRules = "app.custom.allowRules";
inline constexpr std::string_view kDnsStageAppBlockRules = "app.custom.blockRules";
inline constexpr std::string_view kDnsStageDeviceAllow = "deviceWide.allow";
inline constexpr std::string_view kDnsStageDeviceBlock = "deviceWide.block";
inline constexpr std::string_view kDnsStageMaskFallback = "maskFallback";

inline constexpr std::string_view kPktStageIfaceBlock = "ifaceBlock";
inline constexpr std::string_view kPktStageIpRulesEnforce = "iprules.enforce";
inline constexpr std::string_view kPktStageDomainIpLeak = "domainIpLeak";
inline constexpr std::string_view kPktStageIpRulesWould = "iprules.would";

inline constexpr std::string_view kSkipDisabled = "disabled";
inline constexpr std::string_view kSkipShortCircuited = "shortCircuited";
inline constexpr std::string_view kSkipNoMatch = "noMatch";
inline constexpr std::string_view kSkipL4Unavailable = "l4Unavailable";
inline constexpr std::string_view kSkipFragment = "fragment";
inline constexpr std::string_view kSkipCtUnavailable = "ctUnavailable";

template <class Snapshot, class RuleIdOf>
void capCandidateSnapshots(std::vector<Snapshot> &snapshots,
                           const std::optional<std::uint32_t> winningRuleId,
                           RuleIdOf ruleIdOf,
                           bool &truncated,
                           std::optional<std::uint32_t> &omittedCandidateCount) {
    truncated = false;
    omittedCandidateCount.reset();
    if (snapshots.size() <= maxExplainCandidatesPerStage) {
        return;
    }

    truncated = true;
    omittedCandidateCount =
        static_cast<std::uint32_t>(snapshots.size() - maxExplainCandidatesPerStage);

    std::vector<Snapshot> capped;
    capped.reserve(maxExplainCandidatesPerStage);

    const auto keep = maxExplainCandidatesPerStage - 1;
    const auto begin = snapshots.begin();
    const auto firstEnd = begin + static_cast<std::ptrdiff_t>(keep);
    capped.insert(capped.end(), begin, firstEnd);

    bool winnerAlreadyKept = !winningRuleId.has_value();
    if (winningRuleId.has_value()) {
        winnerAlreadyKept = std::any_of(capped.begin(), capped.end(), [&](const Snapshot &snapshot) {
            return ruleIdOf(snapshot) == *winningRuleId;
        });
    }

    if (!winnerAlreadyKept && winningRuleId.has_value()) {
        const auto winnerIt = std::find_if(snapshots.begin(), snapshots.end(), [&](const Snapshot &snapshot) {
            return ruleIdOf(snapshot) == *winningRuleId;
        });
        if (winnerIt != snapshots.end()) {
            capped.push_back(*winnerIt);
        }
    }

    while (capped.size() < maxExplainCandidatesPerStage) {
        capped.push_back(snapshots[capped.size()]);
    }
    snapshots = std::move(capped);
}

struct DnsRuleSnapshot {
    std::uint32_t ruleId = 0;
    std::string type;
    std::string pattern;
    std::string scope;
    std::string action;
};

struct DnsListEntrySnapshot {
    std::string type;
    std::string pattern;
    std::string scope;
    std::string action;
};

struct DnsMaskEvidence {
    std::uint32_t domMask = 0;
    std::uint32_t appMask = 0;
    std::uint32_t effectiveMask = 0;
    bool blocked = false;
};

struct DnsStageSnapshot {
    std::string name;
    bool enabled = false;
    bool evaluated = false;
    bool matched = false;
    std::string outcome;
    bool winner = false;
    std::optional<std::string> skipReason;
    std::vector<std::uint32_t> ruleIds;
    std::vector<DnsRuleSnapshot> ruleSnapshots;
    std::vector<DnsListEntrySnapshot> listEntrySnapshots;
    bool truncated = false;
    std::optional<std::uint32_t> omittedCandidateCount;
    std::optional<DnsMaskEvidence> maskFallback;
};

struct DnsInputs {
    bool blockEnabled = false;
    bool tracked = false;
    bool domainCustomEnabled = false;
    bool useCustomList = false;
    std::string domain;
    std::uint32_t domMask = 0;
    std::uint32_t appMask = 0;
};

struct DnsFinal {
    bool blocked = false;
    bool getips = false;
    DomainPolicySource policySource = DomainPolicySource::MASK_FALLBACK;
    std::string scope;
    std::optional<std::uint32_t> ruleId;
};

struct DnsExplainSnapshot {
    std::uint32_t version = 1;
    std::string kind{std::string(kDnsKind)};
    DnsInputs inputs;
    DnsFinal final;
    std::vector<DnsStageSnapshot> stages;
};

struct IpRulesRuleSnapshot {
    std::uint32_t ruleId = 0;
    std::string clientRuleId;
    std::string matchKey;
    std::string action;
    bool enforce = false;
    bool log = false;
    std::string family;
    std::string dir;
    std::string iface;
    std::uint32_t ifindex = 0;
    std::string proto;
    std::string ctState;
    std::string ctDirection;
    std::string src;
    std::string dst;
    std::string sport;
    std::string dport;
    std::int32_t priority = 0;
};

struct PktIfaceBlockEvidence {
    std::uint32_t appIfaceMask = 0;
    std::uint32_t packetIfaceKindBit = 0;
    std::uint32_t evaluatedIntersection = 0;
    std::string packetIfaceKind;
    bool blocked = false;
    std::optional<std::string> shortCircuitReason;
};

struct PktStageSnapshot {
    std::string name;
    bool enabled = false;
    bool evaluated = false;
    bool matched = false;
    std::string outcome;
    bool winner = false;
    std::optional<std::string> skipReason;
    std::vector<std::uint32_t> ruleIds;
    std::vector<IpRulesRuleSnapshot> ruleSnapshots;
    bool truncated = false;
    std::optional<std::uint32_t> omittedCandidateCount;
    std::optional<PktIfaceBlockEvidence> ifaceBlock;
};

struct PktInputs {
    bool blockEnabled = false;
    bool iprulesEnabled = false;
    std::string direction;
    std::uint8_t ipVersion = 0;
    std::string protocol;
    std::string l4Status;
    std::uint32_t ifindex = 0;
    std::uint32_t ifaceKindBit = 0;
    std::string ifaceKind;
    bool conntrackEvaluated = false;
    std::optional<std::string> conntrackState;
    std::optional<std::string> conntrackDirection;
};

struct PktFinal {
    bool accepted = false;
    PacketReasonId reasonId = PacketReasonId::ALLOW_DEFAULT;
    std::optional<std::uint32_t> ruleId;
    std::optional<std::uint32_t> wouldRuleId;
    bool wouldDrop = false;
};

struct PktExplainSnapshot {
    std::uint32_t version = 1;
    std::string kind{std::string(kPktKind)};
    PktInputs inputs;
    PktFinal final;
    std::vector<PktStageSnapshot> stages;
};

} // namespace ControlVNextStreamExplain
