/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

#include <IpRulesContract.hpp>

#include <ControlVNextSessionSelectors.hpp>

#include <PacketManager.hpp>

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ControlVNextSessionCommands {

namespace {

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] std::optional<std::string_view>
unknownArgsKey(const rapidjson::Value &args, const std::initializer_list<std::string_view> allowed) {
    return ControlVNext::findUnknownKey(args, allowed);
}

[[nodiscard]] bool isValidToggleValue(const rapidjson::Value &value, uint32_t &out) {
    if (!value.IsUint()) {
        return false;
    }
    const uint32_t v = value.GetUint();
    if (v > 1) {
        return false;
    }
    out = v;
    return true;
}

[[nodiscard]] bool parseCidrV4(const std::string_view v, IpRulesEngine::CidrV4 &out) {
    if (v == "any") {
        out = IpRulesEngine::CidrV4::anyCidr();
        return true;
    }

    const auto slash = v.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= v.size()) {
        return false;
    }
    const std::string ipStr(v.substr(0, slash));
    const std::string_view prefixStr = v.substr(slash + 1);
    uint32_t prefix = 0;
    if (!IpRulesContract::parseDec(prefixStr, prefix) || prefix > 32) {
        return false;
    }

    in_addr a{};
    if (inet_pton(AF_INET, ipStr.c_str(), &a) != 1) {
        return false;
    }

    const auto prefixLen = static_cast<uint8_t>(prefix);
    const uint32_t addrHost = ntohl(a.s_addr) & IpRulesContract::maskFromPrefix(prefixLen);
    out = IpRulesEngine::CidrV4::cidr(addrHost, prefixLen);
    return true;
}

[[nodiscard]] std::string formatCidrV4(const IpRulesEngine::CidrV4 &c) {
    if (c.any) {
        return "any";
    }
    in_addr a{};
    a.s_addr = htonl(c.addr);
    char buf[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) {
        return "any";
    }
    return std::string(buf) + "/" + std::to_string(static_cast<uint32_t>(c.prefix));
}

[[nodiscard]] bool parsePortPredicate(const std::string_view v, IpRulesEngine::PortPredicate &out) {
    if (v == "any") {
        out = IpRulesEngine::PortPredicate::any();
        return true;
    }

    const auto dash = v.find('-');
    if (dash != std::string_view::npos) {
        if (dash == 0 || dash + 1 >= v.size()) {
            return false;
        }
        uint32_t lo = 0;
        uint32_t hi = 0;
        if (!IpRulesContract::parseDec(v.substr(0, dash), lo) ||
            !IpRulesContract::parseDec(v.substr(dash + 1), hi)) {
            return false;
        }
        if (lo > 65535u || hi > 65535u || lo > hi) {
            return false;
        }
        out = IpRulesEngine::PortPredicate::range(static_cast<uint16_t>(lo), static_cast<uint16_t>(hi));
        return true;
    }

    uint32_t p = 0;
    if (!IpRulesContract::parseDec(v, p) || p > 65535u) {
        return false;
    }
    out = IpRulesEngine::PortPredicate::exact(static_cast<uint16_t>(p));
    return true;
}

[[nodiscard]] std::string formatPortPredicate(const IpRulesEngine::PortPredicate &p) {
    switch (p.kind) {
    case IpRulesEngine::PortPredicate::Kind::ANY:
        return "any";
    case IpRulesEngine::PortPredicate::Kind::EXACT:
        return std::to_string(static_cast<uint32_t>(p.lo));
    case IpRulesEngine::PortPredicate::Kind::RANGE:
        return std::to_string(static_cast<uint32_t>(p.lo)) + "-" +
               std::to_string(static_cast<uint32_t>(p.hi));
    }
    return "any";
}

[[nodiscard]] std::optional<IpRulesEngine::Action> parseAction(const std::string_view action) noexcept {
    if (action == "allow") {
        return IpRulesEngine::Action::ALLOW;
    }
    if (action == "block") {
        return IpRulesEngine::Action::BLOCK;
    }
    return std::nullopt;
}

[[nodiscard]] const char *actionStr(const IpRulesEngine::Action action) noexcept {
    switch (action) {
    case IpRulesEngine::Action::ALLOW:
        return "allow";
    case IpRulesEngine::Action::BLOCK:
        return "block";
    }
    return "allow";
}

[[nodiscard]] std::optional<IpRulesEngine::Direction> parseDirection(const std::string_view dir) noexcept {
    if (dir == "any") {
        return IpRulesEngine::Direction::ANY;
    }
    if (dir == "in") {
        return IpRulesEngine::Direction::IN;
    }
    if (dir == "out") {
        return IpRulesEngine::Direction::OUT;
    }
    return std::nullopt;
}

[[nodiscard]] const char *directionStr(const IpRulesEngine::Direction dir) noexcept {
    switch (dir) {
    case IpRulesEngine::Direction::ANY:
        return "any";
    case IpRulesEngine::Direction::IN:
        return "in";
    case IpRulesEngine::Direction::OUT:
        return "out";
    }
    return "any";
}

[[nodiscard]] std::optional<IpRulesEngine::IfaceKind> parseIface(const std::string_view iface) noexcept {
    if (iface == "any") {
        return IpRulesEngine::IfaceKind::ANY;
    }
    if (iface == "wifi") {
        return IpRulesEngine::IfaceKind::WIFI;
    }
    if (iface == "data") {
        return IpRulesEngine::IfaceKind::DATA;
    }
    if (iface == "vpn") {
        return IpRulesEngine::IfaceKind::VPN;
    }
    if (iface == "unmanaged") {
        return IpRulesEngine::IfaceKind::UNMANAGED;
    }
    return std::nullopt;
}

[[nodiscard]] const char *ifaceStr(const IpRulesEngine::IfaceKind iface) noexcept {
    switch (iface) {
    case IpRulesEngine::IfaceKind::ANY:
        return "any";
    case IpRulesEngine::IfaceKind::WIFI:
        return "wifi";
    case IpRulesEngine::IfaceKind::DATA:
        return "data";
    case IpRulesEngine::IfaceKind::VPN:
        return "vpn";
    case IpRulesEngine::IfaceKind::UNMANAGED:
        return "unmanaged";
    }
    return "any";
}

[[nodiscard]] std::optional<IpRulesEngine::Proto> parseProto(const std::string_view proto) noexcept {
    if (proto == "any") {
        return IpRulesEngine::Proto::ANY;
    }
    if (proto == "tcp") {
        return IpRulesEngine::Proto::TCP;
    }
    if (proto == "udp") {
        return IpRulesEngine::Proto::UDP;
    }
    if (proto == "icmp") {
        return IpRulesEngine::Proto::ICMP;
    }
    return std::nullopt;
}

[[nodiscard]] const char *protoStr(const IpRulesEngine::Proto proto) noexcept {
    switch (proto) {
    case IpRulesEngine::Proto::ANY:
        return "any";
    case IpRulesEngine::Proto::TCP:
        return "tcp";
    case IpRulesEngine::Proto::UDP:
        return "udp";
    case IpRulesEngine::Proto::ICMP:
        return "icmp";
    }
    return "any";
}

[[nodiscard]] std::optional<IpRulesEngine::CtState> parseCtState(const std::string_view s) noexcept {
    if (s == "any") {
        return IpRulesEngine::CtState::ANY;
    }
    if (s == "new") {
        return IpRulesEngine::CtState::NEW;
    }
    if (s == "established") {
        return IpRulesEngine::CtState::ESTABLISHED;
    }
    if (s == "invalid") {
        return IpRulesEngine::CtState::INVALID;
    }
    return std::nullopt;
}

[[nodiscard]] const char *ctStateStr(const IpRulesEngine::CtState s) noexcept {
    switch (s) {
    case IpRulesEngine::CtState::ANY:
        return "any";
    case IpRulesEngine::CtState::NEW:
        return "new";
    case IpRulesEngine::CtState::ESTABLISHED:
        return "established";
    case IpRulesEngine::CtState::INVALID:
        return "invalid";
    }
    return "any";
}

[[nodiscard]] std::optional<IpRulesEngine::CtDirection> parseCtDirection(const std::string_view s) noexcept {
    if (s == "any") {
        return IpRulesEngine::CtDirection::ANY;
    }
    if (s == "orig") {
        return IpRulesEngine::CtDirection::ORIG;
    }
    if (s == "reply") {
        return IpRulesEngine::CtDirection::REPLY;
    }
    return std::nullopt;
}

[[nodiscard]] const char *ctDirStr(const IpRulesEngine::CtDirection d) noexcept {
    switch (d) {
    case IpRulesEngine::CtDirection::ANY:
        return "any";
    case IpRulesEngine::CtDirection::ORIG:
        return "orig";
    case IpRulesEngine::CtDirection::REPLY:
        return "reply";
    }
    return "any";
}

template <class RuleLike> [[nodiscard]] std::string matchKeyMk1(const RuleLike &r) {
    std::string out;
    out.reserve(192);
    out.append("mk1");
    out.append("|dir=").append(directionStr(r.dir));
    out.append("|iface=").append(ifaceStr(r.iface));
    out.append("|ifindex=").append(std::to_string(r.ifindex));
    out.append("|proto=").append(protoStr(r.proto));
    out.append("|ctstate=").append(ctStateStr(r.ctState));
    out.append("|ctdir=").append(ctDirStr(r.ctDir));
    out.append("|src=").append(formatCidrV4(r.src));
    out.append("|dst=").append(formatCidrV4(r.dst));
    out.append("|sport=").append(formatPortPredicate(r.sport));
    out.append("|dport=").append(formatPortPredicate(r.dport));
    return out;
}

void addPreflightReport(rapidjson::Value &dst, rapidjson::Document::AllocatorType &alloc,
                        const IpRulesEngine::PreflightReport &rep) {
    rapidjson::Value summary(rapidjson::kObjectType);
    summary.AddMember("rulesTotal", rep.summary.rulesTotal, alloc);
    summary.AddMember("rangeRulesTotal", rep.summary.rangeRulesTotal, alloc);
    summary.AddMember("ctRulesTotal", rep.summary.ctRulesTotal, alloc);
    summary.AddMember("ctUidsTotal", rep.summary.ctUidsTotal, alloc);
    summary.AddMember("subtablesTotal", rep.summary.subtablesTotal, alloc);
    summary.AddMember("maxSubtablesPerUid", rep.summary.maxSubtablesPerUid, alloc);
    summary.AddMember("maxRangeRulesPerBucket", rep.summary.maxRangeRulesPerBucket, alloc);
    dst.AddMember("summary", summary, alloc);

    rapidjson::Value limits(rapidjson::kObjectType);
    rapidjson::Value recommended(rapidjson::kObjectType);
    recommended.AddMember("maxRulesTotal", rep.recommended.maxRulesTotal, alloc);
    recommended.AddMember("maxSubtablesPerUid", rep.recommended.maxSubtablesPerUid, alloc);
    recommended.AddMember("maxRangeRulesPerBucket", rep.recommended.maxRangeRulesPerBucket, alloc);
    limits.AddMember("recommended", recommended, alloc);
    rapidjson::Value hard(rapidjson::kObjectType);
    hard.AddMember("maxRulesTotal", rep.hard.maxRulesTotal, alloc);
    hard.AddMember("maxSubtablesPerUid", rep.hard.maxSubtablesPerUid, alloc);
    hard.AddMember("maxRangeRulesPerBucket", rep.hard.maxRangeRulesPerBucket, alloc);
    limits.AddMember("hard", hard, alloc);
    dst.AddMember("limits", limits, alloc);

    const auto makeIssues = [&](const std::vector<IpRulesEngine::PreflightIssue> &issues) {
        rapidjson::Value arr(rapidjson::kArrayType);
        for (const auto &it : issues) {
            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("metric", makeString(it.metric, alloc), alloc);
            item.AddMember("value", it.value, alloc);
            item.AddMember("limit", it.limit, alloc);
            item.AddMember("message", makeString(it.message, alloc), alloc);
            arr.PushBack(item, alloc);
        }
        return arr;
    };

    dst.AddMember("warnings", makeIssues(rep.warnings), alloc);
    dst.AddMember("violations", makeIssues(rep.violations), alloc);
}

} // namespace

std::optional<ResponsePlan> handleIpRulesCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)limits;
    const uint32_t id = request.id;
    const rapidjson::Value &args = *request.args;

    if (request.cmd == "IPRULES.PREFLIGHT") {
        if (const auto unknown = unknownArgsKey(args, {}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto rep = pktManager.ipRules().preflight();

        rapidjson::Document result(rapidjson::kObjectType);
        addPreflightReport(result, result.GetAllocator(), rep);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "IPRULES.PRINT") {
        if (const auto unknown = unknownArgsKey(args, {"app"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto appIt = args.FindMember("app");
        if (appIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.app");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!appIt->value.IsObject()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.app must be object");
            return ResponsePlan{.response = std::move(response)};
        }

        auto [app, selectorErr] = resolveAppSelector(id, appIt->value);
        if (selectorErr.has_value()) {
            return ResponsePlan{.response = std::move(*selectorErr)};
        }
        const uint32_t uid = app->uid();

        auto rules = pktManager.ipRules().listRules(uid, std::nullopt);
        std::sort(rules.begin(), rules.end(),
                  [](const IpRulesEngine::RuleDef &a, const IpRulesEngine::RuleDef &b) {
                      return a.ruleId < b.ruleId;
                  });

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        result.AddMember("uid", uid, alloc);
        rapidjson::Value rulesValue(rapidjson::kArrayType);

        for (const auto &r : rules) {
            const auto stats = pktManager.ipRules().statsSnapshot(r.ruleId);
            const IpRulesEngine::RuleStatsSnapshot s =
                stats.value_or(IpRulesEngine::RuleStatsSnapshot{});

            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("ruleId", r.ruleId, alloc);
            item.AddMember("clientRuleId", makeString(r.clientRuleId, alloc), alloc);
            item.AddMember("matchKey", makeString(matchKeyMk1(r), alloc), alloc);

            item.AddMember("action", makeString(actionStr(r.action), alloc), alloc);
            item.AddMember("priority", r.priority, alloc);
            item.AddMember("enabled", static_cast<uint32_t>(r.enabled ? 1 : 0), alloc);
            item.AddMember("enforce", static_cast<uint32_t>(r.enforce ? 1 : 0), alloc);
            item.AddMember("log", static_cast<uint32_t>(r.log ? 1 : 0), alloc);

            item.AddMember("dir", makeString(directionStr(r.dir), alloc), alloc);
            item.AddMember("iface", makeString(ifaceStr(r.iface), alloc), alloc);
            item.AddMember("ifindex", r.ifindex, alloc);
            item.AddMember("proto", makeString(protoStr(r.proto), alloc), alloc);

            rapidjson::Value ct(rapidjson::kObjectType);
            ct.AddMember("state", makeString(ctStateStr(r.ctState), alloc), alloc);
            ct.AddMember("direction", makeString(ctDirStr(r.ctDir), alloc), alloc);
            item.AddMember("ct", ct, alloc);

            item.AddMember("src", makeString(formatCidrV4(r.src), alloc), alloc);
            item.AddMember("dst", makeString(formatCidrV4(r.dst), alloc), alloc);
            item.AddMember("sport", makeString(formatPortPredicate(r.sport), alloc), alloc);
            item.AddMember("dport", makeString(formatPortPredicate(r.dport), alloc), alloc);

            rapidjson::Value statsValue(rapidjson::kObjectType);
            statsValue.AddMember("hitPackets", s.hitPackets, alloc);
            statsValue.AddMember("hitBytes", s.hitBytes, alloc);
            statsValue.AddMember("lastHitTsNs", s.lastHitTsNs, alloc);
            statsValue.AddMember("wouldHitPackets", s.wouldHitPackets, alloc);
            statsValue.AddMember("wouldHitBytes", s.wouldHitBytes, alloc);
            statsValue.AddMember("lastWouldHitTsNs", s.lastWouldHitTsNs, alloc);
            item.AddMember("stats", statsValue, alloc);

            rulesValue.PushBack(item, alloc);
        }

        result.AddMember("rules", rulesValue, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "IPRULES.APPLY") {
        if (const auto unknown = unknownArgsKey(args, {"app", "rules"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto appIt = args.FindMember("app");
        if (appIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.app");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!appIt->value.IsObject()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.app must be object");
            return ResponsePlan{.response = std::move(response)};
        }

        const auto rulesIt = args.FindMember("rules");
        if (rulesIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.rules");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!rulesIt->value.IsArray()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.rules must be array");
            return ResponsePlan{.response = std::move(response)};
        }

        auto [app, selectorErr] = resolveAppSelector(id, appIt->value);
        if (selectorErr.has_value()) {
            return ResponsePlan{.response = std::move(*selectorErr)};
        }
        const uint32_t uid = app->uid();

        std::vector<IpRulesEngine::ApplyRule> rules;
        rules.reserve(rulesIt->value.Size());

        std::unordered_set<std::string> seenClientIds;
        seenClientIds.reserve(rulesIt->value.Size());

        std::unordered_map<std::string, std::vector<size_t>> matchKeyToIndexes;
        matchKeyToIndexes.reserve(rulesIt->value.Size());

        for (rapidjson::SizeType idx = 0; idx < rulesIt->value.Size(); ++idx) {
            const auto &rule = rulesIt->value[idx];
            if (!rule.IsObject()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rules[] items must be objects");
                return ResponsePlan{.response = std::move(response)};
            }

            // Explicitly reject forbidden fields with INVALID_ARGUMENT.
            if (rule.HasMember("ruleId")) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule must not include ruleId");
                return ResponsePlan{.response = std::move(response)};
            }
            if (rule.HasMember("matchKey")) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule must not include matchKey");
                return ResponsePlan{.response = std::move(response)};
            }
            if (rule.HasMember("stats")) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule must not include stats");
                return ResponsePlan{.response = std::move(response)};
            }

            if (const auto unknown = ControlVNext::findUnknownKey(
                    rule, {"clientRuleId", "action", "priority", "enabled", "enforce", "log",
                           "dir", "iface", "ifindex", "proto", "ct", "src", "dst", "sport", "dport"});
                unknown.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown rule key: " + std::string(*unknown));
                return ResponsePlan{.response = std::move(response)};
            }

            const auto clientRuleIdIt = rule.FindMember("clientRuleId");
            if (clientRuleIdIt == rule.MemberEnd()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "MISSING_ARGUMENT", "missing rule.clientRuleId");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!clientRuleIdIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.clientRuleId must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view clientRuleId(clientRuleIdIt->value.GetString(),
                                                clientRuleIdIt->value.GetStringLength());
            if (!IpRulesContract::isValidClientRuleId(clientRuleId)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT",
                    "rule.clientRuleId must match [A-Za-z0-9._:-]{1,64}");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!seenClientIds.emplace(clientRuleId).second) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "duplicate rule.clientRuleId");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto actionIt = rule.FindMember("action");
            if (actionIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.action");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!actionIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.action must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view actionStrView(actionIt->value.GetString(),
                                                 actionIt->value.GetStringLength());
            const auto action = parseAction(actionStrView);
            if (!action.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.action must be allow|block");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto priorityIt = rule.FindMember("priority");
            if (priorityIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.priority");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!priorityIt->value.IsInt()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.priority must be i32");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto enabledIt = rule.FindMember("enabled");
            if (enabledIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.enabled");
                return ResponsePlan{.response = std::move(response)};
            }
            uint32_t enabled = 0;
            if (!isValidToggleValue(enabledIt->value, enabled)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.enabled must be 0|1");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto enforceIt = rule.FindMember("enforce");
            if (enforceIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.enforce");
                return ResponsePlan{.response = std::move(response)};
            }
            uint32_t enforce = 0;
            if (!isValidToggleValue(enforceIt->value, enforce)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.enforce must be 0|1");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto logIt = rule.FindMember("log");
            if (logIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.log");
                return ResponsePlan{.response = std::move(response)};
            }
            uint32_t log = 0;
            if (!isValidToggleValue(logIt->value, log)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.log must be 0|1");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto dirIt = rule.FindMember("dir");
            if (dirIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.dir");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!dirIt->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rule.dir must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view dirStrView(dirIt->value.GetString(), dirIt->value.GetStringLength());
            const auto dir = parseDirection(dirStrView);
            if (!dir.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.dir must be any|in|out");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto ifaceIt = rule.FindMember("iface");
            if (ifaceIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.iface");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!ifaceIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.iface must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view ifaceStrView(ifaceIt->value.GetString(),
                                                ifaceIt->value.GetStringLength());
            const auto iface = parseIface(ifaceStrView);
            if (!iface.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.iface must be any|wifi|data|vpn|unmanaged");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto ifindexIt = rule.FindMember("ifindex");
            if (ifindexIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.ifindex");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!ifindexIt->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.ifindex must be u32");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto protoIt = rule.FindMember("proto");
            if (protoIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.proto");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!protoIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.proto must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view protoStrView(protoIt->value.GetString(),
                                                protoIt->value.GetStringLength());
            const auto proto = parseProto(protoStrView);
            if (!proto.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.proto must be any|tcp|udp|icmp");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto ctIt = rule.FindMember("ct");
            if (ctIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.ct");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!ctIt->value.IsObject()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rule.ct must be object");
                return ResponsePlan{.response = std::move(response)};
            }
            if (const auto unknown = ControlVNext::findUnknownKey(ctIt->value, {"state", "direction"});
                unknown.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown ct key: " + std::string(*unknown));
                return ResponsePlan{.response = std::move(response)};
            }
            const auto ctStateIt = ctIt->value.FindMember("state");
            if (ctStateIt == ctIt->value.MemberEnd()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "MISSING_ARGUMENT", "missing rule.ct.state");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!ctStateIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.ct.state must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view ctStateStrView(ctStateIt->value.GetString(),
                                                  ctStateIt->value.GetStringLength());
            const auto ctState = parseCtState(ctStateStrView);
            if (!ctState.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.ct.state must be any|new|established|invalid");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto ctDirIt = ctIt->value.FindMember("direction");
            if (ctDirIt == ctIt->value.MemberEnd()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "MISSING_ARGUMENT", "missing rule.ct.direction");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!ctDirIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.ct.direction must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view ctDirStrView(ctDirIt->value.GetString(),
                                                ctDirIt->value.GetStringLength());
            const auto ctDir = parseCtDirection(ctDirStrView);
            if (!ctDir.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.ct.direction must be any|orig|reply");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto srcIt = rule.FindMember("src");
            if (srcIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.src");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!srcIt->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rule.src must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            IpRulesEngine::CidrV4 src;
            if (!parseCidrV4(std::string_view(srcIt->value.GetString(), srcIt->value.GetStringLength()),
                             src)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.src must be any or CIDR a.b.c.d/prefix");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto dstIt = rule.FindMember("dst");
            if (dstIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.dst");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!dstIt->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rule.dst must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            IpRulesEngine::CidrV4 dst;
            if (!parseCidrV4(std::string_view(dstIt->value.GetString(), dstIt->value.GetStringLength()),
                             dst)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.dst must be any or CIDR a.b.c.d/prefix");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto sportIt = rule.FindMember("sport");
            if (sportIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.sport");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!sportIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.sport must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            IpRulesEngine::PortPredicate sport;
            if (!parsePortPredicate(
                    std::string_view(sportIt->value.GetString(), sportIt->value.GetStringLength()),
                    sport)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.sport must be any|N|lo-hi");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto dportIt = rule.FindMember("dport");
            if (dportIt == rule.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.dport");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!dportIt->value.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.dport must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            IpRulesEngine::PortPredicate dport;
            if (!parsePortPredicate(
                    std::string_view(dportIt->value.GetString(), dportIt->value.GetStringLength()),
                    dport)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.dport must be any|N|lo-hi");
                return ResponsePlan{.response = std::move(response)};
            }

            IpRulesEngine::ApplyRule r{};
            r.clientRuleId = std::string(clientRuleId);
            r.action = *action;
            r.priority = priorityIt->value.GetInt();
            r.enabled = enabled == 1;
            r.enforce = enforce == 1;
            r.log = log == 1;
            r.dir = *dir;
            r.iface = *iface;
            r.ifindex = ifindexIt->value.GetUint();
            r.proto = *proto;
            r.ctState = *ctState;
            r.ctDir = *ctDir;
            r.src = src;
            r.dst = dst;
            r.sport = sport;
            r.dport = dport;

            const std::string mk = matchKeyMk1(r);
            matchKeyToIndexes[mk].push_back(static_cast<size_t>(idx));

            rules.push_back(std::move(r));
        }

        // Reject duplicate matchKey within payload.
        std::vector<std::string> duplicatedMatchKeys;
        duplicatedMatchKeys.reserve(matchKeyToIndexes.size());
        for (const auto &[mk, indexes] : matchKeyToIndexes) {
            if (indexes.size() > 1) {
                duplicatedMatchKeys.push_back(mk);
            }
        }
        if (!duplicatedMatchKeys.empty()) {
            std::sort(duplicatedMatchKeys.begin(), duplicatedMatchKeys.end());
            duplicatedMatchKeys.erase(
                std::unique(duplicatedMatchKeys.begin(), duplicatedMatchKeys.end()),
                duplicatedMatchKeys.end());

            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "iprules conflict: duplicated matchKey");
            auto &alloc = response.GetAllocator();

            rapidjson::Value conflicts(rapidjson::kArrayType);
            bool truncated = false;

            constexpr size_t kMaxConflicts = 64;
            size_t added = 0;
            for (const auto &mk : duplicatedMatchKeys) {
                if (added >= kMaxConflicts) {
                    truncated = true;
                    break;
                }
                const auto it = matchKeyToIndexes.find(mk);
                if (it == matchKeyToIndexes.end()) {
                    continue;
                }

                rapidjson::Value conflict(rapidjson::kObjectType);
                conflict.AddMember("uid", uid, alloc);
                conflict.AddMember("matchKey", makeString(mk, alloc), alloc);

                rapidjson::Value conflictRules(rapidjson::kArrayType);
                for (const size_t i : it->second) {
                    if (i >= rules.size()) {
                        continue;
                    }
                    const auto &r = rules[i];
                    rapidjson::Value rr(rapidjson::kObjectType);
                    rr.AddMember("clientRuleId", makeString(r.clientRuleId, alloc), alloc);
                    rr.AddMember("action", makeString(actionStr(r.action), alloc), alloc);
                    rr.AddMember("priority", r.priority, alloc);
                    rr.AddMember("enabled", static_cast<uint32_t>(r.enabled ? 1 : 0), alloc);
                    rr.AddMember("enforce", static_cast<uint32_t>(r.enforce ? 1 : 0), alloc);
                    rr.AddMember("log", static_cast<uint32_t>(r.log ? 1 : 0), alloc);
                    conflictRules.PushBack(rr, alloc);
                }
                conflict.AddMember("rules", conflictRules, alloc);

                conflicts.PushBack(conflict, alloc);
                added++;
            }

            response["error"].AddMember("conflicts", conflicts, alloc);
            response["error"].AddMember("truncated", truncated, alloc);
            return ResponsePlan{.response = std::move(response)};
        }

        const auto res = pktManager.ipRules().replaceRulesForUid(uid, rules);
        if (!res.ok) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", res.error);
            if (!res.preflight.ok()) {
                auto &alloc = response.GetAllocator();
                rapidjson::Value preflight(rapidjson::kObjectType);
                addPreflightReport(preflight, alloc, res.preflight);
                response["error"].AddMember("preflight", preflight, alloc);
            }
            return ResponsePlan{.response = std::move(response)};
        }

        // Success: return committed mapping.
        auto committed = pktManager.ipRules().listRules(uid, std::nullopt);
        std::sort(committed.begin(), committed.end(),
                  [](const IpRulesEngine::RuleDef &a, const IpRulesEngine::RuleDef &b) {
                      return a.ruleId < b.ruleId;
                  });

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        result.AddMember("uid", uid, alloc);
        rapidjson::Value mapRules(rapidjson::kArrayType);
        for (const auto &r : committed) {
            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("clientRuleId", makeString(r.clientRuleId, alloc), alloc);
            item.AddMember("ruleId", r.ruleId, alloc);
            item.AddMember("matchKey", makeString(matchKeyMk1(r), alloc), alloc);
            mapRules.PushBack(item, alloc);
        }
        result.AddMember("rules", mapRules, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    return std::nullopt;
}

} // namespace ControlVNextSessionCommands
