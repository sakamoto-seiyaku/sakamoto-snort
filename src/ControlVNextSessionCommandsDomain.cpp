/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

#include <AppManager.hpp>
#include <BlockingListManager.hpp>
#include <DomainManager.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <limits.h>
#include <optional>
#include <sstream>
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
unknownArgsKey(const rapidjson::Value &args, std::initializer_list<std::string_view> allowed) {
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

[[nodiscard]] bool isValidDomainString(const std::string_view domain, std::string &reason) {
    if (domain.empty()) {
        reason = "domain must be non-empty";
        return false;
    }
    if (domain.size() > HOST_NAME_MAX) {
        reason = "domain is too long";
        return false;
    }

    for (unsigned char ch : domain) {
        if (ch == '\0') {
            reason = "domain must not contain NUL";
            return false;
        }
        if (ch < 0x20) {
            reason = "domain must not contain control chars";
            return false;
        }
        if (ch == ' ') {
            reason = "domain must not contain ASCII whitespace";
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::pair<App::Ptr, std::optional<rapidjson::Document>>
resolveAppSelector(const uint32_t id, const rapidjson::Value &selector) {
    if (const auto unknown = ControlVNext::findUnknownKey(selector, {"uid", "pkg", "userId"});
        unknown.has_value()) {
        rapidjson::Document response = ControlVNext::makeErrorResponse(
            id, "SYNTAX_ERROR", "unknown selector key: " + std::string(*unknown));
        return {nullptr, std::move(response)};
    }

    const auto uidIt = selector.FindMember("uid");
    const auto pkgIt = selector.FindMember("pkg");
    const auto userIt = selector.FindMember("userId");

    const bool hasUid = uidIt != selector.MemberEnd();
    const bool hasPkg = pkgIt != selector.MemberEnd();
    const bool hasUser = userIt != selector.MemberEnd();

    if (hasUid) {
        if (hasPkg || hasUser) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "selector must be either {uid} or {pkg,userId}");
            return {nullptr, std::move(response)};
        }
        if (!uidIt->value.IsUint()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "selector.uid must be u32");
            return {nullptr, std::move(response)};
        }
        const auto app = appManager.find(uidIt->value.GetUint());
        if (!app) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "SELECTOR_NOT_FOUND", "app selector not found");
            auto &alloc = response.GetAllocator();
            rapidjson::Value candidates(rapidjson::kArrayType);
            response["error"].AddMember("candidates", candidates, alloc);
            return {nullptr, std::move(response)};
        }
        return {app, std::nullopt};
    }

    if (hasPkg || hasUser) {
        if (!hasPkg || !hasUser) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "MISSING_ARGUMENT", "selector requires pkg and userId");
            return {nullptr, std::move(response)};
        }
        if (!pkgIt->value.IsString()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "selector.pkg must be string");
            return {nullptr, std::move(response)};
        }
        if (!userIt->value.IsUint()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "selector.userId must be u32");
            return {nullptr, std::move(response)};
        }
        const std::string pkg(pkgIt->value.GetString(), pkgIt->value.GetStringLength());
        const uint32_t userId = userIt->value.GetUint();
        const auto app = appManager.findByName(pkg, userId);
        if (!app) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "SELECTOR_NOT_FOUND", "app selector not found");
            auto &alloc = response.GetAllocator();
            rapidjson::Value candidates(rapidjson::kArrayType);
            response["error"].AddMember("candidates", candidates, alloc);
            return {nullptr, std::move(response)};
        }
        return {app, std::nullopt};
    }

    rapidjson::Document response =
        ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "selector requires uid or pkg+userId");
    return {nullptr, std::move(response)};
}

[[nodiscard]] bool isValidGuid36(const std::string_view guid) noexcept {
    if (guid.size() != 36) {
        return false;
    }
    const auto isHyphenPos = [](const size_t i) {
        return i == 8 || i == 13 || i == 18 || i == 23;
    };
    for (size_t i = 0; i < guid.size(); ++i) {
        const char ch = guid[i];
        if (isHyphenPos(i)) {
            if (ch != '-') {
                return false;
            }
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<Stats::Color> parseListKind(const std::string_view kind) noexcept {
    if (kind == "block") {
        return Stats::BLACK;
    }
    if (kind == "allow") {
        return Stats::WHITE;
    }
    return std::nullopt;
}

[[nodiscard]] const char *listKindStr(const Stats::Color color) noexcept {
    switch (color) {
    case Stats::BLACK:
        return "block";
    case Stats::WHITE:
        return "allow";
    default:
        return "block";
    }
}

[[nodiscard]] std::string formatUpdatedAt(const time_t updatedAt) {
    if (updatedAt == 0) {
        return {};
    }
    std::tm tm{};
    if (localtime_r(&updatedAt, &tm) == nullptr) {
        return {};
    }
    char buf[20];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d_%H:%M:%S", &tm) != 19) {
        return {};
    }
    return std::string(buf);
}

[[nodiscard]] bool isValidUpdatedAtString(const std::string_view updatedAt) {
    if (updatedAt.empty()) {
        return true;
    }
    std::tm tm{};
    std::istringstream ss{std::string(updatedAt)};
    return static_cast<bool>(ss >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S"));
}

[[nodiscard]] bool ensureFileExists(const std::string &path) {
    std::ofstream out(path, std::ofstream::app);
    return out.good();
}

[[nodiscard]] std::optional<Rule::Type> parseRuleType(const std::string_view type) noexcept {
    if (type == "domain") {
        return Rule::DOMAIN;
    }
    if (type == "wildcard") {
        return Rule::WILDCARD;
    }
    if (type == "regex") {
        return Rule::REGEX;
    }
    return std::nullopt;
}

[[nodiscard]] const char *ruleTypeStr(const Rule::Type type) noexcept {
    switch (type) {
    case Rule::DOMAIN:
        return "domain";
    case Rule::WILDCARD:
        return "wildcard";
    case Rule::REGEX:
        return "regex";
    default:
        return "domain";
    }
}

[[nodiscard]] rapidjson::Value makeRuleItem(const uint32_t ruleId, const Rule::Type type,
                                            const std::string_view pattern,
                                            rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("ruleId", ruleId, alloc);
    out.AddMember("type", makeString(ruleTypeStr(type), alloc), alloc);
    out.AddMember("pattern", makeString(pattern, alloc), alloc);
    return out;
}

struct DesiredRule {
    std::optional<uint32_t> ruleId;
    Rule::Type type = Rule::DOMAIN;
    std::string pattern;
};

[[nodiscard]] std::string ruleKey(const Rule::Type type, const std::string_view pattern) {
    std::string key(ruleTypeStr(type));
    key.push_back('\x1f');
    key.append(pattern);
    return key;
}

} // namespace

std::optional<ResponsePlan> handleDomainCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)limits;
    const uint32_t id = request.id;
    const rapidjson::Value &args = *request.args;

    const auto requireEmptyArgs = [&](const std::string_view cmd) -> std::optional<rapidjson::Document> {
        if (const auto unknown = unknownArgsKey(args, {}); unknown.has_value()) {
            return ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
        }
        (void)cmd;
        return std::nullopt;
    };

    if (request.cmd == "DOMAINRULES.GET") {
        if (auto err = requireEmptyArgs("DOMAINRULES.GET"); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }

        auto rules = rulesManager.snapshotBaseline();
        std::sort(rules.begin(), rules.end(),
                  [](const auto &a, const auto &b) { return a.ruleId < b.ruleId; });

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        rapidjson::Value rulesValue(rapidjson::kArrayType);

        for (const auto &r : rules) {
            rulesValue.PushBack(makeRuleItem(r.ruleId, r.type, r.pattern, alloc), alloc);
        }

        result.AddMember("rules", rulesValue, alloc);
        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "DOMAINRULES.APPLY") {
        if (const auto unknown = unknownArgsKey(args, {"rules"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
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

        const auto baseline = rulesManager.snapshotBaseline();
        std::unordered_map<std::string, uint32_t> baselineByKey;
        baselineByKey.reserve(baseline.size());
        for (const auto &r : baseline) {
            baselineByKey.emplace(ruleKey(r.type, r.pattern), r.ruleId);
        }

        std::unordered_set<uint32_t> seenRuleIds;
        std::unordered_set<std::string> seenRules;

        std::vector<DesiredRule> desired;
        desired.reserve(rulesIt->value.Size());

        std::optional<uint32_t> maxRuleIdInPayload;
        std::unordered_set<uint32_t> desiredRuleIds;

        for (const auto &itemVal : rulesIt->value.GetArray()) {
            if (!itemVal.IsObject()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.rules items must be object");
                return ResponsePlan{.response = std::move(response)};
            }

            if (const auto unknown =
                    ControlVNext::findUnknownKey(itemVal, {"ruleId", "type", "pattern"});
                unknown.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown rule key: " + std::string(*unknown));
                return ResponsePlan{.response = std::move(response)};
            }

            const auto typeIt = itemVal.FindMember("type");
            if (typeIt == itemVal.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.type");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!typeIt->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rule.type must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view typeStr(typeIt->value.GetString(), typeIt->value.GetStringLength());
            const auto type = parseRuleType(typeStr);
            if (!type.has_value()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "rule.type must be \"domain\"|\"wildcard\"|\"regex\"");
                return ResponsePlan{.response = std::move(response)};
            }

            const auto patIt = itemVal.FindMember("pattern");
            if (patIt == itemVal.MemberEnd()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing rule.pattern");
                return ResponsePlan{.response = std::move(response)};
            }
            if (!patIt->value.IsString()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "rule.pattern must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view pattern(patIt->value.GetString(), patIt->value.GetStringLength());

            DesiredRule d{};
            d.type = *type;
            d.pattern.assign(pattern);

            if (const auto ruleIdIt = itemVal.FindMember("ruleId"); ruleIdIt != itemVal.MemberEnd()) {
                if (!ruleIdIt->value.IsUint()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "rule.ruleId must be u32");
                    return ResponsePlan{.response = std::move(response)};
                }
                const uint32_t ruleId = ruleIdIt->value.GetUint();
                if (!seenRuleIds.insert(ruleId).second) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "duplicate ruleId in payload");
                    return ResponsePlan{.response = std::move(response)};
                }
                d.ruleId = ruleId;
                desiredRuleIds.insert(ruleId);
                maxRuleIdInPayload = maxRuleIdInPayload.has_value()
                                         ? std::max(*maxRuleIdInPayload, ruleId)
                                         : ruleId;
            } else {
                const auto itExisting = baselineByKey.find(ruleKey(*type, pattern));
                if (itExisting != baselineByKey.end()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT",
                        "missing ruleId for existing rule; call DOMAINRULES.GET first");
                    auto &alloc = response.GetAllocator();
                    response["error"].AddMember(
                        "hint", makeString("include ruleId when updating existing rules", alloc), alloc);
                    return ResponsePlan{.response = std::move(response)};
                }
            }

            if (!seenRules.insert(ruleKey(*type, pattern)).second) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "duplicate (type,pattern) in payload");
                return ResponsePlan{.response = std::move(response)};
            }

            const Rule tmp(*type, 0, d.pattern);
            if (!tmp.valid()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "invalid rule regex");
                return ResponsePlan{.response = std::move(response)};
            }

            desired.push_back(std::move(d));
        }

        std::vector<uint32_t> removedRuleIds;
        removedRuleIds.reserve(baseline.size());
        for (const auto &r : baseline) {
            if (desiredRuleIds.find(r.ruleId) == desiredRuleIds.end()) {
                removedRuleIds.push_back(r.ruleId);
            }
        }

        const auto conflicts = rulesManager.conflictsForRemoval(removedRuleIds);
        if (!conflicts.empty()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "rule removal violates referential integrity");
            auto &alloc = response.GetAllocator();
            rapidjson::Value conflictsValue(rapidjson::kArrayType);

            for (const auto &c : conflicts) {
                rapidjson::Value item(rapidjson::kObjectType);
                item.AddMember("ruleId", c.ruleId, alloc);

                rapidjson::Value refsValue(rapidjson::kArrayType);
                if (c.device) {
                    rapidjson::Value ref(rapidjson::kObjectType);
                    ref.AddMember("scope", makeString("device", alloc), alloc);
                    refsValue.PushBack(ref, alloc);
                }
                for (const auto uid : c.appUids) {
                    rapidjson::Value ref(rapidjson::kObjectType);
                    ref.AddMember("scope", makeString("app", alloc), alloc);
                    rapidjson::Value appObj(rapidjson::kObjectType);
                    appObj.AddMember("uid", uid, alloc);
                    ref.AddMember("app", appObj, alloc);
                    refsValue.PushBack(ref, alloc);
                }
                item.AddMember("refs", refsValue, alloc);
                conflictsValue.PushBack(item, alloc);
            }

            response["error"].AddMember("conflicts", conflictsValue, alloc);
            response["error"].AddMember(
                "hint",
                makeString("remove references via DOMAINPOLICY.APPLY before removing rules", alloc),
                alloc);
            return ResponsePlan{.response = std::move(response)};
        }

        if (maxRuleIdInPayload.has_value()) {
            rulesManager.ensureNextRuleIdAtLeast(*maxRuleIdInPayload + 1);
        }

        for (auto &d : desired) {
            if (d.ruleId.has_value()) {
                rulesManager.upsertRuleWithId(*d.ruleId, d.type, d.pattern);
            } else {
                d.ruleId = rulesManager.addRule(d.type, d.pattern);
            }
        }
        for (const auto ruleId : removedRuleIds) {
            rulesManager.removeRule(ruleId);
        }

        auto finalRules = rulesManager.snapshotBaseline();
        std::sort(finalRules.begin(), finalRules.end(),
                  [](const auto &a, const auto &b) { return a.ruleId < b.ruleId; });

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        rapidjson::Value rulesValue(rapidjson::kArrayType);
        for (const auto &r : finalRules) {
            rulesValue.PushBack(makeRuleItem(r.ruleId, r.type, r.pattern, alloc), alloc);
        }
        result.AddMember("rules", rulesValue, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "DOMAINPOLICY.GET") {
        if (const auto unknown = unknownArgsKey(args, {"scope", "app"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto scopeIt = args.FindMember("scope");
        if (scopeIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.scope");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!scopeIt->value.IsString()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.scope must be string");
            return ResponsePlan{.response = std::move(response)};
        }
        const std::string_view scope(scopeIt->value.GetString(), scopeIt->value.GetStringLength());

        const bool deviceScope = scope == "device";
        const bool appScope = scope == "app";
        if (!deviceScope && !appScope) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.scope must be \"device\" or \"app\"");
            return ResponsePlan{.response = std::move(response)};
        }

        const auto appIt = args.FindMember("app");
        if (deviceScope) {
            if (appIt != args.MemberEnd()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.app not allowed for device scope");
                return ResponsePlan{.response = std::move(response)};
            }
        } else {
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
        }

        App::Ptr targetApp;
        if (appScope) {
            auto [resolved, selectorError] = resolveAppSelector(id, appIt->value);
            if (selectorError.has_value()) {
                return ResponsePlan{.response = std::move(*selectorError)};
            }
            targetApp = std::move(resolved);
        }

        auto allowDomains =
            deviceScope ? domManager.snapshotCustomDomains(Stats::WHITE)
                        : targetApp->snapshotCustomDomains(Stats::WHITE);
        auto blockDomains =
            deviceScope ? domManager.snapshotCustomDomains(Stats::BLACK)
                        : targetApp->snapshotCustomDomains(Stats::BLACK);
        auto allowRuleIds =
            deviceScope ? domManager.snapshotCustomRuleIds(Stats::WHITE)
                        : targetApp->snapshotCustomRuleIds(Stats::WHITE);
        auto blockRuleIds =
            deviceScope ? domManager.snapshotCustomRuleIds(Stats::BLACK)
                        : targetApp->snapshotCustomRuleIds(Stats::BLACK);

        std::sort(allowDomains.begin(), allowDomains.end());
        std::sort(blockDomains.begin(), blockDomains.end());
        std::sort(allowRuleIds.begin(), allowRuleIds.end());
        std::sort(blockRuleIds.begin(), blockRuleIds.end());

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();

        const auto makeDomainsArray = [&](const std::vector<std::string> &domains) -> rapidjson::Value {
            rapidjson::Value out(rapidjson::kArrayType);
            for (const auto &d : domains) {
                out.PushBack(makeString(d, alloc), alloc);
            }
            return out;
        };

        const auto makeRuleIdsArray = [&](const std::vector<Rule::Id> &ruleIds) -> rapidjson::Value {
            rapidjson::Value out(rapidjson::kArrayType);
            for (const auto ruleId : ruleIds) {
                out.PushBack(ruleId, alloc);
            }
            return out;
        };

        rapidjson::Value allow(rapidjson::kObjectType);
        allow.AddMember("domains", makeDomainsArray(allowDomains), alloc);
        allow.AddMember("ruleIds", makeRuleIdsArray(allowRuleIds), alloc);

        rapidjson::Value block(rapidjson::kObjectType);
        block.AddMember("domains", makeDomainsArray(blockDomains), alloc);
        block.AddMember("ruleIds", makeRuleIdsArray(blockRuleIds), alloc);

        rapidjson::Value policy(rapidjson::kObjectType);
        policy.AddMember("allow", allow, alloc);
        policy.AddMember("block", block, alloc);

        result.AddMember("policy", policy, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "DOMAINPOLICY.APPLY") {
        if (const auto unknown = unknownArgsKey(args, {"scope", "app", "policy"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto scopeIt = args.FindMember("scope");
        if (scopeIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.scope");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!scopeIt->value.IsString()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.scope must be string");
            return ResponsePlan{.response = std::move(response)};
        }
        const std::string_view scope(scopeIt->value.GetString(), scopeIt->value.GetStringLength());

        const bool deviceScope = scope == "device";
        const bool appScope = scope == "app";
        if (!deviceScope && !appScope) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.scope must be \"device\" or \"app\"");
            return ResponsePlan{.response = std::move(response)};
        }

        const auto appIt = args.FindMember("app");
        if (deviceScope) {
            if (appIt != args.MemberEnd()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.app not allowed for device scope");
                return ResponsePlan{.response = std::move(response)};
            }
        } else {
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
        }

        const auto policyIt = args.FindMember("policy");
        if (policyIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.policy");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!policyIt->value.IsObject()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.policy must be object");
            return ResponsePlan{.response = std::move(response)};
        }

        const rapidjson::Value &policyObj = policyIt->value;
        if (const auto unknown = ControlVNext::findUnknownKey(policyObj, {"allow", "block"});
            unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown policy key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto allowIt = policyObj.FindMember("allow");
        const auto blockIt = policyObj.FindMember("block");
        if (allowIt == policyObj.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing policy.allow");
            return ResponsePlan{.response = std::move(response)};
        }
        if (blockIt == policyObj.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing policy.block");
            return ResponsePlan{.response = std::move(response)};
        }
        if (!allowIt->value.IsObject() || !blockIt->value.IsObject()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "policy.allow and policy.block must be objects");
            return ResponsePlan{.response = std::move(response)};
        }

        const auto parseSide = [&](const rapidjson::Value &sideObj, const std::string_view sideName,
                                   std::vector<std::string> &outDomains,
                                   std::vector<uint32_t> &outRuleIds) -> std::optional<rapidjson::Document> {
            if (const auto unknown = ControlVNext::findUnknownKey(sideObj, {"domains", "ruleIds"});
                unknown.has_value()) {
                return ControlVNext::makeErrorResponse(
                    id, "SYNTAX_ERROR", "unknown policy." + std::string(sideName) + " key: " + std::string(*unknown));
            }

            const auto domainsIt = sideObj.FindMember("domains");
            if (domainsIt == sideObj.MemberEnd()) {
                return ControlVNext::makeErrorResponse(
                    id, "MISSING_ARGUMENT",
                    "missing policy." + std::string(sideName) + ".domains");
            }
            if (!domainsIt->value.IsArray()) {
                return ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT",
                    "policy." + std::string(sideName) + ".domains must be array");
            }

            const auto ruleIdsIt = sideObj.FindMember("ruleIds");
            if (ruleIdsIt == sideObj.MemberEnd()) {
                return ControlVNext::makeErrorResponse(
                    id, "MISSING_ARGUMENT",
                    "missing policy." + std::string(sideName) + ".ruleIds");
            }
            if (!ruleIdsIt->value.IsArray()) {
                return ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT",
                    "policy." + std::string(sideName) + ".ruleIds must be array");
            }

            for (const auto &domVal : domainsIt->value.GetArray()) {
                if (!domVal.IsString()) {
                    return ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT",
                        "policy." + std::string(sideName) + ".domains items must be string");
                }
                const std::string_view domain(domVal.GetString(), domVal.GetStringLength());
                std::string reason;
                if (!isValidDomainString(domain, reason)) {
                    return ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT",
                        "invalid policy." + std::string(sideName) + ".domains item: " + reason);
                }
                outDomains.emplace_back(domain);
            }

            for (const auto &ruleIdVal : ruleIdsIt->value.GetArray()) {
                if (!ruleIdVal.IsUint()) {
                    return ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT",
                        "policy." + std::string(sideName) + ".ruleIds items must be u32");
                }
                const uint32_t ruleId = ruleIdVal.GetUint();
                if (!rulesManager.findThreadSafe(ruleId)) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT",
                        "unknown ruleId in policy." + std::string(sideName) + ".ruleIds");
                    auto &alloc = response.GetAllocator();
                    response["error"].AddMember(
                        "hint", makeString("call DOMAINRULES.GET and use existing ruleIds", alloc), alloc);
                    return std::move(response);
                }
                outRuleIds.push_back(ruleId);
            }

            return std::nullopt;
        };

        std::vector<std::string> allowDomains;
        std::vector<std::string> blockDomains;
        std::vector<uint32_t> allowRuleIds;
        std::vector<uint32_t> blockRuleIds;

        if (auto err = parseSide(allowIt->value, "allow", allowDomains, allowRuleIds); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }
        if (auto err = parseSide(blockIt->value, "block", blockDomains, blockRuleIds); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }

        App::Ptr targetApp;
        if (appScope) {
            auto [resolved, selectorError] = resolveAppSelector(id, appIt->value);
            if (selectorError.has_value()) {
                return ResponsePlan{.response = std::move(*selectorError)};
            }
            targetApp = std::move(resolved);
        }

        const auto applyDomains = [&](const Stats::Color color, const std::vector<std::string> &desiredDomains) {
            const auto current = deviceScope ? domManager.snapshotCustomDomains(color)
                                             : targetApp->snapshotCustomDomains(color);
            std::unordered_set<std::string> curSet(current.begin(), current.end());
            std::unordered_set<std::string> desiredSet(desiredDomains.begin(), desiredDomains.end());

            for (const auto &d : current) {
                if (desiredSet.find(d) == desiredSet.end()) {
                    if (deviceScope) {
                        domManager.removeCustomDomain(d, color);
                    } else {
                        targetApp->removeCustomDomain(d, color);
                    }
                }
            }
            for (const auto &d : desiredSet) {
                if (curSet.find(d) == curSet.end()) {
                    if (deviceScope) {
                        domManager.addCustomDomain(d, color);
                    } else {
                        targetApp->addCustomDomain(d, color);
                    }
                }
            }
        };

        const auto applyRules = [&](const Stats::Color color, const std::vector<uint32_t> &desiredIds) {
            const auto current = deviceScope ? domManager.snapshotCustomRuleIds(color)
                                             : targetApp->snapshotCustomRuleIds(color);
            std::unordered_set<uint32_t> curSet;
            curSet.reserve(current.size());
            for (const auto rid : current) curSet.insert(rid);

            std::unordered_set<uint32_t> desiredSet;
            desiredSet.reserve(desiredIds.size());
            for (const auto rid : desiredIds) desiredSet.insert(rid);

            for (const auto rid : current) {
                if (desiredSet.find(rid) == desiredSet.end()) {
                    if (deviceScope) {
                        rulesManager.removeCustom(rid, color);
                    } else {
                        rulesManager.removeCustom(targetApp, rid, color);
                    }
                }
            }
            for (const auto rid : desiredSet) {
                if (curSet.find(rid) == curSet.end()) {
                    if (deviceScope) {
                        rulesManager.addCustom(rid, color, true);
                    } else {
                        rulesManager.addCustom(targetApp, rid, color, true);
                    }
                }
            }
        };

        applyDomains(Stats::WHITE, allowDomains);
        applyDomains(Stats::BLACK, blockDomains);
        applyRules(Stats::WHITE, allowRuleIds);
        applyRules(Stats::BLACK, blockRuleIds);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "DOMAINLISTS.GET") {
        if (auto err = requireEmptyArgs("DOMAINLISTS.GET"); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }

        struct ListEntry {
            std::string listId;
            Stats::Color color = Stats::BLACK;
            uint8_t mask = 0;
            bool enabled = false;
            std::string url;
            std::string name;
            std::string updatedAt;
            std::string etag;
            bool outdated = true;
            uint32_t domainsCount = 0;
        };

        std::vector<ListEntry> entries;
        const auto lists = blockingListManager.listsSnapshot();
        entries.reserve(lists.size());

        for (const auto &bl : lists) {
            ListEntry e{};
            e.listId = bl.getId();
            e.color = bl.getColor();
            e.mask = bl.getBlockMask();
            e.enabled = bl.isEnabled();
            e.url = bl.getUrl();
            e.name = bl.getName();
            e.updatedAt = formatUpdatedAt(bl.getUpdatedAt());
            e.etag = bl.getEtag();
            e.outdated = bl.isOutdated();
            e.domainsCount = bl.getDomainsCount();
            entries.push_back(std::move(e));
        }

        std::sort(entries.begin(), entries.end(), [&](const ListEntry &a, const ListEntry &b) {
            const std::string_view ak = listKindStr(a.color);
            const std::string_view bk = listKindStr(b.color);
            if (ak != bk) {
                return ak < bk;
            }
            return a.listId < b.listId;
        });

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        rapidjson::Value listsValue(rapidjson::kArrayType);

        for (const auto &e : entries) {
            rapidjson::Value item(rapidjson::kObjectType);
            item.AddMember("listId", makeString(e.listId, alloc), alloc);
            item.AddMember("listKind", makeString(listKindStr(e.color), alloc), alloc);
            item.AddMember("mask", static_cast<uint32_t>(e.mask), alloc);
            item.AddMember("enabled", e.enabled ? 1 : 0, alloc);
            item.AddMember("url", makeString(e.url, alloc), alloc);
            item.AddMember("name", makeString(e.name, alloc), alloc);
            item.AddMember("updatedAt", makeString(e.updatedAt, alloc), alloc);
            item.AddMember("etag", makeString(e.etag, alloc), alloc);
            item.AddMember("outdated", e.outdated ? 1 : 0, alloc);
            item.AddMember("domainsCount", e.domainsCount, alloc);
            listsValue.PushBack(item, alloc);
        }

        result.AddMember("lists", listsValue, alloc);
        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "DOMAINLISTS.APPLY") {
        if (const auto unknown = unknownArgsKey(args, {"upsert", "remove"}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        std::vector<std::string> removeOrder;
        {
            const auto removeIt = args.FindMember("remove");
            if (removeIt != args.MemberEnd()) {
                if (!removeIt->value.IsArray()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "args.remove must be array");
                    return ResponsePlan{.response = std::move(response)};
                }
                std::unordered_set<std::string> seen;
                for (const auto &v : removeIt->value.GetArray()) {
                    if (!v.IsString()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "args.remove items must be string");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    const std::string_view listId(v.GetString(), v.GetStringLength());
                    if (!isValidGuid36(listId)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "remove listId must be GUID string");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    if (seen.insert(std::string(listId)).second) {
                        removeOrder.emplace_back(listId);
                    }
                }
            }
        }

        struct PlannedList {
            std::string listId;
            bool exists = false;
            Stats::Color oldColor = Stats::BLACK;
            uint8_t oldMask = 0;
            bool oldEnabled = false;

            Stats::Color color = Stats::BLACK;
            uint8_t mask = 0;
            bool enabled = false;

            std::string url;
            std::string name;
            std::string updatedAt;
            std::string etag;
            bool outdated = true;
            uint32_t domainsCount = 0;
        };

        std::vector<PlannedList> planned;
        std::unordered_set<std::string> plannedIds;

        const auto current = blockingListManager.getAll();

        const auto upsertIt = args.FindMember("upsert");
        if (upsertIt != args.MemberEnd()) {
            if (!upsertIt->value.IsArray()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.upsert must be array");
                return ResponsePlan{.response = std::move(response)};
            }

            planned.reserve(upsertIt->value.Size());

            for (const auto &itemVal : upsertIt->value.GetArray()) {
                if (!itemVal.IsObject()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "args.upsert items must be object");
                    return ResponsePlan{.response = std::move(response)};
                }

                if (const auto unknown = ControlVNext::findUnknownKey(
                        itemVal, {"listId", "listKind", "mask", "enabled", "url", "name", "updatedAt",
                                  "etag", "outdated", "domainsCount"});
                    unknown.has_value()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "SYNTAX_ERROR", "unknown list key: " + std::string(*unknown));
                    return ResponsePlan{.response = std::move(response)};
                }

                const auto listIdIt = itemVal.FindMember("listId");
                const auto listKindIt = itemVal.FindMember("listKind");
                const auto maskIt = itemVal.FindMember("mask");
                const auto enabledIt = itemVal.FindMember("enabled");

                if (listIdIt == itemVal.MemberEnd()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing list.listId");
                    return ResponsePlan{.response = std::move(response)};
                }
                if (listKindIt == itemVal.MemberEnd()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing list.listKind");
                    return ResponsePlan{.response = std::move(response)};
                }
                if (maskIt == itemVal.MemberEnd()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing list.mask");
                    return ResponsePlan{.response = std::move(response)};
                }
                if (enabledIt == itemVal.MemberEnd()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing list.enabled");
                    return ResponsePlan{.response = std::move(response)};
                }

                if (!listIdIt->value.IsString()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "list.listId must be string");
                    return ResponsePlan{.response = std::move(response)};
                }
                const std::string listId(listIdIt->value.GetString(), listIdIt->value.GetStringLength());
                if (!isValidGuid36(listId)) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "list.listId must be GUID string");
                    return ResponsePlan{.response = std::move(response)};
                }
                if (!plannedIds.insert(listId).second) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "duplicate listId in args.upsert");
                    return ResponsePlan{.response = std::move(response)};
                }

                if (!listKindIt->value.IsString()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "list.listKind must be string");
                    return ResponsePlan{.response = std::move(response)};
                }
                const std::string_view listKind(listKindIt->value.GetString(),
                                                listKindIt->value.GetStringLength());
                const auto parsedKind = parseListKind(listKind);
                if (!parsedKind.has_value()) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "list.listKind must be \"block\" or \"allow\"");
                    return ResponsePlan{.response = std::move(response)};
                }

                if (!maskIt->value.IsUint()) {
                    rapidjson::Document response =
                        ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "list.mask must be u32");
                    return ResponsePlan{.response = std::move(response)};
                }
                const uint32_t maskU32 = maskIt->value.GetUint();
                if (maskU32 > 255 || !Settings::isValidBlockingListMask(maskU32)) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "list.mask must be a single supported bit");
                    return ResponsePlan{.response = std::move(response)};
                }

                uint32_t enabledToggle = 0;
                if (!isValidToggleValue(enabledIt->value, enabledToggle)) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INVALID_ARGUMENT", "list.enabled must be 0 or 1");
                    return ResponsePlan{.response = std::move(response)};
                }

                PlannedList p{};
                p.listId = listId;
                p.color = *parsedKind;
                p.mask = static_cast<uint8_t>(maskU32);
                p.enabled = enabledToggle == 1;

                if (auto it = current.find(listId); it != current.end()) {
                    const BlockingList &bl = it->second;
                    p.exists = true;
                    p.oldColor = bl.getColor();
                    p.oldMask = bl.getBlockMask();
                    p.oldEnabled = bl.isEnabled();

                    const bool kindChanged = p.oldColor != p.color;
                    const bool maskChanged = p.oldMask != p.mask;
                    if (kindChanged && maskChanged) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "cannot change listKind and mask in one upsert");
                        return ResponsePlan{.response = std::move(response)};
                    }

                    p.url = bl.getUrl();
                    p.name = bl.getName();
                    p.updatedAt = formatUpdatedAt(bl.getUpdatedAt());
                    p.etag = bl.getEtag();
                    p.outdated = bl.isOutdated();
                    p.domainsCount = bl.getDomainsCount();
                } else {
                    // Defaults for new list.
                    p.url = "";
                    p.name = "";
                    p.updatedAt = "";
                    p.etag = "";
                    p.outdated = true;
                    p.domainsCount = 0;
                }

                if (const auto it = itemVal.FindMember("url"); it != itemVal.MemberEnd()) {
                    if (!it->value.IsString()) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "list.url must be string");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    p.url.assign(it->value.GetString(), it->value.GetStringLength());
                }
                if (const auto it = itemVal.FindMember("name"); it != itemVal.MemberEnd()) {
                    if (!it->value.IsString()) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "list.name must be string");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    p.name.assign(it->value.GetString(), it->value.GetStringLength());
                }
                if (const auto it = itemVal.FindMember("updatedAt"); it != itemVal.MemberEnd()) {
                    if (!it->value.IsString()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "list.updatedAt must be string");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    const std::string_view updatedAt(it->value.GetString(), it->value.GetStringLength());
                    if (!isValidUpdatedAtString(updatedAt)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "list.updatedAt must be \"YYYY-MM-DD_HH:MM:SS\" or \"\"");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    p.updatedAt.assign(updatedAt);
                }
                if (const auto it = itemVal.FindMember("etag"); it != itemVal.MemberEnd()) {
                    if (!it->value.IsString()) {
                        rapidjson::Document response =
                            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "list.etag must be string");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    p.etag.assign(it->value.GetString(), it->value.GetStringLength());
                }
                if (const auto it = itemVal.FindMember("outdated"); it != itemVal.MemberEnd()) {
                    uint32_t v = 0;
                    if (!isValidToggleValue(it->value, v)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "list.outdated must be 0 or 1");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    p.outdated = v == 1;
                }
                if (const auto it = itemVal.FindMember("domainsCount"); it != itemVal.MemberEnd()) {
                    if (!it->value.IsUint()) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INVALID_ARGUMENT", "list.domainsCount must be u32");
                        return ResponsePlan{.response = std::move(response)};
                    }
                    p.domainsCount = it->value.GetUint();
                }

                planned.push_back(std::move(p));
            }
        }

        for (const auto &rid : removeOrder) {
            if (plannedIds.find(rid) != plannedIds.end()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "listId must not appear in both upsert and remove");
                return ResponsePlan{.response = std::move(response)};
            }
        }

        // Apply removals (unknown ids are reported as notFound, do not fail).
        std::vector<std::string> removed;
        std::vector<std::string> notFound;

        for (const auto &listId : removeOrder) {
            auto it = current.find(listId);
            if (it == current.end()) {
                notFound.push_back(listId);
                continue;
            }
            removed.push_back(listId);

            const Stats::Color color = it->second.getColor();
            (void)domManager.removeDomainList(listId, color);
            (void)blockingListManager.removeBlockingList(listId);
        }

        // Apply upserts.
        for (const auto &p : planned) {
            const std::string enabledPath = Settings::saveDirDomainListsPath() + p.listId;
            const std::string disabledPath = enabledPath + ".disabled";

            if (!p.exists) {
                // Always create a disabled-form file; enable() is responsible for rename+load.
                (void)ensureFileExists(disabledPath);
                (void)blockingListManager.addBlockingList(p.listId, p.url, p.name, p.color, p.mask);
            } else {
                const bool enabling = !p.oldEnabled && p.enabled;
                const bool disabling = p.oldEnabled && !p.enabled;

                if (disabling) {
                    (void)ensureFileExists(enabledPath);
                    if (!domManager.disableList(p.listId, p.oldColor)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INTERNAL_ERROR", "failed to disable list");
                        return ResponsePlan{.response = std::move(response)};
                    }
                }

                if (enabling) {
                    (void)ensureFileExists(disabledPath);
                    if (!domManager.enableList(p.listId, p.mask, p.color)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INTERNAL_ERROR", "failed to enable list");
                        return ResponsePlan{.response = std::move(response)};
                    }
                }

                if (p.oldEnabled && p.enabled && p.oldColor != p.color) {
                    domManager.switchListColor(p.listId, p.color);
                }
                if (p.oldEnabled && p.enabled && p.oldMask != p.mask) {
                    domManager.changeBlockMask(p.listId, p.mask, p.color);
                }

                if (!p.oldEnabled && !p.enabled) {
                    (void)ensureFileExists(disabledPath);
                }
            }

            if (p.exists) {
                if (!blockingListManager.updateBlockingList(p.listId, p.url, p.name, p.color, p.mask,
                                                           p.domainsCount, p.updatedAt, p.etag,
                                                           p.enabled, p.outdated)) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INTERNAL_ERROR", "failed to update list metadata");
                    return ResponsePlan{.response = std::move(response)};
                }
            } else {
                if (!blockingListManager.updateBlockingList(p.listId, p.url, p.name, p.color, p.mask,
                                                           p.domainsCount, p.updatedAt, p.etag,
                                                           p.enabled, p.outdated)) {
                    rapidjson::Document response = ControlVNext::makeErrorResponse(
                        id, "INTERNAL_ERROR", "failed to update list metadata");
                    return ResponsePlan{.response = std::move(response)};
                }

                if (p.enabled) {
                    if (!domManager.enableList(p.listId, p.mask, p.color)) {
                        rapidjson::Document response = ControlVNext::makeErrorResponse(
                            id, "INTERNAL_ERROR", "failed to enable list");
                        return ResponsePlan{.response = std::move(response)};
                    }
                } else {
                    (void)ensureFileExists(disabledPath);
                }
            }
        }

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();

        rapidjson::Value removedValue(rapidjson::kArrayType);
        for (const auto &listId : removed) {
            removedValue.PushBack(makeString(listId, alloc), alloc);
        }
        rapidjson::Value notFoundValue(rapidjson::kArrayType);
        for (const auto &listId : notFound) {
            notFoundValue.PushBack(makeString(listId, alloc), alloc);
        }

        result.AddMember("removed", removedValue, alloc);
        result.AddMember("notFound", notFoundValue, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd == "DOMAINLISTS.IMPORT") {
        if (const auto unknown = unknownArgsKey(args, {"listId", "listKind", "mask", "clear", "domains"});
            unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto listIdIt = args.FindMember("listId");
        const auto listKindIt = args.FindMember("listKind");
        const auto maskIt = args.FindMember("mask");
        const auto clearIt = args.FindMember("clear");
        const auto domainsIt = args.FindMember("domains");

        if (listIdIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.listId");
            return ResponsePlan{.response = std::move(response)};
        }
        if (listKindIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.listKind");
            return ResponsePlan{.response = std::move(response)};
        }
        if (maskIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.mask");
            return ResponsePlan{.response = std::move(response)};
        }
        if (domainsIt == args.MemberEnd()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.domains");
            return ResponsePlan{.response = std::move(response)};
        }

        if (!listIdIt->value.IsString()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.listId must be string");
            return ResponsePlan{.response = std::move(response)};
        }
        const std::string listId(listIdIt->value.GetString(), listIdIt->value.GetStringLength());
        if (!isValidGuid36(listId)) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.listId must be GUID string");
            return ResponsePlan{.response = std::move(response)};
        }

        if (!listKindIt->value.IsString()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.listKind must be string");
            return ResponsePlan{.response = std::move(response)};
        }
        const std::string_view listKind(listKindIt->value.GetString(), listKindIt->value.GetStringLength());
        const auto parsedKind = parseListKind(listKind);
        if (!parsedKind.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.listKind must be \"block\" or \"allow\"");
            return ResponsePlan{.response = std::move(response)};
        }

        if (!maskIt->value.IsUint()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.mask must be u32");
            return ResponsePlan{.response = std::move(response)};
        }
        const uint32_t maskU32 = maskIt->value.GetUint();
        if (maskU32 > 255 || !Settings::isValidBlockingListMask(maskU32)) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "args.mask must be a single supported bit");
            return ResponsePlan{.response = std::move(response)};
        }

        uint32_t clearToggle = 0;
        if (clearIt != args.MemberEnd()) {
            if (!isValidToggleValue(clearIt->value, clearToggle)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.clear must be 0 or 1");
                return ResponsePlan{.response = std::move(response)};
            }
        }

        if (!domainsIt->value.IsArray()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.domains must be array");
            return ResponsePlan{.response = std::move(response)};
        }

        constexpr uint32_t maxImportDomains = 1'000'000;
        constexpr uint32_t maxImportBytes = 16u * 1024u * 1024u;

        const auto &domainsArr = domainsIt->value.GetArray();
        if (domainsArr.Size() > maxImportDomains) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "import payload too large");
            auto &alloc = response.GetAllocator();
            rapidjson::Value limitsObj(rapidjson::kObjectType);
            limitsObj.AddMember("maxImportDomains", maxImportDomains, alloc);
            limitsObj.AddMember("maxImportBytes", maxImportBytes, alloc);
            response["error"].AddMember("limits", limitsObj, alloc);
            response["error"].AddMember("hint", makeString("chunk the import payload", alloc), alloc);
            return ResponsePlan{.response = std::move(response)};
        }

        uint32_t importBytes = 0;
        std::vector<std::string> domains;
        domains.reserve(domainsArr.Size());
        for (const auto &v : domainsArr) {
            if (!v.IsString()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.domains items must be string");
                return ResponsePlan{.response = std::move(response)};
            }
            const std::string_view domain(v.GetString(), v.GetStringLength());
            std::string reason;
            if (!isValidDomainString(domain, reason)) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "invalid args.domains item: " + reason);
                return ResponsePlan{.response = std::move(response)};
            }
            importBytes += static_cast<uint32_t>(domain.size());
            if (importBytes > maxImportBytes) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "import payload too large");
                auto &alloc = response.GetAllocator();
                rapidjson::Value limitsObj(rapidjson::kObjectType);
                limitsObj.AddMember("maxImportDomains", maxImportDomains, alloc);
                limitsObj.AddMember("maxImportBytes", maxImportBytes, alloc);
                response["error"].AddMember("limits", limitsObj, alloc);
                response["error"].AddMember("hint", makeString("chunk the import payload", alloc), alloc);
                return ResponsePlan{.response = std::move(response)};
            }
            domains.emplace_back(domain);
        }

        const auto current = blockingListManager.getAll();
        const auto it = current.find(listId);
        if (it == current.end()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "unknown listId");
            auto &alloc = response.GetAllocator();
            response["error"].AddMember(
                "hint", makeString("create listId via DOMAINLISTS.APPLY before importing", alloc), alloc);
            return ResponsePlan{.response = std::move(response)};
        }

        const BlockingList &bl = it->second;
        if (bl.getColor() != *parsedKind || bl.getBlockMask() != static_cast<uint8_t>(maskU32)) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INVALID_ARGUMENT", "listKind/mask mismatch with stored metadata");
            return ResponsePlan{.response = std::move(response)};
        }

        const auto importRes =
            domManager.importDomainsToListAtomic(listId, static_cast<uint8_t>(maskU32), clearToggle == 1,
                                                 domains, *parsedKind, bl.isEnabled());
        if (!importRes.ok) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "INTERNAL_ERROR", "import failed");
            return ResponsePlan{.response = std::move(response)};
        }

        (void)blockingListManager.updateDomainsCount(listId, importRes.total);

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        result.AddMember("imported", importRes.imported, alloc);
        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    (void)request;
    (void)limits;
    return std::nullopt;
}

} // namespace ControlVNextSessionCommands
