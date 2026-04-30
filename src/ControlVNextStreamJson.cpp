/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextStreamJson.hpp>

#include <ControlVNextCodec.hpp>
#include <Domain.hpp>
#include <Host.hpp>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace ControlVNextStreamJson {

namespace {

namespace Explain = ControlVNextStreamExplain;

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] const char *streamStr(const ControlVNextStreamManager::Type stream) noexcept {
    switch (stream) {
    case ControlVNextStreamManager::Type::Dns:
        return "dns";
    case ControlVNextStreamManager::Type::Pkt:
        return "pkt";
    case ControlVNextStreamManager::Type::Activity:
        return "activity";
    }
    return "unknown";
}

[[nodiscard]] std::string formatTimestamp(const timespec &ts) {
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%lld.%09ld", static_cast<long long>(ts.tv_sec),
                  static_cast<long>(ts.tv_nsec));
    return std::string(buf);
}

[[nodiscard]] std::optional<std::string> ipToString(const std::array<std::uint8_t, 16> &bytes,
                                                    const std::uint8_t ipVersion) {
    char buf[INET6_ADDRSTRLEN]{};
    if (ipVersion == 4) {
        in_addr addr{};
        std::memcpy(&addr, bytes.data(), 4);
        if (::inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == nullptr) {
            return std::nullopt;
        }
        return std::string(buf);
    }
    if (ipVersion == 6) {
        in6_addr addr{};
        std::memcpy(&addr, bytes.data(), 16);
        if (::inet_ntop(AF_INET6, &addr, buf, sizeof(buf)) == nullptr) {
            return std::nullopt;
        }
        return std::string(buf);
    }
    return std::nullopt;
}

[[nodiscard]] const char *protocolStr(const std::uint16_t proto) noexcept {
    switch (proto) {
    case IPPROTO_TCP:
        return "tcp";
    case IPPROTO_UDP:
        return "udp";
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        return "icmp";
    default:
        return "other";
    }
}

[[nodiscard]] const char *l4StatusStr(const L4Status s) noexcept {
    switch (s) {
    case L4Status::KNOWN_L4:
        return "known-l4";
    case L4Status::OTHER_TERMINAL:
        return "other-terminal";
    case L4Status::FRAGMENT:
        return "fragment";
    case L4Status::INVALID_OR_UNAVAILABLE_L4:
        return "invalid-or-unavailable-l4";
    }
    return "invalid-or-unavailable-l4";
}

[[nodiscard]] const char *dnsScopeStr(const DomainPolicySource source) noexcept {
    switch (source) {
    case DomainPolicySource::CUSTOM_WHITELIST:
    case DomainPolicySource::CUSTOM_BLACKLIST:
    case DomainPolicySource::CUSTOM_RULE_WHITE:
    case DomainPolicySource::CUSTOM_RULE_BLACK:
        return "APP";
    case DomainPolicySource::DOMAIN_DEVICE_WIDE_AUTHORIZED:
    case DomainPolicySource::DOMAIN_DEVICE_WIDE_BLOCKED:
        return "DEVICE_WIDE";
    case DomainPolicySource::MASK_FALLBACK:
        return "FALLBACK";
    }
    return "FALLBACK";
}

void addTraffic(rapidjson::Value &dst, rapidjson::Document::AllocatorType &alloc,
                const TrafficSnapshot &traffic) {
    rapidjson::Value trafficObj(rapidjson::kObjectType);
    for (size_t i = 0; i < kTrafficMetricKeys.size(); ++i) {
        rapidjson::Value countsObj(rapidjson::kObjectType);
        countsObj.AddMember("allow", static_cast<std::uint64_t>(traffic.dims[i].allow), alloc);
        countsObj.AddMember("block", static_cast<std::uint64_t>(traffic.dims[i].block), alloc);
        trafficObj.AddMember(makeString(kTrafficMetricKeys[i], alloc), countsObj, alloc);
    }
    dst.AddMember("traffic", trafficObj, alloc);
}

void addStringMember(rapidjson::Value &dst, const char *key, const std::string &value,
                     rapidjson::Document::AllocatorType &alloc) {
    dst.AddMember(rapidjson::Value(key, alloc), makeString(value, alloc), alloc);
}

void addOptionalStringMember(rapidjson::Value &dst, const char *key,
                             const std::optional<std::string> &value,
                             rapidjson::Document::AllocatorType &alloc) {
    if (value.has_value()) {
        addStringMember(dst, key, *value, alloc);
    }
}

rapidjson::Value makeRuleIdsArray(const std::vector<std::uint32_t> &ruleIds,
                                  rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value arr(rapidjson::kArrayType);
    for (const auto ruleId : ruleIds) {
        arr.PushBack(ruleId, alloc);
    }
    return arr;
}

rapidjson::Value makeDnsRuleSnapshot(const Explain::DnsRuleSnapshot &snapshot,
                                     rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    obj.AddMember("ruleId", snapshot.ruleId, alloc);
    addStringMember(obj, "type", snapshot.type, alloc);
    addStringMember(obj, "pattern", snapshot.pattern, alloc);
    addStringMember(obj, "scope", snapshot.scope, alloc);
    addStringMember(obj, "action", snapshot.action, alloc);
    return obj;
}

rapidjson::Value makeDnsListEntrySnapshot(const Explain::DnsListEntrySnapshot &snapshot,
                                          rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    addStringMember(obj, "type", snapshot.type, alloc);
    addStringMember(obj, "pattern", snapshot.pattern, alloc);
    addStringMember(obj, "scope", snapshot.scope, alloc);
    addStringMember(obj, "action", snapshot.action, alloc);
    return obj;
}

rapidjson::Value makeDnsStage(const Explain::DnsStageSnapshot &stage,
                              rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    addStringMember(obj, "name", stage.name, alloc);
    obj.AddMember("enabled", stage.enabled, alloc);
    obj.AddMember("evaluated", stage.evaluated, alloc);
    obj.AddMember("matched", stage.matched, alloc);
    addStringMember(obj, "outcome", stage.outcome, alloc);
    obj.AddMember("winner", stage.winner, alloc);
    addOptionalStringMember(obj, "skipReason", stage.skipReason, alloc);
    obj.AddMember("truncated", stage.truncated, alloc);
    if (stage.omittedCandidateCount.has_value()) {
        obj.AddMember("omittedCandidateCount", *stage.omittedCandidateCount, alloc);
    }
    if (!stage.ruleIds.empty()) {
        obj.AddMember("ruleIds", makeRuleIdsArray(stage.ruleIds, alloc), alloc);
    }
    if (!stage.ruleSnapshots.empty()) {
        rapidjson::Value arr(rapidjson::kArrayType);
        for (const auto &snapshot : stage.ruleSnapshots) {
            arr.PushBack(makeDnsRuleSnapshot(snapshot, alloc), alloc);
        }
        obj.AddMember("ruleSnapshots", arr, alloc);
    }
    if (!stage.listEntrySnapshots.empty()) {
        rapidjson::Value arr(rapidjson::kArrayType);
        for (const auto &snapshot : stage.listEntrySnapshots) {
            arr.PushBack(makeDnsListEntrySnapshot(snapshot, alloc), alloc);
        }
        obj.AddMember("listEntrySnapshots", arr, alloc);
    }
    if (stage.maskFallback.has_value()) {
        rapidjson::Value mask(rapidjson::kObjectType);
        mask.AddMember("domMask", stage.maskFallback->domMask, alloc);
        mask.AddMember("appMask", stage.maskFallback->appMask, alloc);
        mask.AddMember("effectiveMask", stage.maskFallback->effectiveMask, alloc);
        mask.AddMember("outcome", makeString(stage.maskFallback->blocked ? "block" : "allow", alloc), alloc);
        obj.AddMember("maskFallback", mask, alloc);
    }
    return obj;
}

rapidjson::Value makeDnsExplain(const Explain::DnsExplainSnapshot &explain,
                                rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    obj.AddMember("version", explain.version, alloc);
    addStringMember(obj, "kind", explain.kind, alloc);

    rapidjson::Value inputs(rapidjson::kObjectType);
    inputs.AddMember("blockEnabled", explain.inputs.blockEnabled, alloc);
    inputs.AddMember("tracked", explain.inputs.tracked, alloc);
    inputs.AddMember("domainCustomEnabled", explain.inputs.domainCustomEnabled, alloc);
    inputs.AddMember("useCustomList", explain.inputs.useCustomList, alloc);
    addStringMember(inputs, "domain", explain.inputs.domain, alloc);
    inputs.AddMember("domMask", explain.inputs.domMask, alloc);
    inputs.AddMember("appMask", explain.inputs.appMask, alloc);
    obj.AddMember("inputs", inputs, alloc);

    rapidjson::Value final(rapidjson::kObjectType);
    final.AddMember("blocked", explain.final.blocked, alloc);
    final.AddMember("getips", explain.final.getips, alloc);
    final.AddMember("policySource", makeString(domainPolicySourceStr(explain.final.policySource), alloc), alloc);
    addStringMember(final, "scope", explain.final.scope, alloc);
    if (explain.final.ruleId.has_value()) {
        final.AddMember("ruleId", *explain.final.ruleId, alloc);
    }
    obj.AddMember("final", final, alloc);

    rapidjson::Value stages(rapidjson::kArrayType);
    for (const auto &stage : explain.stages) {
        stages.PushBack(makeDnsStage(stage, alloc), alloc);
    }
    obj.AddMember("stages", stages, alloc);
    return obj;
}

rapidjson::Value makeIpRulesRuleSnapshot(const Explain::IpRulesRuleSnapshot &snapshot,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    obj.AddMember("ruleId", snapshot.ruleId, alloc);
    addStringMember(obj, "clientRuleId", snapshot.clientRuleId, alloc);
    addStringMember(obj, "matchKey", snapshot.matchKey, alloc);
    addStringMember(obj, "action", snapshot.action, alloc);
    obj.AddMember("enforce", snapshot.enforce, alloc);
    obj.AddMember("log", snapshot.log, alloc);
    addStringMember(obj, "family", snapshot.family, alloc);
    addStringMember(obj, "dir", snapshot.dir, alloc);
    addStringMember(obj, "iface", snapshot.iface, alloc);
    obj.AddMember("ifindex", snapshot.ifindex, alloc);
    addStringMember(obj, "proto", snapshot.proto, alloc);

    rapidjson::Value ct(rapidjson::kObjectType);
    addStringMember(ct, "state", snapshot.ctState, alloc);
    addStringMember(ct, "direction", snapshot.ctDirection, alloc);
    obj.AddMember("ct", ct, alloc);

    addStringMember(obj, "src", snapshot.src, alloc);
    addStringMember(obj, "dst", snapshot.dst, alloc);
    addStringMember(obj, "sport", snapshot.sport, alloc);
    addStringMember(obj, "dport", snapshot.dport, alloc);
    obj.AddMember("priority", snapshot.priority, alloc);
    return obj;
}

rapidjson::Value makePktStage(const Explain::PktStageSnapshot &stage,
                              rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    addStringMember(obj, "name", stage.name, alloc);
    obj.AddMember("enabled", stage.enabled, alloc);
    obj.AddMember("evaluated", stage.evaluated, alloc);
    obj.AddMember("matched", stage.matched, alloc);
    addStringMember(obj, "outcome", stage.outcome, alloc);
    obj.AddMember("winner", stage.winner, alloc);
    addOptionalStringMember(obj, "skipReason", stage.skipReason, alloc);
    obj.AddMember("truncated", stage.truncated, alloc);
    if (stage.omittedCandidateCount.has_value()) {
        obj.AddMember("omittedCandidateCount", *stage.omittedCandidateCount, alloc);
    }
    if (!stage.ruleIds.empty()) {
        obj.AddMember("ruleIds", makeRuleIdsArray(stage.ruleIds, alloc), alloc);
    }
    if (!stage.ruleSnapshots.empty()) {
        rapidjson::Value arr(rapidjson::kArrayType);
        for (const auto &snapshot : stage.ruleSnapshots) {
            arr.PushBack(makeIpRulesRuleSnapshot(snapshot, alloc), alloc);
        }
        obj.AddMember("ruleSnapshots", arr, alloc);
    }
    if (stage.ifaceBlock.has_value()) {
        rapidjson::Value iface(rapidjson::kObjectType);
        iface.AddMember("appIfaceMask", stage.ifaceBlock->appIfaceMask, alloc);
        iface.AddMember("packetIfaceKindBit", stage.ifaceBlock->packetIfaceKindBit, alloc);
        iface.AddMember("evaluatedIntersection", stage.ifaceBlock->evaluatedIntersection, alloc);
        addStringMember(iface, "packetIfaceKind", stage.ifaceBlock->packetIfaceKind, alloc);
        iface.AddMember("outcome", makeString(stage.ifaceBlock->blocked ? "block" : "allow", alloc), alloc);
        addOptionalStringMember(iface, "shortCircuitReason", stage.ifaceBlock->shortCircuitReason, alloc);
        obj.AddMember("ifaceBlock", iface, alloc);
    }
    return obj;
}

rapidjson::Value makePktExplain(const Explain::PktExplainSnapshot &explain,
                                rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value obj(rapidjson::kObjectType);
    obj.AddMember("version", explain.version, alloc);
    addStringMember(obj, "kind", explain.kind, alloc);

    rapidjson::Value inputs(rapidjson::kObjectType);
    inputs.AddMember("blockEnabled", explain.inputs.blockEnabled, alloc);
    inputs.AddMember("iprulesEnabled", explain.inputs.iprulesEnabled, alloc);
    addStringMember(inputs, "direction", explain.inputs.direction, alloc);
    inputs.AddMember("ipVersion", static_cast<std::uint32_t>(explain.inputs.ipVersion), alloc);
    addStringMember(inputs, "protocol", explain.inputs.protocol, alloc);
    addStringMember(inputs, "l4Status", explain.inputs.l4Status, alloc);
    inputs.AddMember("ifindex", explain.inputs.ifindex, alloc);
    inputs.AddMember("ifaceKindBit", explain.inputs.ifaceKindBit, alloc);
    addStringMember(inputs, "ifaceKind", explain.inputs.ifaceKind, alloc);
    inputs.AddMember("conntrackEvaluated", explain.inputs.conntrackEvaluated, alloc);
    if (explain.inputs.conntrackEvaluated) {
        rapidjson::Value ct(rapidjson::kObjectType);
        if (explain.inputs.conntrackState.has_value()) {
            addStringMember(ct, "state", *explain.inputs.conntrackState, alloc);
        }
        if (explain.inputs.conntrackDirection.has_value()) {
            addStringMember(ct, "direction", *explain.inputs.conntrackDirection, alloc);
        }
        inputs.AddMember("conntrack", ct, alloc);
    }
    obj.AddMember("inputs", inputs, alloc);

    rapidjson::Value final(rapidjson::kObjectType);
    final.AddMember("accepted", explain.final.accepted, alloc);
    final.AddMember("reasonId", makeString(packetReasonIdStr(explain.final.reasonId), alloc), alloc);
    if (explain.final.ruleId.has_value()) {
        final.AddMember("ruleId", *explain.final.ruleId, alloc);
    }
    if (explain.final.wouldRuleId.has_value()) {
        final.AddMember("wouldRuleId", *explain.final.wouldRuleId, alloc);
    }
    if (explain.final.wouldDrop) {
        final.AddMember("wouldDrop", true, alloc);
    }
    obj.AddMember("final", final, alloc);

    rapidjson::Value stages(rapidjson::kArrayType);
    for (const auto &stage : explain.stages) {
        stages.PushBack(makePktStage(stage, alloc), alloc);
    }
    obj.AddMember("stages", stages, alloc);
    return obj;
}

} // namespace

rapidjson::Document makeStartedNotice(const ControlVNextStreamManager::Type stream,
                                     const std::uint32_t effectiveHorizonSec,
                                     const std::uint32_t effectiveMinSize) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("type", makeString("notice", alloc), alloc);
    doc.AddMember("notice", makeString("started", alloc), alloc);
    doc.AddMember("stream", makeString(streamStr(stream), alloc), alloc);
    if (stream == ControlVNextStreamManager::Type::Dns || stream == ControlVNextStreamManager::Type::Pkt) {
        doc.AddMember("horizonSec", effectiveHorizonSec, alloc);
        doc.AddMember("minSize", effectiveMinSize, alloc);
    }
    return doc;
}

rapidjson::Document makeSuppressedNotice(const ControlVNextStreamManager::Type stream,
                                        const std::uint32_t windowMs,
                                        const TrafficSnapshot &traffic) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("type", makeString("notice", alloc), alloc);
    doc.AddMember("notice", makeString("suppressed", alloc), alloc);
    doc.AddMember("stream", makeString(streamStr(stream), alloc), alloc);
    doc.AddMember("windowMs", windowMs, alloc);
    addTraffic(doc, alloc, traffic);
    doc.AddMember("hint",
                  makeString("untracked apps have traffic; enable tracked via CONFIG.SET (scope=app,set={tracked:1}) or query METRICS.GET(name=traffic)",
                             alloc),
                  alloc);
    return doc;
}

rapidjson::Document makeDroppedNotice(const ControlVNextStreamManager::Type stream,
                                     const std::uint32_t windowMs,
                                     const std::uint64_t droppedEvents) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("type", makeString("notice", alloc), alloc);
    doc.AddMember("notice", makeString("dropped", alloc), alloc);
    doc.AddMember("stream", makeString(streamStr(stream), alloc), alloc);
    doc.AddMember("windowMs", windowMs, alloc);
    doc.AddMember("droppedEvents", static_cast<std::uint64_t>(droppedEvents), alloc);
    return doc;
}

rapidjson::Document makeDnsEvent(const ControlVNextStreamManager::DnsEvent &event) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("type", makeString("dns", alloc), alloc);

    const std::string ts = formatTimestamp(event.timestamp);
    doc.AddMember("timestamp", makeString(ts, alloc), alloc);
    doc.AddMember("uid", event.uid, alloc);
    doc.AddMember("userId", event.userId, alloc);

    const std::string_view appName = (event.app != nullptr) ? std::string_view(*event.app) : std::string_view();
    doc.AddMember("app", makeString(appName, alloc), alloc);

    const std::string_view domainName =
        (event.domain != nullptr) ? std::string_view(event.domain->name()) : std::string_view();
    doc.AddMember("domain", makeString(domainName, alloc), alloc);
    doc.AddMember("domMask", event.domMask, alloc);
    doc.AddMember("appMask", event.appMask, alloc);
    doc.AddMember("blocked", event.blocked, alloc);

    doc.AddMember("policySource", makeString(domainPolicySourceStr(event.policySource), alloc), alloc);
    doc.AddMember("useCustomList", event.useCustomList, alloc);
    doc.AddMember("scope", makeString(dnsScopeStr(event.policySource), alloc), alloc);
    doc.AddMember("getips", event.getips, alloc);

    if (event.ruleId.has_value()) {
        doc.AddMember("ruleId", *event.ruleId, alloc);
    }
    if (event.explain.has_value()) {
        doc.AddMember("explain", makeDnsExplain(*event.explain, alloc), alloc);
    }

    return doc;
}

rapidjson::Document makePktEvent(const ControlVNextStreamManager::PktEvent &event) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("type", makeString("pkt", alloc), alloc);

    const std::string ts = formatTimestamp(event.timestamp);
    doc.AddMember("timestamp", makeString(ts, alloc), alloc);
    doc.AddMember("uid", event.uid, alloc);
    doc.AddMember("userId", event.userId, alloc);

    const std::string_view appName = (event.app != nullptr) ? std::string_view(*event.app) : std::string_view();
    doc.AddMember("app", makeString(appName, alloc), alloc);

    doc.AddMember("direction", makeString(event.input ? "in" : "out", alloc), alloc);
    doc.AddMember("ipVersion", static_cast<std::uint32_t>(event.ipVersion), alloc);
    doc.AddMember("protocol", makeString(protocolStr(event.proto), alloc), alloc);
    doc.AddMember("l4Status", makeString(l4StatusStr(event.l4Status), alloc), alloc);

    if (const auto src = ipToString(event.srcIp, event.ipVersion); src.has_value()) {
        doc.AddMember("srcIp", makeString(*src, alloc), alloc);
    }
    if (const auto dst = ipToString(event.dstIp, event.ipVersion); dst.has_value()) {
        doc.AddMember("dstIp", makeString(*dst, alloc), alloc);
    }

    const bool portsKnown = event.l4Status == L4Status::KNOWN_L4;
    doc.AddMember("srcPort", static_cast<std::uint32_t>(portsKnown ? event.srcPort : 0), alloc);
    doc.AddMember("dstPort", static_cast<std::uint32_t>(portsKnown ? event.dstPort : 0), alloc);
    doc.AddMember("length", static_cast<std::uint32_t>(event.length), alloc);
    doc.AddMember("ifindex", event.ifindex, alloc);
    doc.AddMember("ifaceKindBit", static_cast<std::uint32_t>(event.ifaceKindBit), alloc);

    char ifaceBuf[IF_NAMESIZE]{};
    if (event.ifindex != 0 && ::if_indextoname(event.ifindex, ifaceBuf) != nullptr) {
        doc.AddMember("interface", makeString(ifaceBuf, alloc), alloc);
    }

    if (event.host != nullptr) {
        if (event.host->hasName()) {
            const std::string hostName = event.host->name();
            doc.AddMember("host", makeString(hostName, alloc), alloc);
        }
        if (const auto domain = event.host->domain(); domain != nullptr && domain->validIP()) {
            doc.AddMember("domain", makeString(domain->name(), alloc), alloc);
        }
    }

    doc.AddMember("accepted", event.accepted, alloc);
    doc.AddMember("reasonId", makeString(packetReasonIdStr(event.reasonId), alloc), alloc);
    if (event.ruleId.has_value()) {
        doc.AddMember("ruleId", *event.ruleId, alloc);
    }
    if (event.wouldRuleId.has_value()) {
        doc.AddMember("wouldRuleId", *event.wouldRuleId, alloc);
        doc.AddMember("wouldDrop", true, alloc);
    }
    if (event.explain.has_value()) {
        doc.AddMember("explain", makePktExplain(*event.explain, alloc), alloc);
    }

    return doc;
}

rapidjson::Document makeActivityEvent(const ControlVNextStreamManager::ActivityEvent &event) {
    rapidjson::Document doc(rapidjson::kObjectType);
    auto &alloc = doc.GetAllocator();

    doc.AddMember("type", makeString("activity", alloc), alloc);
    const std::string ts = formatTimestamp(event.timestamp);
    doc.AddMember("timestamp", makeString(ts, alloc), alloc);
    doc.AddMember("blockEnabled", event.blockEnabled, alloc);
    return doc;
}

} // namespace ControlVNextStreamJson
