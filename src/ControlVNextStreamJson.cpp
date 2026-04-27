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
#include <string>

namespace ControlVNextStreamJson {

namespace {

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
