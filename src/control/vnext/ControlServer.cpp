/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>

#include <ControlVNextCodec.hpp>
#include <DaemonRuntime.hpp>
#include <RuntimeConfig.hpp>
#include <RuntimeControl.hpp>

#include <rapidjson/document.h>

#include <array>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr int kSendFlags =
#ifdef MSG_NOSIGNAL
    MSG_NOSIGNAL;
#else
    0;
#endif

constexpr int kControlPollTimeoutMs = 250;
constexpr std::uint8_t kTcpProtocol = 6;
constexpr std::uint8_t kUdpProtocol = 17;

bool writeAll(const int fd, const std::string_view bytes) {
    const char *data = bytes.data();
    std::size_t remaining = bytes.size();
    while (remaining > 0) {
        const ssize_t n = ::send(fd, data, remaining, kSendFlags);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        data += n;
        remaining -= static_cast<std::size_t>(n);
    }
    return true;
}

int androidInitSocketFd(const char *const name) noexcept {
    if (name == nullptr || *name == '\0') {
        return -1;
    }

    const std::string envName = std::string("ANDROID_SOCKET_") + name;
    const char *const value = std::getenv(envName.c_str());
    if (value == nullptr || *value == '\0') {
        return -1;
    }

    errno = 0;
    char *end = nullptr;
    const long fd = std::strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || fd < 0 || fd > INT_MAX) {
        return -1;
    }
    return static_cast<int>(fd);
}

rapidjson::Document makeHelloResult(const SnortRuntime::BaseRuntimeControl &runtime) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();

    result.AddMember("protocol", "control-vnext", alloc);
    result.AddMember("protocolVersion", SnortConfig::kControlProtocolVersion, alloc);
    result.AddMember("framing", "netstring", alloc);
    result.AddMember("maxRequestBytes",
                     static_cast<std::uint64_t>(SnortConfig::kControlMaxRequestBytes), alloc);
    result.AddMember("maxResponseBytes",
                     static_cast<std::uint64_t>(SnortConfig::kControlMaxResponseBytes), alloc);

#ifdef SUCRE_SNORT_DAEMON_BUILD_ID
    result.AddMember("daemonBuildId", SUCRE_SNORT_DAEMON_BUILD_ID, alloc);
#else
    result.AddMember("daemonBuildId", "snort10-base-unknown", alloc);
#endif

#ifdef SUCRE_SNORT_ARTIFACT_ABI
    result.AddMember("artifactAbi", SUCRE_SNORT_ARTIFACT_ABI, alloc);
#else
    result.AddMember("artifactAbi", "host", alloc);
#endif

    rapidjson::Value capabilities(rapidjson::kArrayType);
    capabilities.PushBack("snort10-base", alloc);
    if (runtime.nfqueuePassThroughReady()) {
        capabilities.PushBack("nfqueue-pass-through", alloc);
    }
    if (runtime.packetAdapterReady() && !runtime.packetAdapterName().empty()) {
        const std::string capability =
            "packet-adapter-" + std::string(runtime.packetAdapterName());
        rapidjson::Value value;
        value.SetString(capability.c_str(),
                        static_cast<rapidjson::SizeType>(capability.size()), alloc);
        capabilities.PushBack(value, alloc);
    }
    if (runtime.nfqueueRuntimeCountersReady()) {
        capabilities.PushBack("nfqueue-runtime-counters", alloc);
    }
    if (runtime.packetPolicyControlReady()) {
        capabilities.PushBack("packet-policy-control", alloc);
    }
    result.AddMember("capabilities", capabilities, alloc);

    return result;
}

rapidjson::Document makeStatusResult(
    const SnortDatapath::Policy::PacketPolicySnapshotStatus status) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("revision", status.revision, alloc);
    result.AddMember("subjectCount", static_cast<std::uint64_t>(status.subjectCount), alloc);
    result.AddMember("networkGateRuleCount",
                     static_cast<std::uint64_t>(status.networkGateRuleCount), alloc);
    result.AddMember("l4RuleCount", static_cast<std::uint64_t>(status.l4RuleCount), alloc);
    result.AddMember("ruleCount", static_cast<std::uint64_t>(status.ruleCount()), alloc);
    return result;
}

rapidjson::Document makeNfqueueStatusResult(
    const SnortRuntime::NfqueueRuntimeCounters counters) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("packetsSeen", counters.packetsSeen, alloc);
    result.AddMember("acceptedPackets", counters.acceptedPackets, alloc);
    result.AddMember("droppedPackets", counters.droppedPackets, alloc);
    result.AddMember("parsePassThroughPackets", counters.parsePassThroughPackets, alloc);
    result.AddMember("capacityPassThroughPackets", counters.capacityPassThroughPackets, alloc);
    result.AddMember("ownerFaultPassThroughPackets",
                     counters.ownerFaultPassThroughPackets, alloc);
    result.AddMember("verdictSendFailures", counters.verdictSendFailures, alloc);
    result.AddMember("fragmentBufferedPackets",
                     counters.fragmentBufferedPackets, alloc);
    result.AddMember("fragmentReassembledPackets",
                     counters.fragmentReassembledPackets, alloc);
    result.AddMember("uidMetadataPresentPackets",
                     counters.uidMetadataPresentPackets, alloc);
    result.AddMember("uidMetadataMissingPackets",
                     counters.uidMetadataMissingPackets, alloc);
    result.AddMember("lastObservedLinuxUid", counters.lastObservedLinuxUid, alloc);
    result.AddMember("lastObservedUidKnown", counters.lastObservedUidKnown, alloc);
    result.AddMember("lastObservedNetworkContext",
                     counters.lastObservedNetworkContext, alloc);
    result.AddMember("lastObservedHook", counters.lastObservedHook, alloc);
    result.AddMember("lastObservedInputInterfaceIndex",
                     counters.lastObservedInputInterfaceIndex, alloc);
    result.AddMember("lastObservedOutputInterfaceIndex",
                     counters.lastObservedOutputInterfaceIndex, alloc);
    rapidjson::Value lastObservedResult;
    lastObservedResult.SetString(counters.lastObservedResult.c_str(),
                                 static_cast<rapidjson::SizeType>(
                                     counters.lastObservedResult.size()),
                                 alloc);
    result.AddMember("lastObservedResult", lastObservedResult, alloc);
    return result;
}

const rapidjson::Value *member(const rapidjson::Value &object,
                               const std::string_view key) noexcept {
    for (auto it = object.MemberBegin(); it != object.MemberEnd(); ++it) {
        const std::string_view candidate(it->name.GetString(), it->name.GetStringLength());
        if (candidate == key) {
            return &it->value;
        }
    }
    return nullptr;
}

std::optional<std::string> rejectUnknown(
    const rapidjson::Value &object,
    const std::initializer_list<std::string_view> allowedKeys) {
    if (const auto unknown = ControlVNext::findUnknownKey(object, allowedKeys);
        unknown.has_value()) {
        return "unknown argument: " + std::string(*unknown);
    }
    return std::nullopt;
}

bool readUint32(const rapidjson::Value &object, const std::string_view key,
                std::uint32_t &out, std::string &error, const bool required = true) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        if (!required) {
            return true;
        }
        error = "missing " + std::string(key);
        return false;
    }
    if (!value->IsUint()) {
        error = std::string(key) + " must be u32";
        return false;
    }
    out = value->GetUint();
    return true;
}

bool readUint64(const rapidjson::Value &object, const std::string_view key,
                std::uint64_t &out, std::string &error, const bool required = true) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        if (!required) {
            return true;
        }
        error = "missing " + std::string(key);
        return false;
    }
    if (!value->IsUint64()) {
        error = std::string(key) + " must be u64";
        return false;
    }
    out = value->GetUint64();
    return true;
}

bool readBool(const rapidjson::Value &object, const std::string_view key,
              bool &out, std::string &error, const bool required = true) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        if (!required) {
            return true;
        }
        error = "missing " + std::string(key);
        return false;
    }
    if (!value->IsBool()) {
        error = std::string(key) + " must be bool";
        return false;
    }
    out = value->GetBool();
    return true;
}

bool readUint8(const rapidjson::Value &object, const std::string_view key,
               std::uint8_t &out, std::string &error, const bool required = true) {
    std::uint32_t value = 0;
    if (!readUint32(object, key, value, error, required)) {
        return false;
    }
    if (value > UINT8_MAX) {
        error = std::string(key) + " must be u8";
        return false;
    }
    out = static_cast<std::uint8_t>(value);
    return true;
}

bool readUint16(const rapidjson::Value &object, const std::string_view key,
                std::uint16_t &out, std::string &error, const bool required = true) {
    std::uint32_t value = 0;
    if (!readUint32(object, key, value, error, required)) {
        return false;
    }
    if (value > UINT16_MAX) {
        error = std::string(key) + " must be u16";
        return false;
    }
    out = static_cast<std::uint16_t>(value);
    return true;
}

bool readContextArray(const rapidjson::Value &object, const std::string_view key,
                      std::vector<std::uint32_t> &out, std::string &error,
                      const bool required = false) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        if (!required) {
            return true;
        }
        error = "missing " + std::string(key);
        return false;
    }
    if (!value->IsArray()) {
        error = std::string(key) + " must be array";
        return false;
    }
    out.clear();
    out.reserve(value->Size());
    for (const auto &entry : value->GetArray()) {
        if (!entry.IsUint()) {
            error = std::string(key) + " entries must be u32";
            return false;
        }
        out.push_back(entry.GetUint());
    }
    return true;
}

std::optional<SnortDatapath::Flow::AddressFamily> parseFamily(
    const rapidjson::Value &object, const std::string_view key, std::string &error,
    const bool required) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        if (!required) {
            return std::nullopt;
        }
        error = "missing " + std::string(key);
        return std::nullopt;
    }
    if (!value->IsString()) {
        error = std::string(key) + " must be string";
        return std::nullopt;
    }
    const std::string_view text(value->GetString(), value->GetStringLength());
    if (text == "ipv4") {
        return SnortDatapath::Flow::AddressFamily::Ipv4;
    }
    if (text == "ipv6") {
        return SnortDatapath::Flow::AddressFamily::Ipv6;
    }
    error = std::string(key) + " must be ipv4 or ipv6";
    return std::nullopt;
}

std::optional<SnortDatapath::Flow::DevicePacketDirection> parseDirection(
    const rapidjson::Value &object, const std::string_view key, std::string &error,
    const bool required) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        if (!required) {
            return std::nullopt;
        }
        error = "missing " + std::string(key);
        return std::nullopt;
    }
    if (!value->IsString()) {
        error = std::string(key) + " must be string";
        return std::nullopt;
    }
    const std::string_view text(value->GetString(), value->GetStringLength());
    if (text == "input") {
        return SnortDatapath::Flow::DevicePacketDirection::Input;
    }
    if (text == "output") {
        return SnortDatapath::Flow::DevicePacketDirection::Output;
    }
    error = std::string(key) + " must be input or output";
    return std::nullopt;
}

bool parsePortRange(const rapidjson::Value &object, const std::string_view key,
                    std::optional<SnortDatapath::Policy::PortRange> &out,
                    std::string &error) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        out.reset();
        return true;
    }
    if (!value->IsObject()) {
        error = std::string(key) + " must be object";
        return false;
    }
    if (const auto err = rejectUnknown(*value, {"first", "last"}); err.has_value()) {
        error = *err;
        return false;
    }
    std::uint16_t first = 0;
    std::uint16_t last = 0;
    if (!readUint16(*value, "first", first, error)
        || !readUint16(*value, "last", last, error)) {
        return false;
    }
    if (first > last) {
        error = std::string(key) + ".first must be <= last";
        return false;
    }
    out = SnortDatapath::Policy::PortRange::inclusive(first, last);
    return true;
}

bool parseL4RuleMatch(const rapidjson::Value &object,
                      SnortDatapath::Policy::L4RuleMatch &out,
                      std::string &error) {
    if (!object.IsObject()) {
        error = "match must be object";
        return false;
    }
    if (const auto err = rejectUnknown(
            object, {"family", "direction", "ipProtocol", "networkContextBits",
                     "networkContexts", "sourcePorts", "destinationPorts"});
        err.has_value()) {
        error = *err;
        return false;
    }
    out.family = parseFamily(object, "family", error, false);
    if (!error.empty()) {
        return false;
    }
    out.direction = parseDirection(object, "direction", error, false);
    if (!error.empty()) {
        return false;
    }
    if (!readUint8(object, "ipProtocol", out.ipProtocol.emplace(), error, false)) {
        return false;
    }
    if (member(object, "ipProtocol") == nullptr) {
        out.ipProtocol.reset();
    }
    if (!readUint64(object, "networkContextBits", out.networkContextBits, error, false)
        || !readContextArray(object, "networkContexts", out.networkContexts, error)
        || !parsePortRange(object, "sourcePorts", out.sourcePorts, error)
        || !parsePortRange(object, "destinationPorts", out.destinationPorts, error)) {
        return false;
    }
    return true;
}

bool parseL4Rule(const rapidjson::Value &object,
                 SnortDatapath::Policy::L4Rule &out,
                 std::string &error) {
    if (!object.IsObject()) {
        error = "l4Rules entries must be object";
        return false;
    }
    if (const auto err = rejectUnknown(
            object, {"ruleId", "reasonId", "priority", "order", "action", "match"});
        err.has_value()) {
        error = *err;
        return false;
    }
    if (!readUint64(object, "ruleId", out.ruleId, error)
        || !readUint32(object, "reasonId", out.reasonId, error)
        || !readUint32(object, "order", out.order, error)) {
        return false;
    }
    const rapidjson::Value *priority = member(object, "priority");
    if (priority == nullptr || !priority->IsInt()) {
        error = "priority must be i32";
        return false;
    }
    out.priority = priority->GetInt();

    const rapidjson::Value *action = member(object, "action");
    if (action == nullptr || !action->IsString()) {
        error = "action must be string";
        return false;
    }
    const std::string_view actionText(action->GetString(), action->GetStringLength());
    if (actionText == "drop") {
        out.action = SnortDatapath::Policy::L4RuleAction::Drop;
    } else if (actionText == "allow") {
        out.action = SnortDatapath::Policy::L4RuleAction::Allow;
    } else {
        error = "action must be allow or drop";
        return false;
    }

    const rapidjson::Value *match = member(object, "match");
    if (match == nullptr) {
        error = "missing match";
        return false;
    }
    return parseL4RuleMatch(*match, out.match, error);
}

bool parseNetworkGate(const rapidjson::Value &object,
                      SnortDatapath::Policy::NetworkGateView &out,
                      std::string &error) {
    if (!object.IsObject()) {
        error = "networkGate must be object";
        return false;
    }
    if (const auto err = rejectUnknown(
            object, {"blockedNetworkContextBits", "blockedNetworkContexts",
                     "reasonId", "ruleId"});
        err.has_value()) {
        error = *err;
        return false;
    }
    return readUint64(object, "blockedNetworkContextBits",
                      out.blockedNetworkContextBits, error, false)
        && readContextArray(object, "blockedNetworkContexts",
                            out.blockedNetworkContexts, error)
        && readUint32(object, "reasonId", out.reasonId, error, false)
        && readUint64(object, "ruleId", out.ruleId, error, false);
}

bool parsePolicySubject(const rapidjson::Value &object,
                        SnortDatapath::Policy::PacketPolicySubjectView &out,
                        std::string &error) {
    if (!object.IsObject()) {
        error = "subjects entries must be object";
        return false;
    }
    if (const auto err = rejectUnknown(object, {"linuxUid", "uidKnown", "networkGate", "l4Rules"});
        err.has_value()) {
        error = *err;
        return false;
    }
    out.uidKnown = true;
    if (!readBool(object, "uidKnown", out.uidKnown, error, false)) {
        return false;
    }
    if (out.uidKnown && !readUint32(object, "linuxUid", out.linuxUid, error)) {
        return false;
    }
    if (!out.uidKnown && member(object, "linuxUid") != nullptr
        && !readUint32(object, "linuxUid", out.linuxUid, error, false)) {
        return false;
    }
    if (const rapidjson::Value *gate = member(object, "networkGate");
        gate != nullptr && !parseNetworkGate(*gate, out.networkGate, error)) {
        return false;
    }
    const rapidjson::Value *rules = member(object, "l4Rules");
    if (rules == nullptr) {
        return true;
    }
    if (!rules->IsArray()) {
        error = "l4Rules must be array";
        return false;
    }
    out.l4Rules.clear();
    out.l4Rules.reserve(rules->Size());
    for (const auto &ruleValue : rules->GetArray()) {
        SnortDatapath::Policy::L4Rule rule;
        if (!parseL4Rule(ruleValue, rule, error)) {
            return false;
        }
        out.l4Rules.push_back(std::move(rule));
    }
    return true;
}

bool parsePolicyApplyArgs(
    const rapidjson::Value &args,
    std::vector<SnortDatapath::Policy::PacketPolicySubjectView> &subjects,
    std::uint64_t &revision,
    std::string &error) {
    if (const auto err = rejectUnknown(args, {"revision", "subjects"}); err.has_value()) {
        error = *err;
        return false;
    }
    if (!readUint64(args, "revision", revision, error)) {
        return false;
    }
    const rapidjson::Value *subjectsValue = member(args, "subjects");
    if (subjectsValue == nullptr || !subjectsValue->IsArray()) {
        error = "subjects must be array";
        return false;
    }
    subjects.clear();
    subjects.reserve(subjectsValue->Size());
    for (const auto &subjectValue : subjectsValue->GetArray()) {
        SnortDatapath::Policy::PacketPolicySubjectView subject;
        if (!parsePolicySubject(subjectValue, subject, error)) {
            return false;
        }
        subjects.push_back(std::move(subject));
    }
    return true;
}

bool parsePacketFacts(const rapidjson::Value &args,
                      SnortDatapath::Flow::PacketFacts &facts,
                      std::string &error) {
    if (const auto err = rejectUnknown(
            args, {"linuxUid", "uidKnown", "networkContext", "family", "direction",
                   "ipProtocol", "sourcePort", "destinationPort", "portsAvailable"});
        err.has_value()) {
        error = *err;
        return false;
    }

    const auto family = parseFamily(args, "family", error, true);
    if (!family.has_value()) {
        return false;
    }
    facts.source = *family == SnortDatapath::Flow::AddressFamily::Ipv4
        ? SnortDatapath::Flow::IpAddress::v4({10, 0, 0, 1})
        : SnortDatapath::Flow::IpAddress::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 1});
    facts.destination = *family == SnortDatapath::Flow::AddressFamily::Ipv4
        ? SnortDatapath::Flow::IpAddress::v4({192, 0, 2, 1})
        : SnortDatapath::Flow::IpAddress::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 2});

    const auto direction = parseDirection(args, "direction", error, true);
    if (!direction.has_value()) {
        return false;
    }
    facts.deviceDirection = *direction;

    const rapidjson::Value *portsAvailable = member(args, "portsAvailable");
    if (portsAvailable == nullptr || !portsAvailable->IsBool()) {
        error = "portsAvailable must be bool";
        return false;
    }
    facts.portsAvailable = portsAvailable->GetBool();
    facts.parseStatus = SnortDatapath::Flow::ParseStatus::Ready;
    facts.fragmented = false;
    facts.originalLength = 128;
    facts.boundedPrefixLength = 128;
    facts.domain.uidKnown = true;

    return readBool(args, "uidKnown", facts.domain.uidKnown, error, false)
        && (!facts.domain.uidKnown || readUint32(args, "linuxUid", facts.domain.linuxUid, error))
        && (facts.domain.uidKnown || member(args, "linuxUid") == nullptr
            || readUint32(args, "linuxUid", facts.domain.linuxUid, error, false))
        && readUint32(args, "networkContext", facts.domain.networkContext, error)
        && readUint8(args, "ipProtocol", facts.ipProtocol, error)
        && readUint16(args, "sourcePort", facts.sourcePort, error, facts.portsAvailable)
        && readUint16(args, "destinationPort", facts.destinationPort, error,
                      facts.portsAvailable)
        && (facts.ipProtocol == kTcpProtocol || facts.ipProtocol == kUdpProtocol
            || !facts.portsAvailable);
}

const char *verdictName(const SnortDatapath::Policy::PacketPolicyVerdict verdict) noexcept {
    switch (verdict) {
    case SnortDatapath::Policy::PacketPolicyVerdict::PASS_NEXT:
        return "PASS_NEXT";
    case SnortDatapath::Policy::PacketPolicyVerdict::DROP:
        return "DROP";
    }
    return "PASS_NEXT";
}

const char *stageName(const SnortDatapath::Policy::PacketPolicyStage stage) noexcept {
    switch (stage) {
    case SnortDatapath::Policy::PacketPolicyStage::None:
        return "None";
    case SnortDatapath::Policy::PacketPolicyStage::NetworkGate:
        return "NetworkGate";
    case SnortDatapath::Policy::PacketPolicyStage::L4:
        return "L4";
    }
    return "None";
}

rapidjson::Document makeDecisionResult(
    const SnortDatapath::Policy::PacketPolicyDecision decision) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("verdict", rapidjson::Value(verdictName(decision.verdict), alloc), alloc);
    result.AddMember("stage", rapidjson::Value(stageName(decision.stage), alloc), alloc);
    result.AddMember("reasonId", decision.reasonId, alloc);
    result.AddMember("ruleId", decision.ruleId, alloc);
    result.AddMember("revision", decision.revision, alloc);
    return result;
}

rapidjson::Document dispatchRequest(const ControlVNext::RequestView &request,
                                    SnortRuntime::BaseRuntimeControl &runtime) {
    if (request.cmd == "HELLO") {
        rapidjson::Document result = makeHelloResult(runtime);
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "RESETALL") {
        if (!runtime.resetBaseRuntime()) {
            return ControlVNext::makeErrorResponse(request.id, "RUNTIME_RESET_FAILED",
                                                   "base runtime reset failed");
        }
        return ControlVNext::makeOkResponse(request.id, nullptr);
    }

    if (request.cmd == "QUIT") {
        SnortRuntime::requestShutdown();
        return ControlVNext::makeOkResponse(request.id, nullptr);
    }

    if (request.cmd == "POLICY.STATUS") {
        if (!runtime.packetPolicyControlReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND", "packet policy control unavailable");
        }
        if (const auto err = rejectUnknown(*request.args, {}); err.has_value()) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", *err);
        }
        rapidjson::Document result = makeStatusResult(runtime.packetPolicyStatus());
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "NFQUEUE.STATUS") {
        if (!runtime.nfqueueRuntimeCountersReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND", "nfqueue runtime counters unavailable");
        }
        if (const auto err = rejectUnknown(*request.args, {}); err.has_value()) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", *err);
        }
        rapidjson::Document result = makeNfqueueStatusResult(runtime.nfqueueRuntimeCounters());
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "POLICY.APPLY") {
        if (!runtime.packetPolicyControlReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND", "packet policy control unavailable");
        }
        std::vector<SnortDatapath::Policy::PacketPolicySubjectView> subjects;
        std::uint64_t revision = 0;
        std::string error;
        if (!parsePolicyApplyArgs(*request.args, subjects, revision, error)) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", error);
        }
        if (!runtime.applyPacketPolicy(std::move(subjects), revision)) {
            return ControlVNext::makeErrorResponse(request.id, "POLICY_APPLY_FAILED",
                                                   "packet policy apply failed");
        }
        rapidjson::Document result = makeStatusResult(runtime.packetPolicyStatus());
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "POLICY.EVALUATE") {
        if (!runtime.packetPolicyControlReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND", "packet policy control unavailable");
        }
        SnortDatapath::Flow::PacketFacts facts;
        std::string error;
        if (!parsePacketFacts(*request.args, facts, error)) {
            if (error.empty()) {
                error = "invalid packet facts";
            }
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", error);
        }
        rapidjson::Document result = makeDecisionResult(runtime.evaluatePacketPolicy(facts));
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    return ControlVNext::makeErrorResponse(request.id, "UNSUPPORTED_COMMAND",
                                           "unsupported command in SNORT-10 base");
}

bool sendDocument(const int fd, const rapidjson::Document &doc) {
    const std::string json = ControlVNext::encodeJson(doc, ControlVNext::JsonFormat::Compact);
    if (json.size() > SnortConfig::kControlMaxResponseBytes) {
        const auto err = ControlVNext::makeErrorResponse(0, "RESPONSE_TOO_LARGE",
                                                         "response exceeds maxResponseBytes");
        const std::string errJson = ControlVNext::encodeJson(err, ControlVNext::JsonFormat::Compact);
        return writeAll(fd, ControlVNext::encodeNetstring(errJson));
    }
    return writeAll(fd, ControlVNext::encodeNetstring(json));
}

} // namespace

namespace SnortControlVNext {

ControlServer::ControlServer(SnortRuntime::BaseRuntimeControl &runtime) : runtime_(runtime) {}

int ControlServer::createAbstractListener() {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        std::cerr << "control socket create failed: " << std::strerror(errno) << "\n";
        return -1;
    }

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    std::strncpy(addr.sun_path + 1, SnortConfig::kControlVNextSocketName,
                 sizeof(addr.sun_path) - 2);

    const std::size_t nameLen =
        strnlen(SnortConfig::kControlVNextSocketName, sizeof(addr.sun_path) - 1);
    const auto addrLen =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);

    if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), addrLen) < 0) {
        std::cerr << "control socket bind failed: " << std::strerror(errno) << "\n";
        ::close(fd);
        return -1;
    }

    if (::listen(fd, SnortConfig::kControlListenBacklog) < 0) {
        std::cerr << "control socket listen failed: " << std::strerror(errno) << "\n";
        ::close(fd);
        return -1;
    }

    return fd;
}

void ControlServer::serveClient(const int clientFd) {
    ControlVNext::NetstringDecoder decoder(SnortConfig::kControlMaxRequestBytes);
    char buffer[4096];

    while (!SnortRuntime::shutdownRequested()) {
        const ssize_t n = ::recv(clientFd, buffer, sizeof(buffer), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }

        const auto bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buffer), static_cast<std::size_t>(n));
        if (const auto netErr = decoder.feed(bytes); netErr.has_value()) {
            const auto response = ControlVNext::makeErrorResponse(
                0, "SYNTAX_ERROR", netErr->message);
            (void)sendDocument(clientFd, response);
            return;
        }

        while (auto payload = decoder.pop()) {
            rapidjson::Document requestDoc;
            ControlVNext::JsonError jsonError;
            if (!ControlVNext::parseStrictJsonObject(*payload, requestDoc, jsonError)) {
                const auto response =
                    ControlVNext::makeErrorResponse(0, "SYNTAX_ERROR", jsonError.message);
                (void)sendDocument(clientFd, response);
                return;
            }

            ControlVNext::RequestView request;
            if (const auto envErr = ControlVNext::parseRequestEnvelope(requestDoc, request);
                envErr.has_value()) {
                const auto response =
                    ControlVNext::makeErrorResponse(0, envErr->code, envErr->message);
                (void)sendDocument(clientFd, response);
                return;
            }

            const auto response = dispatchRequest(request, runtime_);
            if (!sendDocument(clientFd, response)) {
                return;
            }
            if (request.cmd == "QUIT") {
                return;
            }
        }
    }
}

int ControlServer::run() {
    std::vector<int> serverFds;

    const int initFd = androidInitSocketFd(SnortConfig::kControlVNextSocketName);
    if (initFd >= 0) {
        if (::listen(initFd, SnortConfig::kControlListenBacklog) < 0) {
            std::cerr << "control init socket listen failed: " << std::strerror(errno) << "\n";
            ::close(initFd);
            return 1;
        }
        serverFds.push_back(initFd);
        std::cerr << "SNORT-10 base control listening on init socket "
                  << SnortConfig::kControlVNextSocketName << "\n";
    }

    const int abstractFd = createAbstractListener();
    if (abstractFd >= 0) {
        serverFds.push_back(abstractFd);
        std::cerr << "SNORT-10 base control listening on @"
                  << SnortConfig::kControlVNextSocketName << "\n";
    } else if (serverFds.empty()) {
        return 1;
    }

    std::vector<pollfd> pollFds;
    pollFds.reserve(serverFds.size());
    for (const int fd : serverFds) {
        pollFds.push_back(pollfd{.fd = fd, .events = POLLIN, .revents = 0});
    }

    while (!SnortRuntime::shutdownRequested()) {
        for (auto &pollFd : pollFds) {
            pollFd.revents = 0;
        }

        const int ready = ::poll(pollFds.data(), pollFds.size(), kControlPollTimeoutMs);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "control poll failed: " << std::strerror(errno) << "\n";
            break;
        }

        for (const auto &pollFd : pollFds) {
            if ((pollFd.revents & POLLIN) == 0) {
                continue;
            }

            const int clientFd = ::accept(pollFd.fd, nullptr, nullptr);
            if (clientFd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "control accept failed: " << std::strerror(errno) << "\n";
                continue;
            }
            serveClient(clientFd);
            ::close(clientFd);
            if (SnortRuntime::shutdownRequested()) {
                break;
            }
        }
    }

    for (const int fd : serverFds) {
        ::close(fd);
    }
    return 0;
}

} // namespace SnortControlVNext
