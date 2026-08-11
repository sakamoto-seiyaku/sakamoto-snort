/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>

#include <ControlVNextCodec.hpp>
#include <DaemonRuntime.hpp>
#include <RuntimeConfig.hpp>
#include <RuntimeControl.hpp>
#include <core/protocol/ApplicationProtocolCatalog.hpp>

#include <rapidjson/document.h>

#include <arpa/inet.h>

#include <algorithm>
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

void closeFd(int &fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

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

struct RecvChunk {
    ssize_t bytes = -1;
    int receivedFd = -1;
    bool ancillaryTruncated = false;
};

RecvChunk recvChunkWithOptionalFd(const int fd, char *buffer, const std::size_t bufferSize) {
    std::array<char, CMSG_SPACE(sizeof(int) * 4)> control{};
    iovec iov{
        .iov_base = buffer,
        .iov_len = bufferSize,
    };
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    RecvChunk chunk;
    chunk.bytes = ::recvmsg(fd, &msg, 0);
    if (chunk.bytes <= 0) {
        return chunk;
    }
    chunk.ancillaryTruncated = (msg.msg_flags & MSG_CTRUNC) != 0;

    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        const auto dataBytes = static_cast<std::size_t>(
            cmsg->cmsg_len - CMSG_LEN(0));
        const auto fdCount = dataBytes / sizeof(int);
        const int *fds = reinterpret_cast<const int *>(CMSG_DATA(cmsg));
        for (std::size_t i = 0; i < fdCount; ++i) {
            int received = fds[i];
            if (received < 0) {
                continue;
            }
            if (chunk.receivedFd < 0) {
                chunk.receivedFd = received;
            } else {
                ::close(received);
            }
        }
    }
    return chunk;
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
    if (runtime.vpnTunFdHandoffReady()) {
        capabilities.PushBack("vpn-tun-fd-handoff", alloc);
    }
    if (runtime.vpnTunTransportFdHandoffReady()) {
        capabilities.PushBack("vpn-tun-transport-fd-handoff", alloc);
    }
    if (runtime.nfqueueRuntimeCountersReady()) {
        capabilities.PushBack("nfqueue-runtime-counters", alloc);
    }
    if (runtime.vpnTunRuntimeCountersReady()) {
        capabilities.PushBack("vpn-tun-runtime-counters", alloc);
    }
    if (runtime.packetPolicyControlReady()) {
        capabilities.PushBack("packet-policy-control", alloc);
    }
    if (runtime.vpnTunAttributionControlReady()) {
        capabilities.PushBack("vpn-tun-attribution-control", alloc);
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

const char *stageName(SnortDatapath::Policy::PacketPolicyStage stage) noexcept;

rapidjson::Value makePolicyDropActivityResult(
    const SnortDatapath::Policy::PacketPolicyDropActivityCounters &activity,
    rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value result(rapidjson::kObjectType);
    result.AddMember("capacity", activity.capacity, alloc);
    result.AddMember("records", activity.records, alloc);
    result.AddMember("totalRecords", activity.totalRecords, alloc);
    result.AddMember("evictedRecords", activity.evictedRecords, alloc);
    result.AddMember("hasLastRecord", activity.hasLastRecord, alloc);
    result.AddMember("lastLinuxUid", activity.lastLinuxUid, alloc);
    result.AddMember("lastUidKnown", activity.lastUidKnown, alloc);
    result.AddMember("lastNetworkContext", activity.lastNetworkContext, alloc);
    rapidjson::Value lastStage;
    lastStage.SetString(stageName(activity.lastDecision.stage), alloc);
    result.AddMember("lastStage", lastStage, alloc);
    result.AddMember("lastReasonId", activity.lastDecision.reasonId, alloc);
    result.AddMember("lastRuleId", activity.lastDecision.ruleId, alloc);
    result.AddMember("lastRevision", activity.lastDecision.revision, alloc);
    return result;
}

std::string ipAddressToString(const SnortDatapath::Flow::IpAddress &address) {
    char buffer[INET6_ADDRSTRLEN] = {};
    const int family = address.family == SnortDatapath::Flow::AddressFamily::Ipv6
        ? AF_INET6
        : AF_INET;
    const void *source = address.bytes.data();
    if (::inet_ntop(family, source, buffer, sizeof(buffer)) == nullptr) {
        return {};
    }
    return buffer;
}

const char *devicePacketDirectionName(
    const SnortDatapath::Flow::DevicePacketDirection direction) noexcept {
    switch (direction) {
    case SnortDatapath::Flow::DevicePacketDirection::Input:
        return "input";
    case SnortDatapath::Flow::DevicePacketDirection::Output:
        return "output";
    }
    return "unknown";
}

const char *flowRelativeDirectionName(
    const SnortDatapath::Flow::FlowRelativeDirection direction) noexcept {
    switch (direction) {
    case SnortDatapath::Flow::FlowRelativeDirection::Orig:
        return "orig";
    case SnortDatapath::Flow::FlowRelativeDirection::Reply:
        return "reply";
    }
    return "unknown";
}

const char *protocolRecognitionStateName(
    const SnortDatapath::Flow::LpiRecognitionState &state) noexcept {
    if (state.payloadPacketsSubmitted == 0 && state.mappedResultsEmpty()
        && state.terminalState
            == SnortDatapath::Flow::LpiRecognitionTerminalState::Detecting) {
        return "";
    }
    if (state.latestExactResult().has_value()) {
        return "identified";
    }
    if (state.terminal()) {
        return "unidentified";
    }
    return "detecting";
}

std::string applicationProtocolKeyString(
    const sucre::protocol::ApplicationProtocolId id) {
    const auto key = sucre::protocol::applicationProtocolKey(id);
    if (!key.empty()) {
        return std::string{key};
    }
    return std::to_string(static_cast<std::uint32_t>(id));
}

std::string protocolRecognitionSequence(
    const SnortDatapath::Flow::LpiRecognitionState &state) {
    std::string out;
    for (const auto &result : state.mappedResults()) {
        if (!out.empty()) {
            out += ",";
        }
        out += std::to_string(result.firstPayloadPacketSequence);
        out += ":";
        out += applicationProtocolKeyString(result.protocolId);
        out += ":";
        out += flowRelativeDirectionName(result.direction);
    }
    return out;
}

rapidjson::Value makeAllowedFlowActivityResult(
    const SnortDatapath::Flow::FlowEntryActivityCounters &activity,
    rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value result(rapidjson::kObjectType);
    result.AddMember("capacity", activity.capacity, alloc);
    result.AddMember("records", activity.records, alloc);
    result.AddMember("totalRecords", activity.totalRecords, alloc);
    result.AddMember("evictedRecords", activity.evictedRecords, alloc);
    result.AddMember("hasLastRecord", activity.hasLastRecord, alloc);
    const auto source = ipAddressToString(activity.lastSource);
    rapidjson::Value lastSourceAddress;
    lastSourceAddress.SetString(source.c_str(),
                                static_cast<rapidjson::SizeType>(source.size()),
                                alloc);
    result.AddMember("lastSourceAddress", lastSourceAddress, alloc);
    const auto destination = ipAddressToString(activity.lastDestination);
    rapidjson::Value lastDestinationAddress;
    lastDestinationAddress.SetString(
        destination.c_str(),
        static_cast<rapidjson::SizeType>(destination.size()),
        alloc);
    result.AddMember("lastDestinationAddress", lastDestinationAddress, alloc);
    result.AddMember("lastIpProtocol", activity.lastIpProtocol, alloc);
    result.AddMember("lastSourcePort", activity.lastSourcePort, alloc);
    result.AddMember("lastDestinationPort", activity.lastDestinationPort, alloc);
    result.AddMember("lastPortsAvailable", activity.lastPortsAvailable, alloc);
    rapidjson::Value lastDeviceDirection;
    lastDeviceDirection.SetString(
        devicePacketDirectionName(activity.lastDeviceDirection), alloc);
    result.AddMember("lastDeviceDirection", lastDeviceDirection, alloc);
    rapidjson::Value lastFlowDirection;
    lastFlowDirection.SetString(
        flowRelativeDirectionName(activity.lastFlowDirection), alloc);
    result.AddMember("lastFlowDirection", lastFlowDirection, alloc);
    result.AddMember("lastLinuxUid", activity.lastLinuxUid, alloc);
    result.AddMember("lastUidKnown", activity.lastUidKnown, alloc);
    result.AddMember("lastNetworkContext", activity.lastNetworkContext, alloc);
    result.AddMember("lastPolicyRevision", activity.lastPolicyRevision, alloc);
    result.AddMember("lastPackets", activity.lastPackets, alloc);
    result.AddMember("lastBytes", activity.lastBytes, alloc);
    rapidjson::Value recognitionState;
    recognitionState.SetString(
        protocolRecognitionStateName(activity.lastLpiRecognition), alloc);
    result.AddMember("lastProtocolRecognitionState", recognitionState, alloc);
    const auto latestProtocol = activity.lastLpiRecognition.latestExactResult();
    const auto protocolKey = latestProtocol.has_value()
        ? applicationProtocolKeyString(*latestProtocol)
        : std::string{};
    rapidjson::Value latestProtocolKey;
    latestProtocolKey.SetString(
        protocolKey.c_str(), static_cast<rapidjson::SizeType>(protocolKey.size()), alloc);
    result.AddMember("lastApplicationProtocolKey", latestProtocolKey, alloc);
    const auto category = latestProtocol.has_value()
        ? std::string{sucre::protocol::applicationProtocolCategory(*latestProtocol)}
        : std::string{};
    rapidjson::Value latestProtocolCategory;
    latestProtocolCategory.SetString(
        category.c_str(), static_cast<rapidjson::SizeType>(category.size()), alloc);
    result.AddMember("lastApplicationProtocolCategory", latestProtocolCategory, alloc);
    const auto sequence = protocolRecognitionSequence(activity.lastLpiRecognition);
    rapidjson::Value recognitionSequence;
    recognitionSequence.SetString(
        sequence.c_str(), static_cast<rapidjson::SizeType>(sequence.size()), alloc);
    result.AddMember("lastProtocolRecognitionSequence", recognitionSequence, alloc);
    result.AddMember("lastProtocolPayloadPackets",
                     activity.lastLpiRecognition.payloadPacketsSubmitted, alloc);
    return result;
}

rapidjson::Value makeLpiProviderStatusResult(
    const SnortDatapath::Protocol::LpiProviderStatus &status,
    rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value result(rapidjson::kObjectType);
    result.AddMember("available", status.available, alloc);
    rapidjson::Value name;
    const auto *providerName = status.providerName.empty()
        ? ""
        : status.providerName.data();
    name.SetString(
        providerName,
        static_cast<rapidjson::SizeType>(status.providerName.size()),
        alloc);
    result.AddMember("name", name, alloc);
    result.AddMember("payloadBudgetPackets", status.payloadBudgetPackets, alloc);
    result.AddMember("mappedResultCapacity", status.mappedResultCapacity, alloc);
    result.AddMember("packetsObserved", status.counters.packetsObserved, alloc);
    result.AddMember("payloadEligiblePackets",
                     status.counters.payloadEligiblePackets, alloc);
    result.AddMember("terminalSkippedPackets",
                     status.counters.terminalSkippedPackets, alloc);
    result.AddMember("providerUnavailablePackets",
                     status.counters.providerUnavailablePackets, alloc);
    result.AddMember("flowSlotUnavailablePackets",
                     status.counters.flowSlotUnavailablePackets, alloc);
    result.AddMember("providerContextUnavailablePackets",
                     status.counters.providerContextUnavailablePackets, alloc);
    result.AddMember("packetsSubmittedToProvider",
                     status.counters.packetsSubmittedToProvider, alloc);
    result.AddMember("providerNoResultPackets",
                     status.counters.providerNoResultPackets, alloc);
    result.AddMember("providerFactPackets", status.counters.providerFactPackets, alloc);
    result.AddMember("detectorDonePackets",
                     status.counters.detectorDonePackets, alloc);
    result.AddMember("budgetExhaustedPackets",
                     status.counters.budgetExhaustedPackets, alloc);
    return result;
}

template <typename Counters>
void addFlowStatusMembers(rapidjson::Document &result, const Counters &counters,
                          rapidjson::Document::AllocatorType &alloc) {
    result.AddMember("flowTableEntries", counters.flowTableEntries, alloc);
    result.AddMember("flowTableCapacity", counters.flowTableCapacity, alloc);
    result.AddMember("flowTableHighWatermark", counters.flowTableHighWatermark, alloc);
    result.AddMember("flowTableCapacityMisses", counters.flowTableCapacityMisses, alloc);
    result.AddMember("lpiProvider",
                     makeLpiProviderStatusResult(counters.lpiProvider, alloc),
                     alloc);
}

template <typename Counters>
void addFlowActivityStatusMembers(rapidjson::Document &result,
                                  const Counters &counters,
                                  rapidjson::Document::AllocatorType &alloc) {
    result.AddMember("policyDropActivity",
                     makePolicyDropActivityResult(counters.policyDropActivity, alloc),
                     alloc);
    result.AddMember("allowedFlowActivity",
                     makeAllowedFlowActivityResult(counters.allowedFlowActivity, alloc),
                     alloc);
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
    result.AddMember("queueCapacity", counters.queueCapacity, alloc);
    result.AddMember("queueHighWatermark", counters.queueHighWatermark, alloc);
    result.AddMember("queueCompletionCapacity", counters.queueCompletionCapacity, alloc);
    result.AddMember("queueCompletionHighWatermark",
                     counters.queueCompletionHighWatermark, alloc);
    addFlowStatusMembers(result, counters, alloc);
    result.AddMember("uidMetadataPresentPackets",
                     counters.uidMetadataPresentPackets, alloc);
    result.AddMember("uidMetadataMissingPackets",
                     counters.uidMetadataMissingPackets, alloc);
    addFlowActivityStatusMembers(result, counters, alloc);
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

rapidjson::Document makeVpnTunStatusResult(
    const SnortRuntime::VpnTunRuntimeCounters counters) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("packetsSeen", counters.packetsSeen, alloc);
    result.AddMember("normalizedPackets", counters.normalizedPackets, alloc);
    result.AddMember("forwardedPackets", counters.forwardedPackets, alloc);
    result.AddMember("droppedPackets", counters.droppedPackets, alloc);
    result.AddMember("parsePolicyBypassPackets",
                     counters.parsePolicyBypassPackets, alloc);
    result.AddMember("capacityPolicyBypassPackets",
                     counters.capacityPolicyBypassPackets, alloc);
    result.AddMember("ownerFaultRuntimeDrops",
                     counters.ownerFaultRuntimeDrops, alloc);
    result.AddMember("fragmentBufferedPackets",
                     counters.fragmentBufferedPackets, alloc);
    result.AddMember("fragmentReassembledPackets",
                     counters.fragmentReassembledPackets, alloc);
    result.AddMember("uidAttributionHitPackets",
                     counters.uidAttributionHitPackets, alloc);
    result.AddMember("uidUnknownFallbackPackets",
                     counters.uidUnknownFallbackPackets, alloc);
    result.AddMember("outboundPackets", counters.outboundPackets, alloc);
    result.AddMember("transportReturnPackets",
                     counters.transportReturnPackets, alloc);
    result.AddMember("transportSucceededPackets",
                     counters.transportSucceededPackets, alloc);
    result.AddMember("transportFailedPackets",
                     counters.transportFailedPackets, alloc);
    result.AddMember("transportUnsupportedPackets",
                     counters.transportUnsupportedPackets, alloc);
    result.AddMember("directPackets", counters.directPackets, alloc);
    addFlowStatusMembers(result, counters, alloc);
    result.AddMember("ownerGuardPasses", counters.ownerGuardPasses, alloc);
    result.AddMember("ownerGuardMismatches", counters.ownerGuardMismatches, alloc);
    result.AddMember("attributionUpdates", counters.attributionUpdates, alloc);
    result.AddMember("attributionMisses", counters.attributionMisses, alloc);
    result.AddMember("attributionResolutions", counters.attributionResolutions, alloc);
    addFlowActivityStatusMembers(result, counters, alloc);
    result.AddMember("lastObservedLinuxUid", counters.lastObservedLinuxUid, alloc);
    result.AddMember("lastObservedUidKnown", counters.lastObservedUidKnown, alloc);
    result.AddMember("lastObservedNetworkContext",
                     counters.lastObservedNetworkContext, alloc);
    result.AddMember("lastObservedInterfaceIndex",
                     counters.lastObservedInterfaceIndex, alloc);
    rapidjson::Value lastObservedDirection;
    lastObservedDirection.SetString(counters.lastObservedDirection.c_str(),
                                    static_cast<rapidjson::SizeType>(
                                        counters.lastObservedDirection.size()),
                                    alloc);
    result.AddMember("lastObservedDirection", lastObservedDirection, alloc);
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

std::optional<SnortDatapath::Flow::IpAddress> parseIpAddressText(
    const std::string_view text, std::string &error) {
    std::array<std::uint8_t, 16> bytes{};
    const std::string value(text);
    if (value.find(':') != std::string::npos) {
        if (::inet_pton(AF_INET6, value.c_str(), bytes.data()) != 1) {
            error = "invalid ipv6 address";
            return std::nullopt;
        }
        return SnortDatapath::Flow::IpAddress::v6(bytes);
    }

    std::array<std::uint8_t, 4> v4{};
    if (::inet_pton(AF_INET, value.c_str(), v4.data()) != 1) {
        error = "invalid ipv4 address";
        return std::nullopt;
    }
    return SnortDatapath::Flow::IpAddress::v4(v4);
}

bool parseOptionalIpAddress(const rapidjson::Value &object,
                            const std::string_view key,
                            const SnortDatapath::Flow::AddressFamily family,
                            SnortDatapath::Flow::IpAddress &out,
                            std::string &error) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        return true;
    }
    if (!value->IsString()) {
        error = std::string(key) + " must be string";
        return false;
    }
    const auto parsed = parseIpAddressText(
        std::string_view(value->GetString(), value->GetStringLength()), error);
    if (!parsed.has_value()) {
        error = std::string(key) + ": " + error;
        return false;
    }
    if (parsed->family != family) {
        error = std::string(key) + " family must match family";
        return false;
    }
    out = *parsed;
    return true;
}

bool parseCidr(const rapidjson::Value &object, const std::string_view key,
               std::optional<SnortDatapath::Policy::CidrMatch> &out,
               std::string &error) {
    const rapidjson::Value *value = member(object, key);
    if (value == nullptr) {
        out.reset();
        return true;
    }
    if (!value->IsString()) {
        error = std::string(key) + " must be CIDR string";
        return false;
    }

    const std::string text(value->GetString(), value->GetStringLength());
    const auto slash = text.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= text.size()) {
        error = std::string(key) + " must be address/prefix";
        return false;
    }

    std::string parseError;
    const auto address = parseIpAddressText(
        std::string_view(text).substr(0, slash), parseError);
    if (!address.has_value()) {
        error = std::string(key) + ": " + parseError;
        return false;
    }

    char *end = nullptr;
    errno = 0;
    const unsigned long prefix = std::strtoul(text.c_str() + slash + 1, &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0' || prefix > 128UL) {
        error = std::string(key) + " prefix must be 0..128";
        return false;
    }
    const auto maxPrefix = address->family == SnortDatapath::Flow::AddressFamily::Ipv4
        ? 32UL
        : 128UL;
    if (prefix > maxPrefix) {
        error = std::string(key) + " prefix exceeds address family width";
        return false;
    }

    out = SnortDatapath::Policy::CidrMatch{
        .network = *address,
        .prefixLength = static_cast<std::uint8_t>(prefix),
    };
    return true;
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
                     "networkContexts", "sourceCidr", "destinationCidr",
                     "sourcePorts", "destinationPorts"});
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
        || !parseCidr(object, "sourceCidr", out.sourceCidr, error)
        || !parseCidr(object, "destinationCidr", out.destinationCidr, error)
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
                     "reasonId", "ruleId", "rules"});
        err.has_value()) {
        error = *err;
        return false;
    }
    if (!readUint64(object, "blockedNetworkContextBits",
                    out.blockedNetworkContextBits, error, false)
        || !readContextArray(object, "blockedNetworkContexts",
                             out.blockedNetworkContexts, error)
        || !readUint32(object, "reasonId", out.reasonId, error, false)
        || !readUint64(object, "ruleId", out.ruleId, error, false)) {
        return false;
    }
    const rapidjson::Value *rules = member(object, "rules");
    if (rules == nullptr) {
        return true;
    }
    if (!rules->IsArray()) {
        error = "rules must be array";
        return false;
    }
    out.contextRules.clear();
    out.contextRules.reserve(rules->Size());
    for (const auto &ruleValue : rules->GetArray()) {
        if (!ruleValue.IsObject()) {
            error = "rules entries must be object";
            return false;
        }
        if (const auto err = rejectUnknown(
                ruleValue, {"networkContext", "reasonId", "ruleId"});
            err.has_value()) {
            error = *err;
            return false;
        }
        SnortDatapath::Policy::NetworkGateView::ContextRule rule;
        if (!readUint32(ruleValue, "networkContext", rule.networkContext, error)
            || !readUint32(ruleValue, "reasonId", rule.reasonId, error)
            || !readUint64(ruleValue, "ruleId", rule.ruleId, error)) {
            return false;
        }
        if (std::find_if(
                out.contextRules.begin(), out.contextRules.end(),
                [&rule](const auto &candidate) noexcept {
                    return candidate.networkContext == rule.networkContext;
                }) != out.contextRules.end()) {
            error = "duplicate networkGate context rule";
            return false;
        }
        out.contextRules.push_back(rule);
    }
    return true;
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
                   "ipProtocol", "sourceIp", "destinationIp", "sourcePort",
                   "destinationPort", "portsAvailable"});
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
    if (!parseOptionalIpAddress(args, "sourceIp", *family, facts.source, error)
        || !parseOptionalIpAddress(args, "destinationIp", *family, facts.destination, error)) {
        return false;
    }

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

bool parseVpnTunAttributionApplyArgs(
    const rapidjson::Value &args,
    SnortDatapath::Flow::PacketFacts &facts,
    std::uint32_t &resolvedLinuxUid,
    bool &resolvedUidKnown,
    std::string &error) {
    if (const auto err = rejectUnknown(
            args, {"linuxUid", "uidKnown", "networkContext", "family", "direction",
                   "ipProtocol", "sourceIp", "destinationIp", "sourcePort",
                   "destinationPort", "portsAvailable", "resolvedLinuxUid",
                   "resolvedUidKnown"});
        err.has_value()) {
        error = *err;
        return false;
    }

    if (!readUint32(args, "resolvedLinuxUid", resolvedLinuxUid, error)
        || !readBool(args, "resolvedUidKnown", resolvedUidKnown, error, false)) {
        return false;
    }

    rapidjson::Document packetArgs(rapidjson::kObjectType);
    auto &alloc = packetArgs.GetAllocator();
    for (auto it = args.MemberBegin(); it != args.MemberEnd(); ++it) {
        const std::string_view key(it->name.GetString(), it->name.GetStringLength());
        if (key == "resolvedLinuxUid" || key == "resolvedUidKnown") {
            continue;
        }
        rapidjson::Value name;
        name.SetString(it->name.GetString(), it->name.GetStringLength(), alloc);
        rapidjson::Value value;
        value.CopyFrom(it->value, alloc);
        packetArgs.AddMember(name, value, alloc);
    }
    return parsePacketFacts(packetArgs, facts, error);
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

rapidjson::Document makeVpnTunAttachResult(const bool enableIpv6) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("adapter", "vpn-tun-hev", alloc);
    result.AddMember("fdAttached", true, alloc);
    result.AddMember("ipv6Enabled", enableIpv6, alloc);
    return result;
}

rapidjson::Document makeVpnTransportAttachResult() {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("adapter", "vpn-tun-hev", alloc);
    result.AddMember("transportFdAttached", true, alloc);
    return result;
}

rapidjson::Document makeFlowAttributionResult(
    const SnortDatapath::Flow::FlowAttributionObservation &observation) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("found", observation.found, alloc);
    result.AddMember("updated", observation.updated, alloc);
    result.AddMember("previousLinuxUid", observation.previousLinuxUid, alloc);
    result.AddMember("previousUidKnown", observation.previousUidKnown, alloc);
    result.AddMember("currentLinuxUid", observation.currentLinuxUid, alloc);
    result.AddMember("currentUidKnown", observation.currentUidKnown, alloc);
    result.AddMember("attributionUpdates", observation.attributionUpdates, alloc);
    return result;
}

rapidjson::Document dispatchRequest(const ControlVNext::RequestView &request,
                                    SnortRuntime::BaseRuntimeControl &runtime,
                                    int &receivedFd) {
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

    if (request.cmd == "VPN_TUN.STATUS") {
        if (!runtime.vpnTunRuntimeCountersReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND", "VPN/TUN runtime counters unavailable");
        }
        if (const auto err = rejectUnknown(*request.args, {}); err.has_value()) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", *err);
        }
        rapidjson::Document result = makeVpnTunStatusResult(runtime.vpnTunRuntimeCounters());
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "VPN_TUN.ATTRIBUTION.APPLY") {
        if (!runtime.vpnTunAttributionControlReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND",
                "VPN/TUN attribution control unavailable");
        }
        SnortDatapath::Flow::PacketFacts facts;
        std::uint32_t resolvedLinuxUid = 0;
        bool resolvedUidKnown = true;
        std::string error;
        if (!parseVpnTunAttributionApplyArgs(
                *request.args, facts, resolvedLinuxUid, resolvedUidKnown, error)) {
            if (error.empty()) {
                error = "invalid VPN/TUN attribution apply facts";
            }
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", error);
        }
        const auto observation = runtime.applyResolvedVpnTunAttribution(
            facts, resolvedLinuxUid, resolvedUidKnown);
        if (!observation.has_value()) {
            return ControlVNext::makeErrorResponse(
                request.id, "INVALID_ARGUMENT",
                "VPN_TUN.ATTRIBUTION.APPLY requires canonical packet facts");
        }
        rapidjson::Document result = makeFlowAttributionResult(*observation);
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "VPN_TUN.ATTACH") {
        if (!runtime.vpnTunFdHandoffReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND", "VPN TUN fd handoff unavailable");
        }
        bool enableIpv6 = false;
        std::string error;
        if (const auto err = rejectUnknown(*request.args, {"enableIpv6"}); err.has_value()) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", *err);
        }
        if (!readBool(*request.args, "enableIpv6", enableIpv6, error)) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", error);
        }
        if (receivedFd < 0) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT",
                                                   "VPN_TUN.ATTACH requires one SCM_RIGHTS fd");
        }
        const int tunFd = receivedFd;
        receivedFd = -1;
        const auto attach = runtime.attachVpnTunFd(tunFd, enableIpv6);
        if (!attach.ok) {
            return ControlVNext::makeErrorResponse(
                request.id,
                attach.errorCode.empty() ? "VPN_TUN_ATTACH_FAILED" : attach.errorCode,
                attach.errorMessage.empty() ? "VPN TUN fd attach failed"
                                            : attach.errorMessage);
        }
        rapidjson::Document result = makeVpnTunAttachResult(enableIpv6);
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "VPN_TRANSPORT.ATTACH") {
        if (!runtime.vpnTunTransportFdHandoffReady()) {
            return ControlVNext::makeErrorResponse(
                request.id, "UNSUPPORTED_COMMAND",
                "VPN transport fd handoff unavailable");
        }
        if (const auto err = rejectUnknown(*request.args, {}); err.has_value()) {
            return ControlVNext::makeErrorResponse(request.id, "INVALID_ARGUMENT", *err);
        }
        if (receivedFd < 0) {
            return ControlVNext::makeErrorResponse(
                request.id, "INVALID_ARGUMENT",
                "VPN_TRANSPORT.ATTACH requires one SCM_RIGHTS fd");
        }
        const int transportFd = receivedFd;
        receivedFd = -1;
        const auto attach = runtime.attachVpnTransportFd(transportFd);
        if (!attach.ok) {
            return ControlVNext::makeErrorResponse(
                request.id,
                attach.errorCode.empty() ? "VPN_TRANSPORT_ATTACH_FAILED"
                                         : attach.errorCode,
                attach.errorMessage.empty() ? "VPN transport fd attach failed"
                                            : attach.errorMessage);
        }
        rapidjson::Document result = makeVpnTransportAttachResult();
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
        RecvChunk chunk = recvChunkWithOptionalFd(clientFd, buffer, sizeof(buffer));
        const ssize_t n = chunk.bytes;
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }
        if (chunk.ancillaryTruncated) {
            closeFd(chunk.receivedFd);
            const auto response = ControlVNext::makeErrorResponse(
                0, "INVALID_ARGUMENT", "ancillary fd data truncated");
            (void)sendDocument(clientFd, response);
            return;
        }

        const auto bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buffer), static_cast<std::size_t>(n));
        if (const auto netErr = decoder.feed(bytes); netErr.has_value()) {
            closeFd(chunk.receivedFd);
            const auto response = ControlVNext::makeErrorResponse(
                0, "SYNTAX_ERROR", netErr->message);
            (void)sendDocument(clientFd, response);
            return;
        }

        while (auto payload = decoder.pop()) {
            rapidjson::Document requestDoc;
            ControlVNext::JsonError jsonError;
            if (!ControlVNext::parseStrictJsonObject(*payload, requestDoc, jsonError)) {
                closeFd(chunk.receivedFd);
                const auto response =
                    ControlVNext::makeErrorResponse(0, "SYNTAX_ERROR", jsonError.message);
                (void)sendDocument(clientFd, response);
                return;
            }

            ControlVNext::RequestView request;
            if (const auto envErr = ControlVNext::parseRequestEnvelope(requestDoc, request);
                envErr.has_value()) {
                closeFd(chunk.receivedFd);
                const auto response =
                    ControlVNext::makeErrorResponse(0, envErr->code, envErr->message);
                (void)sendDocument(clientFd, response);
                return;
            }

            const auto response = dispatchRequest(request, runtime_, chunk.receivedFd);
            closeFd(chunk.receivedFd);
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
