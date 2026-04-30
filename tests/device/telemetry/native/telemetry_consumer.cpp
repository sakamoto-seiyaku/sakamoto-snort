// SPDX-FileCopyrightText: 2024-2028 sucré Technologies
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Device-side Flow Telemetry consumer (POC).
//
// This tool is intentionally dependency-light (no rapidjson) so it can be built with the
// kernel NDK toolchain as a standalone binary.

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr const char *kDefaultSocketName = "sucre-snort-control-vnext"; // localabstract

constexpr std::uint32_t kSlotHeaderBytes = 24;
constexpr std::uint32_t kSlotOffsetState = 0;
constexpr std::uint32_t kSlotOffsetRecordType = 4;
constexpr std::uint32_t kSlotOffsetTicket = 8;
constexpr std::uint32_t kSlotOffsetPayloadSize = 16;

enum class SlotState : std::uint32_t {
    Empty = 0,
    Writing = 1,
    Committed = 2,
};

enum class RecordType : std::uint16_t {
    Flow = 1,
    DnsDecision = 2,
};

constexpr std::uint32_t kFlowV1OffsetPayloadVersion = 0;
constexpr std::uint32_t kFlowV1OffsetKind = 1;
constexpr std::uint32_t kFlowV1OffsetCtState = 2;
constexpr std::uint32_t kFlowV1OffsetCtDir = 3;
constexpr std::uint32_t kFlowV1OffsetReasonId = 4;
constexpr std::uint32_t kFlowV1OffsetIfaceKindBit = 5;
constexpr std::uint32_t kFlowV1OffsetFlags = 6;
constexpr std::uint32_t kFlowV1OffsetTimestampNs = 8;
constexpr std::uint32_t kFlowV1OffsetFlowInstanceId = 16;
constexpr std::uint32_t kFlowV1OffsetRecordSeq = 24;
constexpr std::uint32_t kFlowV1OffsetUid = 32;
constexpr std::uint32_t kFlowV1OffsetUserId = 36;
constexpr std::uint32_t kFlowV1OffsetIfindex = 40;
constexpr std::uint32_t kFlowV1OffsetProto = 44;
constexpr std::uint32_t kFlowV1OffsetSrcPort = 46;
constexpr std::uint32_t kFlowV1OffsetDstPort = 48;
constexpr std::uint32_t kFlowV1OffsetSrcAddr = 50;
constexpr std::uint32_t kFlowV1OffsetDstAddr = 66;
constexpr std::uint32_t kFlowV1OffsetTotalPackets = 82;
constexpr std::uint32_t kFlowV1OffsetTotalBytes = 90;
constexpr std::uint32_t kFlowV1OffsetRuleId = 98;
constexpr std::uint32_t kFlowV1Bytes = 102;
constexpr std::uint8_t kFlowFlagHasRuleId = 1u << 0;
constexpr std::uint8_t kFlowFlagIsIpv6 = 1u << 1;

constexpr std::uint32_t kDnsV1OffsetPayloadVersion = 0;
constexpr std::uint32_t kDnsV1OffsetFlags = 1;
constexpr std::uint32_t kDnsV1OffsetPolicySource = 2;
constexpr std::uint32_t kDnsV1OffsetQueryNameLen = 4;
constexpr std::uint32_t kDnsV1OffsetTimestampNs = 8;
constexpr std::uint32_t kDnsV1OffsetUid = 16;
constexpr std::uint32_t kDnsV1OffsetUserId = 20;
constexpr std::uint32_t kDnsV1OffsetRuleId = 24;
constexpr std::uint32_t kDnsV1OffsetQueryName = 32;
constexpr std::uint32_t kDnsV1FixedBytes = 32;
constexpr std::uint8_t kDnsDecisionFlagHasRuleId = 1u << 0;
constexpr std::uint8_t kDnsDecisionFlagQueryNameTruncated = 1u << 1;

struct Args {
    const char *socketName = kDefaultSocketName;
    int timeoutSec = 10;
    int pollMs = 100;
    int wantFlow = 1;
    int wantDns = 0;
    int collectMs = 0;
    int initialSleepMs = 0;
    bool jsonl = false;

    std::uint32_t slotBytes = 0;
    std::uint64_t ringDataBytes = 0;
    std::uint64_t packetsThreshold = 1;
    std::uint64_t bytesThreshold = 1;
    std::uint32_t maxExportIntervalMs = 500;
};

[[nodiscard]] std::uint16_t readU16Le(const std::byte *p) noexcept {
    const auto b0 = static_cast<std::uint16_t>(p[0]);
    const auto b1 = static_cast<std::uint16_t>(p[1]);
    return static_cast<std::uint16_t>(b0 | (b1 << 8));
}

[[nodiscard]] std::uint32_t readU32Le(const std::byte *p) noexcept {
    const auto b0 = static_cast<std::uint32_t>(p[0]);
    const auto b1 = static_cast<std::uint32_t>(p[1]);
    const auto b2 = static_cast<std::uint32_t>(p[2]);
    const auto b3 = static_cast<std::uint32_t>(p[3]);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

[[nodiscard]] std::uint64_t readU64Le(const std::byte *p) noexcept {
    const std::uint64_t lo = readU32Le(p);
    const std::uint64_t hi = readU32Le(p + 4);
    return lo | (hi << 32);
}

[[nodiscard]] std::string jsonEscape(const std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const unsigned char ch : s) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (ch < 0x20) {
                char buf[7]{};
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(ch));
                out += buf;
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    return out;
}

[[nodiscard]] const char *flowKindStr(const std::uint8_t kind) noexcept {
    switch (kind) {
    case 1:
        return "BEGIN";
    case 2:
        return "UPDATE";
    case 3:
        return "END";
    default:
        return "UNKNOWN";
    }
}

[[nodiscard]] const char *reasonStr(const std::uint8_t reason) noexcept {
    switch (reason) {
    case 0:
        return "IFACE_BLOCK";
    case 1:
        return "IP_LEAK_BLOCK";
    case 2:
        return "ALLOW_DEFAULT";
    case 3:
        return "IP_RULE_ALLOW";
    case 4:
        return "IP_RULE_BLOCK";
    default:
        return "UNKNOWN";
    }
}

[[nodiscard]] const char *policySourceStr(const std::uint8_t source) noexcept {
    switch (source) {
    case 0:
        return "CUSTOM_WHITELIST";
    case 1:
        return "CUSTOM_BLACKLIST";
    case 2:
        return "CUSTOM_RULE_WHITE";
    case 3:
        return "CUSTOM_RULE_BLACK";
    case 4:
        return "DOMAIN_DEVICE_WIDE_AUTHORIZED";
    case 5:
        return "DOMAIN_DEVICE_WIDE_BLOCKED";
    case 6:
        return "MASK_FALLBACK";
    default:
        return "UNKNOWN";
    }
}

[[nodiscard]] std::string ipString(const bool ipv6, const std::byte *addr) {
    char out[INET6_ADDRSTRLEN]{};
    if (ipv6) {
        if (::inet_ntop(AF_INET6, addr, out, sizeof(out)) == nullptr) {
            return {};
        }
    } else {
        if (::inet_ntop(AF_INET, addr, out, sizeof(out)) == nullptr) {
            return {};
        }
    }
    return std::string(out);
}

[[nodiscard]] bool isDigitsOnly(std::string_view s) noexcept {
    if (s.empty()) {
        return false;
    }
    for (const char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool jsonFindU64(const std::string_view json, const std::string_view key,
                               std::uint64_t &out) noexcept {
    const std::string needle = "\"" + std::string(key) + "\":";
    const std::size_t pos = json.find(needle);
    if (pos == std::string_view::npos) {
        return false;
    }
    std::size_t i = pos + needle.size();
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\n' || json[i] == '\r')) {
        ++i;
    }
    std::size_t j = i;
    while (j < json.size() && json[j] >= '0' && json[j] <= '9') {
        ++j;
    }
    const std::string_view digits = json.substr(i, j - i);
    if (!isDigitsOnly(digits)) {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(std::string(digits).c_str(), &end, 10);
    if (errno != 0 || end == nullptr) {
        return false;
    }
    out = static_cast<std::uint64_t>(v);
    return true;
}

[[nodiscard]] std::string encodeNetstring(const std::string_view payload) {
    std::string out;
    out.reserve(payload.size() + 64);
    out.append(std::to_string(payload.size()));
    out.push_back(':');
    out.append(payload.data(), payload.size());
    out.push_back(',');
    return out;
}

[[nodiscard]] bool parseOneNetstring(std::string_view buf, std::string_view &outPayload,
                                     std::size_t &outConsumed) {
    // Parse "<len>:<payload>,"
    std::size_t i = 0;
    while (i < buf.size() && buf[i] >= '0' && buf[i] <= '9') {
        ++i;
    }
    if (i == 0 || i >= buf.size() || buf[i] != ':') {
        return false;
    }
    const std::string_view lenStr = buf.substr(0, i);
    if (!isDigitsOnly(lenStr)) {
        return false;
    }
    const std::size_t len = static_cast<std::size_t>(std::strtoull(std::string(lenStr).c_str(), nullptr, 10));
    const std::size_t payloadOff = i + 1;
    const std::size_t need = payloadOff + len + 1;
    if (need > buf.size()) {
        return false;
    }
    if (buf[payloadOff + len] != ',') {
        return false;
    }
    outPayload = buf.substr(payloadOff, len);
    outConsumed = need;
    return true;
}

[[nodiscard]] int connectAbstractUnix(const char *name) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        std::fprintf(stderr, "socket(AF_UNIX) failed: %s\n", std::strerror(errno));
        return -1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    // abstract: sun_path[0] = '\0'
    const std::size_t nameLen = std::strlen(name);
    if (nameLen + 1 >= sizeof(addr.sun_path)) {
        std::fprintf(stderr, "socket name too long: %s\n", name);
        ::close(fd);
        return -1;
    }
    addr.sun_path[0] = '\0';
    std::memcpy(addr.sun_path + 1, name, nameLen);

    const socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), addrLen) != 0) {
        std::fprintf(stderr, "connect(@%s) failed: %s\n", name, std::strerror(errno));
        ::close(fd);
        return -1;
    }
    return fd;
}

struct OpenResult {
    int shmFd = -1;
    std::uint64_t slotBytes = 0;
    std::uint64_t slotCount = 0;
    std::uint64_t ringDataBytes = 0;
    std::uint64_t writeTicketSnapshot = 0;
};

void appendConfigU64(std::string &json, bool &first, const char *key, const std::uint64_t value) {
    if (!first) {
        json.push_back(',');
    }
    first = false;
    json.push_back('"');
    json += key;
    json += "\":";
    json += std::to_string(value);
}

[[nodiscard]] std::string buildTelemetryOpenRequest(const Args &args) {
    std::string reqJson = "{\"id\":1,\"cmd\":\"TELEMETRY.OPEN\",\"args\":{\"level\":\"flow\",\"config\":{";
    bool first = true;
    if (args.slotBytes != 0) {
        appendConfigU64(reqJson, first, "slotBytes", args.slotBytes);
    }
    if (args.ringDataBytes != 0) {
        appendConfigU64(reqJson, first, "ringDataBytes", args.ringDataBytes);
    }
    appendConfigU64(reqJson, first, "packetsThreshold", args.packetsThreshold);
    appendConfigU64(reqJson, first, "bytesThreshold", args.bytesThreshold);
    appendConfigU64(reqJson, first, "maxExportIntervalMs", args.maxExportIntervalMs);
    reqJson += "}}}";
    return reqJson;
}

[[nodiscard]] bool telemetryOpen(const int sockFd, const Args &args, OpenResult &out) {
    const std::string reqJson = buildTelemetryOpenRequest(args);

    const std::string frame = encodeNetstring(reqJson);
    if (::send(sockFd, frame.data(), frame.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(frame.size())) {
        std::fprintf(stderr, "send(TELEMETRY.OPEN) failed: %s\n", std::strerror(errno));
        return false;
    }

    std::vector<char> buf(64 * 1024);
    alignas(struct cmsghdr) char cmsgBuf[CMSG_SPACE(sizeof(int))]{};

    iovec iov{};
    iov.iov_base = buf.data();
    iov.iov_len = buf.size();

    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgBuf;
    msg.msg_controllen = sizeof(cmsgBuf);

    const ssize_t n = ::recvmsg(sockFd, &msg, 0);
    if (n <= 0) {
        std::fprintf(stderr, "recvmsg(TELEMETRY.OPEN) failed: %s\n",
                     (n == 0) ? "eof" : std::strerror(errno));
        return false;
    }

    // Extract SCM_RIGHTS fd.
    int shmFd = -1;
    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            std::memcpy(&shmFd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }

    std::string_view payload;
    std::size_t consumed = 0;
    const std::string_view view(buf.data(), static_cast<std::size_t>(n));
    if (!parseOneNetstring(view, payload, consumed)) {
        std::fprintf(stderr, "failed to parse netstring response (bytes=%zd)\n", n);
        if (shmFd >= 0) {
            ::close(shmFd);
        }
        return false;
    }

    // Basic sanity: ok=true
    if (payload.find("\"ok\":true") == std::string_view::npos) {
        std::fprintf(stderr, "TELEMETRY.OPEN returned non-ok: %.*s\n",
                     static_cast<int>(payload.size()), payload.data());
        if (shmFd >= 0) {
            ::close(shmFd);
        }
        return false;
    }

    std::uint64_t slotBytes = 0, slotCount = 0, ringDataBytes = 0, writeTicketSnapshot = 0;
    if (!jsonFindU64(payload, "slotBytes", slotBytes) ||
        !jsonFindU64(payload, "slotCount", slotCount) ||
        !jsonFindU64(payload, "ringDataBytes", ringDataBytes) ||
        !jsonFindU64(payload, "writeTicketSnapshot", writeTicketSnapshot)) {
        std::fprintf(stderr, "failed to parse required metadata from response: %.*s\n",
                     static_cast<int>(payload.size()), payload.data());
        if (shmFd >= 0) {
            ::close(shmFd);
        }
        return false;
    }

    if (shmFd < 0) {
        std::fprintf(stderr, "missing SCM_RIGHTS fd in TELEMETRY.OPEN response: %.*s\n",
                     static_cast<int>(payload.size()), payload.data());
        return false;
    }

    out.shmFd = shmFd;
    out.slotBytes = slotBytes;
    out.slotCount = slotCount;
    out.ringDataBytes = ringDataBytes;
    out.writeTicketSnapshot = writeTicketSnapshot;
    return true;
}

[[nodiscard]] bool telemetryClose(const int sockFd) {
    const std::string reqJson = "{\"id\":2,\"cmd\":\"TELEMETRY.CLOSE\",\"args\":{}}";
    const std::string frame = encodeNetstring(reqJson);
    if (::send(sockFd, frame.data(), frame.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(frame.size())) {
        return false;
    }
    // Best-effort: ignore response.
    return true;
}

[[nodiscard]] bool parseArgs(int argc, char **argv, Args &out) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view a(argv[i]);
        auto next = [&](const char *flag) -> const char * {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", flag);
                return nullptr;
            }
            return argv[++i];
        };

        if (a == "--socket") {
            const char *v = next("--socket");
            if (!v) return false;
            out.socketName = v;
        } else if (a == "--timeoutSec") {
            const char *v = next("--timeoutSec");
            if (!v) return false;
            out.timeoutSec = std::atoi(v);
        } else if (a == "--pollMs") {
            const char *v = next("--pollMs");
            if (!v) return false;
            out.pollMs = std::atoi(v);
        } else if (a == "--wantFlow") {
            const char *v = next("--wantFlow");
            if (!v) return false;
            out.wantFlow = std::atoi(v);
        } else if (a == "--wantDns") {
            const char *v = next("--wantDns");
            if (!v) return false;
            out.wantDns = std::atoi(v);
        } else if (a == "--collectMs") {
            const char *v = next("--collectMs");
            if (!v) return false;
            out.collectMs = std::atoi(v);
        } else if (a == "--initialSleepMs") {
            const char *v = next("--initialSleepMs");
            if (!v) return false;
            out.initialSleepMs = std::atoi(v);
        } else if (a == "--slotBytes") {
            const char *v = next("--slotBytes");
            if (!v) return false;
            out.slotBytes = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10));
        } else if (a == "--ringDataBytes") {
            const char *v = next("--ringDataBytes");
            if (!v) return false;
            out.ringDataBytes = static_cast<std::uint64_t>(std::strtoull(v, nullptr, 10));
        } else if (a == "--packetsThreshold") {
            const char *v = next("--packetsThreshold");
            if (!v) return false;
            out.packetsThreshold = static_cast<std::uint64_t>(std::strtoull(v, nullptr, 10));
        } else if (a == "--bytesThreshold") {
            const char *v = next("--bytesThreshold");
            if (!v) return false;
            out.bytesThreshold = static_cast<std::uint64_t>(std::strtoull(v, nullptr, 10));
        } else if (a == "--maxExportIntervalMs") {
            const char *v = next("--maxExportIntervalMs");
            if (!v) return false;
            out.maxExportIntervalMs = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10));
        } else if (a == "--jsonl") {
            out.jsonl = true;
        } else if (a == "-h" || a == "--help") {
            std::printf(
                "usage: telemetry-consumer [--socket NAME] [--timeoutSec N] [--pollMs N]\n"
                "                          [--wantFlow N] [--wantDns N] [--collectMs N]\n"
                "                          [--initialSleepMs N] [--slotBytes N] [--ringDataBytes N]\n"
                "                          [--packetsThreshold N] [--bytesThreshold N]\n"
                "                          [--maxExportIntervalMs N] [--jsonl]\n");
            return false;
        } else {
            std::fprintf(stderr, "unknown arg: %.*s\n", static_cast<int>(a.size()), a.data());
            return false;
        }
    }

    if (out.timeoutSec <= 0) out.timeoutSec = 10;
    if (out.pollMs <= 0) out.pollMs = 100;
    if (out.wantFlow < 0) out.wantFlow = 0;
    if (out.wantDns < 0) out.wantDns = 0;
    if (out.collectMs < 0) out.collectMs = 0;
    if (out.initialSleepMs < 0) out.initialSleepMs = 0;
    return true;
}

[[nodiscard]] std::uint64_t nowMs() {
    timeval tv{};
    ::gettimeofday(&tv, nullptr);
    return static_cast<std::uint64_t>(tv.tv_sec) * 1000ull + static_cast<std::uint64_t>(tv.tv_usec) / 1000ull;
}

struct Summary {
    int foundFlow = 0;
    int foundDns = 0;
    std::uint64_t recordSeqGaps = 0;
    std::uint64_t transportGaps = 0;
    std::uint64_t missedTickets = 0;
    std::uint64_t expectedTicket = 0;
    std::unordered_map<std::uint64_t, std::uint64_t> lastSeqByFlow;
};

void emitFlow(const Args &args, Summary &summary, const std::uint64_t ticket,
              const std::byte *payload, const std::uint32_t payloadSize) {
    ++summary.foundFlow;
    if (payloadSize < kFlowV1Bytes) {
        if (args.jsonl) {
            std::printf("{\"type\":\"FLOW\",\"ticket\":%" PRIu64 ",\"payloadSize\":%" PRIu32
                        ",\"decodeError\":\"shortPayload\"}\n",
                        ticket, payloadSize);
        } else {
            std::printf("FOUND FLOW: ticket=%" PRIu64 " payloadSize=%" PRIu32 " decodeError=shortPayload\n",
                        ticket, payloadSize);
        }
        return;
    }

    const std::uint8_t payloadVersion = static_cast<std::uint8_t>(payload[kFlowV1OffsetPayloadVersion]);
    const std::uint8_t kind = static_cast<std::uint8_t>(payload[kFlowV1OffsetKind]);
    const std::uint8_t ctState = static_cast<std::uint8_t>(payload[kFlowV1OffsetCtState]);
    const std::uint8_t ctDir = static_cast<std::uint8_t>(payload[kFlowV1OffsetCtDir]);
    const std::uint8_t reasonId = static_cast<std::uint8_t>(payload[kFlowV1OffsetReasonId]);
    const std::uint8_t ifaceKindBit = static_cast<std::uint8_t>(payload[kFlowV1OffsetIfaceKindBit]);
    const std::uint8_t flags = static_cast<std::uint8_t>(payload[kFlowV1OffsetFlags]);
    const bool isIpv6 = (flags & kFlowFlagIsIpv6) != 0;
    const bool hasRuleId = (flags & kFlowFlagHasRuleId) != 0;

    const std::uint64_t timestampNs = readU64Le(payload + kFlowV1OffsetTimestampNs);
    const std::uint64_t flowInstanceId = readU64Le(payload + kFlowV1OffsetFlowInstanceId);
    const std::uint64_t recordSeq = readU64Le(payload + kFlowV1OffsetRecordSeq);
    const std::uint32_t uid = readU32Le(payload + kFlowV1OffsetUid);
    const std::uint32_t userId = readU32Le(payload + kFlowV1OffsetUserId);
    const std::uint32_t ifindex = readU32Le(payload + kFlowV1OffsetIfindex);
    const std::uint8_t proto = static_cast<std::uint8_t>(payload[kFlowV1OffsetProto]);
    const std::uint16_t srcPort = readU16Le(payload + kFlowV1OffsetSrcPort);
    const std::uint16_t dstPort = readU16Le(payload + kFlowV1OffsetDstPort);
    const std::uint64_t totalPackets = readU64Le(payload + kFlowV1OffsetTotalPackets);
    const std::uint64_t totalBytes = readU64Le(payload + kFlowV1OffsetTotalBytes);
    const std::uint32_t ruleId = readU32Le(payload + kFlowV1OffsetRuleId);
    const std::string srcAddr = ipString(isIpv6, payload + kFlowV1OffsetSrcAddr);
    const std::string dstAddr = ipString(isIpv6, payload + kFlowV1OffsetDstAddr);

    bool recordSeqGap = false;
    std::uint64_t expectedSeq = 0;
    auto it = summary.lastSeqByFlow.find(flowInstanceId);
    if (it != summary.lastSeqByFlow.end()) {
        expectedSeq = it->second + 1;
        if (recordSeq > expectedSeq) {
            recordSeqGap = true;
            ++summary.recordSeqGaps;
        }
        if (recordSeq >= expectedSeq) {
            it->second = recordSeq;
        }
    } else {
        summary.lastSeqByFlow.emplace(flowInstanceId, recordSeq);
    }

    if (args.jsonl) {
        std::printf("{\"type\":\"FLOW\",\"ticket\":%" PRIu64 ",\"payloadSize\":%" PRIu32
                    ",\"payloadVersion\":%u,\"kind\":\"%s\",\"kindId\":%u"
                    ",\"ctState\":%u,\"ctDir\":%u,\"reasonId\":%u,\"reason\":\"%s\""
                    ",\"ifaceKindBit\":%u,\"flags\":%u,\"isIpv6\":%s,\"timestampNs\":%" PRIu64
                    ",\"flowInstanceId\":%" PRIu64 ",\"recordSeq\":%" PRIu64
                    ",\"recordSeqGap\":%s,\"expectedRecordSeq\":%" PRIu64
                    ",\"uid\":%" PRIu32 ",\"userId\":%" PRIu32 ",\"ifindex\":%" PRIu32
                    ",\"proto\":%u,\"srcPort\":%" PRIu16 ",\"dstPort\":%" PRIu16
                    ",\"srcAddr\":\"%s\",\"dstAddr\":\"%s\",\"totalPackets\":%" PRIu64
                    ",\"totalBytes\":%" PRIu64,
                    ticket, payloadSize, static_cast<unsigned>(payloadVersion), flowKindStr(kind),
                    static_cast<unsigned>(kind), static_cast<unsigned>(ctState),
                    static_cast<unsigned>(ctDir), static_cast<unsigned>(reasonId), reasonStr(reasonId),
                    static_cast<unsigned>(ifaceKindBit), static_cast<unsigned>(flags),
                    isIpv6 ? "true" : "false", timestampNs, flowInstanceId, recordSeq,
                    recordSeqGap ? "true" : "false", expectedSeq, uid, userId, ifindex,
                    static_cast<unsigned>(proto), srcPort, dstPort, srcAddr.c_str(), dstAddr.c_str(),
                    totalPackets, totalBytes);
        if (hasRuleId) {
            std::printf(",\"ruleId\":%" PRIu32, ruleId);
        }
        std::printf("}\n");
    } else {
        std::printf("FOUND FLOW: ticket=%" PRIu64 " payloadSize=%" PRIu32
                    " kind=%s flowInstanceId=%" PRIu64 " recordSeq=%" PRIu64
                    " reason=%s proto=%u isIpv6=%d src=%s:%" PRIu16 " dst=%s:%" PRIu16
                    " totalPackets=%" PRIu64 " totalBytes=%" PRIu64 " recordSeqGap=%d\n",
                    ticket, payloadSize, flowKindStr(kind), flowInstanceId, recordSeq,
                    reasonStr(reasonId), static_cast<unsigned>(proto), isIpv6 ? 1 : 0,
                    srcAddr.c_str(), srcPort, dstAddr.c_str(), dstPort, totalPackets, totalBytes,
                    recordSeqGap ? 1 : 0);
    }
}

void emitDns(const Args &args, Summary &summary, const std::uint64_t ticket,
             const std::byte *payload, const std::uint32_t payloadSize) {
    ++summary.foundDns;
    if (payloadSize < kDnsV1FixedBytes) {
        if (args.jsonl) {
            std::printf("{\"type\":\"DNS_DECISION\",\"ticket\":%" PRIu64 ",\"payloadSize\":%" PRIu32
                        ",\"decodeError\":\"shortPayload\"}\n",
                        ticket, payloadSize);
        } else {
            std::printf("FOUND DNS_DECISION: ticket=%" PRIu64 " payloadSize=%" PRIu32
                        " decodeError=shortPayload\n",
                        ticket, payloadSize);
        }
        return;
    }

    const std::uint8_t payloadVersion = static_cast<std::uint8_t>(payload[kDnsV1OffsetPayloadVersion]);
    const std::uint8_t flags = static_cast<std::uint8_t>(payload[kDnsV1OffsetFlags]);
    const std::uint8_t policySource = static_cast<std::uint8_t>(payload[kDnsV1OffsetPolicySource]);
    const std::uint16_t queryNameLen = readU16Le(payload + kDnsV1OffsetQueryNameLen);
    const std::uint64_t timestampNs = readU64Le(payload + kDnsV1OffsetTimestampNs);
    const std::uint32_t uid = readU32Le(payload + kDnsV1OffsetUid);
    const std::uint32_t userId = readU32Le(payload + kDnsV1OffsetUserId);
    const std::uint32_t ruleId = readU32Le(payload + kDnsV1OffsetRuleId);
    const bool hasRuleId = (flags & kDnsDecisionFlagHasRuleId) != 0;
    const bool truncated = (flags & kDnsDecisionFlagQueryNameTruncated) != 0;
    const bool queryFits =
        static_cast<std::uint32_t>(kDnsV1OffsetQueryName) + static_cast<std::uint32_t>(queryNameLen) <= payloadSize;
    const std::string_view queryName(
        queryFits ? reinterpret_cast<const char *>(payload + kDnsV1OffsetQueryName) : "",
        queryFits ? queryNameLen : 0);
    const std::string escapedQuery = jsonEscape(queryName);

    if (args.jsonl) {
        std::printf("{\"type\":\"DNS_DECISION\",\"ticket\":%" PRIu64 ",\"payloadSize\":%" PRIu32
                    ",\"payloadVersion\":%u,\"flags\":%u,\"policySource\":%u"
                    ",\"policySourceName\":\"%s\",\"timestampNs\":%" PRIu64
                    ",\"uid\":%" PRIu32 ",\"userId\":%" PRIu32
                    ",\"queryName\":\"%s\",\"queryNameLen\":%" PRIu16
                    ",\"queryNameTruncated\":%s",
                    ticket, payloadSize, static_cast<unsigned>(payloadVersion), static_cast<unsigned>(flags),
                    static_cast<unsigned>(policySource), policySourceStr(policySource), timestampNs,
                    uid, userId, escapedQuery.c_str(), queryNameLen, truncated ? "true" : "false");
        if (hasRuleId) {
            std::printf(",\"ruleId\":%" PRIu32, ruleId);
        }
        if (!queryFits) {
            std::printf(",\"decodeError\":\"queryNameOutOfBounds\"");
        }
        std::printf("}\n");
    } else {
        std::printf("FOUND DNS_DECISION: ticket=%" PRIu64 " payloadSize=%" PRIu32
                    " uid=%" PRIu32 " policySource=%s queryName=%s truncated=%d\n",
                    ticket, payloadSize, uid, policySourceStr(policySource), escapedQuery.c_str(),
                    truncated ? 1 : 0);
    }
}

} // namespace

int main(int argc, char **argv) {
    Args args{};
    if (!parseArgs(argc, argv, args)) {
        return 2;
    }

    const int sockFd = connectAbstractUnix(args.socketName);
    if (sockFd < 0) {
        return 77;
    }

    OpenResult open{};
    if (!telemetryOpen(sockFd, args, open)) {
        ::close(sockFd);
        return 77;
    }

    if (args.jsonl) {
        std::printf("{\"type\":\"open\",\"slotBytes\":%" PRIu64 ",\"slotCount\":%" PRIu64
                    ",\"ringDataBytes\":%" PRIu64 ",\"writeTicketSnapshot\":%" PRIu64
                    ",\"fd\":%d}\n",
                    open.slotBytes, open.slotCount, open.ringDataBytes, open.writeTicketSnapshot, open.shmFd);
    } else {
        std::printf("OPEN ok: slotBytes=%" PRIu64 " slotCount=%" PRIu64 " ringDataBytes=%" PRIu64
                    " writeTicketSnapshot=%" PRIu64 " fd=%d\n",
                    open.slotBytes, open.slotCount, open.ringDataBytes, open.writeTicketSnapshot, open.shmFd);
    }

    void *map = ::mmap(nullptr, static_cast<size_t>(open.ringDataBytes), PROT_READ, MAP_SHARED, open.shmFd, 0);
    if (map == MAP_FAILED) {
        std::fprintf(stderr, "mmap failed: %s\n", std::strerror(errno));
        (void)telemetryClose(sockFd);
        ::close(open.shmFd);
        ::close(sockFd);
        return 77;
    }

    const auto *base = static_cast<const std::byte *>(map);

    if (args.initialSleepMs > 0) {
        ::usleep(static_cast<useconds_t>(args.initialSleepMs * 1000));
    }

    const std::uint64_t runMs =
        (args.collectMs > 0) ? static_cast<std::uint64_t>(args.collectMs)
                             : static_cast<std::uint64_t>(args.timeoutSec) * 1000ull;
    const std::uint64_t deadline = nowMs() + runMs;
    Summary summary{};
    summary.expectedTicket = open.writeTicketSnapshot;
    std::unordered_set<std::uint64_t> seenTickets;

    while (nowMs() < deadline) {
        for (std::uint64_t idx = 0; idx < open.slotCount; ++idx) {
            const std::byte *slot = base + static_cast<size_t>(idx * open.slotBytes);
            const auto *statePtr = reinterpret_cast<const std::uint32_t *>(slot + kSlotOffsetState);
            const std::uint32_t rawState = __atomic_load_n(statePtr, __ATOMIC_ACQUIRE);
            const auto state = static_cast<SlotState>(rawState);
            if (state != SlotState::Committed) {
                continue;
            }

            const std::uint16_t recordTypeRaw = readU16Le(slot + kSlotOffsetRecordType);
            const std::uint64_t ticket = readU64Le(slot + kSlotOffsetTicket);
            const std::uint32_t payloadSize = readU32Le(slot + kSlotOffsetPayloadSize);
            if (ticket < open.writeTicketSnapshot) {
                continue; // old record from previous sessions
            }
            if (!seenTickets.insert(ticket).second) {
                continue;
            }
            if (payloadSize > open.slotBytes || payloadSize > (open.slotBytes - kSlotHeaderBytes)) {
                continue;
            }
            if (ticket > summary.expectedTicket) {
                ++summary.transportGaps;
                summary.missedTickets += ticket - summary.expectedTicket;
            }
            if (ticket >= summary.expectedTicket) {
                summary.expectedTicket = ticket + 1;
            }

            const std::byte *payload = slot + kSlotHeaderBytes;

            if (recordTypeRaw == static_cast<std::uint16_t>(RecordType::Flow)) {
                emitFlow(args, summary, ticket, payload, payloadSize);
            } else if (recordTypeRaw == static_cast<std::uint16_t>(RecordType::DnsDecision)) {
                emitDns(args, summary, ticket, payload, payloadSize);
            } else {
                if (args.jsonl) {
                    std::printf("{\"type\":\"UNKNOWN\",\"recordType\":%u,\"ticket\":%" PRIu64
                                ",\"payloadSize\":%" PRIu32 "}\n",
                                static_cast<unsigned>(recordTypeRaw), ticket, payloadSize);
                } else {
                    std::printf("FOUND UNKNOWN: recordType=%u ticket=%" PRIu64 " payloadSize=%" PRIu32 "\n",
                                static_cast<unsigned>(recordTypeRaw), ticket, payloadSize);
                }
            }

            if (args.collectMs == 0 && summary.foundFlow >= args.wantFlow && summary.foundDns >= args.wantDns) {
                (void)telemetryClose(sockFd);
                ::munmap(map, static_cast<size_t>(open.ringDataBytes));
                ::close(open.shmFd);
                ::close(sockFd);
                if (args.jsonl) {
                    std::printf("{\"type\":\"summary\",\"foundFlow\":%d,\"foundDns\":%d"
                                ",\"recordSeqGaps\":%" PRIu64 ",\"transportGaps\":%" PRIu64
                                ",\"missedTickets\":%" PRIu64 "}\n",
                                summary.foundFlow, summary.foundDns, summary.recordSeqGaps,
                                summary.transportGaps, summary.missedTickets);
                } else {
                    std::printf("OK\n");
                }
                return 0;
            }
        }

        ::usleep(static_cast<useconds_t>(args.pollMs * 1000));
    }

    (void)telemetryClose(sockFd);
    ::munmap(map, static_cast<size_t>(open.ringDataBytes));
    ::close(open.shmFd);
    ::close(sockFd);
    if (args.jsonl) {
        std::printf("{\"type\":\"summary\",\"foundFlow\":%d,\"foundDns\":%d"
                    ",\"recordSeqGaps\":%" PRIu64 ",\"transportGaps\":%" PRIu64
                    ",\"missedTickets\":%" PRIu64 "}\n",
                    summary.foundFlow, summary.foundDns, summary.recordSeqGaps, summary.transportGaps,
                    summary.missedTickets);
    } else if (summary.foundFlow >= args.wantFlow && summary.foundDns >= args.wantDns) {
        std::printf("OK\n");
    } else {
        std::printf("TIMEOUT (foundFlow=%d foundDns=%d)\n", summary.foundFlow, summary.foundDns);
    }
    return (summary.foundFlow >= args.wantFlow && summary.foundDns >= args.wantDns) ? 0 : 3;
}
