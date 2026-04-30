/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <IpRulesEngine.hpp>

#include <IpRulesContract.hpp>

#include <android-base/logging.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <climits>
#include <cstring>
#include <limits>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#include <arpa/inet.h>

namespace {

static constexpr std::int32_t kNoPriority = std::numeric_limits<std::int32_t>::min();

static std::atomic<std::uint64_t> g_ipRulesEngineInstanceId{1};

using IpRulesContract::isValidClientRuleId;
using IpRulesContract::maskFromPrefix;
using IpRulesContract::parseDec;

// Decision cache toggle (compile-time).
//
// Default binary MUST NOT incur any per-packet runtime overhead for this toggle.
// Therefore, cache-off is implemented as a separate build variant that sets:
//   -DSUCRE_SNORT_IPRULES_DECISION_CACHE=0
#ifndef SUCRE_SNORT_IPRULES_DECISION_CACHE
#define SUCRE_SNORT_IPRULES_DECISION_CACHE 1
#endif

static inline IpRulesEngine::ApplyResult okResult(const std::optional<IpRulesEngine::RuleId> ruleId = std::nullopt) {
    IpRulesEngine::ApplyResult r{};
    r.ok = true;
    r.ruleId = ruleId;
    return r;
}

static inline IpRulesEngine::ApplyResult nokResult(const std::string &error) {
    IpRulesEngine::ApplyResult r{};
    r.ok = false;
    r.error = error;
    return r;
}

static inline std::string legacyClientRuleId(const uint32_t uid, const IpRulesEngine::RuleId ruleId) {
    return "legacy:" + std::to_string(uid) + ":" + std::to_string(ruleId);
}

static inline size_t mixHash(size_t h, const size_t v) noexcept {
    // 64-bit mix (works fine on 32-bit too).
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

} // namespace

bool IpRulesEngine::PortPredicate::matches(const std::uint16_t port) const {
    switch (kind) {
    case Kind::ANY:
        return true;
    case Kind::EXACT:
        return port == lo;
    case Kind::RANGE:
        return port >= lo && port <= hi;
    }
    return false;
}

std::uint32_t IpRulesEngine::CidrV4::mask() const {
    if (any) {
        return 0u;
    }
    return maskFromPrefix(prefix);
}

bool IpRulesEngine::CidrV4::matches(const std::uint32_t ipHost) const {
    if (any) {
        return true;
    }
    const uint32_t m = mask();
    return (ipHost & m) == (addr & m);
}

bool IpRulesEngine::CidrV6::matches(const std::array<std::uint8_t, 16> &ipNet) const noexcept {
    if (any) {
        return true;
    }
    if (prefix == 0) {
        return true;
    }
    const std::uint8_t fullBytes = static_cast<std::uint8_t>(prefix / 8u);
    const std::uint8_t remBits = static_cast<std::uint8_t>(prefix % 8u);

    for (std::uint8_t i = 0; i < fullBytes; ++i) {
        if (addr[i] != ipNet[i]) {
            return false;
        }
    }
    if (remBits == 0) {
        return true;
    }
    if (fullBytes >= addr.size()) {
        return true;
    }
    const std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8u - remBits));
    return (addr[fullBytes] & mask) == (ipNet[fullBytes] & mask);
}

IpRulesEngine::RuleStatsSnapshot IpRulesEngine::RuleStats::snapshot() const {
    RuleStatsSnapshot s{};
    s.hitPackets = hitPackets.load(std::memory_order_relaxed);
    s.hitBytes = hitBytes.load(std::memory_order_relaxed);
    s.lastHitTsNs = lastHitTsNs.load(std::memory_order_relaxed);
    s.wouldHitPackets = wouldHitPackets.load(std::memory_order_relaxed);
    s.wouldHitBytes = wouldHitBytes.load(std::memory_order_relaxed);
    s.lastWouldHitTsNs = lastWouldHitTsNs.load(std::memory_order_relaxed);
    return s;
}

std::optional<std::pair<std::string_view, std::string_view>>
IpRulesEngine::splitKv(const std::string &token) {
    const auto pos = token.find('=');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= token.size()) {
        return std::nullopt;
    }
    return std::make_pair(std::string_view(token.data(), pos),
                          std::string_view(token.data() + pos + 1, token.size() - pos - 1));
}

bool IpRulesEngine::parseBool01(const std::string_view v, bool &out) {
    if (v == "0") {
        out = false;
        return true;
    }
    if (v == "1") {
        out = true;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseAction(const std::string_view v, Action &out) {
    if (v == "allow") {
        out = Action::ALLOW;
        return true;
    }
    if (v == "block") {
        out = Action::BLOCK;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseDirection(const std::string_view v, Direction &out) {
    if (v == "any") {
        out = Direction::ANY;
        return true;
    }
    if (v == "in") {
        out = Direction::IN;
        return true;
    }
    if (v == "out") {
        out = Direction::OUT;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseIfaceKind(const std::string_view v, IfaceKind &out) {
    if (v == "any") {
        out = IfaceKind::ANY;
        return true;
    }
    if (v == "wifi") {
        out = IfaceKind::WIFI;
        return true;
    }
    if (v == "data") {
        out = IfaceKind::DATA;
        return true;
    }
    if (v == "vpn") {
        out = IfaceKind::VPN;
        return true;
    }
    if (v == "unmanaged") {
        out = IfaceKind::UNMANAGED;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseProto(const std::string_view v, Proto &out) {
    if (v == "any") {
        out = Proto::ANY;
        return true;
    }
    if (v == "tcp") {
        out = Proto::TCP;
        return true;
    }
    if (v == "udp") {
        out = Proto::UDP;
        return true;
    }
    if (v == "icmp") {
        out = Proto::ICMP;
        return true;
    }
    if (v == "other") {
        out = Proto::OTHER;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseCtState(const std::string_view v, CtState &out) {
    if (v == "any") {
        out = CtState::ANY;
        return true;
    }
    if (v == "new") {
        out = CtState::NEW;
        return true;
    }
    if (v == "established") {
        out = CtState::ESTABLISHED;
        return true;
    }
    if (v == "invalid") {
        out = CtState::INVALID;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseCtDirection(const std::string_view v, CtDirection &out) {
    if (v == "any") {
        out = CtDirection::ANY;
        return true;
    }
    if (v == "orig") {
        out = CtDirection::ORIG;
        return true;
    }
    if (v == "reply") {
        out = CtDirection::REPLY;
        return true;
    }
    return false;
}

bool IpRulesEngine::parseIfindex(const std::string_view v, std::uint32_t &outIfindex) {
    if (v == "any") {
        outIfindex = 0;
        return true;
    }
    std::uint32_t tmp = 0;
    if (!parseDec(v, tmp)) {
        return false;
    }
    outIfindex = tmp; // 0 == any is allowed as an input synonym
    return true;
}

bool IpRulesEngine::parsePriority(const std::string_view v, std::int32_t &outPriority) {
    std::int32_t tmp = 0;
    if (!parseDec(v, tmp)) {
        return false;
    }
    outPriority = tmp;
    return true;
}

bool IpRulesEngine::parseCidrV4(const std::string_view v, CidrV4 &out) {
    if (v == "any") {
        out = CidrV4::anyCidr();
        return true;
    }

    const auto slash = v.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= v.size()) {
        return false;
    }
    const std::string ipStr(v.substr(0, slash));
    const std::string_view prefixStr = v.substr(slash + 1);
    std::uint32_t prefix = 0;
    if (!parseDec(prefixStr, prefix) || prefix > 32) {
        return false;
    }

    in_addr a{};
    if (inet_pton(AF_INET, ipStr.c_str(), &a) != 1) {
        return false;
    }

    out.any = false;
    const auto prefixLen = static_cast<std::uint8_t>(prefix);
    out.addr = ntohl(a.s_addr) & maskFromPrefix(prefixLen); // canonical: network-address form
    out.prefix = prefixLen;
    return true;
}

bool IpRulesEngine::parsePortPredicate(const std::string_view v, PortPredicate &out) {
    if (v == "any") {
        out = PortPredicate::any();
        return true;
    }

    const auto dash = v.find('-');
    if (dash != std::string_view::npos) {
        if (dash == 0 || dash + 1 >= v.size()) {
            return false;
        }
        std::uint32_t lo = 0;
        std::uint32_t hi = 0;
        if (!parseDec(v.substr(0, dash), lo) || !parseDec(v.substr(dash + 1), hi)) {
            return false;
        }
        if (lo > 65535u || hi > 65535u || lo > hi) {
            return false;
        }
        out = PortPredicate::range(static_cast<std::uint16_t>(lo), static_cast<std::uint16_t>(hi));
        return true;
    }

    std::uint32_t p = 0;
    if (!parseDec(v, p) || p > 65535u) {
        return false;
    }
    out = PortPredicate::exact(static_cast<std::uint16_t>(p));
    return true;
}

std::string IpRulesEngine::normalizeAction(const Action a) {
    return a == Action::ALLOW ? "allow" : "block";
}

std::string IpRulesEngine::normalizeDirection(const Direction d) {
    switch (d) {
    case Direction::ANY:
        return "any";
    case Direction::IN:
        return "in";
    case Direction::OUT:
        return "out";
    }
    return "any";
}

std::string IpRulesEngine::normalizeIfaceKind(const IfaceKind k) {
    switch (k) {
    case IfaceKind::ANY:
        return "any";
    case IfaceKind::WIFI:
        return "wifi";
    case IfaceKind::DATA:
        return "data";
    case IfaceKind::VPN:
        return "vpn";
    case IfaceKind::UNMANAGED:
        return "unmanaged";
    }
    return "any";
}

std::string IpRulesEngine::normalizeProto(const Proto p) {
    switch (p) {
    case Proto::ANY:
        return "any";
    case Proto::TCP:
        return "tcp";
    case Proto::UDP:
        return "udp";
    case Proto::ICMP:
        return "icmp";
    case Proto::OTHER:
        return "other";
    case Proto::UNKNOWN:
        break;
    }
    return "any";
}

std::string IpRulesEngine::normalizeCtState(const CtState s) {
    switch (s) {
    case CtState::ANY:
        return "any";
    case CtState::NEW:
        return "new";
    case CtState::ESTABLISHED:
        return "established";
    case CtState::INVALID:
        return "invalid";
    }
    return "any";
}

std::string IpRulesEngine::normalizeCtDirection(const CtDirection d) {
    switch (d) {
    case CtDirection::ANY:
        return "any";
    case CtDirection::ORIG:
        return "orig";
    case CtDirection::REPLY:
        return "reply";
    }
    return "any";
}

std::string IpRulesEngine::normalizeCidrV4(const CidrV4 &c) {
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

std::string IpRulesEngine::normalizeCidrV6(const CidrV6 &c) {
    if (c.any) {
        return "any";
    }
    in6_addr a{};
    std::memcpy(&a, c.addr.data(), c.addr.size());
    char buf[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET6, &a, buf, sizeof(buf)) == nullptr) {
        return "any";
    }
    return std::string(buf) + "/" + std::to_string(static_cast<uint32_t>(c.prefix));
}

std::string IpRulesEngine::normalizePortPredicate(const PortPredicate &p) {
    switch (p.kind) {
    case PortPredicate::Kind::ANY:
        return "any";
    case PortPredicate::Kind::EXACT:
        return std::to_string(static_cast<uint32_t>(p.lo));
    case PortPredicate::Kind::RANGE:
        return std::to_string(static_cast<uint32_t>(p.lo)) + "-" +
               std::to_string(static_cast<uint32_t>(p.hi));
    }
    return "any";
}

bool IpRulesEngine::validateRuleDef(const RuleDef &def, std::string &error) {
    if (def.family != Family::IPV4 && def.family != Family::IPV6) {
        error = "invalid family";
        return false;
    }
    if (static_cast<std::uint8_t>(def.ctState) > static_cast<std::uint8_t>(CtState::INVALID)) {
        error = "invalid ct.state";
        return false;
    }
    if (static_cast<std::uint8_t>(def.ctDir) > static_cast<std::uint8_t>(CtDirection::REPLY)) {
        error = "invalid ct.direction";
        return false;
    }
    if (def.ctState == CtState::INVALID && def.ctDir != CtDirection::ANY) {
        error = "ct.state=invalid requires ct.direction=any";
        return false;
    }
    if (def.proto == Proto::UNKNOWN) {
        error = "invalid proto";
        return false;
    }
    if (!def.enforce) {
        if (!(def.action == Action::BLOCK && def.log)) {
            error = "enforce=0 is only supported for action=block,log=1";
            return false;
        }
    }
    if (def.proto == Proto::ICMP || def.proto == Proto::OTHER) {
        if (!def.sport.isAny() || !def.dport.isAny()) {
            error = (def.proto == Proto::ICMP) ? "proto=icmp requires sport=any and dport=any"
                                               : "proto=other requires sport=any and dport=any";
            return false;
        }
    }
    if (def.family == Family::IPV4) {
        if (!def.src6.any || !def.dst6.any) {
            error = "family=ipv4 requires IPv6 CIDR fields to be any";
            return false;
        }
    } else {
        if (!def.src.any || !def.dst.any) {
            error = "family=ipv6 requires IPv4 CIDR fields to be any";
            return false;
        }
        if (!def.src6.any && def.src6.prefix > 128) {
            error = "invalid ipv6 src prefix";
            return false;
        }
        if (!def.dst6.any && def.dst6.prefix > 128) {
            error = "invalid ipv6 dst prefix";
            return false;
        }
    }
    return true;
}

struct IpRulesEngine::Snapshot {
    struct MaskSig {
        bool dir = false;
        bool iface = false;
        bool ifindex = false;
        bool proto = false;
        bool ctState = false;
        bool ctDir = false;
        uint8_t srcPrefix = 255; // 255 == any, otherwise 0..32
        uint8_t dstPrefix = 255;
        bool sportExact = false;
        bool dportExact = false;

        bool operator==(const MaskSig &) const = default;
    };

    struct MaskSigLess {
        bool operator()(const MaskSig &a, const MaskSig &b) const {
            if (a.dir != b.dir) return a.dir < b.dir;
            if (a.iface != b.iface) return a.iface < b.iface;
            if (a.ifindex != b.ifindex) return a.ifindex < b.ifindex;
            if (a.proto != b.proto) return a.proto < b.proto;
            if (a.ctState != b.ctState) return a.ctState < b.ctState;
            if (a.ctDir != b.ctDir) return a.ctDir < b.ctDir;
            if (a.srcPrefix != b.srcPrefix) return a.srcPrefix < b.srcPrefix;
            if (a.dstPrefix != b.dstPrefix) return a.dstPrefix < b.dstPrefix;
            if (a.sportExact != b.sportExact) return a.sportExact < b.sportExact;
            if (a.dportExact != b.dportExact) return a.dportExact < b.dportExact;
            return false;
        }
    };

    struct MaskedKey {
        uint8_t dir = 0;
        uint8_t ifaceKind = 0;
        uint8_t proto = 0;
        uint8_t ctState = 0;
        uint8_t ctDir = 0;
        uint32_t ifindex = 0;
        uint32_t srcIpMasked = 0;
        uint32_t dstIpMasked = 0;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;

        bool operator==(const MaskedKey &o) const = default;
    };

    struct MaskedKeyHash {
        size_t operator()(const MaskedKey &k) const noexcept {
            size_t h = 0;
            h = mixHash(h, k.dir);
            h = mixHash(h, k.ifaceKind);
            h = mixHash(h, k.proto);
            h = mixHash(h, k.ctState);
            h = mixHash(h, k.ctDir);
            h = mixHash(h, k.ifindex);
            h = mixHash(h, k.srcIpMasked);
            h = mixHash(h, k.dstIpMasked);
            h = mixHash(h, k.srcPort);
            h = mixHash(h, k.dstPort);
            return h;
        }
    };

    struct RuleRef {
        RuleId ruleId = 0;
        uint32_t uid = 0;
        std::string clientRuleId;
        Action action = Action::ALLOW;
        std::int32_t priority = 0;
        bool enforce = true;
        bool log = false;

        Direction dir = Direction::ANY;
        IfaceKind iface = IfaceKind::ANY;
        std::uint32_t ifindex = 0;
        Proto proto = Proto::ANY;
        CtState ctState = CtState::ANY;
        CtDirection ctDir = CtDirection::ANY;

        CidrV4 src = CidrV4::anyCidr();
        CidrV4 dst = CidrV4::anyCidr();
        PortPredicate sport = PortPredicate::any();
        PortPredicate dport = PortPredicate::any();

        RuleStats *stats = nullptr;
        std::shared_ptr<RuleStats> statsStrong;

        bool matches(const PacketKeyV4 &k) const {
            if (uid != k.uid) return false;
            if (k.portsAvailable == 0) {
                // Port predicates only apply when ports are safely available (known-l4 TCP/UDP).
                // When ports are unavailable, any non-any predicate MUST NOT match.
                if (!sport.isAny() || !dport.isAny()) return false;
            }
            if (dir == Direction::IN && k.dir != 0) return false;
            if (dir == Direction::OUT && k.dir != 1) return false;
            if (iface != IfaceKind::ANY && k.ifaceKind != static_cast<uint8_t>(iface)) return false;
            if (ifindex != 0 && k.ifindex != ifindex) return false;
            if (proto != Proto::ANY && k.proto != static_cast<uint8_t>(proto)) return false;
            if (ctState != CtState::ANY && k.ctState != static_cast<uint8_t>(ctState)) return false;
            if (ctDir != CtDirection::ANY && k.ctDir != static_cast<uint8_t>(ctDir)) return false;
            if (!src.matches(k.srcIp)) return false;
            if (!dst.matches(k.dstIp)) return false;
            if (!sport.matches(k.srcPort)) return false;
            if (!dport.matches(k.dstPort)) return false;
            return true;
        }
    };

    struct Bucket {
        std::vector<RuleRef> exactEnforce;
        std::vector<RuleRef> rangeEnforce;
        std::vector<RuleRef> exactWould;
        std::vector<RuleRef> rangeWould;

        static bool ruleLess(const RuleRef &a, const RuleRef &b) {
            if (a.priority != b.priority) return a.priority > b.priority;
            return a.ruleId < b.ruleId;
        }

        void sortAll() {
            std::sort(exactEnforce.begin(), exactEnforce.end(), ruleLess);
            std::sort(rangeEnforce.begin(), rangeEnforce.end(), ruleLess);
            std::sort(exactWould.begin(), exactWould.end(), ruleLess);
            std::sort(rangeWould.begin(), rangeWould.end(), ruleLess);
        }

        const RuleRef *bestEnforce(const PacketKeyV4 &k) const {
            const RuleRef *exact = exactEnforce.empty() ? nullptr : &exactEnforce[0];
            if (exact && !exact->matches(k)) {
                exact = nullptr;
            }

            if (exact) {
                const std::int32_t pExact = exact->priority;
                for (const auto &cand : rangeEnforce) {
                    if (cand.priority <= pExact) {
                        break;
                    }
                    if (cand.matches(k)) {
                        return &cand;
                    }
                }
                return exact;
            }

            for (const auto &cand : rangeEnforce) {
                if (cand.matches(k)) {
                    return &cand;
                }
            }
            return nullptr;
        }

        const RuleRef *bestWould(const PacketKeyV4 &k) const {
            const RuleRef *exact = exactWould.empty() ? nullptr : &exactWould[0];
            if (exact && !exact->matches(k)) {
                exact = nullptr;
            }

            if (exact) {
                const std::int32_t pExact = exact->priority;
                for (const auto &cand : rangeWould) {
                    if (cand.priority <= pExact) {
                        break;
                    }
                    if (cand.matches(k)) {
                        return &cand;
                    }
                }
                return exact;
            }

            for (const auto &cand : rangeWould) {
                if (cand.matches(k)) {
                    return &cand;
                }
            }
            return nullptr;
        }
    };

    struct Subtable {
        MaskSig sig;
        std::int32_t maxEnforcePriority = kNoPriority;
        std::int32_t maxWouldPriority = kNoPriority;
        std::unordered_map<MaskedKey, Bucket, MaskedKeyHash> buckets;
    };

    struct UidView {
        std::vector<Subtable> subtables;
        std::vector<size_t> enforceOrder;
        std::vector<size_t> wouldOrder;
        bool usesCt = false;
    };

    std::uint64_t rulesEpoch = 0;
    std::unordered_map<std::uint32_t, UidView> byUid;
    // IPv6 compiled views (separate layout to preserve IPv4 hot path).
    struct MaskSigV6 {
        bool dir = false;
        bool iface = false;
        bool ifindex = false;
        bool proto = false;
        bool ctState = false;
        bool ctDir = false;
        uint8_t srcPrefix = 255; // 255 == any, otherwise 0..128
        uint8_t dstPrefix = 255;
        bool sportExact = false;
        bool dportExact = false;

        bool operator==(const MaskSigV6 &) const = default;
    };

    struct MaskSigV6Less {
        bool operator()(const MaskSigV6 &a, const MaskSigV6 &b) const {
            if (a.dir != b.dir) return a.dir < b.dir;
            if (a.iface != b.iface) return a.iface < b.iface;
            if (a.ifindex != b.ifindex) return a.ifindex < b.ifindex;
            if (a.proto != b.proto) return a.proto < b.proto;
            if (a.ctState != b.ctState) return a.ctState < b.ctState;
            if (a.ctDir != b.ctDir) return a.ctDir < b.ctDir;
            if (a.srcPrefix != b.srcPrefix) return a.srcPrefix < b.srcPrefix;
            if (a.dstPrefix != b.dstPrefix) return a.dstPrefix < b.dstPrefix;
            if (a.sportExact != b.sportExact) return a.sportExact < b.sportExact;
            if (a.dportExact != b.dportExact) return a.dportExact < b.dportExact;
            return false;
        }
    };

    struct MaskedKeyV6 {
        uint8_t dir = 0;
        uint8_t ifaceKind = 0;
        uint8_t proto = 0;
        uint8_t ctState = 0;
        uint8_t ctDir = 0;
        uint32_t ifindex = 0;
        std::array<std::uint8_t, 16> srcIpMasked{};
        std::array<std::uint8_t, 16> dstIpMasked{};
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;

        bool operator==(const MaskedKeyV6 &o) const = default;
    };

    struct MaskedKeyV6Hash {
        size_t operator()(const MaskedKeyV6 &k) const noexcept {
            size_t h = 0;
            h = mixHash(h, k.dir);
            h = mixHash(h, k.ifaceKind);
            h = mixHash(h, k.proto);
            h = mixHash(h, k.ctState);
            h = mixHash(h, k.ctDir);
            h = mixHash(h, k.ifindex);

            std::uint64_t a0 = 0, a1 = 0, b0 = 0, b1 = 0;
            std::memcpy(&a0, k.srcIpMasked.data(), 8);
            std::memcpy(&a1, k.srcIpMasked.data() + 8, 8);
            std::memcpy(&b0, k.dstIpMasked.data(), 8);
            std::memcpy(&b1, k.dstIpMasked.data() + 8, 8);
            h = mixHash(h, static_cast<size_t>(a0));
            h = mixHash(h, static_cast<size_t>(a1));
            h = mixHash(h, static_cast<size_t>(b0));
            h = mixHash(h, static_cast<size_t>(b1));
            h = mixHash(h, k.srcPort);
            h = mixHash(h, k.dstPort);
            return h;
        }
    };

    struct RuleRefV6 {
        RuleId ruleId = 0;
        uint32_t uid = 0;
        std::string clientRuleId;
        Action action = Action::ALLOW;
        std::int32_t priority = 0;
        bool enforce = true;
        bool log = false;

        Direction dir = Direction::ANY;
        IfaceKind iface = IfaceKind::ANY;
        std::uint32_t ifindex = 0;
        Proto proto = Proto::ANY;
        CtState ctState = CtState::ANY;
        CtDirection ctDir = CtDirection::ANY;

        CidrV6 src = CidrV6::anyCidr();
        CidrV6 dst = CidrV6::anyCidr();
        PortPredicate sport = PortPredicate::any();
        PortPredicate dport = PortPredicate::any();

        RuleStats *stats = nullptr;
        std::shared_ptr<RuleStats> statsStrong;

        bool matches(const PacketKeyV6 &k) const {
            if (uid != k.uid) return false;
            if (k.portsAvailable == 0) {
                if (!sport.isAny() || !dport.isAny()) return false;
            }
            if (dir == Direction::IN && k.dir != 0) return false;
            if (dir == Direction::OUT && k.dir != 1) return false;
            if (iface != IfaceKind::ANY && k.ifaceKind != static_cast<uint8_t>(iface)) return false;
            if (ifindex != 0 && k.ifindex != ifindex) return false;
            if (proto != Proto::ANY && k.proto != static_cast<uint8_t>(proto)) return false;
            if (ctState != CtState::ANY && k.ctState != static_cast<uint8_t>(ctState)) return false;
            if (ctDir != CtDirection::ANY && k.ctDir != static_cast<uint8_t>(ctDir)) return false;
            if (!src.matches(k.srcIp)) return false;
            if (!dst.matches(k.dstIp)) return false;
            if (!sport.matches(k.srcPort)) return false;
            if (!dport.matches(k.dstPort)) return false;
            return true;
        }
    };

    struct BucketV6 {
        std::vector<RuleRefV6> exactEnforce;
        std::vector<RuleRefV6> rangeEnforce;
        std::vector<RuleRefV6> exactWould;
        std::vector<RuleRefV6> rangeWould;

        static bool ruleLess(const RuleRefV6 &a, const RuleRefV6 &b) {
            if (a.priority != b.priority) return a.priority > b.priority;
            return a.ruleId < b.ruleId;
        }

        void sortAll() {
            std::sort(exactEnforce.begin(), exactEnforce.end(), ruleLess);
            std::sort(rangeEnforce.begin(), rangeEnforce.end(), ruleLess);
            std::sort(exactWould.begin(), exactWould.end(), ruleLess);
            std::sort(rangeWould.begin(), rangeWould.end(), ruleLess);
        }

        const RuleRefV6 *bestEnforce(const PacketKeyV6 &k) const {
            const RuleRefV6 *exact = exactEnforce.empty() ? nullptr : &exactEnforce[0];
            if (exact && !exact->matches(k)) {
                exact = nullptr;
            }

            if (exact) {
                const std::int32_t pExact = exact->priority;
                for (const auto &cand : rangeEnforce) {
                    if (cand.priority <= pExact) {
                        break;
                    }
                    if (cand.matches(k)) {
                        return &cand;
                    }
                }
                return exact;
            }

            for (const auto &cand : rangeEnforce) {
                if (cand.matches(k)) {
                    return &cand;
                }
            }
            return nullptr;
        }

        const RuleRefV6 *bestWould(const PacketKeyV6 &k) const {
            const RuleRefV6 *exact = exactWould.empty() ? nullptr : &exactWould[0];
            if (exact && !exact->matches(k)) {
                exact = nullptr;
            }

            if (exact) {
                const std::int32_t pExact = exact->priority;
                for (const auto &cand : rangeWould) {
                    if (cand.priority <= pExact) {
                        break;
                    }
                    if (cand.matches(k)) {
                        return &cand;
                    }
                }
                return exact;
            }

            for (const auto &cand : rangeWould) {
                if (cand.matches(k)) {
                    return &cand;
                }
            }
            return nullptr;
        }
    };

    struct SubtableV6 {
        MaskSigV6 sig;
        std::int32_t maxEnforcePriority = kNoPriority;
        std::int32_t maxWouldPriority = kNoPriority;
        std::unordered_map<MaskedKeyV6, BucketV6, MaskedKeyV6Hash> buckets;
    };

    struct UidViewV6 {
        std::vector<SubtableV6> subtables;
        std::vector<size_t> enforceOrder;
        std::vector<size_t> wouldOrder;
        bool usesCt = false;
    };

    std::unordered_map<std::uint32_t, UidViewV6> byUid6;

    static MaskSig maskSigForRule(const RuleDef &r) {
        MaskSig s{};
        s.dir = (r.dir != Direction::ANY);
        s.iface = (r.iface != IfaceKind::ANY);
        s.ifindex = (r.ifindex != 0);
        s.proto = (r.proto != Proto::ANY);
        s.ctState = (r.ctState != CtState::ANY);
        s.ctDir = (r.ctDir != CtDirection::ANY);
        s.srcPrefix = r.src.any ? 255 : r.src.prefix;
        s.dstPrefix = r.dst.any ? 255 : r.dst.prefix;
        s.sportExact = (r.sport.kind == PortPredicate::Kind::EXACT);
        s.dportExact = (r.dport.kind == PortPredicate::Kind::EXACT);
        return s;
    }

    static inline uint8_t dirValue(const Direction d) {
        return d == Direction::OUT ? 1 : 0; // IN=0, OUT=1
    }

    static MaskedKey maskedKeyFromPacket(const MaskSig &sig, const PacketKeyV4 &k) {
        MaskedKey mk{};
        mk.dir = sig.dir ? k.dir : 0;
        mk.ifaceKind = sig.iface ? k.ifaceKind : 0;
        mk.proto = sig.proto ? k.proto : 0;
        mk.ctState = sig.ctState ? k.ctState : 0;
        mk.ctDir = sig.ctDir ? k.ctDir : 0;
        mk.ifindex = sig.ifindex ? k.ifindex : 0;
        mk.srcIpMasked = (sig.srcPrefix == 255) ? 0 : (k.srcIp & maskFromPrefix(sig.srcPrefix));
        mk.dstIpMasked = (sig.dstPrefix == 255) ? 0 : (k.dstIp & maskFromPrefix(sig.dstPrefix));
        mk.srcPort = sig.sportExact ? k.srcPort : 0;
        mk.dstPort = sig.dportExact ? k.dstPort : 0;
        return mk;
    }

    static MaskedKey maskedKeyFromRule(const MaskSig &sig, const RuleDef &r) {
        MaskedKey mk{};
        mk.dir = sig.dir ? dirValue(r.dir) : 0;
        mk.ifaceKind = sig.iface ? static_cast<uint8_t>(r.iface) : 0;
        mk.proto = sig.proto ? static_cast<uint8_t>(r.proto) : 0;
        mk.ctState = sig.ctState ? static_cast<uint8_t>(r.ctState) : 0;
        mk.ctDir = sig.ctDir ? static_cast<uint8_t>(r.ctDir) : 0;
        mk.ifindex = sig.ifindex ? r.ifindex : 0;
        mk.srcIpMasked = (sig.srcPrefix == 255) ? 0 : (r.src.addr & maskFromPrefix(sig.srcPrefix));
        mk.dstIpMasked = (sig.dstPrefix == 255) ? 0 : (r.dst.addr & maskFromPrefix(sig.dstPrefix));
        mk.srcPort = sig.sportExact ? r.sport.lo : 0;
        mk.dstPort = sig.dportExact ? r.dport.lo : 0;
        return mk;
    }

    static MaskSigV6 maskSigForRuleV6(const RuleDef &r) {
        MaskSigV6 s{};
        s.dir = (r.dir != Direction::ANY);
        s.iface = (r.iface != IfaceKind::ANY);
        s.ifindex = (r.ifindex != 0);
        s.proto = (r.proto != Proto::ANY);
        s.ctState = (r.ctState != CtState::ANY);
        s.ctDir = (r.ctDir != CtDirection::ANY);
        s.srcPrefix = r.src6.any ? 255 : r.src6.prefix;
        s.dstPrefix = r.dst6.any ? 255 : r.dst6.prefix;
        s.sportExact = (r.sport.kind == PortPredicate::Kind::EXACT);
        s.dportExact = (r.dport.kind == PortPredicate::Kind::EXACT);
        return s;
    }

    static inline void maskIpV6(std::array<std::uint8_t, 16> &out,
                                const std::array<std::uint8_t, 16> &in,
                                const std::uint8_t prefix) {
        out = in;
        if (prefix == 0) {
            out.fill(0);
            return;
        }
        if (prefix >= 128) {
            return;
        }
        const std::uint8_t fullBytes = static_cast<std::uint8_t>(prefix / 8u);
        const std::uint8_t remBits = static_cast<std::uint8_t>(prefix % 8u);
        for (std::uint8_t i = fullBytes + (remBits ? 1u : 0u); i < out.size(); ++i) {
            out[i] = 0;
        }
        if (remBits != 0 && fullBytes < out.size()) {
            const std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8u - remBits));
            out[fullBytes] &= mask;
        }
    }

    static MaskedKeyV6 maskedKeyFromPacketV6(const MaskSigV6 &sig, const PacketKeyV6 &k) {
        MaskedKeyV6 mk{};
        mk.dir = sig.dir ? k.dir : 0;
        mk.ifaceKind = sig.iface ? k.ifaceKind : 0;
        mk.proto = sig.proto ? k.proto : 0;
        mk.ctState = sig.ctState ? k.ctState : 0;
        mk.ctDir = sig.ctDir ? k.ctDir : 0;
        mk.ifindex = sig.ifindex ? k.ifindex : 0;
        if (sig.srcPrefix == 255) {
            mk.srcIpMasked.fill(0);
        } else {
            maskIpV6(mk.srcIpMasked, k.srcIp, sig.srcPrefix);
        }
        if (sig.dstPrefix == 255) {
            mk.dstIpMasked.fill(0);
        } else {
            maskIpV6(mk.dstIpMasked, k.dstIp, sig.dstPrefix);
        }
        mk.srcPort = sig.sportExact ? k.srcPort : 0;
        mk.dstPort = sig.dportExact ? k.dstPort : 0;
        return mk;
    }

    static MaskedKeyV6 maskedKeyFromRuleV6(const MaskSigV6 &sig, const RuleDef &r) {
        MaskedKeyV6 mk{};
        mk.dir = sig.dir ? dirValue(r.dir) : 0;
        mk.ifaceKind = sig.iface ? static_cast<uint8_t>(r.iface) : 0;
        mk.proto = sig.proto ? static_cast<uint8_t>(r.proto) : 0;
        mk.ctState = sig.ctState ? static_cast<uint8_t>(r.ctState) : 0;
        mk.ctDir = sig.ctDir ? static_cast<uint8_t>(r.ctDir) : 0;
        mk.ifindex = sig.ifindex ? r.ifindex : 0;
        if (sig.srcPrefix == 255) {
            mk.srcIpMasked.fill(0);
        } else {
            maskIpV6(mk.srcIpMasked, r.src6.addr, sig.srcPrefix);
        }
        if (sig.dstPrefix == 255) {
            mk.dstIpMasked.fill(0);
        } else {
            maskIpV6(mk.dstIpMasked, r.dst6.addr, sig.dstPrefix);
        }
        mk.srcPort = sig.sportExact ? r.sport.lo : 0;
        mk.dstPort = sig.dportExact ? r.dport.lo : 0;
        return mk;
    }

    struct DecisionData {
        DecisionKind kind = DecisionKind::NOMATCH;
        RuleId ruleId = 0;
        RuleStats *stats = nullptr;
    };

    const RuleRef *lookupBestEnforce(const PacketKeyV4 &k) const {
        const auto it = byUid.find(k.uid);
        if (it == byUid.end()) return nullptr;
        const UidView &view = it->second;

        const RuleRef *best = nullptr;
        std::int32_t bestPriority = kNoPriority;

        for (const size_t idx : view.enforceOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxEnforcePriority == kNoPriority) {
                break;
            }
            if (best && st.maxEnforcePriority < bestPriority) {
                break;
            }

            const MaskedKey mk = maskedKeyFromPacket(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            const Bucket &bucket = bit->second;
            const RuleRef *cand = bucket.bestEnforce(k);
            if (cand && (!best || cand->priority > bestPriority)) {
                best = cand;
                bestPriority = cand->priority;
            }
        }
        return best;
    }

    const RuleRef *lookupBestWould(const PacketKeyV4 &k) const {
        const auto it = byUid.find(k.uid);
        if (it == byUid.end()) return nullptr;
        const UidView &view = it->second;

        const RuleRef *best = nullptr;
        std::int32_t bestPriority = kNoPriority;

        for (const size_t idx : view.wouldOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxWouldPriority == kNoPriority) {
                break;
            }
            if (best && st.maxWouldPriority < bestPriority) {
                break;
            }

            const MaskedKey mk = maskedKeyFromPacket(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            const Bucket &bucket = bit->second;
            const RuleRef *cand = bucket.bestWould(k);
            if (cand && (!best || cand->priority > bestPriority)) {
                best = cand;
                bestPriority = cand->priority;
            }
        }
        return best;
    }

    DecisionData evaluate(const PacketKeyV4 &k) const {
        if (const RuleRef *enforce = lookupBestEnforce(k)) {
            DecisionData d{};
            d.kind = (enforce->action == Action::ALLOW) ? DecisionKind::ALLOW : DecisionKind::BLOCK;
            d.ruleId = enforce->ruleId;
            d.stats = enforce->stats;
            return d;
        }

        if (const RuleRef *would = lookupBestWould(k)) {
            DecisionData d{};
            d.kind = DecisionKind::WOULD_BLOCK;
            d.ruleId = would->ruleId;
            d.stats = would->stats;
            return d;
        }

        return {};
    }

    const RuleRefV6 *lookupBestEnforce(const PacketKeyV6 &k) const {
        const auto it = byUid6.find(k.uid);
        if (it == byUid6.end()) return nullptr;
        const UidViewV6 &view = it->second;

        const RuleRefV6 *best = nullptr;
        std::int32_t bestPriority = kNoPriority;

        for (const size_t idx : view.enforceOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxEnforcePriority == kNoPriority) {
                break;
            }
            if (best && st.maxEnforcePriority < bestPriority) {
                break;
            }

            const MaskedKeyV6 mk = maskedKeyFromPacketV6(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            const BucketV6 &bucket = bit->second;
            const RuleRefV6 *cand = bucket.bestEnforce(k);
            if (cand && (!best || cand->priority > bestPriority)) {
                best = cand;
                bestPriority = cand->priority;
            }
        }
        return best;
    }

    const RuleRefV6 *lookupBestWould(const PacketKeyV6 &k) const {
        const auto it = byUid6.find(k.uid);
        if (it == byUid6.end()) return nullptr;
        const UidViewV6 &view = it->second;

        const RuleRefV6 *best = nullptr;
        std::int32_t bestPriority = kNoPriority;

        for (const size_t idx : view.wouldOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxWouldPriority == kNoPriority) {
                break;
            }
            if (best && st.maxWouldPriority < bestPriority) {
                break;
            }

            const MaskedKeyV6 mk = maskedKeyFromPacketV6(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            const BucketV6 &bucket = bit->second;
            const RuleRefV6 *cand = bucket.bestWould(k);
            if (cand && (!best || cand->priority > bestPriority)) {
                best = cand;
                bestPriority = cand->priority;
            }
        }
        return best;
    }

    DecisionData evaluate(const PacketKeyV6 &k) const {
        if (const RuleRefV6 *enforce = lookupBestEnforce(k)) {
            DecisionData d{};
            d.kind = (enforce->action == Action::ALLOW) ? DecisionKind::ALLOW : DecisionKind::BLOCK;
            d.ruleId = enforce->ruleId;
            d.stats = enforce->stats;
            return d;
        }

        if (const RuleRefV6 *would = lookupBestWould(k)) {
            DecisionData d{};
            d.kind = DecisionKind::WOULD_BLOCK;
            d.ruleId = would->ruleId;
            d.stats = would->stats;
            return d;
        }

        return {};
    }

    static std::string matchKeyMk2(const RuleRef &r) {
        std::string out = "mk2";
        out.append("|family=ipv4");
        out.append("|dir=").append(normalizeDirection(r.dir));
        out.append("|iface=").append(normalizeIfaceKind(r.iface));
        out.append("|ifindex=").append(std::to_string(r.ifindex));
        out.append("|proto=").append(normalizeProto(r.proto));
        out.append("|ctstate=").append(normalizeCtState(r.ctState));
        out.append("|ctdir=").append(normalizeCtDirection(r.ctDir));
        out.append("|src=").append(normalizeCidrV4(r.src));
        out.append("|dst=").append(normalizeCidrV4(r.dst));
        out.append("|sport=").append(normalizePortPredicate(r.sport));
        out.append("|dport=").append(normalizePortPredicate(r.dport));
        return out;
    }

    static std::string matchKeyMk2(const RuleRefV6 &r) {
        std::string out = "mk2";
        out.append("|family=ipv6");
        out.append("|dir=").append(normalizeDirection(r.dir));
        out.append("|iface=").append(normalizeIfaceKind(r.iface));
        out.append("|ifindex=").append(std::to_string(r.ifindex));
        out.append("|proto=").append(normalizeProto(r.proto));
        out.append("|ctstate=").append(normalizeCtState(r.ctState));
        out.append("|ctdir=").append(normalizeCtDirection(r.ctDir));
        out.append("|src=").append(normalizeCidrV6(r.src));
        out.append("|dst=").append(normalizeCidrV6(r.dst));
        out.append("|sport=").append(normalizePortPredicate(r.sport));
        out.append("|dport=").append(normalizePortPredicate(r.dport));
        return out;
    }

    static ControlVNextStreamExplain::IpRulesRuleSnapshot ruleSnapshot(const RuleRef &r) {
        return ControlVNextStreamExplain::IpRulesRuleSnapshot{
            .ruleId = r.ruleId,
            .clientRuleId = r.clientRuleId,
            .matchKey = matchKeyMk2(r),
            .action = normalizeAction(r.action),
            .enforce = r.enforce,
            .log = r.log,
            .family = "ipv4",
            .dir = normalizeDirection(r.dir),
            .iface = normalizeIfaceKind(r.iface),
            .ifindex = r.ifindex,
            .proto = normalizeProto(r.proto),
            .ctState = normalizeCtState(r.ctState),
            .ctDirection = normalizeCtDirection(r.ctDir),
            .src = normalizeCidrV4(r.src),
            .dst = normalizeCidrV4(r.dst),
            .sport = normalizePortPredicate(r.sport),
            .dport = normalizePortPredicate(r.dport),
            .priority = r.priority,
        };
    }

    static ControlVNextStreamExplain::IpRulesRuleSnapshot ruleSnapshot(const RuleRefV6 &r) {
        return ControlVNextStreamExplain::IpRulesRuleSnapshot{
            .ruleId = r.ruleId,
            .clientRuleId = r.clientRuleId,
            .matchKey = matchKeyMk2(r),
            .action = normalizeAction(r.action),
            .enforce = r.enforce,
            .log = r.log,
            .family = "ipv6",
            .dir = normalizeDirection(r.dir),
            .iface = normalizeIfaceKind(r.iface),
            .ifindex = r.ifindex,
            .proto = normalizeProto(r.proto),
            .ctState = normalizeCtState(r.ctState),
            .ctDirection = normalizeCtDirection(r.ctDir),
            .src = normalizeCidrV6(r.src),
            .dst = normalizeCidrV6(r.dst),
            .sport = normalizePortPredicate(r.sport),
            .dport = normalizePortPredicate(r.dport),
            .priority = r.priority,
        };
    }

    static bool explainLess(const ControlVNextStreamExplain::IpRulesRuleSnapshot &a,
                            const ControlVNextStreamExplain::IpRulesRuleSnapshot &b) {
        if (a.priority != b.priority) {
            return a.priority > b.priority;
        }
        return a.ruleId < b.ruleId;
    }

    static void appendMatching(const std::vector<RuleRef> &rules, const PacketKeyV4 &k,
                               std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot> &out) {
        for (const auto &rule : rules) {
            if (rule.matches(k)) {
                out.push_back(ruleSnapshot(rule));
            }
        }
    }

    static void appendMatching(const std::vector<RuleRefV6> &rules, const PacketKeyV6 &k,
                               std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot> &out) {
        for (const auto &rule : rules) {
            if (rule.matches(k)) {
                out.push_back(ruleSnapshot(rule));
            }
        }
    }

    std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
    explainEnforce(const PacketKeyV4 &k) const {
        std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot> out;
        const auto it = byUid.find(k.uid);
        if (it == byUid.end()) return out;
        const UidView &view = it->second;
        for (const size_t idx : view.enforceOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxEnforcePriority == kNoPriority) break;
            const MaskedKey mk = maskedKeyFromPacket(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            appendMatching(bit->second.exactEnforce, k, out);
            appendMatching(bit->second.rangeEnforce, k, out);
        }
        std::sort(out.begin(), out.end(), explainLess);
        return out;
    }

    std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
    explainWould(const PacketKeyV4 &k) const {
        std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot> out;
        const auto it = byUid.find(k.uid);
        if (it == byUid.end()) return out;
        const UidView &view = it->second;
        for (const size_t idx : view.wouldOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxWouldPriority == kNoPriority) break;
            const MaskedKey mk = maskedKeyFromPacket(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            appendMatching(bit->second.exactWould, k, out);
            appendMatching(bit->second.rangeWould, k, out);
        }
        std::sort(out.begin(), out.end(), explainLess);
        return out;
    }

    std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
    explainEnforce(const PacketKeyV6 &k) const {
        std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot> out;
        const auto it = byUid6.find(k.uid);
        if (it == byUid6.end()) return out;
        const UidViewV6 &view = it->second;
        for (const size_t idx : view.enforceOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxEnforcePriority == kNoPriority) break;
            const MaskedKeyV6 mk = maskedKeyFromPacketV6(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            appendMatching(bit->second.exactEnforce, k, out);
            appendMatching(bit->second.rangeEnforce, k, out);
        }
        std::sort(out.begin(), out.end(), explainLess);
        return out;
    }

    std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
    explainWould(const PacketKeyV6 &k) const {
        std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot> out;
        const auto it = byUid6.find(k.uid);
        if (it == byUid6.end()) return out;
        const UidViewV6 &view = it->second;
        for (const size_t idx : view.wouldOrder) {
            const auto &st = view.subtables[idx];
            if (st.maxWouldPriority == kNoPriority) break;
            const MaskedKeyV6 mk = maskedKeyFromPacketV6(st.sig, k);
            const auto bit = st.buckets.find(mk);
            if (bit == st.buckets.end()) continue;
            appendMatching(bit->second.exactWould, k, out);
            appendMatching(bit->second.rangeWould, k, out);
        }
        std::sort(out.begin(), out.end(), explainLess);
        return out;
    }
};

IpRulesEngine::CompileResult IpRulesEngine::compile(const RulesMap &rules,
                                                    const std::uint64_t rulesEpoch) {
    PreflightReport report{};
    report.recommended = PreflightLimitSet{.maxRulesTotal = kRecommendedMaxRulesTotal,
                                           .maxSubtablesPerUid = kRecommendedMaxSubtablesPerUid,
                                           .maxRangeRulesPerBucket = kRecommendedMaxRangeRulesPerBucket};
    report.hard = PreflightLimitSet{.maxRulesTotal = kHardMaxRulesTotal,
                                    .maxSubtablesPerUid = kHardMaxSubtablesPerUid,
                                    .maxRangeRulesPerBucket = kHardMaxRangeRulesPerBucket};

    using V4SubtablesMap =
        std::map<Snapshot::MaskSig, Snapshot::Subtable, Snapshot::MaskSigLess>;
    using V6SubtablesMap =
        std::map<Snapshot::MaskSigV6, Snapshot::SubtableV6, Snapshot::MaskSigV6Less>;

    std::map<std::uint32_t, V4SubtablesMap> uidTables4;
    std::map<std::uint32_t, V6SubtablesMap> uidTables6;

    std::unordered_set<std::uint32_t> uidUsesCt4;
    std::unordered_set<std::uint32_t> uidUsesCt6;

    std::uint64_t maxRangeBucket4 = 0;
    std::uint64_t maxRangeBucket6 = 0;

    for (const auto &[_, state] : rules) {
        const RuleDef &def = state.def;
        if (!def.enabled) {
            continue;
        }

        report.summary.rulesTotal++;
        if (def.family == Family::IPV4) {
            report.byFamily.ipv4.rulesTotal++;
        } else if (def.family == Family::IPV6) {
            report.byFamily.ipv6.rulesTotal++;
        }

        if (def.hasRangePorts()) {
            report.summary.rangeRulesTotal++;
            if (def.family == Family::IPV4) {
                report.byFamily.ipv4.rangeRulesTotal++;
            } else if (def.family == Family::IPV6) {
                report.byFamily.ipv6.rangeRulesTotal++;
            }
        }

        const bool ctConsumer = (def.ctState != CtState::ANY || def.ctDir != CtDirection::ANY);
        if (ctConsumer) {
            report.summary.ctRulesTotal++;
            if (def.family == Family::IPV4) {
                report.byFamily.ipv4.ctRulesTotal++;
                uidUsesCt4.emplace(def.uid);
            } else if (def.family == Family::IPV6) {
                report.byFamily.ipv6.ctRulesTotal++;
                uidUsesCt6.emplace(def.uid);
            }
        }

        if (def.family == Family::IPV4) {
            const Snapshot::MaskSig sig = Snapshot::maskSigForRule(def);
            Snapshot::Subtable &st = uidTables4[def.uid][sig];
            st.sig = sig;

            const Snapshot::MaskedKey mk = Snapshot::maskedKeyFromRule(sig, def);
            Snapshot::Bucket &bucket = st.buckets[mk];

            Snapshot::RuleRef ref{};
            ref.ruleId = def.ruleId;
            ref.uid = def.uid;
            ref.clientRuleId = def.clientRuleId;
            ref.action = def.action;
            ref.priority = def.priority;
            ref.enforce = def.enforce;
            ref.log = def.log;
            ref.dir = def.dir;
            ref.iface = def.iface;
            ref.ifindex = def.ifindex;
            ref.proto = def.proto;
            ref.ctState = def.ctState;
            ref.ctDir = def.ctDir;
            ref.src = def.src;
            ref.dst = def.dst;
            ref.sport = def.sport;
            ref.dport = def.dport;
            ref.stats = state.stats.get();
            ref.statsStrong = state.stats;

            if (def.enforce) {
                st.maxEnforcePriority = std::max(st.maxEnforcePriority, def.priority);
                if (def.hasRangePorts()) {
                    bucket.rangeEnforce.push_back(std::move(ref));
                    maxRangeBucket4 = std::max<std::uint64_t>(
                        maxRangeBucket4, bucket.rangeEnforce.size() + bucket.rangeWould.size());
                } else {
                    bucket.exactEnforce.push_back(std::move(ref));
                }
            } else {
                st.maxWouldPriority = std::max(st.maxWouldPriority, def.priority);
                if (def.hasRangePorts()) {
                    bucket.rangeWould.push_back(std::move(ref));
                    maxRangeBucket4 = std::max<std::uint64_t>(
                        maxRangeBucket4, bucket.rangeEnforce.size() + bucket.rangeWould.size());
                } else {
                    bucket.exactWould.push_back(std::move(ref));
                }
            }
        } else if (def.family == Family::IPV6) {
            const Snapshot::MaskSigV6 sig = Snapshot::maskSigForRuleV6(def);
            Snapshot::SubtableV6 &st = uidTables6[def.uid][sig];
            st.sig = sig;

            const Snapshot::MaskedKeyV6 mk = Snapshot::maskedKeyFromRuleV6(sig, def);
            Snapshot::BucketV6 &bucket = st.buckets[mk];

            Snapshot::RuleRefV6 ref{};
            ref.ruleId = def.ruleId;
            ref.uid = def.uid;
            ref.clientRuleId = def.clientRuleId;
            ref.action = def.action;
            ref.priority = def.priority;
            ref.enforce = def.enforce;
            ref.log = def.log;
            ref.dir = def.dir;
            ref.iface = def.iface;
            ref.ifindex = def.ifindex;
            ref.proto = def.proto;
            ref.ctState = def.ctState;
            ref.ctDir = def.ctDir;
            ref.src = def.src6;
            ref.dst = def.dst6;
            ref.sport = def.sport;
            ref.dport = def.dport;
            ref.stats = state.stats.get();
            ref.statsStrong = state.stats;

            if (def.enforce) {
                st.maxEnforcePriority = std::max(st.maxEnforcePriority, def.priority);
                if (def.hasRangePorts()) {
                    bucket.rangeEnforce.push_back(std::move(ref));
                    maxRangeBucket6 = std::max<std::uint64_t>(
                        maxRangeBucket6, bucket.rangeEnforce.size() + bucket.rangeWould.size());
                } else {
                    bucket.exactEnforce.push_back(std::move(ref));
                }
            } else {
                st.maxWouldPriority = std::max(st.maxWouldPriority, def.priority);
                if (def.hasRangePorts()) {
                    bucket.rangeWould.push_back(std::move(ref));
                    maxRangeBucket6 = std::max<std::uint64_t>(
                        maxRangeBucket6, bucket.rangeEnforce.size() + bucket.rangeWould.size());
                } else {
                    bucket.exactWould.push_back(std::move(ref));
                }
            }
        }
    }

    auto snap = std::make_shared<Snapshot>();
    snap->rulesEpoch = rulesEpoch;

    report.byFamily.ipv4.maxRangeRulesPerBucket = maxRangeBucket4;
    report.byFamily.ipv6.maxRangeRulesPerBucket = maxRangeBucket6;
    report.summary.maxRangeRulesPerBucket = std::max(maxRangeBucket4, maxRangeBucket6);

    std::unordered_set<std::uint32_t> uidUsesCtAll = uidUsesCt4;
    uidUsesCtAll.insert(uidUsesCt6.begin(), uidUsesCt6.end());
    report.byFamily.ipv4.ctUidsTotal = uidUsesCt4.size();
    report.byFamily.ipv6.ctUidsTotal = uidUsesCt6.size();
    report.summary.ctUidsTotal = uidUsesCtAll.size();

    report.summary.subtablesTotal = 0;
    report.byFamily.ipv4.subtablesTotal = 0;
    report.byFamily.ipv6.subtablesTotal = 0;
    report.summary.maxSubtablesPerUid = 0;
    report.byFamily.ipv4.maxSubtablesPerUid = 0;
    report.byFamily.ipv6.maxSubtablesPerUid = 0;

    // Compile and publish per-family views.
    for (auto &[uid, subtablesMap] : uidTables4) {
        Snapshot::UidView view{};
        view.usesCt = uidUsesCt4.find(uid) != uidUsesCt4.end();
        view.subtables.reserve(subtablesMap.size());
        for (auto &[_, st] : subtablesMap) {
            for (auto &[_, bucket] : st.buckets) {
                bucket.sortAll();
            }
            view.subtables.push_back(std::move(st));
        }

        const size_t n = view.subtables.size();
        report.summary.subtablesTotal += static_cast<std::uint64_t>(n);
        report.byFamily.ipv4.subtablesTotal += static_cast<std::uint64_t>(n);
        report.summary.maxSubtablesPerUid =
            std::max<std::uint64_t>(report.summary.maxSubtablesPerUid, n);
        report.byFamily.ipv4.maxSubtablesPerUid =
            std::max<std::uint64_t>(report.byFamily.ipv4.maxSubtablesPerUid, n);

        view.enforceOrder.resize(n);
        view.wouldOrder.resize(n);
        for (size_t i = 0; i < n; ++i) {
            view.enforceOrder[i] = i;
            view.wouldOrder[i] = i;
        }

        Snapshot::MaskSigLess less{};
        std::sort(view.enforceOrder.begin(), view.enforceOrder.end(),
                  [&](const size_t a, const size_t b) {
                      const auto &sa = view.subtables[a];
                      const auto &sb = view.subtables[b];
                      if (sa.maxEnforcePriority != sb.maxEnforcePriority) {
                          return sa.maxEnforcePriority > sb.maxEnforcePriority;
                      }
                      return less(sa.sig, sb.sig);
                  });
        std::sort(view.wouldOrder.begin(), view.wouldOrder.end(),
                  [&](const size_t a, const size_t b) {
                      const auto &sa = view.subtables[a];
                      const auto &sb = view.subtables[b];
                      if (sa.maxWouldPriority != sb.maxWouldPriority) {
                          return sa.maxWouldPriority > sb.maxWouldPriority;
                      }
                      return less(sa.sig, sb.sig);
                  });

        snap->byUid.emplace(uid, std::move(view));
    }

    for (auto &[uid, subtablesMap] : uidTables6) {
        Snapshot::UidViewV6 view{};
        view.usesCt = uidUsesCt6.find(uid) != uidUsesCt6.end();
        view.subtables.reserve(subtablesMap.size());
        for (auto &[_, st] : subtablesMap) {
            for (auto &[_, bucket] : st.buckets) {
                bucket.sortAll();
            }
            view.subtables.push_back(std::move(st));
        }

        const size_t n = view.subtables.size();
        report.summary.subtablesTotal += static_cast<std::uint64_t>(n);
        report.byFamily.ipv6.subtablesTotal += static_cast<std::uint64_t>(n);
        report.summary.maxSubtablesPerUid =
            std::max<std::uint64_t>(report.summary.maxSubtablesPerUid, n);
        report.byFamily.ipv6.maxSubtablesPerUid =
            std::max<std::uint64_t>(report.byFamily.ipv6.maxSubtablesPerUid, n);

        view.enforceOrder.resize(n);
        view.wouldOrder.resize(n);
        for (size_t i = 0; i < n; ++i) {
            view.enforceOrder[i] = i;
            view.wouldOrder[i] = i;
        }

        Snapshot::MaskSigV6Less less{};
        std::sort(view.enforceOrder.begin(), view.enforceOrder.end(),
                  [&](const size_t a, const size_t b) {
                      const auto &sa = view.subtables[a];
                      const auto &sb = view.subtables[b];
                      if (sa.maxEnforcePriority != sb.maxEnforcePriority) {
                          return sa.maxEnforcePriority > sb.maxEnforcePriority;
                      }
                      return less(sa.sig, sb.sig);
                  });
        std::sort(view.wouldOrder.begin(), view.wouldOrder.end(),
                  [&](const size_t a, const size_t b) {
                      const auto &sa = view.subtables[a];
                      const auto &sb = view.subtables[b];
                      if (sa.maxWouldPriority != sb.maxWouldPriority) {
                          return sa.maxWouldPriority > sb.maxWouldPriority;
                      }
                      return less(sa.sig, sb.sig);
                  });

        snap->byUid6.emplace(uid, std::move(view));
    }

    const auto addIssue = [&](std::vector<PreflightIssue> &dst, const std::string &metric,
                              const std::uint64_t value, const std::uint64_t limit,
                              const std::string &message) {
        PreflightIssue it{};
        it.metric = metric;
        it.value = value;
        it.limit = limit;
        it.message = message;
        dst.push_back(std::move(it));
    };

    if (report.summary.rulesTotal > kHardMaxRulesTotal) {
        addIssue(report.violations, "rulesTotal", report.summary.rulesTotal, kHardMaxRulesTotal,
                 "active rules exceed hard limit");
    } else if (report.summary.rulesTotal > kRecommendedMaxRulesTotal) {
        addIssue(report.warnings, "rulesTotal", report.summary.rulesTotal, kRecommendedMaxRulesTotal,
                 "active rules exceed recommended limit");
    }

    if (report.byFamily.ipv4.rulesTotal > kHardMaxRulesTotal) {
        addIssue(report.violations, "byFamily.ipv4.rulesTotal", report.byFamily.ipv4.rulesTotal,
                 kHardMaxRulesTotal, "active ipv4 rules exceed hard limit");
    } else if (report.byFamily.ipv4.rulesTotal > kRecommendedMaxRulesTotal) {
        addIssue(report.warnings, "byFamily.ipv4.rulesTotal", report.byFamily.ipv4.rulesTotal,
                 kRecommendedMaxRulesTotal, "active ipv4 rules exceed recommended limit");
    }
    if (report.byFamily.ipv6.rulesTotal > kHardMaxRulesTotal) {
        addIssue(report.violations, "byFamily.ipv6.rulesTotal", report.byFamily.ipv6.rulesTotal,
                 kHardMaxRulesTotal, "active ipv6 rules exceed hard limit");
    } else if (report.byFamily.ipv6.rulesTotal > kRecommendedMaxRulesTotal) {
        addIssue(report.warnings, "byFamily.ipv6.rulesTotal", report.byFamily.ipv6.rulesTotal,
                 kRecommendedMaxRulesTotal, "active ipv6 rules exceed recommended limit");
    }

    if (report.summary.maxSubtablesPerUid > kHardMaxSubtablesPerUid) {
        addIssue(report.violations, "maxSubtablesPerUid", report.summary.maxSubtablesPerUid,
                 kHardMaxSubtablesPerUid, "subtables per uid exceed hard limit");
    } else if (report.summary.maxSubtablesPerUid > kRecommendedMaxSubtablesPerUid) {
        addIssue(report.warnings, "maxSubtablesPerUid", report.summary.maxSubtablesPerUid,
                 kRecommendedMaxSubtablesPerUid, "subtables per uid exceed recommended limit");
    }

    if (report.byFamily.ipv4.maxSubtablesPerUid > kHardMaxSubtablesPerUid) {
        addIssue(report.violations, "byFamily.ipv4.maxSubtablesPerUid",
                 report.byFamily.ipv4.maxSubtablesPerUid, kHardMaxSubtablesPerUid,
                 "ipv4 subtables per uid exceed hard limit");
    } else if (report.byFamily.ipv4.maxSubtablesPerUid > kRecommendedMaxSubtablesPerUid) {
        addIssue(report.warnings, "byFamily.ipv4.maxSubtablesPerUid",
                 report.byFamily.ipv4.maxSubtablesPerUid, kRecommendedMaxSubtablesPerUid,
                 "ipv4 subtables per uid exceed recommended limit");
    }
    if (report.byFamily.ipv6.maxSubtablesPerUid > kHardMaxSubtablesPerUid) {
        addIssue(report.violations, "byFamily.ipv6.maxSubtablesPerUid",
                 report.byFamily.ipv6.maxSubtablesPerUid, kHardMaxSubtablesPerUid,
                 "ipv6 subtables per uid exceed hard limit");
    } else if (report.byFamily.ipv6.maxSubtablesPerUid > kRecommendedMaxSubtablesPerUid) {
        addIssue(report.warnings, "byFamily.ipv6.maxSubtablesPerUid",
                 report.byFamily.ipv6.maxSubtablesPerUid, kRecommendedMaxSubtablesPerUid,
                 "ipv6 subtables per uid exceed recommended limit");
    }

    if (report.summary.maxRangeRulesPerBucket > kHardMaxRangeRulesPerBucket) {
        addIssue(report.violations, "maxRangeRulesPerBucket", report.summary.maxRangeRulesPerBucket,
                 kHardMaxRangeRulesPerBucket, "range candidates per bucket exceed hard limit");
    } else if (report.summary.maxRangeRulesPerBucket > kRecommendedMaxRangeRulesPerBucket) {
        addIssue(report.warnings, "maxRangeRulesPerBucket", report.summary.maxRangeRulesPerBucket,
                 kRecommendedMaxRangeRulesPerBucket, "range candidates per bucket exceed recommended limit");
    }

    if (report.byFamily.ipv4.maxRangeRulesPerBucket > kHardMaxRangeRulesPerBucket) {
        addIssue(report.violations, "byFamily.ipv4.maxRangeRulesPerBucket",
                 report.byFamily.ipv4.maxRangeRulesPerBucket, kHardMaxRangeRulesPerBucket,
                 "ipv4 range candidates per bucket exceed hard limit");
    } else if (report.byFamily.ipv4.maxRangeRulesPerBucket > kRecommendedMaxRangeRulesPerBucket) {
        addIssue(report.warnings, "byFamily.ipv4.maxRangeRulesPerBucket",
                 report.byFamily.ipv4.maxRangeRulesPerBucket, kRecommendedMaxRangeRulesPerBucket,
                 "ipv4 range candidates per bucket exceed recommended limit");
    }
    if (report.byFamily.ipv6.maxRangeRulesPerBucket > kHardMaxRangeRulesPerBucket) {
        addIssue(report.violations, "byFamily.ipv6.maxRangeRulesPerBucket",
                 report.byFamily.ipv6.maxRangeRulesPerBucket, kHardMaxRangeRulesPerBucket,
                 "ipv6 range candidates per bucket exceed hard limit");
    } else if (report.byFamily.ipv6.maxRangeRulesPerBucket > kRecommendedMaxRangeRulesPerBucket) {
        addIssue(report.warnings, "byFamily.ipv6.maxRangeRulesPerBucket",
                 report.byFamily.ipv6.maxRangeRulesPerBucket, kRecommendedMaxRangeRulesPerBucket,
                 "ipv6 range candidates per bucket exceed recommended limit");
    }

    return CompileResult{.snapshot = std::move(snap), .report = std::move(report)};
}

IpRulesEngine::IpRulesEngine()
    : _instanceId(g_ipRulesEngineInstanceId.fetch_add(1, std::memory_order_relaxed)) {
    // Always publish an initial empty snapshot so evaluate() is safe without locks.
    const auto cr = compile(_rules, _rulesEpoch.load(std::memory_order_relaxed));
    _snapshot = cr.snapshot;
    _lastPreflight = cr.report;
}

IpRulesEngine::~IpRulesEngine() = default;

IpRulesEngine::PreflightReport IpRulesEngine::preflight() const {
    const std::shared_lock<std::shared_mutex> g(_mutex);
    return _lastPreflight;
}

std::optional<IpRulesEngine::RuleDef> IpRulesEngine::getRule(const RuleId ruleId) const {
    const std::shared_lock<std::shared_mutex> g(_mutex);
    const auto it = _rules.find(ruleId);
    if (it == _rules.end()) {
        return std::nullopt;
    }
    return it->second.def;
}

std::vector<IpRulesEngine::RuleDef>
IpRulesEngine::listRules(const std::optional<std::uint32_t> uidFilter,
                         const std::optional<RuleId> ruleFilter) const {
    const std::shared_lock<std::shared_mutex> g(_mutex);
    std::vector<RuleDef> out;
    out.reserve(_rules.size());
    for (const auto &[rid, state] : _rules) {
        if (ruleFilter.has_value() && rid != ruleFilter.value()) {
            continue;
        }
        if (uidFilter.has_value() && state.def.uid != uidFilter.value()) {
            continue;
        }
        out.push_back(state.def);
    }
    std::sort(out.begin(), out.end(),
              [](const RuleDef &a, const RuleDef &b) { return a.ruleId < b.ruleId; });
    return out;
}

IpRulesEngine::PolicySnapshot IpRulesEngine::policySnapshot() const {
    const std::shared_lock<std::shared_mutex> g(_mutex);
    PolicySnapshot out{};
    out.nextRuleId = _nextRuleId;
    out.rules.reserve(_rules.size());
    for (const auto &[_, state] : _rules) {
        out.rules.push_back(state.def);
    }
    std::sort(out.rules.begin(), out.rules.end(),
              [](const RuleDef &a, const RuleDef &b) { return a.ruleId < b.ruleId; });
    return out;
}

IpRulesEngine::ApplyResult
IpRulesEngine::validatePolicySnapshot(const PolicySnapshot &snapshot) const {
    RulesMap staged;
    staged.clear();
    RuleId maxRuleId = 0;
    bool hasAny = false;
    for (const auto &def : snapshot.rules) {
        std::string error;
        if (!validateRuleDef(def, error)) {
            return nokResult(error);
        }
        RuleState state{};
        state.def = def;
        state.stats = std::make_shared<RuleStats>();
        if (!staged.emplace(def.ruleId, std::move(state)).second) {
            return nokResult("duplicate ruleId");
        }
        maxRuleId = std::max(maxRuleId, def.ruleId);
        hasAny = true;
    }
    if (hasAny && snapshot.nextRuleId <= maxRuleId) {
        return nokResult("nextRuleId must be greater than all ruleId values");
    }

    const std::uint64_t newEpoch = _rulesEpoch.load(std::memory_order_relaxed) + 1;
    auto cr = compile(staged, newEpoch);
    if (!cr.report.ok()) {
        ApplyResult r{};
        r.ok = false;
        r.error = "preflight violations";
        r.preflight = std::move(cr.report);
        return r;
    }

    ApplyResult r{};
    r.ok = true;
    r.preflight = std::move(cr.report);
    return r;
}

IpRulesEngine::ApplyResult
IpRulesEngine::restorePolicySnapshot(const PolicySnapshot &snapshot) {
    std::unique_lock<std::shared_mutex> g(_mutex);

    RulesMap staged;
    staged.clear();
    RuleId maxRuleId = 0;
    bool hasAny = false;
    for (const auto &def : snapshot.rules) {
        std::string error;
        if (!validateRuleDef(def, error)) {
            return nokResult(error);
        }
        RuleState state{};
        state.def = def;
        state.stats = std::make_shared<RuleStats>();
        if (!staged.emplace(def.ruleId, std::move(state)).second) {
            return nokResult("duplicate ruleId");
        }
        maxRuleId = std::max(maxRuleId, def.ruleId);
        hasAny = true;
    }
    if (hasAny && snapshot.nextRuleId <= maxRuleId) {
        return nokResult("nextRuleId must be greater than all ruleId values");
    }

    const std::uint64_t newEpoch = _rulesEpoch.load(std::memory_order_relaxed) + 1;
    auto cr = compile(staged, newEpoch);
    if (!cr.report.ok()) {
        ApplyResult r{};
        r.ok = false;
        r.error = "preflight violations";
        r.preflight = std::move(cr.report);
        return r;
    }

    _rules = std::move(staged);
    _nextRuleId = snapshot.nextRuleId;
    _lastPreflight = cr.report;
    _rulesEpoch.store(newEpoch, std::memory_order_relaxed);
    std::atomic_store_explicit(&_snapshot, std::move(cr.snapshot), std::memory_order_release);

    ApplyResult r{};
    r.ok = true;
    r.preflight = _lastPreflight;
    return r;
}

std::optional<IpRulesEngine::RuleStatsSnapshot> IpRulesEngine::statsSnapshot(const RuleId ruleId) const {
    const std::shared_lock<std::shared_mutex> g(_mutex);
    const auto it = _rules.find(ruleId);
    if (it == _rules.end()) {
        return std::nullopt;
    }
    return it->second.stats->snapshot();
}

IpRulesEngine::ApplyResult IpRulesEngine::applyNewRules(RulesMap &&newRules,
                                                        const std::optional<RuleId> newRuleId) {
    const std::uint64_t newEpoch = _rulesEpoch.load(std::memory_order_relaxed) + 1;
    auto cr = compile(newRules, newEpoch);

    if (!cr.report.ok()) {
        ApplyResult r{};
        r.ok = false;
        r.ruleId = std::nullopt;
        r.error = "preflight violations";
        r.preflight = std::move(cr.report);
        return r;
    }

    _rules = std::move(newRules);
    if (newRuleId.has_value()) {
        _nextRuleId = static_cast<RuleId>(*newRuleId + 1);
    }
    _lastPreflight = cr.report;
    _rulesEpoch.store(newEpoch, std::memory_order_relaxed);
    std::atomic_store_explicit(&_snapshot, std::move(cr.snapshot), std::memory_order_release);

    ApplyResult r{};
    r.ok = true;
    r.ruleId = newRuleId;
    r.preflight = _lastPreflight;
    return r;
}

IpRulesEngine::ApplyResult IpRulesEngine::addFromKv(const std::uint32_t uid,
                                                    const std::vector<std::string> &kvTokens) {
    std::unique_lock<std::shared_mutex> g(_mutex);

    RuleDef def{};
    def.ruleId = _nextRuleId;
    def.uid = uid;
    def.clientRuleId = legacyClientRuleId(uid, def.ruleId);
    def.enabled = true;
    def.enforce = true;
    def.log = false;

    bool hasAction = false;
    bool hasPriority = false;

    for (const auto &tok : kvTokens) {
        const auto kv = splitKv(tok);
        if (!kv.has_value()) {
            return nokResult("invalid kv token");
        }
        const auto [k, v] = *kv;

        if (k == "action") {
            hasAction = true;
            if (!parseAction(v, def.action)) {
                return nokResult("invalid action");
            }
        } else if (k == "priority") {
            hasPriority = true;
            if (!parsePriority(v, def.priority)) {
                return nokResult("invalid priority");
            }
        } else if (k == "enabled") {
            if (!parseBool01(v, def.enabled)) {
                return nokResult("invalid enabled");
            }
        } else if (k == "enforce") {
            if (!parseBool01(v, def.enforce)) {
                return nokResult("invalid enforce");
            }
        } else if (k == "log") {
            if (!parseBool01(v, def.log)) {
                return nokResult("invalid log");
            }
        } else if (k == "dir") {
            if (!parseDirection(v, def.dir)) {
                return nokResult("invalid dir");
            }
        } else if (k == "iface") {
            if (!parseIfaceKind(v, def.iface)) {
                return nokResult("invalid iface");
            }
        } else if (k == "ifindex") {
            if (!parseIfindex(v, def.ifindex)) {
                return nokResult("invalid ifindex");
            }
        } else if (k == "proto") {
            if (!parseProto(v, def.proto)) {
                return nokResult("invalid proto");
            }
        } else if (k == "src") {
            if (!parseCidrV4(v, def.src)) {
                return nokResult("invalid src");
            }
        } else if (k == "dst") {
            if (!parseCidrV4(v, def.dst)) {
                return nokResult("invalid dst");
            }
        } else if (k == "sport") {
            if (!parsePortPredicate(v, def.sport)) {
                return nokResult("invalid sport");
            }
        } else if (k == "dport") {
            if (!parsePortPredicate(v, def.dport)) {
                return nokResult("invalid dport");
            }
        } else if (k == "ct.state") {
            if (!parseCtState(v, def.ctState)) {
                return nokResult("invalid ct.state");
            }
        } else if (k == "ct.direction") {
            if (!parseCtDirection(v, def.ctDir)) {
                return nokResult("invalid ct.direction");
            }
        } else if (k == "ct") {
            return nokResult("ct is not supported");
        } else {
            return nokResult("unknown key");
        }
    }

    if (!hasAction) {
        return nokResult("missing action");
    }
    if (!hasPriority) {
        return nokResult("missing priority");
    }

    std::string error;
    if (!validateRuleDef(def, error)) {
        return nokResult(error);
    }

    RuleState st{};
    st.def = def;
    st.stats = std::make_shared<RuleStats>();

    RulesMap newRules = _rules;
    newRules.emplace(def.ruleId, std::move(st));

    return applyNewRules(std::move(newRules), def.ruleId);
}

IpRulesEngine::ApplyResult IpRulesEngine::updateFromKv(const RuleId ruleId,
                                                       const std::vector<std::string> &kvTokens) {
    std::unique_lock<std::shared_mutex> g(_mutex);

    const auto it = _rules.find(ruleId);
    if (it == _rules.end()) {
        return nokResult("rule not found");
    }

    RuleDef def = it->second.def;

    for (const auto &tok : kvTokens) {
        const auto kv = splitKv(tok);
        if (!kv.has_value()) {
            return nokResult("invalid kv token");
        }
        const auto [k, v] = *kv;

        if (k == "action") {
            if (!parseAction(v, def.action)) {
                return nokResult("invalid action");
            }
        } else if (k == "priority") {
            if (!parsePriority(v, def.priority)) {
                return nokResult("invalid priority");
            }
        } else if (k == "enabled") {
            if (!parseBool01(v, def.enabled)) {
                return nokResult("invalid enabled");
            }
        } else if (k == "enforce") {
            if (!parseBool01(v, def.enforce)) {
                return nokResult("invalid enforce");
            }
        } else if (k == "log") {
            if (!parseBool01(v, def.log)) {
                return nokResult("invalid log");
            }
        } else if (k == "dir") {
            if (!parseDirection(v, def.dir)) {
                return nokResult("invalid dir");
            }
        } else if (k == "iface") {
            if (!parseIfaceKind(v, def.iface)) {
                return nokResult("invalid iface");
            }
        } else if (k == "ifindex") {
            if (!parseIfindex(v, def.ifindex)) {
                return nokResult("invalid ifindex");
            }
        } else if (k == "proto") {
            if (!parseProto(v, def.proto)) {
                return nokResult("invalid proto");
            }
        } else if (k == "src") {
            if (!parseCidrV4(v, def.src)) {
                return nokResult("invalid src");
            }
        } else if (k == "dst") {
            if (!parseCidrV4(v, def.dst)) {
                return nokResult("invalid dst");
            }
        } else if (k == "sport") {
            if (!parsePortPredicate(v, def.sport)) {
                return nokResult("invalid sport");
            }
        } else if (k == "dport") {
            if (!parsePortPredicate(v, def.dport)) {
                return nokResult("invalid dport");
            }
        } else if (k == "ct.state") {
            if (!parseCtState(v, def.ctState)) {
                return nokResult("invalid ct.state");
            }
        } else if (k == "ct.direction") {
            if (!parseCtDirection(v, def.ctDir)) {
                return nokResult("invalid ct.direction");
            }
        } else if (k == "ct") {
            return nokResult("ct is not supported");
        } else {
            return nokResult("unknown key");
        }
    }

    std::string error;
    if (!validateRuleDef(def, error)) {
        return nokResult(error);
    }

    RulesMap newRules = _rules;
    auto &st = newRules.find(ruleId)->second;
    st.def = def;
    st.stats = std::make_shared<RuleStats>(); // UPDATE MUST reset runtime stats

    return applyNewRules(std::move(newRules), std::nullopt);
}

IpRulesEngine::ApplyResult IpRulesEngine::removeRule(const RuleId ruleId) {
    std::unique_lock<std::shared_mutex> g(_mutex);
    if (_rules.find(ruleId) == _rules.end()) {
        return nokResult("rule not found");
    }
    RulesMap newRules = _rules;
    newRules.erase(ruleId);
    return applyNewRules(std::move(newRules), std::nullopt);
}

IpRulesEngine::ApplyResult IpRulesEngine::enableRule(const RuleId ruleId, const bool enabled) {
    std::unique_lock<std::shared_mutex> g(_mutex);
    const auto it = _rules.find(ruleId);
    if (it == _rules.end()) {
        return nokResult("rule not found");
    }

    if (it->second.def.enabled == enabled) {
        return okResult();
    }

    RulesMap newRules = _rules;
    auto &st = newRules.find(ruleId)->second;
    const bool wasEnabled = st.def.enabled;
    st.def.enabled = enabled;
    if (!wasEnabled && enabled) {
        st.stats = std::make_shared<RuleStats>(); // ENABLE 0->1 MUST reset stats
    }

    return applyNewRules(std::move(newRules), std::nullopt);
}

IpRulesEngine::ApplyResult
IpRulesEngine::replaceRulesForUid(const std::uint32_t uid, const std::vector<ApplyRule> &rules) {
    std::unique_lock<std::shared_mutex> g(_mutex);

    std::unordered_set<std::string> seenClientIds;
    seenClientIds.reserve(rules.size());
    for (const auto &r : rules) {
        if (!isValidClientRuleId(r.clientRuleId)) {
            return nokResult("invalid clientRuleId");
        }
        if (!seenClientIds.emplace(r.clientRuleId).second) {
            return nokResult("duplicate clientRuleId");
        }
    }

    std::unordered_map<std::string, const RuleState *> prevByClientId;
    prevByClientId.reserve(rules.size());
    for (const auto &[_, st] : _rules) {
        if (st.def.uid != uid) {
            continue;
        }
        if (st.def.clientRuleId.empty()) {
            continue;
        }
        prevByClientId.emplace(st.def.clientRuleId, &st);
    }

    const auto sameMatch = [](const RuleDef &a, const RuleDef &b) {
        return a.family == b.family && a.dir == b.dir && a.iface == b.iface && a.ifindex == b.ifindex &&
               a.proto == b.proto && a.ctState == b.ctState && a.ctDir == b.ctDir &&
               a.src.any == b.src.any && a.src.addr == b.src.addr && a.src.prefix == b.src.prefix &&
               a.dst.any == b.dst.any && a.dst.addr == b.dst.addr && a.dst.prefix == b.dst.prefix &&
               a.src6.any == b.src6.any && a.src6.addr == b.src6.addr && a.src6.prefix == b.src6.prefix &&
               a.dst6.any == b.dst6.any && a.dst6.addr == b.dst6.addr && a.dst6.prefix == b.dst6.prefix &&
               a.sport.kind == b.sport.kind && a.sport.lo == b.sport.lo && a.sport.hi == b.sport.hi &&
               a.dport.kind == b.dport.kind && a.dport.lo == b.dport.lo && a.dport.hi == b.dport.hi;
    };

    const auto sameBehavior = [](const RuleDef &a, const RuleDef &b) {
        return a.action == b.action && a.priority == b.priority && a.enabled == b.enabled &&
               a.enforce == b.enforce && a.log == b.log;
    };

    RulesMap newRules = _rules;
    for (auto it = newRules.begin(); it != newRules.end();) {
        if (it->second.def.uid == uid) {
            it = newRules.erase(it);
        } else {
            ++it;
        }
    }

    RuleId nextRuleId = _nextRuleId;
    std::optional<RuleId> maxAllocatedRuleId = std::nullopt;

    for (const auto &r : rules) {
        const auto prevIt = prevByClientId.find(r.clientRuleId);
        const bool hasPrev = prevIt != prevByClientId.end();

        const RuleId assignedRuleId = hasPrev ? prevIt->second->def.ruleId : nextRuleId++;
        if (!hasPrev) {
            maxAllocatedRuleId = assignedRuleId;
        }

        RuleDef def{};
        def.ruleId = assignedRuleId;
        def.uid = uid;
        def.clientRuleId = r.clientRuleId;
        def.family = r.family;
        def.action = r.action;
        def.priority = r.priority;
        def.enabled = r.enabled;
        def.enforce = r.enforce;
        def.log = r.log;
        def.dir = r.dir;
        def.iface = r.iface;
        def.ifindex = r.ifindex;
        def.proto = r.proto;
        def.src = r.src;
        def.dst = r.dst;
        def.src6 = r.src6;
        def.dst6 = r.dst6;
        def.sport = r.sport;
        def.dport = r.dport;
        def.ctState = r.ctState;
        def.ctDir = r.ctDir;

        std::string error;
        if (!validateRuleDef(def, error)) {
            return nokResult(error);
        }

        RuleState st{};
        st.def = def;
        if (hasPrev) {
            const auto *prev = prevIt->second;
            if (sameMatch(prev->def, def) && sameBehavior(prev->def, def)) {
                st.stats = prev->stats;
            } else {
                st.stats = std::make_shared<RuleStats>();
            }
        } else {
            st.stats = std::make_shared<RuleStats>();
        }

        if (!newRules.emplace(def.ruleId, std::move(st)).second) {
            return nokResult("internal error: duplicate ruleId");
        }
    }

    return applyNewRules(std::move(newRules), maxAllocatedRuleId);
}

void IpRulesEngine::resetAll() {
    std::unique_lock<std::shared_mutex> g(_mutex);
    RulesMap empty;
    _nextRuleId = 0;
    _saver.remove();
    (void)applyNewRules(std::move(empty), std::nullopt);
}

void IpRulesEngine::save() {
    RuleId nextRuleId = 0;
    std::vector<RuleDef> defs;
    {
        const std::shared_lock<std::shared_mutex> g(_mutex);
        nextRuleId = _nextRuleId;
        defs.reserve(_rules.size());
        for (const auto &[_, st] : _rules) {
            defs.push_back(st.def);
        }
    }
    std::sort(defs.begin(), defs.end(),
              [](const RuleDef &a, const RuleDef &b) { return a.ruleId < b.ruleId; });

    _saver.save([&] {
        constexpr uint32_t kFormatVersion = 4;
        _saver.write<uint32_t>(kFormatVersion);
        _saver.write<RuleId>(nextRuleId);
        _saver.write<uint32_t>(static_cast<uint32_t>(defs.size()));

        for (const auto &d : defs) {
            _saver.write<RuleId>(d.ruleId);
            _saver.write<uint32_t>(d.uid);
            _saver.write(d.clientRuleId);
            _saver.write<uint8_t>(static_cast<uint8_t>(d.family));
            _saver.write<uint8_t>(static_cast<uint8_t>(d.action));
            _saver.write<std::int32_t>(d.priority);
            _saver.write<bool>(d.enabled);
            _saver.write<bool>(d.enforce);
            _saver.write<bool>(d.log);
            _saver.write<uint8_t>(static_cast<uint8_t>(d.dir));
            _saver.write<uint8_t>(static_cast<uint8_t>(d.iface));
            _saver.write<uint32_t>(d.ifindex);
            _saver.write<uint8_t>(static_cast<uint8_t>(d.proto));

            _saver.write<bool>(d.src.any);
            _saver.write<uint32_t>(d.src.addr);
            _saver.write<uint8_t>(d.src.prefix);

            _saver.write<bool>(d.dst.any);
            _saver.write<uint32_t>(d.dst.addr);
            _saver.write<uint8_t>(d.dst.prefix);

            _saver.write<bool>(d.src6.any);
            _saver.write(d.src6.addr.data(), static_cast<uint32_t>(d.src6.addr.size()));
            _saver.write<uint8_t>(d.src6.prefix);

            _saver.write<bool>(d.dst6.any);
            _saver.write(d.dst6.addr.data(), static_cast<uint32_t>(d.dst6.addr.size()));
            _saver.write<uint8_t>(d.dst6.prefix);

            _saver.write<uint8_t>(static_cast<uint8_t>(d.sport.kind));
            _saver.write<uint16_t>(d.sport.lo);
            _saver.write<uint16_t>(d.sport.hi);

            _saver.write<uint8_t>(static_cast<uint8_t>(d.dport.kind));
            _saver.write<uint16_t>(d.dport.lo);
            _saver.write<uint16_t>(d.dport.hi);

            _saver.write<uint8_t>(static_cast<uint8_t>(d.ctState));
            _saver.write<uint8_t>(static_cast<uint8_t>(d.ctDir));
        }
    });
}

void IpRulesEngine::restore() {
    bool restoreAttempted = false;
    bool restoreOk = true;

    _saver.restore([&] {
        restoreAttempted = true;
        try {
            const auto formatVersion = _saver.read<uint32_t>();
            if (formatVersion != 4) {
                throw RestoreException();
            }

            RuleId nextRuleId = _saver.read<RuleId>();
            const auto count = _saver.read<uint32_t>();

            RulesMap restored;
            restored.clear();

            RuleId maxSeenId = 0;
            bool hasAny = false;

            auto maskV6HostBits = [](std::array<std::uint8_t, 16> &addr,
                                     const std::uint8_t prefix) {
                if (prefix == 0) {
                    addr.fill(0);
                    return;
                }
                const std::uint8_t fullBytes = static_cast<std::uint8_t>(prefix / 8u);
                const std::uint8_t remBits = static_cast<std::uint8_t>(prefix % 8u);
                std::uint8_t i = fullBytes;
                if (i >= addr.size()) {
                    return;
                }
                if (remBits != 0) {
                    const std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8u - remBits));
                    addr[i] &= mask;
                    ++i;
                }
                for (; i < addr.size(); ++i) {
                    addr[i] = 0;
                }
            };

            for (uint32_t i = 0; i < count; ++i) {
                RuleDef d{};
                d.ruleId = _saver.read<RuleId>();
                d.uid = _saver.read<uint32_t>();

                _saver.read(d.clientRuleId, 1, 64);
                if (!isValidClientRuleId(d.clientRuleId)) {
                    throw RestoreException();
                }

                d.family = static_cast<Family>(_saver.read<uint8_t>());
                d.action = static_cast<Action>(_saver.read<uint8_t>());
                d.priority = _saver.read<std::int32_t>();
                d.enabled = _saver.read<bool>();
                d.enforce = _saver.read<bool>();
                d.log = _saver.read<bool>();
                d.dir = static_cast<Direction>(_saver.read<uint8_t>());
                d.iface = static_cast<IfaceKind>(_saver.read<uint8_t>());
                d.ifindex = _saver.read<uint32_t>();
                d.proto = static_cast<Proto>(_saver.read<uint8_t>());

                d.src.any = _saver.read<bool>();
                d.src.addr = _saver.read<uint32_t>();
                d.src.prefix = _saver.read<uint8_t>();
                if (!d.src.any) {
                    if (d.src.prefix > 32) {
                        throw RestoreException();
                    }
                    d.src.addr &= maskFromPrefix(d.src.prefix);
                }

                d.dst.any = _saver.read<bool>();
                d.dst.addr = _saver.read<uint32_t>();
                d.dst.prefix = _saver.read<uint8_t>();
                if (!d.dst.any) {
                    if (d.dst.prefix > 32) {
                        throw RestoreException();
                    }
                    d.dst.addr &= maskFromPrefix(d.dst.prefix);
                }

                d.src6.any = _saver.read<bool>();
                _saver.read(d.src6.addr.data(), static_cast<uint32_t>(d.src6.addr.size()));
                d.src6.prefix = _saver.read<uint8_t>();
                if (!d.src6.any) {
                    if (d.src6.prefix > 128) {
                        throw RestoreException();
                    }
                    maskV6HostBits(d.src6.addr, d.src6.prefix);
                } else {
                    d.src6.addr.fill(0);
                    d.src6.prefix = 0;
                }

                d.dst6.any = _saver.read<bool>();
                _saver.read(d.dst6.addr.data(), static_cast<uint32_t>(d.dst6.addr.size()));
                d.dst6.prefix = _saver.read<uint8_t>();
                if (!d.dst6.any) {
                    if (d.dst6.prefix > 128) {
                        throw RestoreException();
                    }
                    maskV6HostBits(d.dst6.addr, d.dst6.prefix);
                } else {
                    d.dst6.addr.fill(0);
                    d.dst6.prefix = 0;
                }

                d.sport.kind = static_cast<PortPredicate::Kind>(_saver.read<uint8_t>());
                d.sport.lo = _saver.read<uint16_t>();
                d.sport.hi = _saver.read<uint16_t>();

                d.dport.kind = static_cast<PortPredicate::Kind>(_saver.read<uint8_t>());
                d.dport.lo = _saver.read<uint16_t>();
                d.dport.hi = _saver.read<uint16_t>();

                d.ctState = static_cast<CtState>(_saver.read<uint8_t>());
                d.ctDir = static_cast<CtDirection>(_saver.read<uint8_t>());

                std::string error;
                if (!validateRuleDef(d, error)) {
                    throw RestoreException();
                }

                RuleState st{};
                st.def = d;
                st.stats = std::make_shared<RuleStats>(); // since-boot; not persisted
                restored.emplace(d.ruleId, std::move(st));

                maxSeenId = std::max(maxSeenId, d.ruleId);
                hasAny = true;
            }

            if (hasAny) {
                nextRuleId = std::max<RuleId>(nextRuleId, static_cast<RuleId>(maxSeenId + 1));
            }

            const std::uint64_t newEpoch = _rulesEpoch.load(std::memory_order_relaxed) + 1;
            auto cr = compile(restored, newEpoch);
            if (!cr.report.ok()) {
                throw RestoreException();
            }

            const std::lock_guard<std::shared_mutex> g(_mutex);
            _rules = std::move(restored);
            _nextRuleId = nextRuleId;
            _lastPreflight = cr.report;
            _rulesEpoch.store(newEpoch, std::memory_order_relaxed);
            std::atomic_store_explicit(&_snapshot, std::move(cr.snapshot), std::memory_order_release);
        } catch (const RestoreException &) {
            restoreOk = false;
            throw;
        } catch (...) {
            restoreOk = false;
            throw RestoreException();
        }
    });

    if (restoreAttempted && !restoreOk) {
        // Unsupported/invalid persisted rules: clear to an empty ruleset and drop the save file.
        LOG(WARNING) << "IPRULES restore failed (unsupported or invalid save format); clearing ruleset";
        resetAll();
    }
}

#if SUCRE_SNORT_IPRULES_DECISION_CACHE
static inline size_t hashPacketKey(const IpRulesEngine::PacketKeyV4 &k) noexcept {
    size_t h = 0;
    h = mixHash(h, k.uid);
    h = mixHash(h, k.dir);
    h = mixHash(h, k.ifaceKind);
    h = mixHash(h, k.proto);
    h = mixHash(h, k.ifindex);
    h = mixHash(h, k.srcIp);
    h = mixHash(h, k.dstIp);
    h = mixHash(h, k.srcPort);
    h = mixHash(h, k.dstPort);
    h = mixHash(h, k.portsAvailable);
    h = mixHash(h, k.ctState);
    h = mixHash(h, k.ctDir);
    return h;
}

static inline size_t hashPacketKey(const IpRulesEngine::PacketKeyV6 &k) noexcept {
    size_t h = 0;
    h = mixHash(h, k.uid);
    h = mixHash(h, k.dir);
    h = mixHash(h, k.ifaceKind);
    h = mixHash(h, k.proto);
    h = mixHash(h, k.ifindex);
    std::uint64_t a0 = 0, a1 = 0, b0 = 0, b1 = 0;
    std::memcpy(&a0, k.srcIp.data(), 8);
    std::memcpy(&a1, k.srcIp.data() + 8, 8);
    std::memcpy(&b0, k.dstIp.data(), 8);
    std::memcpy(&b1, k.dstIp.data() + 8, 8);
    h = mixHash(h, static_cast<size_t>(a0));
    h = mixHash(h, static_cast<size_t>(a1));
    h = mixHash(h, static_cast<size_t>(b0));
    h = mixHash(h, static_cast<size_t>(b1));
    h = mixHash(h, k.srcPort);
    h = mixHash(h, k.dstPort);
    h = mixHash(h, k.portsAvailable);
    h = mixHash(h, k.ctState);
    h = mixHash(h, k.ctDir);
    return h;
}
#endif

IpRulesEngine::Decision IpRulesEngine::evaluate(const PacketKeyV4 &key) const {
    return hotSnapshot().evaluate(key);
}

IpRulesEngine::Decision IpRulesEngine::evaluate(const PacketKeyV6 &key) const {
    return hotSnapshot().evaluate(key);
}

IpRulesEngine::HotSnapshot IpRulesEngine::hotSnapshot() const {
    HotSnapshot hs{};
    hs._instanceId = _instanceId;
    hs._snap = std::atomic_load_explicit(&_snapshot, std::memory_order_acquire);
    return hs;
}

std::uint64_t IpRulesEngine::HotSnapshot::rulesEpoch() const noexcept {
    return _snap ? _snap->rulesEpoch : 0;
}

bool IpRulesEngine::HotSnapshot::uidUsesCt(const std::uint32_t uid) const noexcept {
    if (!_snap) {
        return false;
    }
    return uidUsesCt(uid, Family::IPV4);
}

bool IpRulesEngine::HotSnapshot::uidUsesCt(const std::uint32_t uid, const Family family) const noexcept {
    if (!_snap) {
        return false;
    }
    if (family == Family::IPV4) {
        const auto it = _snap->byUid.find(uid);
        if (it == _snap->byUid.end()) {
            return false;
        }
        return it->second.usesCt;
    }
    if (family == Family::IPV6) {
        const auto it = _snap->byUid6.find(uid);
        if (it == _snap->byUid6.end()) {
            return false;
        }
        return it->second.usesCt;
    }
    return false;
}

IpRulesEngine::Decision IpRulesEngine::HotSnapshot::evaluate(const PacketKeyV4 &key) const {
    Decision out{};
    out.keepAlive = _snap;
    if (!_snap) {
        return out;
    }

#if SUCRE_SNORT_IPRULES_DECISION_CACHE
    struct CacheEntry {
        std::uint64_t epoch = 0;
        PacketKeyV4 key{};
        DecisionKind kind = DecisionKind::NOMATCH;
        RuleId ruleId = 0;
        void *stats = nullptr;
    };

    struct Cache {
        std::uint64_t ownerInstanceId = 0;
        std::array<CacheEntry, 1024> entries{};
    };

    thread_local Cache cache;
    if (cache.ownerInstanceId != _instanceId) {
        cache.ownerInstanceId = _instanceId;
        for (auto &e : cache.entries) {
            e.epoch = 0;
        }
    }

    const std::uint64_t epoch = _snap->rulesEpoch;
    const size_t idx = hashPacketKey(key) & (cache.entries.size() - 1);
    CacheEntry &e = cache.entries[idx];
    if (e.epoch == epoch && e.key == key) {
        out.kind = e.kind;
        out.ruleId = e.ruleId;
        out.stats = e.stats;
        return out;
    }

    const auto d = _snap->evaluate(key);

    e.epoch = epoch;
    e.key = key;
    e.kind = d.kind;
    e.ruleId = d.ruleId;
    e.stats = d.stats;

    out.kind = d.kind;
    out.ruleId = d.ruleId;
    out.stats = d.stats;
    return out;
#else
    const auto d = _snap->evaluate(key);
    out.kind = d.kind;
    out.ruleId = d.ruleId;
    out.stats = d.stats;
    return out;
#endif
}

IpRulesEngine::Decision IpRulesEngine::HotSnapshot::evaluate(const PacketKeyV6 &key) const {
    Decision out{};
    out.keepAlive = _snap;
    if (!_snap) {
        return out;
    }

#if SUCRE_SNORT_IPRULES_DECISION_CACHE
    struct CacheEntry {
        std::uint64_t epoch = 0;
        PacketKeyV6 key{};
        DecisionKind kind = DecisionKind::NOMATCH;
        RuleId ruleId = 0;
        void *stats = nullptr;
    };

    struct Cache {
        std::uint64_t ownerInstanceId = 0;
        std::array<CacheEntry, 512> entries{};
    };

    thread_local Cache cache;
    if (cache.ownerInstanceId != _instanceId) {
        cache.ownerInstanceId = _instanceId;
        for (auto &e : cache.entries) {
            e.epoch = 0;
        }
    }

    const std::uint64_t epoch = _snap->rulesEpoch;
    const size_t idx = hashPacketKey(key) & (cache.entries.size() - 1);
    CacheEntry &e = cache.entries[idx];
    if (e.epoch == epoch && e.key == key) {
        out.kind = e.kind;
        out.ruleId = e.ruleId;
        out.stats = e.stats;
        return out;
    }

    const auto d = _snap->evaluate(key);

    e.epoch = epoch;
    e.key = key;
    e.kind = d.kind;
    e.ruleId = d.ruleId;
    e.stats = d.stats;

    out.kind = d.kind;
    out.ruleId = d.ruleId;
    out.stats = d.stats;
    return out;
#else
    const auto d = _snap->evaluate(key);
    out.kind = d.kind;
    out.ruleId = d.ruleId;
    out.stats = d.stats;
    return out;
#endif
}

std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
IpRulesEngine::HotSnapshot::explainEnforce(
    const PacketKeyV4 &key, const std::optional<RuleId> winningRuleId,
    bool &truncated, std::optional<std::uint32_t> &omittedCandidateCount) const {
    truncated = false;
    omittedCandidateCount.reset();
    if (!_snap) {
        return {};
    }
    auto out = _snap->explainEnforce(key);
    ControlVNextStreamExplain::capCandidateSnapshots(
        out, winningRuleId, [](const auto &snapshot) { return snapshot.ruleId; }, truncated,
        omittedCandidateCount);
    return out;
}

std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
IpRulesEngine::HotSnapshot::explainEnforce(
    const PacketKeyV6 &key, const std::optional<RuleId> winningRuleId,
    bool &truncated, std::optional<std::uint32_t> &omittedCandidateCount) const {
    truncated = false;
    omittedCandidateCount.reset();
    if (!_snap) {
        return {};
    }
    auto out = _snap->explainEnforce(key);
    ControlVNextStreamExplain::capCandidateSnapshots(
        out, winningRuleId, [](const auto &snapshot) { return snapshot.ruleId; }, truncated,
        omittedCandidateCount);
    return out;
}

std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
IpRulesEngine::HotSnapshot::explainWould(
    const PacketKeyV4 &key, const std::optional<RuleId> winningRuleId,
    bool &truncated, std::optional<std::uint32_t> &omittedCandidateCount) const {
    truncated = false;
    omittedCandidateCount.reset();
    if (!_snap) {
        return {};
    }
    auto out = _snap->explainWould(key);
    ControlVNextStreamExplain::capCandidateSnapshots(
        out, winningRuleId, [](const auto &snapshot) { return snapshot.ruleId; }, truncated,
        omittedCandidateCount);
    return out;
}

std::vector<ControlVNextStreamExplain::IpRulesRuleSnapshot>
IpRulesEngine::HotSnapshot::explainWould(
    const PacketKeyV6 &key, const std::optional<RuleId> winningRuleId,
    bool &truncated, std::optional<std::uint32_t> &omittedCandidateCount) const {
    truncated = false;
    omittedCandidateCount.reset();
    if (!_snap) {
        return {};
    }
    auto out = _snap->explainWould(key);
    ControlVNextStreamExplain::capCandidateSnapshots(
        out, winningRuleId, [](const auto &snapshot) { return snapshot.ruleId; }, truncated,
        omittedCandidateCount);
    return out;
}

void IpRulesEngine::observeEnforceHit(const Decision &decision, const std::uint32_t bytes,
                                      const std::uint64_t tsNs) {
    if (!decision.isEnforce() || decision.stats == nullptr) {
        return;
    }
    auto *s = reinterpret_cast<RuleStats *>(decision.stats);
    s->hitPackets.fetch_add(1, std::memory_order_relaxed);
    s->hitBytes.fetch_add(bytes, std::memory_order_relaxed);
    s->lastHitTsNs.store(tsNs, std::memory_order_relaxed);
}

void IpRulesEngine::observeWouldHitIfAccepted(const Decision &decision, const bool accepted,
                                              const std::uint32_t bytes, const std::uint64_t tsNs) {
    if (!accepted || !decision.isWould() || decision.stats == nullptr) {
        return;
    }
    auto *s = reinterpret_cast<RuleStats *>(decision.stats);
    s->wouldHitPackets.fetch_add(1, std::memory_order_relaxed);
    s->wouldHitBytes.fetch_add(bytes, std::memory_order_relaxed);
    s->lastWouldHitTsNs.store(tsNs, std::memory_order_relaxed);
}

std::uint64_t IpRulesEngine::rulesEpoch() const { return _rulesEpoch.load(std::memory_order_relaxed); }
