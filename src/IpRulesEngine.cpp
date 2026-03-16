/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <IpRulesEngine.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <climits>
#include <cstring>
#include <limits>
#include <system_error>
#include <unordered_map>

#include <arpa/inet.h>

namespace {

static constexpr std::int32_t kNoPriority = std::numeric_limits<std::int32_t>::min();

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

static inline uint32_t maskFromPrefix(const uint8_t prefix) noexcept {
    if (prefix == 0) {
        return 0u;
    }
    if (prefix >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32u - prefix);
}

template <class T> static bool parseDec(const std::string_view s, T &out) {
    if (s.empty()) {
        return false;
    }
    T v{};
    const char *begin = s.data();
    const char *end = s.data() + s.size();
    auto res = std::from_chars(begin, end, v);
    if (res.ec != std::errc() || res.ptr != end) {
        return false;
    }
    out = v;
    return true;
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
    out.addr = ntohl(a.s_addr);
    out.prefix = static_cast<std::uint8_t>(prefix);
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
    if (!def.enforce) {
        if (!(def.action == Action::BLOCK && def.log)) {
            error = "enforce=0 is only supported for action=block,log=1";
            return false;
        }
    }
    if (def.proto == Proto::ICMP) {
        if (!def.sport.isAny() || !def.dport.isAny()) {
            error = "proto=icmp requires sport=any and dport=any";
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
        Action action = Action::ALLOW;
        std::int32_t priority = 0;
        bool enforce = true;

        Direction dir = Direction::ANY;
        IfaceKind iface = IfaceKind::ANY;
        std::uint32_t ifindex = 0;
        Proto proto = Proto::ANY;

        CidrV4 src = CidrV4::anyCidr();
        CidrV4 dst = CidrV4::anyCidr();
        PortPredicate sport = PortPredicate::any();
        PortPredicate dport = PortPredicate::any();

        RuleStats *stats = nullptr;
        std::shared_ptr<RuleStats> statsStrong;

        bool matches(const PacketKeyV4 &k) const {
            if (uid != k.uid) return false;
            const bool packetTcpUdp = (k.proto == static_cast<uint8_t>(Proto::TCP) ||
                                       k.proto == static_cast<uint8_t>(Proto::UDP));
            if (!packetTcpUdp) {
                // Port predicates apply to TCP/UDP only.
                if (!sport.isAny() || !dport.isAny()) return false;
            }
            if (dir == Direction::IN && k.dir != 0) return false;
            if (dir == Direction::OUT && k.dir != 1) return false;
            if (iface != IfaceKind::ANY && k.ifaceKind != static_cast<uint8_t>(iface)) return false;
            if (ifindex != 0 && k.ifindex != ifindex) return false;
            if (proto != Proto::ANY && k.proto != static_cast<uint8_t>(proto)) return false;
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
            const std::int32_t pExact = exact ? exact->priority : kNoPriority;

            for (const auto &cand : rangeEnforce) {
                if (exact && cand.priority <= pExact) {
                    break;
                }
                if (cand.matches(k)) {
                    return &cand;
                }
            }

            if (exact) {
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
            const std::int32_t pExact = exact ? exact->priority : kNoPriority;

            for (const auto &cand : rangeWould) {
                if (exact && cand.priority <= pExact) {
                    break;
                }
                if (cand.matches(k)) {
                    return &cand;
                }
            }

            if (exact) {
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
    };

    std::uint64_t rulesEpoch = 0;
    std::unordered_map<std::uint32_t, UidView> byUid;

    static MaskSig maskSigForRule(const RuleDef &r) {
        MaskSig s{};
        s.dir = (r.dir != Direction::ANY);
        s.iface = (r.iface != IfaceKind::ANY);
        s.ifindex = (r.ifindex != 0);
        s.proto = (r.proto != Proto::ANY);
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
        mk.ifindex = sig.ifindex ? r.ifindex : 0;
        mk.srcIpMasked = (sig.srcPrefix == 255) ? 0 : (r.src.addr & maskFromPrefix(sig.srcPrefix));
        mk.dstIpMasked = (sig.dstPrefix == 255) ? 0 : (r.dst.addr & maskFromPrefix(sig.dstPrefix));
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

    std::map<std::uint32_t, std::map<Snapshot::MaskSig, Snapshot::Subtable, Snapshot::MaskSigLess>>
        uidTables;

    std::uint64_t maxRangeBucket = 0;

    for (const auto &[_, state] : rules) {
        const RuleDef &def = state.def;
        if (!def.enabled) {
            continue;
        }

        report.summary.rulesTotal++;
        if (def.hasRangePorts()) {
            report.summary.rangeRulesTotal++;
        }

        const Snapshot::MaskSig sig = Snapshot::maskSigForRule(def);
        Snapshot::Subtable &st = uidTables[def.uid][sig];
        st.sig = sig;

        const Snapshot::MaskedKey mk = Snapshot::maskedKeyFromRule(sig, def);
        Snapshot::Bucket &bucket = st.buckets[mk];

        Snapshot::RuleRef ref{};
        ref.ruleId = def.ruleId;
        ref.uid = def.uid;
        ref.action = def.action;
        ref.priority = def.priority;
        ref.enforce = def.enforce;
        ref.dir = def.dir;
        ref.iface = def.iface;
        ref.ifindex = def.ifindex;
        ref.proto = def.proto;
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
                maxRangeBucket =
                    std::max<std::uint64_t>(maxRangeBucket, bucket.rangeEnforce.size() + bucket.rangeWould.size());
            } else {
                bucket.exactEnforce.push_back(std::move(ref));
            }
        } else {
            st.maxWouldPriority = std::max(st.maxWouldPriority, def.priority);
            if (def.hasRangePorts()) {
                bucket.rangeWould.push_back(std::move(ref));
                maxRangeBucket =
                    std::max<std::uint64_t>(maxRangeBucket, bucket.rangeEnforce.size() + bucket.rangeWould.size());
            } else {
                bucket.exactWould.push_back(std::move(ref));
            }
        }
    }

    auto snap = std::make_shared<Snapshot>();
    snap->rulesEpoch = rulesEpoch;

    report.summary.subtablesTotal = 0;
    report.summary.maxSubtablesPerUid = 0;
    report.summary.maxRangeRulesPerBucket = maxRangeBucket;

    for (auto &[uid, subtablesMap] : uidTables) {
        Snapshot::UidView view{};
        view.subtables.reserve(subtablesMap.size());
        for (auto &[_, st] : subtablesMap) {
            for (auto &[_, bucket] : st.buckets) {
                bucket.sortAll();
            }
            view.subtables.push_back(std::move(st));
        }

        const size_t n = view.subtables.size();
        report.summary.subtablesTotal += static_cast<std::uint64_t>(n);
        report.summary.maxSubtablesPerUid =
            std::max<std::uint64_t>(report.summary.maxSubtablesPerUid, n);

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

    if (report.summary.maxSubtablesPerUid > kHardMaxSubtablesPerUid) {
        addIssue(report.violations, "maxSubtablesPerUid", report.summary.maxSubtablesPerUid,
                 kHardMaxSubtablesPerUid, "subtables per uid exceed hard limit");
    } else if (report.summary.maxSubtablesPerUid > kRecommendedMaxSubtablesPerUid) {
        addIssue(report.warnings, "maxSubtablesPerUid", report.summary.maxSubtablesPerUid,
                 kRecommendedMaxSubtablesPerUid, "subtables per uid exceed recommended limit");
    }

    if (report.summary.maxRangeRulesPerBucket > kHardMaxRangeRulesPerBucket) {
        addIssue(report.violations, "maxRangeRulesPerBucket", report.summary.maxRangeRulesPerBucket,
                 kHardMaxRangeRulesPerBucket, "range candidates per bucket exceed hard limit");
    } else if (report.summary.maxRangeRulesPerBucket > kRecommendedMaxRangeRulesPerBucket) {
        addIssue(report.warnings, "maxRangeRulesPerBucket", report.summary.maxRangeRulesPerBucket,
                 kRecommendedMaxRangeRulesPerBucket, "range candidates per bucket exceed recommended limit");
    }

    return CompileResult{.snapshot = std::move(snap), .report = std::move(report)};
}

IpRulesEngine::IpRulesEngine() {
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
        constexpr uint32_t kFormatVersion = 1;
        _saver.write<uint32_t>(kFormatVersion);
        _saver.write<RuleId>(nextRuleId);
        _saver.write<uint32_t>(static_cast<uint32_t>(defs.size()));

        for (const auto &d : defs) {
            _saver.write<RuleId>(d.ruleId);
            _saver.write<uint32_t>(d.uid);
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

            _saver.write<uint8_t>(static_cast<uint8_t>(d.sport.kind));
            _saver.write<uint16_t>(d.sport.lo);
            _saver.write<uint16_t>(d.sport.hi);

            _saver.write<uint8_t>(static_cast<uint8_t>(d.dport.kind));
            _saver.write<uint16_t>(d.dport.lo);
            _saver.write<uint16_t>(d.dport.hi);
        }
    });
}

void IpRulesEngine::restore() {
    _saver.restore([&] {
        const auto formatVersion = _saver.read<uint32_t>();
        if (formatVersion != 1) {
            throw RestoreException();
        }

        RuleId nextRuleId = _saver.read<RuleId>();
        const auto count = _saver.read<uint32_t>();

        RulesMap restored;
        restored.clear();

        RuleId maxSeenId = 0;
        bool hasAny = false;

        for (uint32_t i = 0; i < count; ++i) {
            RuleDef d{};
            d.ruleId = _saver.read<RuleId>();
            d.uid = _saver.read<uint32_t>();
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

            d.dst.any = _saver.read<bool>();
            d.dst.addr = _saver.read<uint32_t>();
            d.dst.prefix = _saver.read<uint8_t>();

            d.sport.kind = static_cast<PortPredicate::Kind>(_saver.read<uint8_t>());
            d.sport.lo = _saver.read<uint16_t>();
            d.sport.hi = _saver.read<uint16_t>();

            d.dport.kind = static_cast<PortPredicate::Kind>(_saver.read<uint8_t>());
            d.dport.lo = _saver.read<uint16_t>();
            d.dport.hi = _saver.read<uint16_t>();

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
    });
}

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
    return h;
}

IpRulesEngine::Decision IpRulesEngine::evaluate(const PacketKeyV4 &key) const {
    const auto snap = std::atomic_load_explicit(&_snapshot, std::memory_order_acquire);
    Decision out{};
    out.keepAlive = snap;
    if (!snap) {
        return out;
    }

    struct CacheEntry {
        std::uint64_t epoch = 0;
        PacketKeyV4 key{};
        DecisionKind kind = DecisionKind::NOMATCH;
        RuleId ruleId = 0;
        void *stats = nullptr;
    };

    struct Cache {
        const IpRulesEngine *owner = nullptr;
        std::array<CacheEntry, 1024> entries{};
    };

    thread_local Cache cache;
    if (cache.owner != this) {
        cache.owner = this;
        for (auto &e : cache.entries) {
            e.epoch = 0;
        }
    }

    const std::uint64_t epoch = snap->rulesEpoch;
    const size_t idx = hashPacketKey(key) & (cache.entries.size() - 1);
    CacheEntry &e = cache.entries[idx];
    if (e.epoch == epoch && e.key == key) {
        out.kind = e.kind;
        out.ruleId = e.ruleId;
        out.stats = e.stats;
        return out;
    }

    const auto d = snap->evaluate(key);

    e.epoch = epoch;
    e.key = key;
    e.kind = d.kind;
    e.ruleId = d.ruleId;
    e.stats = d.stats;

    out.kind = d.kind;
    out.ruleId = d.ruleId;
    out.stats = d.stats;
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
