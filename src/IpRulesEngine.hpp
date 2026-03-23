/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include <Saver.hpp>

class IpRulesEngine {
public:
    using RuleId = std::uint32_t;

    enum class Action : std::uint8_t { ALLOW = 0, BLOCK = 1 };
    enum class Direction : std::uint8_t { ANY = 0, IN = 1, OUT = 2 };
    // Values intentionally match PacketManager::IfaceBit for zero-copy interop.
    enum class IfaceKind : std::uint8_t {
        ANY = 0,
        WIFI = 1,
        DATA = 2,
        VPN = 4,
        UNMANAGED = 128,
    };
    enum class Proto : std::uint8_t { ANY = 0, TCP = 6, UDP = 17, ICMP = 1 };

    struct PortPredicate {
        enum class Kind : std::uint8_t { ANY = 0, EXACT = 1, RANGE = 2 };
        Kind kind = Kind::ANY;
        std::uint16_t lo = 0;
        std::uint16_t hi = 0;

        static PortPredicate any() { return {}; }
        static PortPredicate exact(const std::uint16_t port) {
            PortPredicate p;
            p.kind = Kind::EXACT;
            p.lo = port;
            p.hi = port;
            return p;
        }
        static PortPredicate range(const std::uint16_t lo_, const std::uint16_t hi_) {
            PortPredicate p;
            p.kind = Kind::RANGE;
            p.lo = lo_;
            p.hi = hi_;
            return p;
        }

        bool isAny() const { return kind == Kind::ANY; }
        bool isRange() const { return kind == Kind::RANGE; }
        bool matches(const std::uint16_t port) const;
    };

    struct CidrV4 {
        bool any = true;
        std::uint32_t addr = 0;   // host-byte-order
        std::uint8_t prefix = 0;  // 0..32

        static CidrV4 anyCidr() { return {}; }
        static CidrV4 cidr(const std::uint32_t addrHost, const std::uint8_t prefixLen) {
            CidrV4 c;
            c.any = false;
            c.addr = addrHost;
            c.prefix = prefixLen;
            return c;
        }

        std::uint32_t mask() const;
        bool matches(const std::uint32_t ipHost) const;
    };

    struct RuleDef {
        RuleId ruleId = 0;
        std::uint32_t uid = 0;

        Action action = Action::ALLOW;
        std::int32_t priority = 0;

        bool enabled = true;
        bool enforce = true;
        bool log = false;

        Direction dir = Direction::ANY;
        IfaceKind iface = IfaceKind::ANY;
        std::uint32_t ifindex = 0;  // 0 == any
        Proto proto = Proto::ANY;

        CidrV4 src = CidrV4::anyCidr();
        CidrV4 dst = CidrV4::anyCidr();
        PortPredicate sport = PortPredicate::any();
        PortPredicate dport = PortPredicate::any();

        bool hasPortConstraints() const { return !(sport.isAny() && dport.isAny()); }
        bool hasRangePorts() const { return sport.isRange() || dport.isRange(); }
        bool isWouldBlock() const { return action == Action::BLOCK && !enforce && log; }
    };

    struct RuleStatsSnapshot {
        std::uint64_t hitPackets = 0;
        std::uint64_t hitBytes = 0;
        std::uint64_t lastHitTsNs = 0;
        std::uint64_t wouldHitPackets = 0;
        std::uint64_t wouldHitBytes = 0;
        std::uint64_t lastWouldHitTsNs = 0;
    };

    struct PreflightLimitSet {
        std::uint64_t maxRulesTotal = 0;
        std::uint64_t maxSubtablesPerUid = 0;
        std::uint64_t maxRangeRulesPerBucket = 0;
    };

    struct PreflightIssue {
        std::string metric;
        std::uint64_t value = 0;
        std::uint64_t limit = 0;
        std::string message;
    };

    struct PreflightSummary {
        std::uint64_t rulesTotal = 0;
        std::uint64_t rangeRulesTotal = 0;
        std::uint64_t subtablesTotal = 0;
        std::uint64_t maxSubtablesPerUid = 0;
        std::uint64_t maxRangeRulesPerBucket = 0;
    };

    struct PreflightReport {
        PreflightSummary summary;
        PreflightLimitSet recommended;
        PreflightLimitSet hard;
        std::vector<PreflightIssue> warnings;
        std::vector<PreflightIssue> violations;

        bool ok() const { return violations.empty(); }
    };

    struct PacketKeyV4 {
        std::uint32_t uid = 0;
        std::uint8_t dir = 0;       // 0=in, 1=out
        std::uint8_t ifaceKind = 0; // engine kind: 0=unknown, 1=wifi, 2=data, 4=vpn, 128=unmanaged
        std::uint8_t proto = 0;     // IPPROTO_*
        std::uint32_t ifindex = 0;
        std::uint32_t srcIp = 0; // host-byte-order
        std::uint32_t dstIp = 0; // host-byte-order
        std::uint16_t srcPort = 0;
        std::uint16_t dstPort = 0;

        bool operator==(const PacketKeyV4 &o) const = default;
    };

    enum class DecisionKind : std::uint8_t { NOMATCH = 0, ALLOW = 1, BLOCK = 2, WOULD_BLOCK = 3 };

    struct Decision {
        DecisionKind kind = DecisionKind::NOMATCH;
        RuleId ruleId = 0;
        void *stats = nullptr; // opaque hot-path pointer (RuleStats*)
        // Keeps the underlying snapshot (and thus stats pointers) alive across concurrent publishes.
        std::shared_ptr<const void> keepAlive;

        bool matched() const { return kind != DecisionKind::NOMATCH; }
        bool isWould() const { return kind == DecisionKind::WOULD_BLOCK; }
        bool isEnforce() const { return kind == DecisionKind::ALLOW || kind == DecisionKind::BLOCK; }
    };

    struct ApplyResult {
        bool ok = false;
        std::optional<RuleId> ruleId;
        std::string error;
        PreflightReport preflight;
    };

    IpRulesEngine();
    ~IpRulesEngine();

    IpRulesEngine(const IpRulesEngine &) = delete;
    IpRulesEngine &operator=(const IpRulesEngine &) = delete;

    // Control-plane operations (thread-safe).
    ApplyResult addFromKv(const std::uint32_t uid, const std::vector<std::string> &kvTokens);
    ApplyResult updateFromKv(const RuleId ruleId, const std::vector<std::string> &kvTokens);
    ApplyResult removeRule(const RuleId ruleId);
    ApplyResult enableRule(const RuleId ruleId, const bool enabled);
    void resetAll();

    void save();
    void restore();

    PreflightReport preflight() const;

    std::optional<RuleDef> getRule(const RuleId ruleId) const;
    std::vector<RuleDef> listRules(const std::optional<std::uint32_t> uidFilter,
                                   const std::optional<RuleId> ruleFilter) const;
    std::optional<RuleStatsSnapshot> statsSnapshot(const RuleId ruleId) const;

    // Hot-path evaluation (lock-free).
    // Caller is responsible for gating on global switches (BLOCK/IPRULES) and IPv4-only.
    Decision evaluate(const PacketKeyV4 &key) const;
    static void observeEnforceHit(const Decision &decision, const std::uint32_t bytes,
                                  const std::uint64_t tsNs);
    static void observeWouldHitIfAccepted(const Decision &decision, const bool accepted,
                                          const std::uint32_t bytes, const std::uint64_t tsNs);

    // Exposed for tests: current rules epoch (monotonic).
    std::uint64_t rulesEpoch() const;

private:
    struct RuleStats {
        std::atomic<std::uint64_t> hitPackets{0};
        std::atomic<std::uint64_t> hitBytes{0};
        std::atomic<std::uint64_t> lastHitTsNs{0};
        std::atomic<std::uint64_t> wouldHitPackets{0};
        std::atomic<std::uint64_t> wouldHitBytes{0};
        std::atomic<std::uint64_t> lastWouldHitTsNs{0};

        RuleStatsSnapshot snapshot() const;
    };

    struct RuleState {
        RuleDef def;
        std::shared_ptr<RuleStats> stats;
    };

    struct Snapshot;

    using RulesMap = std::map<RuleId, RuleState>;

    static constexpr std::uint64_t kRecommendedMaxRulesTotal = 1000;
    static constexpr std::uint64_t kHardMaxRulesTotal = 5000;
    static constexpr std::uint64_t kRecommendedMaxSubtablesPerUid = 32;
    static constexpr std::uint64_t kHardMaxSubtablesPerUid = 64;
    static constexpr std::uint64_t kRecommendedMaxRangeRulesPerBucket = 16;
    static constexpr std::uint64_t kHardMaxRangeRulesPerBucket = 64;

    static std::optional<std::pair<std::string_view, std::string_view>>
    splitKv(const std::string &token);

    static bool parseBool01(const std::string_view v, bool &out);
    static bool parseAction(const std::string_view v, Action &out);
    static bool parseDirection(const std::string_view v, Direction &out);
    static bool parseIfaceKind(const std::string_view v, IfaceKind &out);
    static bool parseProto(const std::string_view v, Proto &out);
    static bool parseIfindex(const std::string_view v, std::uint32_t &outIfindex);
    static bool parsePriority(const std::string_view v, std::int32_t &outPriority);
    static bool parseCidrV4(const std::string_view v, CidrV4 &out);
    static bool parsePortPredicate(const std::string_view v, PortPredicate &out);

    static std::string normalizeAction(const Action a);
    static std::string normalizeDirection(const Direction d);
    static std::string normalizeIfaceKind(const IfaceKind k);
    static std::string normalizeProto(const Proto p);
    static std::string normalizeCidrV4(const CidrV4 &c);
    static std::string normalizePortPredicate(const PortPredicate &p);

    static bool validateRuleDef(const RuleDef &def, std::string &error);

    struct CompileResult {
        std::shared_ptr<const Snapshot> snapshot;
        PreflightReport report;
    };

    static CompileResult compile(const RulesMap &rules, const std::uint64_t rulesEpoch);

    ApplyResult applyNewRules(RulesMap &&newRules, const std::optional<RuleId> newRuleId);

private:
    mutable std::shared_mutex _mutex;
    RulesMap _rules;
    RuleId _nextRuleId = 0;
    std::atomic<std::uint64_t> _rulesEpoch{1};
    std::uint64_t _instanceId = 0;
    std::shared_ptr<const Snapshot> _snapshot;
    PreflightReport _lastPreflight;
    Saver _saver{"/data/snort/save/iprules"};
};
