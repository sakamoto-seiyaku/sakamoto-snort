#include <IpRulesEngine.hpp>

#include <gtest/gtest.h>

#include <arpa/inet.h>

namespace {

static uint32_t ipHost(const char *s) {
    in_addr a{};
    if (inet_pton(AF_INET, s, &a) != 1) {
        return 0;
    }
    return ntohl(a.s_addr);
}

static IpRulesEngine::PacketKeyV4 keyAnyTcp(const uint32_t uid) {
    IpRulesEngine::PacketKeyV4 k{};
    k.uid = uid;
    k.dir = 0; // in
    k.ifaceKind = 1; // wifi
    k.proto = IPPROTO_TCP;
    k.ifindex = 10;
    k.srcIp = ipHost("10.0.0.1");
    k.dstIp = ipHost("93.184.216.34");
    k.srcPort = 12345;
    k.dstPort = 443;
    return k;
}

static IpRulesEngine::PacketKeyV4 keyAnyTcpOut(const uint32_t uid) {
    auto k = keyAnyTcp(uid);
    k.dir = 1; // out
    return k;
}

TEST(IpRulesEngineTest, AddRejectsMissingPriorityAndDoesNotConsumeRuleId) {
    IpRulesEngine eng;

    const auto r0 = eng.addFromKv(10000, {"action=block"});
    EXPECT_FALSE(r0.ok);
    EXPECT_FALSE(r0.ruleId.has_value());
    EXPECT_TRUE(eng.listRules(std::nullopt, std::nullopt).empty());

    const auto r1 = eng.addFromKv(10000, {"action=block", "priority=10"});
    ASSERT_TRUE(r1.ok);
    ASSERT_TRUE(r1.ruleId.has_value());
    EXPECT_EQ(*r1.ruleId, 0u);
}

TEST(IpRulesEngineTest, AddDefaultsAreNormalizedAndUnknownKeysAreRejectedAtomically) {
    IpRulesEngine eng;

    const auto bad = eng.addFromKv(10000, {"action=block", "priority=10", "bogus=1"});
    EXPECT_FALSE(bad.ok);
    EXPECT_TRUE(eng.listRules(std::nullopt, std::nullopt).empty());

    const auto ok = eng.addFromKv(10000, {"action=block", "priority=10"});
    ASSERT_TRUE(ok.ok);
    ASSERT_TRUE(ok.ruleId.has_value());

    const auto rule = eng.getRule(*ok.ruleId);
    ASSERT_TRUE(rule.has_value());
    EXPECT_EQ(rule->uid, 10000u);
    EXPECT_EQ(rule->ruleId, 0u);
    EXPECT_EQ(rule->action, IpRulesEngine::Action::BLOCK);
    EXPECT_EQ(rule->priority, 10);
    EXPECT_TRUE(rule->enabled);
    EXPECT_TRUE(rule->enforce);
    EXPECT_FALSE(rule->log);
    EXPECT_EQ(rule->dir, IpRulesEngine::Direction::ANY);
    EXPECT_EQ(rule->iface, IpRulesEngine::IfaceKind::ANY);
    EXPECT_EQ(rule->ifindex, 0u);
    EXPECT_EQ(rule->proto, IpRulesEngine::Proto::ANY);
    EXPECT_TRUE(rule->src.any);
    EXPECT_TRUE(rule->dst.any);
    EXPECT_TRUE(rule->sport.isAny());
    EXPECT_TRUE(rule->dport.isAny());
}

TEST(IpRulesEngineTest, EnforceZeroIsOnlyAllowedForWouldBlockAndCtIsRejected) {
    IpRulesEngine eng;

    EXPECT_FALSE(eng.addFromKv(10000, {"action=allow", "priority=1", "enforce=0"}).ok);
    EXPECT_FALSE(eng.addFromKv(10000, {"action=block", "priority=1", "enforce=0"}).ok);
    EXPECT_FALSE(eng.addFromKv(10000, {"action=block", "priority=1", "enforce=0", "log=0"}).ok);

    const auto wouldOk =
        eng.addFromKv(10000, {"action=block", "priority=1", "enforce=0", "log=1"});
    ASSERT_TRUE(wouldOk.ok);
    ASSERT_TRUE(wouldOk.ruleId.has_value());
    const auto w = eng.getRule(*wouldOk.ruleId);
    ASSERT_TRUE(w.has_value());
    EXPECT_TRUE(w->isWouldBlock());

    EXPECT_FALSE(eng.addFromKv(10000, {"action=block", "priority=2", "ct=foo"}).ok);
}

TEST(IpRulesEngineTest, UpdateIsPatchSemanticsAndRejectsUnknownKeysWithoutMutation) {
    IpRulesEngine eng;

    const auto add =
        eng.addFromKv(10000, {"action=allow", "priority=10", "log=1", "dport=80"});
    ASSERT_TRUE(add.ok);
    ASSERT_TRUE(add.ruleId.has_value());

    const auto upd = eng.updateFromKv(*add.ruleId, {"dport=443"});
    EXPECT_TRUE(upd.ok);

    const auto rule1 = eng.getRule(*add.ruleId);
    ASSERT_TRUE(rule1.has_value());
    EXPECT_EQ(rule1->dport.kind, IpRulesEngine::PortPredicate::Kind::EXACT);
    EXPECT_EQ(rule1->dport.lo, 443);
    EXPECT_TRUE(rule1->log) << "UPDATE MUST preserve omitted fields (patch semantics)";

    const auto bad = eng.updateFromKv(*add.ruleId, {"bogus=1"});
    EXPECT_FALSE(bad.ok);

    const auto rule2 = eng.getRule(*add.ruleId);
    ASSERT_TRUE(rule2.has_value());
    EXPECT_EQ(rule2->dport.lo, 443) << "NOK UPDATE MUST be atomic (no mutation)";
    EXPECT_TRUE(rule2->log) << "NOK UPDATE MUST be atomic (no mutation)";
}

TEST(IpRulesEngineTest, DeterministicWinnerUsesPriorityThenStableTieBreak) {
    IpRulesEngine eng;

    const auto a = eng.addFromKv(10000, {"action=allow", "priority=10", "proto=tcp"});
    const auto b = eng.addFromKv(10000, {"action=block", "priority=20", "proto=tcp"});
    ASSERT_TRUE(a.ok && b.ok);

    const auto key = keyAnyTcp(10000);
    const auto d = eng.evaluate(key);
    EXPECT_EQ(d.kind, IpRulesEngine::DecisionKind::BLOCK);
    EXPECT_EQ(d.ruleId, *b.ruleId);

    IpRulesEngine eng2;
    const auto t1 = eng2.addFromKv(10000, {"action=allow", "priority=10", "proto=tcp"});
    const auto t2 = eng2.addFromKv(10000, {"action=block", "priority=10", "proto=tcp"});
    ASSERT_TRUE(t1.ok && t2.ok);
    const auto d2 = eng2.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(d2.kind, IpRulesEngine::DecisionKind::ALLOW);
    EXPECT_EQ(d2.ruleId, *t1.ruleId) << "Same-priority overlap MUST be deterministic";
}

TEST(IpRulesEngineTest, EnforceMatchAlwaysSuppressesWouldMatchRegardlessOfPriority) {
    IpRulesEngine eng;

    const auto enforceAllow =
        eng.addFromKv(10000, {"action=allow", "priority=10", "proto=tcp"});
    const auto wouldBlock =
        eng.addFromKv(10000, {"action=block", "priority=100", "proto=tcp", "enforce=0", "log=1"});
    ASSERT_TRUE(enforceAllow.ok && wouldBlock.ok);

    const auto d = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(d.kind, IpRulesEngine::DecisionKind::ALLOW);
    EXPECT_EQ(d.ruleId, *enforceAllow.ruleId);
}

TEST(IpRulesEngineTest, WouldMatchOnlyWhenNoEnforceRuleMatches) {
    IpRulesEngine eng;

    const auto w =
        eng.addFromKv(10000, {"action=block", "priority=1", "proto=tcp", "enforce=0", "log=1"});
    ASSERT_TRUE(w.ok);

    const auto d = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(d.kind, IpRulesEngine::DecisionKind::WOULD_BLOCK);
    EXPECT_EQ(d.ruleId, *w.ruleId);
}

TEST(IpRulesEngineTest, PreflightCountsOnlyEnabledRulesAndFlagsRangeBucketOverload) {
    IpRulesEngine eng;

    // Force multiple mask signatures (subtables) for a single UID.
    ASSERT_TRUE(eng.addFromKv(10000, {"action=allow", "priority=1"}).ok);            // any/any
    ASSERT_TRUE(eng.addFromKv(10000, {"action=allow", "priority=2", "proto=tcp"}).ok); // proto=tcp

    // Add enough range rules to exceed the recommended range-per-bucket limit (16).
    for (int i = 0; i < 17; ++i) {
        ASSERT_TRUE(
            eng.addFromKv(10000,
                          {"action=block", "priority=10", "proto=tcp", "enforce=0", "log=1",
                           "dport=1000-2000"}).ok);
    }

    // Disabled rules MUST NOT count toward active complexity.
    ASSERT_TRUE(
        eng.addFromKv(10000,
                      {"action=block", "priority=10", "proto=tcp", "enforce=0", "log=1",
                       "enabled=0", "dport=2000-3000"}).ok);

    const auto rep = eng.preflight();
    EXPECT_GE(rep.summary.rulesTotal, 1u);
    EXPECT_EQ(rep.summary.subtablesTotal, 2u);
    EXPECT_EQ(rep.summary.maxSubtablesPerUid, 2u);
    EXPECT_GE(rep.summary.rangeRulesTotal, 17u);
    EXPECT_GE(rep.summary.maxRangeRulesPerBucket, 17u);
    EXPECT_TRUE(rep.ok());
    EXPECT_FALSE(rep.warnings.empty()) << "Expected at least one warning for range bucket overload";
    EXPECT_TRUE(rep.violations.empty());
}

TEST(IpRulesEngineTest, UpdateAndReEnableResetRuntimeStatsAndCacheEpochPreventsStaleStatsPtr) {
    IpRulesEngine eng;

    const auto add =
        eng.addFromKv(10000, {"action=allow", "priority=10", "proto=tcp"});
    ASSERT_TRUE(add.ok);
    ASSERT_TRUE(add.ruleId.has_value());
    const auto rid = *add.ruleId;

    const auto d0 = eng.evaluate(keyAnyTcp(10000));
    ASSERT_EQ(d0.kind, IpRulesEngine::DecisionKind::ALLOW);
    IpRulesEngine::observeEnforceHit(d0, 100, 1);
    {
        const auto s = eng.statsSnapshot(rid);
        ASSERT_TRUE(s.has_value());
        EXPECT_EQ(s->hitPackets, 1u);
    }

    // UPDATE must clear stats and MUST NOT be contaminated by a stale cache entry (epoch mismatch).
    ASSERT_TRUE(eng.updateFromKv(rid, {"priority=11"}).ok);
    {
        const auto s = eng.statsSnapshot(rid);
        ASSERT_TRUE(s.has_value());
        EXPECT_EQ(s->hitPackets, 0u);
    }
    const auto d1 = eng.evaluate(keyAnyTcp(10000));
    ASSERT_EQ(d1.kind, IpRulesEngine::DecisionKind::ALLOW);
    IpRulesEngine::observeEnforceHit(d1, 100, 2);
    {
        const auto s = eng.statsSnapshot(rid);
        ASSERT_TRUE(s.has_value());
        EXPECT_EQ(s->hitPackets, 1u);
    }

    // ENABLE 0->1 must also clear stats.
    ASSERT_TRUE(eng.enableRule(rid, false).ok);
    const auto d2 = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(d2.kind, IpRulesEngine::DecisionKind::NOMATCH);
    ASSERT_TRUE(eng.enableRule(rid, true).ok);
    {
        const auto s = eng.statsSnapshot(rid);
        ASSERT_TRUE(s.has_value());
        EXPECT_EQ(s->hitPackets, 0u);
    }
}

TEST(IpRulesEngineTest, MatchRespectsDirection) {
    IpRulesEngine eng;

    ASSERT_TRUE(eng.addFromKv(10000, {"action=allow", "priority=1", "proto=tcp", "dir=out"}).ok);

    const auto in = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(in.kind, IpRulesEngine::DecisionKind::NOMATCH);

    const auto out = eng.evaluate(keyAnyTcpOut(10000));
    EXPECT_EQ(out.kind, IpRulesEngine::DecisionKind::ALLOW);
}

TEST(IpRulesEngineTest, MatchRespectsIfaceKindAndIfindex) {
    IpRulesEngine eng;

    ASSERT_TRUE(eng.addFromKv(10000, {"action=block", "priority=1", "proto=tcp", "iface=wifi", "ifindex=10"}).ok);

    const auto ok = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(ok.kind, IpRulesEngine::DecisionKind::BLOCK);

    auto wrongIface = keyAnyTcp(10000);
    wrongIface.ifaceKind = 2; // data
    EXPECT_EQ(eng.evaluate(wrongIface).kind, IpRulesEngine::DecisionKind::NOMATCH);

    auto wrongIfindex = keyAnyTcp(10000);
    wrongIfindex.ifindex = 11;
    EXPECT_EQ(eng.evaluate(wrongIfindex).kind, IpRulesEngine::DecisionKind::NOMATCH);
}

TEST(IpRulesEngineTest, MatchRespectsCidrAndPorts) {
    IpRulesEngine eng;

    // Exact port rule (dst in 93.184.216.0/24 and dport=443).
    ASSERT_TRUE(eng.addFromKv(10000, {"action=block", "priority=1", "proto=tcp", "dst=93.184.216.0/24", "dport=443"}).ok);

    const auto ok = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(ok.kind, IpRulesEngine::DecisionKind::BLOCK);

    auto wrongDst = keyAnyTcp(10000);
    wrongDst.dstIp = ipHost("93.184.217.1");
    EXPECT_EQ(eng.evaluate(wrongDst).kind, IpRulesEngine::DecisionKind::NOMATCH);

    auto wrongPort = keyAnyTcp(10000);
    wrongPort.dstPort = 444;
    EXPECT_EQ(eng.evaluate(wrongPort).kind, IpRulesEngine::DecisionKind::NOMATCH);

    // Range port with higher priority wins over exact when both match.
    ASSERT_TRUE(eng.addFromKv(10000, {"action=allow", "priority=10", "proto=tcp", "dport=443"}).ok);
    ASSERT_TRUE(eng.addFromKv(10000, {"action=block", "priority=20", "proto=tcp", "dport=400-500"}).ok);
    const auto mixed = eng.evaluate(keyAnyTcp(10000));
    EXPECT_EQ(mixed.kind, IpRulesEngine::DecisionKind::BLOCK);
}

} // namespace
