#include <gtest/gtest.h>

#include <App.hpp>
#include <DomainManager.hpp>
#include <DomainPolicySources.hpp>
#include <DomainPolicySourcesMetrics.hpp>
#include <RulesManager.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
DomainManager domManager;
RulesManager rulesManager;
std::shared_mutex mutexListeners;

namespace {

class DomainPolicySourcesAttributionTest : public ::testing::Test {
protected:
    void SetUp() override {
        settings.reset();
        domManager.reset();
        rulesManager.reset();
    }
};

TEST(DomainPolicySourcesMetricsTest, StartsZeroObserveReset) {
    DomainPolicySourcesMetrics metrics;

    auto snap = metrics.snapshot();
    for (const auto src : kDomainPolicySources) {
        const size_t idx = static_cast<size_t>(src);
        EXPECT_EQ(snap.sources[idx].allow, 0U);
        EXPECT_EQ(snap.sources[idx].block, 0U);
        EXPECT_NE(domainPolicySourceStr(src), nullptr);
    }

    metrics.observe(DomainPolicySource::CUSTOM_WHITELIST, false);
    metrics.observe(DomainPolicySource::CUSTOM_WHITELIST, false);
    metrics.observe(DomainPolicySource::CUSTOM_BLACKLIST, true);

    snap = metrics.snapshot();
    EXPECT_EQ(snap.sources[static_cast<size_t>(DomainPolicySource::CUSTOM_WHITELIST)].allow, 2U);
    EXPECT_EQ(snap.sources[static_cast<size_t>(DomainPolicySource::CUSTOM_BLACKLIST)].block, 1U);

    metrics.reset();
    snap = metrics.snapshot();
    for (const auto src : kDomainPolicySources) {
        const size_t idx = static_cast<size_t>(src);
        EXPECT_EQ(snap.sources[idx].allow, 0U);
        EXPECT_EQ(snap.sources[idx].block, 0U);
    }
}

TEST(DomainPolicySourcesCountersTest, StartsZeroObserveReset) {
    DomainPolicySourcesCounters counters;

    auto snap = counters.snapshot();
    for (const auto src : kDomainPolicySources) {
        const size_t idx = static_cast<size_t>(src);
        EXPECT_EQ(snap.sources[idx].allow, 0U);
        EXPECT_EQ(snap.sources[idx].block, 0U);
    }

    counters.observe(DomainPolicySource::GLOBAL_AUTHORIZED, false);
    counters.observe(DomainPolicySource::GLOBAL_AUTHORIZED, false);
    counters.observe(DomainPolicySource::GLOBAL_BLOCKED, true);

    snap = counters.snapshot();
    EXPECT_EQ(snap.sources[static_cast<size_t>(DomainPolicySource::GLOBAL_AUTHORIZED)].allow, 2U);
    EXPECT_EQ(snap.sources[static_cast<size_t>(DomainPolicySource::GLOBAL_BLOCKED)].block, 1U);

    counters.reset();
    snap = counters.snapshot();
    for (const auto src : kDomainPolicySources) {
        const size_t idx = static_cast<size_t>(src);
        EXPECT_EQ(snap.sources[idx].allow, 0U);
        EXPECT_EQ(snap.sources[idx].block, 0U);
    }
}

TEST_F(DomainPolicySourcesAttributionTest, CustomWhitelistHasHighestPriority) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");
    app->addCustomDomain("example.com", Stats::WHITE);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_FALSE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::CUSTOM_WHITELIST);
}

TEST_F(DomainPolicySourcesAttributionTest, CustomBlacklistMatches) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");
    app->addCustomDomain("example.com", Stats::BLACK);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_TRUE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::CUSTOM_BLACKLIST);
}

TEST_F(DomainPolicySourcesAttributionTest, CustomWhiteRuleMatches) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");

    const auto rule = std::make_shared<Rule>(Rule::DOMAIN, 1, "example.com");
    ASSERT_TRUE(rule->valid());

    app->addCustomRule(rule, true, Stats::WHITE);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_FALSE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::CUSTOM_RULE_WHITE);
}

TEST_F(DomainPolicySourcesAttributionTest, CustomBlackRuleMatches) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");

    const auto rule = std::make_shared<Rule>(Rule::DOMAIN, 2, "example.com");
    ASSERT_TRUE(rule->valid());

    app->addCustomRule(rule, true, Stats::BLACK);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_TRUE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::CUSTOM_RULE_BLACK);
}

TEST_F(DomainPolicySourcesAttributionTest, GlobalAuthorizedMatches) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");

    domManager.addCustomDomain("example.com", Stats::WHITE);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_FALSE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::GLOBAL_AUTHORIZED);
}

TEST_F(DomainPolicySourcesAttributionTest, GlobalBlockedMatches) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");

    domManager.addCustomDomain("example.com", Stats::BLACK);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_TRUE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::GLOBAL_BLOCKED);
}

TEST_F(DomainPolicySourcesAttributionTest, UseCustomListOffCollapsesToMaskFallback) {
    auto app = std::make_shared<App>(0, "root");
    const auto domain = domManager.make("example.com");

    domManager.addCustomDomain("example.com", Stats::BLACK);
    app->useCustomList(false);

    // Force a fallback-block via mask bits.
    app->blockMask(Settings::standardListBit);
    domain->blockMask(Settings::standardListBit);

    const auto bc = app->blocked(domain);
    const auto bcs = app->blockedWithSource(domain);

    EXPECT_TRUE(bc.first);
    EXPECT_EQ(bc.first, bcs.blocked);
    EXPECT_EQ(bc.second, bcs.color);
    EXPECT_EQ(bcs.policySource, DomainPolicySource::MASK_FALLBACK);
}

} // namespace

