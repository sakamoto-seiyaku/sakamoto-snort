#include <AppStats.hpp>
#include <DomainStats.hpp>

#include <gtest/gtest.h>

namespace {

TEST(DomainStatsTest, UpdatesBlockedAcceptedAndAggregateViews) {
    DomainStats stats;

    stats.update(Stats::DNS, Stats::BLOCK, 3);
    stats.update(Stats::TXB, Stats::AUTH, 7);

    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::BLOCK), 3u);
    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::ALLB), 3u);
    EXPECT_EQ(stats.stat(Stats::ALL, Stats::DNS, Stats::BLOCK), 3u);
    EXPECT_EQ(stats.stat(Stats::WEEK, Stats::DNS, Stats::BLOCK), 3u);
    EXPECT_TRUE(stats.hasBlocked(Stats::DAY0));
    EXPECT_TRUE(stats.hasAccepted(Stats::DAY0));
}

TEST(DomainStatsTest, ResetClearsDayAndAllAccumulators) {
    DomainStats stats;

    stats.update(Stats::DNS, Stats::BLOCK, 2);
    stats.update(Stats::DNS, Stats::AUTH, 5);
    stats.reset(Stats::DAY0);

    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::ALLB), 0u);
    EXPECT_EQ(stats.stat(Stats::ALL, Stats::DNS, Stats::ALLB), 0u);
    EXPECT_FALSE(stats.hasBlocked(Stats::DAY0));
    EXPECT_FALSE(stats.hasAccepted(Stats::DAY0));
}

TEST(AppStatsTest, UpdatesColorBucketsAndTotals) {
    AppStats stats;

    stats.update(Stats::DNS, Stats::BLACK, Stats::BLOCK, 4);
    stats.update(Stats::DNS, Stats::WHITE, Stats::AUTH, 1);

    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::BLACK, Stats::BLOCK), 4u);
    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::ALLC, Stats::BLOCK), 4u);
    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::WHITE, Stats::AUTH), 1u);
    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::DNS, Stats::ALLC, Stats::ALLB), 5u);
    EXPECT_EQ(stats.stat(Stats::ALL, Stats::DNS, Stats::ALLC, Stats::ALLB), 5u);
    EXPECT_EQ(stats.stat(Stats::WEEK, Stats::DNS, Stats::ALLC, Stats::ALLB), 5u);
}

TEST(AppStatsTest, ResetClearsCurrentDayAndAllTotals) {
    AppStats stats;

    stats.update(Stats::TXB, Stats::GREY, Stats::AUTH, 9);
    stats.reset(Stats::DAY0);

    EXPECT_EQ(stats.stat(Stats::DAY0, Stats::TXB, Stats::ALLC, Stats::ALLB), 0u);
    EXPECT_EQ(stats.stat(Stats::ALL, Stats::TXB, Stats::ALLC, Stats::ALLB), 0u);
}

} // namespace
