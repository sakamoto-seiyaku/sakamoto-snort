#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>

TEST(SnortResetEpochTest, TransitionEpochsAreOddOnlyDuringReset) {
    const std::uint64_t before = snortResetEpoch();
    ASSERT_TRUE(snortResetEpochIsStable(before));
    ASSERT_TRUE(snortResetEpochStillCurrent(before));

    snortBeginResetEpoch();
    const std::uint64_t changing = snortResetEpoch();
    EXPECT_FALSE(snortResetEpochIsStable(changing));
    EXPECT_FALSE(snortResetEpochStillCurrent(before));
    EXPECT_FALSE(snortResetEpochStillCurrent(changing));

    snortEndResetEpoch();
    const std::uint64_t after = snortResetEpoch();
    EXPECT_TRUE(snortResetEpochIsStable(after));
    EXPECT_TRUE(snortResetEpochStillCurrent(after));
    EXPECT_FALSE(snortResetEpochStillCurrent(before));
}

TEST(SnortShutdownCoordinatorTest, RequestWakesTimedWait) {
    snortResetShutdownForTests();
    std::atomic_bool woke{false};

    std::thread waiter([&] {
        woke.store(snortWaitForShutdownFor(std::chrono::minutes(60)), std::memory_order_release);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    snortRequestShutdown();
    waiter.join();

    EXPECT_TRUE(woke.load(std::memory_order_acquire));
    EXPECT_TRUE(snortShutdownRequested());
    snortResetShutdownForTests();
}

TEST(SnortSessionBudgetTest, ControlBudgetIsBoundedAndReleasedByToken) {
    snortResetSessionBudgetsForTests();

    std::vector<SnortSessionBudgetToken> tokens;
    const std::uint32_t limit = snortSessionBudgetLimit(SnortSessionBudgetKind::Control);
    tokens.reserve(limit);
    for (std::uint32_t i = 0; i < limit; ++i) {
        auto token = snortTryAcquireSessionBudget(SnortSessionBudgetKind::Control);
        ASSERT_TRUE(token);
        tokens.push_back(std::move(token));
    }

    EXPECT_EQ(snortActiveSessions(SnortSessionBudgetKind::Control), limit);
    EXPECT_FALSE(snortTryAcquireSessionBudget(SnortSessionBudgetKind::Control));

    tokens.pop_back();
    EXPECT_EQ(snortActiveSessions(SnortSessionBudgetKind::Control), limit - 1);
    EXPECT_TRUE(snortTryAcquireSessionBudget(SnortSessionBudgetKind::Control));

    tokens.clear();
    snortResetSessionBudgetsForTests();
}
