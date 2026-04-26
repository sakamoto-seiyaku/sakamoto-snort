#include <sucre-snort.hpp>

#include <gtest/gtest.h>

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
