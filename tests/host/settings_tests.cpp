#include <Settings.hpp>

#include <gtest/gtest.h>

namespace {

TEST(SettingsTest, BlockingListMaskValidationMatchesInterfaceContract) {
    EXPECT_TRUE(Settings::isValidBlockingListMask(1u));
    EXPECT_TRUE(Settings::isValidBlockingListMask(2u));
    EXPECT_TRUE(Settings::isValidBlockingListMask(4u));
    EXPECT_TRUE(Settings::isValidBlockingListMask(8u));
    EXPECT_TRUE(Settings::isValidBlockingListMask(16u));
    EXPECT_TRUE(Settings::isValidBlockingListMask(32u));
    EXPECT_TRUE(Settings::isValidBlockingListMask(64u));

    EXPECT_FALSE(Settings::isValidBlockingListMask(0u));
    EXPECT_FALSE(Settings::isValidBlockingListMask(3u));
    EXPECT_FALSE(Settings::isValidBlockingListMask(128u));
}

TEST(SettingsTest, AppBlockMaskValidationAndNormalizationMatchDocumentedSemantics) {
    EXPECT_TRUE(Settings::isValidAppBlockMask(0u));
    EXPECT_TRUE(Settings::isValidAppBlockMask(129u));
    EXPECT_TRUE(Settings::isValidAppBlockMask(255u));
    EXPECT_FALSE(Settings::isValidAppBlockMask(256u));

    EXPECT_EQ(Settings::normalizeAppBlockMask(0u), 0u);
    EXPECT_EQ(Settings::normalizeAppBlockMask(Settings::standardListBit),
              Settings::standardListBit);
    EXPECT_EQ(Settings::normalizeAppBlockMask(Settings::reinforcedListBit),
              static_cast<uint8_t>(Settings::reinforcedListBit | Settings::standardListBit));
}

TEST(SettingsTest, PerUserPathsFollowCurrentPersistenceLayout) {
    EXPECT_EQ(Settings::systemUserDir(10), "/data/system/users/10");
    EXPECT_EQ(Settings::packageRestrictionsPath(10),
              "/data/system/users/10/package-restrictions.xml");

    EXPECT_EQ(Settings::userSaveDirPackages(0), Settings::saveDirPackages);
    EXPECT_EQ(Settings::userSaveDirSystem(0), Settings::saveDirSystem);
    EXPECT_EQ(Settings::userSaveDirPackages(10), "/data/snort/save/user10/packages/");
    EXPECT_EQ(Settings::userSaveDirSystem(10), "/data/snort/save/user10/system/");
}

} // namespace
