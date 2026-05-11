#include <Settings.hpp>

#include <cstdio>
#include <stdlib.h>
#include <string>

#include <unistd.h>

#include <gtest/gtest.h>

namespace {

class TempFile {
public:
    TempFile() {
        char tmpl[] = "/tmp/sucre-snort-settings-XXXXXX";
        const int fd = mkstemp(tmpl);
        if (fd < 0) {
            return;
        }
        close(fd);
        path_ = tmpl;
    }

    ~TempFile() {
        if (!path_.empty()) {
            std::remove(path_.c_str());
            std::remove((path_ + ".tmp").c_str());
        }
    }

    const std::string &path() const { return path_; }

private:
    std::string path_;
};

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

TEST(SettingsTest, LegacyKnobsRemainFrozenAfterSetters) {
    Settings settings;

    EXPECT_FALSE(settings.getBlackIPs());
    EXPECT_FALSE(settings.blockIPLeaks());
    EXPECT_EQ(settings.maxAgeIP(), Settings::legacyMaxAgeIPFrozenValue);

    settings.getBlackIPs(true);
    settings.blockIPLeaks(true);
    settings.maxAgeIP(1);

    EXPECT_FALSE(settings.getBlackIPs());
    EXPECT_FALSE(settings.blockIPLeaks());
    EXPECT_EQ(settings.maxAgeIP(), Settings::legacyMaxAgeIPFrozenValue);
}

TEST(SettingsTest, NfqueueTopologyDefaultsToSplitInOut) {
    Settings settings;

    EXPECT_EQ(settings.nfqueueTopology(), NfqueueTopology::SplitInOut);

    settings.nfqueueTopology(NfqueueTopology::SharedFlowPool);
    ASSERT_EQ(settings.nfqueueTopology(), NfqueueTopology::SharedFlowPool);

    settings.reset();
    EXPECT_EQ(settings.nfqueueTopology(), NfqueueTopology::SplitInOut);
}

TEST(SettingsTest, NfqueueTopologyPersistsInVersionNineSettings) {
    TempFile tmp;
    ASSERT_FALSE(tmp.path().empty());

    Settings settings;
    settings.setSaveFileOverrideForTesting(tmp.path());
    settings.nfqueueTopology(NfqueueTopology::SharedFlowPool);

    Settings restored;
    restored.setSaveFileOverrideForTesting(tmp.path());
    restored.restore();

    EXPECT_EQ(restored.savedVersion(), 9u);
    EXPECT_EQ(restored.nfqueueTopology(), NfqueueTopology::SharedFlowPool);
}

TEST(SettingsTest, NfqueueTopologyDefaultsForOlderSettingsFiles) {
    TempFile tmp;
    ASSERT_FALSE(tmp.path().empty());

    Saver saver(tmp.path());
    saver.save([&] {
        saver.write<bool>(true);
        saver.write<uint32_t>(8);
        saver.write<uint8_t>(static_cast<uint8_t>(Settings::standardListBit | Settings::customListBit));
        saver.write<uint8_t>(0);
        saver.write<uint8_t>(0);

        const std::string password;
        saver.write(password);

        saver.write<bool>(false);
        saver.write<bool>(false);
        saver.write<bool>(true);
        saver.write<std::time_t>(Settings::legacyMaxAgeIPFrozenValue);
    });

    Settings settings;
    settings.setSaveFileOverrideForTesting(tmp.path());
    settings.restore();

    EXPECT_EQ(settings.savedVersion(), 8u);
    EXPECT_TRUE(settings.ipRulesEnabled());
    EXPECT_EQ(settings.nfqueueTopology(), NfqueueTopology::SplitInOut);
}

TEST(SettingsTest, NfqueueTopologyInvalidPersistedValueFallsBackToSplitInOut) {
    TempFile tmp;
    ASSERT_FALSE(tmp.path().empty());

    Saver saver(tmp.path());
    saver.save([&] {
        saver.write<bool>(true);
        saver.write<uint32_t>(9);
        saver.write<uint8_t>(static_cast<uint8_t>(Settings::standardListBit | Settings::customListBit));
        saver.write<uint8_t>(0);
        saver.write<uint8_t>(0);

        const std::string password;
        saver.write(password);

        saver.write<bool>(false);
        saver.write<bool>(false);
        saver.write<bool>(true);
        saver.write<std::time_t>(Settings::legacyMaxAgeIPFrozenValue);
        saver.write(std::string("unsupported-topology"));
    });

    Settings settings;
    settings.setSaveFileOverrideForTesting(tmp.path());
    settings.restore();

    EXPECT_EQ(settings.savedVersion(), 9u);
    EXPECT_TRUE(settings.ipRulesEnabled());
    EXPECT_EQ(settings.nfqueueTopology(), NfqueueTopology::SplitInOut);
}

TEST(SettingsTest, RestoreIgnoresPersistedNonFrozenValuesForLegacyKnobs) {
    TempFile tmp;
    ASSERT_FALSE(tmp.path().empty());

    Saver saver(tmp.path());
    saver.save([&] {
        saver.write<bool>(true);
        saver.write<uint32_t>(8);
        saver.write<uint8_t>(static_cast<uint8_t>(Settings::standardListBit | Settings::customListBit));
        saver.write<uint8_t>(0);
        saver.write<uint8_t>(0);

        const std::string password;
        saver.write(password);

        saver.write<bool>(true);
        saver.write<bool>(true);
        saver.write<bool>(false);
        saver.write<std::time_t>(1);
    });

    Settings settings;
    settings.setSaveFileOverrideForTesting(tmp.path());
    settings.restore();

    EXPECT_FALSE(settings.getBlackIPs());
    EXPECT_FALSE(settings.blockIPLeaks());
    EXPECT_EQ(settings.maxAgeIP(), Settings::legacyMaxAgeIPFrozenValue);
}

} // namespace
