/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeProfile.hpp>

#include <gtest/gtest.h>

TEST(RuntimeProfileSelection, AcceptsRootAndVpnWireNames) {
    const auto root = SnortRuntime::parseRuntimeProfile("root");
    ASSERT_TRUE(root.ok);
    EXPECT_EQ(root.profile, SnortRuntime::RuntimeProfile::Root);
    EXPECT_EQ(SnortRuntime::runtimeProfileName(root.profile), "root");

    const auto vpn = SnortRuntime::parseRuntimeProfile("vpn");
    ASSERT_TRUE(vpn.ok);
    EXPECT_EQ(vpn.profile, SnortRuntime::RuntimeProfile::Vpn);
    EXPECT_EQ(SnortRuntime::runtimeProfileName(vpn.profile), "vpn");
}

TEST(RuntimeProfileSelection, DefaultsMissingEnvToRootForLegacyLaunchers) {
    const auto missing = SnortRuntime::runtimeProfileFromEnv(nullptr);
    EXPECT_TRUE(missing.ok);
    EXPECT_EQ(missing.profile, SnortRuntime::RuntimeProfile::Root);
}

TEST(RuntimeProfileSelection, RejectsUnknownProfile) {
    const auto unknown = SnortRuntime::parseRuntimeProfile("nfqueue");
    EXPECT_FALSE(unknown.ok);
    EXPECT_EQ(unknown.errorCode, "runtime_profile_unknown");
}
