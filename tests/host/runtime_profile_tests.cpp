/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeProfile.hpp>
#include <RuntimeFactoryPlan.hpp>

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

TEST(RuntimeFactoryPlan, SelectsRootNfqueueRuntimeForRootProfile) {
    const auto plan =
        SnortRuntime::planRuntimeFactory(SnortRuntime::parseRuntimeProfile("root"));

    EXPECT_TRUE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::CreateRootNfqueue);
    EXPECT_EQ(plan.exitCode, 0);
    EXPECT_EQ(plan.adapterName, "root-nfqueue");
}

TEST(RuntimeFactoryPlan, RejectsVpnUntilProductTunHevRuntimeExists) {
    const auto plan =
        SnortRuntime::planRuntimeFactory(SnortRuntime::parseRuntimeProfile("vpn"));

    EXPECT_FALSE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::RejectVpnUnavailable);
    EXPECT_EQ(plan.exitCode, 3);
    EXPECT_EQ(plan.errorCode, "vpn_adapter_unavailable");
    EXPECT_EQ(plan.adapterName, "vpn-tun-hev");
}

TEST(RuntimeFactoryPlan, PropagatesInvalidProfileWithoutSelectingAnAdapter) {
    const auto plan =
        SnortRuntime::planRuntimeFactory(SnortRuntime::parseRuntimeProfile("bad"));

    EXPECT_FALSE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::RejectProfile);
    EXPECT_EQ(plan.exitCode, 2);
    EXPECT_EQ(plan.errorCode, "runtime_profile_unknown");
    EXPECT_TRUE(plan.adapterName.empty());
}
