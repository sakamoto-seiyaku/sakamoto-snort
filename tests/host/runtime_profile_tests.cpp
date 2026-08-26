/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeProfile.hpp>
#include <RuntimeFactoryPlan.hpp>
#include <VpnHevLwipFlowStack.hpp>
#include <VpnTunFdRuntime.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <thread>

namespace {

class IdleHevLwipDriver final : public SnortDatapath::Tun::VpnHevLwipDriver {
public:
    [[nodiscard]] SnortDatapath::Tun::VpnHevLwipAdmissionResult enqueueTunPacket(
        const SnortDatapath::Tun::VpnHevLwipPacketContext &,
        std::span<const std::byte>) noexcept override {
        return SnortDatapath::Tun::VpnHevLwipAdmissionResult{
            .status =
                SnortDatapath::Tun::VpnHevLwipAdmissionStatus::TransportFailed,
        };
    }

    [[nodiscard]] SnortDatapath::Tun::VpnFlowStackReturnResult receiveReturnPacket(
        std::span<std::byte>) noexcept override {
        return SnortDatapath::Tun::VpnFlowStackReturnResult{
            .status = SnortDatapath::Tun::VpnFlowStackReturnStatus::NoPacket,
            .bytes = 0,
        };
    }

    [[nodiscard]] SnortDatapath::Tun::VpnFlowStackDriveStatus driveOwner(
        std::uint32_t,
        SnortDatapath::Tun::VpnFlowStackDriveBudget) noexcept override {
        return SnortDatapath::Tun::VpnFlowStackDriveStatus::Idle;
    }

    [[nodiscard]] SnortDatapath::Tun::VpnFlowStackDriveStatus
    finishOwnerIfReady(std::uint32_t) noexcept override {
        return SnortDatapath::Tun::VpnFlowStackDriveStatus::Completed;
    }

    [[nodiscard]] SnortDatapath::Tun::VpnFlowStackWakeStatus enqueueWake(
        const SnortDatapath::Tun::VpnFlowStackDeferredWork &) noexcept override {
        return SnortDatapath::Tun::VpnFlowStackWakeStatus::Enqueued;
    }

    void resetGeneration(std::uint64_t) noexcept override {}
};

} // namespace

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

TEST(RuntimeFactoryPlan, LaunchesVpnWithoutTunFdSourceForControlAttach) {
    const auto plan =
        SnortRuntime::planRuntimeFactory(SnortRuntime::parseRuntimeProfile("vpn"));

    EXPECT_TRUE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::CreateVpnTunFdHandoff);
    EXPECT_EQ(plan.exitCode, 0);
    EXPECT_TRUE(plan.errorCode.empty());
    EXPECT_EQ(plan.adapterName, "vpn-tun-fd-compat");
    EXPECT_EQ(plan.vpnFlowStackBackend,
              SnortRuntime::VpnFlowStackRuntimeBackend::FdCompatibility);
    EXPECT_FALSE(plan.usingCompatibilityFallback);
}

TEST(RuntimeFactoryPlan, SelectsVpnTunFdHandoffWhenTunSourceExists) {
    const auto plan =
        SnortRuntime::planRuntimeFactory(SnortRuntime::parseRuntimeProfile("vpn"), "/dev/null");

    EXPECT_TRUE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::CreateVpnTunFdHandoff);
    EXPECT_EQ(plan.exitCode, 0);
    EXPECT_TRUE(plan.errorCode.empty());
    EXPECT_EQ(plan.adapterName, "vpn-tun-fd-compat");
    EXPECT_EQ(plan.vpnFlowStackBackend,
              SnortRuntime::VpnFlowStackRuntimeBackend::FdCompatibility);
}

TEST(RuntimeFactoryPlan, SelectsVpnHevLwipFacadeWhenDriverIsAvailable) {
    const auto plan = SnortRuntime::planRuntimeFactory(
        SnortRuntime::parseRuntimeProfile("vpn"),
        SnortRuntime::RuntimeFactoryOptions{
            .preferredVpnFlowStackBackend =
                SnortRuntime::VpnFlowStackRuntimeBackend::HevLwipFacade,
            .vpnHevLwipDriverAvailable = true,
        });

    EXPECT_TRUE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::CreateVpnTunHevLwip);
    EXPECT_EQ(plan.exitCode, 0);
    EXPECT_TRUE(plan.errorCode.empty());
    EXPECT_EQ(plan.adapterName, "vpn-tun-hev-lwip");
    EXPECT_EQ(plan.vpnFlowStackBackend,
              SnortRuntime::VpnFlowStackRuntimeBackend::HevLwipFacade);
    EXPECT_FALSE(plan.usingCompatibilityFallback);
}

TEST(RuntimeFactoryPlan, FallsBackToVpnFdCompatWhenHevDriverIsUnavailable) {
    const auto plan = SnortRuntime::planRuntimeFactory(
        SnortRuntime::parseRuntimeProfile("vpn"),
        SnortRuntime::RuntimeFactoryOptions{
            .preferredVpnFlowStackBackend =
                SnortRuntime::VpnFlowStackRuntimeBackend::HevLwipFacade,
            .vpnHevLwipDriverAvailable = false,
        });

    EXPECT_TRUE(plan.launchable);
    EXPECT_EQ(plan.action, SnortRuntime::RuntimeFactoryAction::CreateVpnTunFdHandoff);
    EXPECT_EQ(plan.adapterName, "vpn-tun-fd-compat");
    EXPECT_EQ(plan.vpnFlowStackBackend,
              SnortRuntime::VpnFlowStackRuntimeBackend::FdCompatibility);
    EXPECT_TRUE(plan.usingCompatibilityFallback);
}

TEST(VpnTunFdRuntime, HoldsDuplicatedTunFdWithoutClaimingAdapterReady) {
    const int tunFd = SnortDatapath::Tun::openVpnTunFdSource("/dev/null");
    ASSERT_GE(tunFd, 0);

    SnortDatapath::Tun::VpnTunFdRuntime runtime{tunFd};
    EXPECT_TRUE(runtime.start());
    EXPECT_FALSE(runtime.nfqueuePassThroughReady());
    EXPECT_FALSE(runtime.packetAdapterReady());
    EXPECT_TRUE(runtime.vpnTunFdHandoffReady());
    EXPECT_EQ(runtime.packetAdapterName(), "vpn-tun-fd-compat");
}

TEST(VpnTunFdRuntime, SupportsAttachLaterBeforeTunFdIsPresent) {
    SnortDatapath::Tun::VpnTunFdRuntime runtime{-1, true};

    EXPECT_TRUE(runtime.start());
    EXPECT_FALSE(runtime.nfqueuePassThroughReady());
    EXPECT_FALSE(runtime.packetAdapterReady());
    EXPECT_TRUE(runtime.vpnTunFdHandoffReady());
    EXPECT_TRUE(runtime.vpnTunTransportFdHandoffReady());
    EXPECT_EQ(runtime.packetAdapterName(), "vpn-tun-fd-compat");
}

TEST(VpnTunFdRuntime, SupportsInjectedHevLwipFlowStackWithoutTransportFdHandoff) {
    IdleHevLwipDriver driver;
    auto flowStack =
        std::make_unique<SnortDatapath::Tun::VpnHevLwipFlowStackBoundary>(
            SnortDatapath::Tun::VpnHevLwipFlowStackConfig{
                .ownerCount = 2,
                .generation = 1,
                .maxPacketBytes = 1500,
            },
            driver);
    SnortDatapath::Tun::VpnTunFdRuntime runtime{
        -1,
        false,
        SnortDatapath::Tun::VpnTunFlowStackRuntimeConfig{
            .flowStack = std::move(flowStack),
            .adapterName = "vpn-tun-hev-lwip",
            .transportFdHandoffReady = false,
            .requiresTransportFdForDrain = false,
            .flowStackReadyWithoutTransport = true,
        }};

    EXPECT_TRUE(runtime.start());
    EXPECT_FALSE(runtime.packetAdapterReady());
    EXPECT_EQ(runtime.packetAdapterName(), "vpn-tun-hev-lwip");
    EXPECT_TRUE(runtime.vpnTunFdHandoffReady());
    EXPECT_FALSE(runtime.vpnTunTransportFdHandoffReady());
    const auto attach = runtime.attachVpnTransportFd(-1);
    EXPECT_FALSE(attach.ok);
    EXPECT_EQ(attach.errorCode, "VPN_TRANSPORT_ATTACH_UNSUPPORTED");
}

TEST(VpnTunFdRuntime,
     StartsAutomaticDrainForInjectedHevLwipFlowStackWithoutTransportFd) {
    const int tunFd = SnortDatapath::Tun::openVpnTunFdSource("/dev/null");
    ASSERT_GE(tunFd, 0);

    IdleHevLwipDriver driver;
    auto flowStack =
        std::make_unique<SnortDatapath::Tun::VpnHevLwipFlowStackBoundary>(
            SnortDatapath::Tun::VpnHevLwipFlowStackConfig{
                .ownerCount = 2,
                .generation = 1,
                .maxPacketBytes = 1500,
            },
            driver);
    SnortDatapath::Tun::VpnTunFdRuntime runtime{
        tunFd,
        true,
        SnortDatapath::Tun::VpnTunFlowStackRuntimeConfig{
            .flowStack = std::move(flowStack),
            .adapterName = "vpn-tun-hev-lwip",
            .transportFdHandoffReady = false,
            .requiresTransportFdForDrain = false,
            .flowStackReadyWithoutTransport = true,
        }};

    ASSERT_TRUE(runtime.start());
    for (int attempt = 0;
         attempt < 50 && !runtime.packetAdapterReady();
         ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    EXPECT_TRUE(runtime.packetAdapterReady());
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
