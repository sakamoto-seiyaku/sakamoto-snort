/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnFlowStackBoundary.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace {

using namespace SnortDatapath::Tun;
namespace Flow = SnortDatapath::Flow;

class RecordingVpnFlowStack final : public VpnFlowStackBoundary {
public:
    VpnFlowStackAdmissionResult nextAdmission{
        .status = VpnFlowStackAdmissionStatus::Accepted,
        .canonicalOwner = 0,
    };
    VpnFlowStackDriveStatus nextDriveStatus =
        VpnFlowStackDriveStatus::MadeProgress;
    VpnFlowStackDriveStatus nextFinishStatus =
        VpnFlowStackDriveStatus::Completed;
    VpnFlowStackWakeStatus nextWakeStatus =
        VpnFlowStackWakeStatus::Enqueued;

    std::uint32_t admitCalls = 0;
    std::uint32_t driveCalls = 0;
    std::uint32_t finishCalls = 0;
    std::uint32_t enqueueCalls = 0;
    std::optional<VpnFlowStackAdmissionRequest> lastAdmission;
    std::size_t lastAdmissionBytes = 0;
    std::uint32_t lastDriveOwner = 0;
    VpnFlowStackDriveBudget lastBudget;
    std::uint32_t lastFinishOwner = 0;
    std::optional<VpnFlowStackDeferredWork> lastWake;

    [[nodiscard]] VpnFlowStackAdmissionResult admitPacket(
        const VpnFlowStackAdmissionRequest &request,
        const std::span<const std::byte> l3Packet) noexcept override {
        ++admitCalls;
        lastAdmission = request;
        lastAdmissionBytes = l3Packet.size();
        auto result = nextAdmission;
        result.canonicalOwner = request.canonicalOwner;
        return result;
    }

    [[nodiscard]] VpnFlowStackDriveStatus driveOwner(
        const std::uint32_t owner,
        const VpnFlowStackDriveBudget budget) noexcept override {
        ++driveCalls;
        lastDriveOwner = owner;
        lastBudget = budget;
        return nextDriveStatus;
    }

    [[nodiscard]] VpnFlowStackDriveStatus finishOwnerIfReady(
        const std::uint32_t owner) noexcept override {
        ++finishCalls;
        lastFinishOwner = owner;
        return nextFinishStatus;
    }

    [[nodiscard]] VpnFlowStackWakeStatus enqueueOwnerWake(
        const VpnFlowStackDeferredWork &work) noexcept override {
        ++enqueueCalls;
        lastWake = work;
        return nextWakeStatus;
    }
};

Flow::PacketFacts packetFacts() {
    Flow::PacketFacts facts;
    facts.source = Flow::IpAddress::v4({10, 0, 0, 2});
    facts.destination = Flow::IpAddress::v4({198, 51, 100, 10});
    facts.ipProtocol = 6;
    facts.sourcePort = 40000;
    facts.destinationPort = 443;
    facts.portsAvailable = true;
    facts.parseStatus = Flow::ParseStatus::Ready;
    facts.deviceDirection = Flow::DevicePacketDirection::Output;
    facts.originalLength = 40;
    facts.boundedPrefixLength = 40;
    facts.domain = Flow::FlowDomain{
        .adapter = Flow::AdapterKind::VpnTun,
        .linuxUid = 12546,
        .uidKnown = true,
        .runtimeProfile = 1,
    };
    return facts;
}

TEST(VpnFlowStackBoundaryTest,
     AdmissionInterfaceCarriesOwnerProvenanceAndFacts) {
    RecordingVpnFlowStack boundary;
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};

    const VpnFlowStackAdmissionRequest request{
        .facts = packetFacts(),
        .canonicalOwner = 3,
        .generation = 42,
        .policyRevision = 7,
        .provenance = VpnFlowStackPacketProvenance::TunOrigin,
    };

    const auto result = boundary.admitPacket(request, packet);

    ASSERT_TRUE(result.accepted());
    EXPECT_EQ(result.canonicalOwner, 3U);
    ASSERT_TRUE(boundary.lastAdmission.has_value());
    EXPECT_EQ(boundary.admitCalls, 1U);
    EXPECT_EQ(boundary.lastAdmissionBytes, packet.size());
    EXPECT_EQ(boundary.lastAdmission->canonicalOwner, 3U);
    EXPECT_EQ(boundary.lastAdmission->generation, 42U);
    EXPECT_EQ(boundary.lastAdmission->policyRevision, 7U);
    EXPECT_EQ(boundary.lastAdmission->provenance,
              VpnFlowStackPacketProvenance::TunOrigin);
    EXPECT_EQ(boundary.lastAdmission->facts.domain.adapter,
              Flow::AdapterKind::VpnTun);
}

TEST(VpnFlowStackBoundaryTest,
     SameOwnerDeferredRearmDrivesLocallyWithoutSelfEnqueue) {
    RecordingVpnFlowStack boundary;
    const VpnFlowStackDeferredWork work{
        .currentWorker = 2,
        .targetOwner = 2,
        .generation = 100,
        .reason = VpnFlowStackDeferredReason::SameOwnerRearm,
    };
    const VpnFlowStackDriveBudget budget{
        .maxPackets = 8,
        .maxCallbacks = 4,
        .maxReturnPackets = 3,
    };

    const auto result = serviceDeferredFlowStackWork(boundary, work, budget);

    EXPECT_EQ(result.action, VpnFlowStackServiceAction::LocalDrive);
    EXPECT_TRUE(result.droveLocally());
    EXPECT_FALSE(result.queuedCrossOwner());
    EXPECT_EQ(result.targetOwner, 2U);
    EXPECT_EQ(result.driveStatus, VpnFlowStackDriveStatus::MadeProgress);
    EXPECT_EQ(result.finishStatus, VpnFlowStackDriveStatus::Completed);
    EXPECT_EQ(result.wakeStatus, VpnFlowStackWakeStatus::NotRequested);
    EXPECT_EQ(boundary.driveCalls, 1U);
    EXPECT_EQ(boundary.lastDriveOwner, 2U);
    EXPECT_EQ(boundary.lastBudget.maxPackets, 8U);
    EXPECT_EQ(boundary.lastBudget.maxCallbacks, 4U);
    EXPECT_EQ(boundary.lastBudget.maxReturnPackets, 3U);
    EXPECT_EQ(boundary.finishCalls, 1U);
    EXPECT_EQ(boundary.lastFinishOwner, 2U);
    EXPECT_EQ(boundary.enqueueCalls, 0U);
}

TEST(VpnFlowStackBoundaryTest,
     SameOwnerDriveFaultStillDoesNotFallbackToSelfEnqueue) {
    RecordingVpnFlowStack boundary;
    boundary.nextDriveStatus = VpnFlowStackDriveStatus::Fault;
    const VpnFlowStackDeferredWork work{
        .currentWorker = 5,
        .targetOwner = 5,
        .generation = 101,
        .reason = VpnFlowStackDeferredReason::SameOwnerRearm,
    };

    const auto result = serviceDeferredFlowStackWork(
        boundary, work, VpnFlowStackDriveBudget{});

    EXPECT_EQ(result.action, VpnFlowStackServiceAction::LocalDrive);
    EXPECT_EQ(result.driveStatus, VpnFlowStackDriveStatus::Fault);
    EXPECT_EQ(boundary.driveCalls, 1U);
    EXPECT_EQ(boundary.finishCalls, 1U);
    EXPECT_EQ(boundary.enqueueCalls, 0U);
}

TEST(VpnFlowStackBoundaryTest,
     CrossOwnerDeferredWorkUsesGenerationTaggedWakeOnly) {
    RecordingVpnFlowStack boundary;
    const VpnFlowStackDeferredWork work{
        .currentWorker = 1,
        .targetOwner = 4,
        .generation = 200,
        .reason = VpnFlowStackDeferredReason::FdWake,
    };

    const auto result = serviceDeferredFlowStackWork(
        boundary, work, VpnFlowStackDriveBudget{.maxPackets = 16});

    EXPECT_EQ(result.action, VpnFlowStackServiceAction::CrossOwnerWake);
    EXPECT_FALSE(result.droveLocally());
    EXPECT_TRUE(result.queuedCrossOwner());
    EXPECT_EQ(result.targetOwner, 4U);
    EXPECT_EQ(result.driveStatus, VpnFlowStackDriveStatus::NotRequested);
    EXPECT_EQ(result.finishStatus, VpnFlowStackDriveStatus::NotRequested);
    EXPECT_EQ(result.wakeStatus, VpnFlowStackWakeStatus::Enqueued);
    EXPECT_EQ(boundary.driveCalls, 0U);
    EXPECT_EQ(boundary.finishCalls, 0U);
    EXPECT_EQ(boundary.enqueueCalls, 1U);
    ASSERT_TRUE(boundary.lastWake.has_value());
    EXPECT_EQ(boundary.lastWake->currentWorker, 1U);
    EXPECT_EQ(boundary.lastWake->targetOwner, 4U);
    EXPECT_EQ(boundary.lastWake->generation, 200U);
    EXPECT_EQ(boundary.lastWake->reason, VpnFlowStackDeferredReason::FdWake);
}

} // namespace
