/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnHevLwipFlowStack.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace {

using namespace SnortDatapath::Tun;
namespace Flow = SnortDatapath::Flow;

class RecordingHevLwipDriver final : public VpnHevLwipDriver {
public:
    VpnHevLwipAdmissionResult nextAdmission{
        .status = VpnHevLwipAdmissionStatus::Enqueued,
    };
    VpnFlowStackReturnResult nextReturn{
        .status = VpnFlowStackReturnStatus::NoPacket,
        .bytes = 0,
    };
    VpnFlowStackDriveStatus nextDriveStatus =
        VpnFlowStackDriveStatus::MadeProgress;
    VpnFlowStackDriveStatus nextFinishStatus =
        VpnFlowStackDriveStatus::Completed;
    VpnFlowStackWakeStatus nextWakeStatus =
        VpnFlowStackWakeStatus::Enqueued;

    std::uint32_t admitCalls = 0;
    std::uint32_t returnCalls = 0;
    std::uint32_t driveCalls = 0;
    std::uint32_t finishCalls = 0;
    std::uint32_t wakeCalls = 0;
    std::uint32_t resetCalls = 0;
    std::optional<VpnHevLwipPacketContext> lastContext;
    std::size_t lastPacketBytes = 0;
    std::uint32_t lastDriveOwner = 0;
    VpnFlowStackDriveBudget lastDriveBudget;
    std::uint32_t lastFinishOwner = 0;
    std::optional<VpnFlowStackDeferredWork> lastWake;
    std::uint64_t lastResetGeneration = 0;
    std::vector<std::byte> returnPacket;

    [[nodiscard]] VpnHevLwipAdmissionResult enqueueTunPacket(
        const VpnHevLwipPacketContext &context,
        const std::span<const std::byte> l3Packet) noexcept override {
        ++admitCalls;
        lastContext = context;
        lastPacketBytes = l3Packet.size();
        return nextAdmission;
    }

    [[nodiscard]] VpnFlowStackReturnResult receiveReturnPacket(
        const std::span<std::byte> packetBuffer) noexcept override {
        ++returnCalls;
        if (nextReturn.status != VpnFlowStackReturnStatus::Packet) {
            return nextReturn;
        }
        if (returnPacket.empty() || returnPacket.size() > packetBuffer.size()) {
            return VpnFlowStackReturnResult{
                .status = VpnFlowStackReturnStatus::PacketTooLarge,
                .bytes = 0,
            };
        }
        std::copy(returnPacket.begin(), returnPacket.end(), packetBuffer.begin());
        return VpnFlowStackReturnResult{
            .status = VpnFlowStackReturnStatus::Packet,
            .bytes = returnPacket.size(),
        };
    }

    [[nodiscard]] VpnFlowStackDriveStatus driveOwner(
        const std::uint32_t owner,
        const VpnFlowStackDriveBudget budget) noexcept override {
        ++driveCalls;
        lastDriveOwner = owner;
        lastDriveBudget = budget;
        return nextDriveStatus;
    }

    [[nodiscard]] VpnFlowStackDriveStatus finishOwnerIfReady(
        const std::uint32_t owner) noexcept override {
        ++finishCalls;
        lastFinishOwner = owner;
        return nextFinishStatus;
    }

    [[nodiscard]] VpnFlowStackWakeStatus enqueueWake(
        const VpnFlowStackDeferredWork &work) noexcept override {
        ++wakeCalls;
        lastWake = work;
        return nextWakeStatus;
    }

    void resetGeneration(const std::uint64_t generation) noexcept override {
        ++resetCalls;
        lastResetGeneration = generation;
    }
};

Flow::PacketFacts packetFacts() {
    Flow::PacketFacts facts;
    facts.source = Flow::IpAddress::v4({10, 0, 0, 2});
    facts.destination = Flow::IpAddress::v4({203, 0, 113, 10});
    facts.ipProtocol = 6;
    facts.sourcePort = 41000;
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

std::array<std::byte, 4> packet() {
    return {
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};
}

VpnFlowStackAdmissionRequest requestFor(
    const std::uint32_t owner,
    const std::uint64_t generation,
    Flow::PacketFacts facts = packetFacts()) {
    return VpnFlowStackAdmissionRequest{
        .facts = facts,
        .canonicalOwner = owner,
        .generation = generation,
        .policyRevision = 12,
        .provenance = VpnFlowStackPacketProvenance::TunOrigin,
    };
}

TEST(VpnHevLwipFlowStackTest,
     FacadeValidatesAdmissionBeforeDriverCall) {
    RecordingHevLwipDriver driver;
    VpnHevLwipFlowStackBoundary boundary{
        VpnHevLwipFlowStackConfig{
            .ownerCount = 4,
            .generation = 77,
            .maxPacketBytes = 64,
        },
        driver};
    const auto l3Packet = packet();

    const auto accepted = boundary.admitPacket(requestFor(2, 77), l3Packet);
    ASSERT_TRUE(accepted.accepted());
    EXPECT_EQ(accepted.canonicalOwner, 2U);
    ASSERT_TRUE(driver.lastContext.has_value());
    EXPECT_EQ(driver.admitCalls, 1U);
    EXPECT_EQ(driver.lastContext->canonicalOwner, 2U);
    EXPECT_EQ(driver.lastContext->generation, 77U);
    EXPECT_EQ(driver.lastContext->policyRevision, 12U);
    EXPECT_EQ(driver.lastContext->facts.domain.adapter,
              Flow::AdapterKind::VpnTun);
    EXPECT_EQ(driver.lastPacketBytes, l3Packet.size());

    auto loopRequest = requestFor(2, 77);
    loopRequest.provenance = VpnFlowStackPacketProvenance::FlowStackOrigin;
    EXPECT_EQ(boundary.admitPacket(loopRequest, l3Packet).status,
              VpnFlowStackAdmissionStatus::LoopRejected);

    EXPECT_EQ(boundary.admitPacket(requestFor(4, 77), l3Packet).status,
              VpnFlowStackAdmissionStatus::OwnerFault);
    EXPECT_EQ(boundary.admitPacket(requestFor(2, 76), l3Packet).status,
              VpnFlowStackAdmissionStatus::StaleGeneration);

    auto unsupportedFacts = packetFacts();
    unsupportedFacts.ipProtocol = 1;
    EXPECT_EQ(boundary
                  .admitPacket(requestFor(2, 77, unsupportedFacts), l3Packet)
                  .status,
              VpnFlowStackAdmissionStatus::UnsupportedProtocol);

    auto noPortFacts = packetFacts();
    noPortFacts.portsAvailable = false;
    EXPECT_EQ(boundary.admitPacket(requestFor(2, 77, noPortFacts), l3Packet)
                  .status,
              VpnFlowStackAdmissionStatus::UnsupportedProtocol);

    const std::array<std::byte, 65> oversized{};
    EXPECT_EQ(boundary.admitPacket(requestFor(2, 77), oversized).status,
              VpnFlowStackAdmissionStatus::DroppedCapacity);

    EXPECT_EQ(driver.admitCalls, 1U);
}

TEST(VpnHevLwipFlowStackTest,
     FacadeMapsDriverAdmissionStatusesToFlowStackOutcomes) {
    struct Case final {
        VpnHevLwipAdmissionStatus driverStatus;
        VpnFlowStackAdmissionStatus expectedStatus;
    };
    const std::array<Case, 7> cases{
        Case{VpnHevLwipAdmissionStatus::Enqueued,
             VpnFlowStackAdmissionStatus::Accepted},
        Case{VpnHevLwipAdmissionStatus::CapacityDrop,
             VpnFlowStackAdmissionStatus::DroppedCapacity},
        Case{VpnHevLwipAdmissionStatus::UnsupportedProtocol,
             VpnFlowStackAdmissionStatus::UnsupportedProtocol},
        Case{VpnHevLwipAdmissionStatus::OwnerFault,
             VpnFlowStackAdmissionStatus::OwnerFault},
        Case{VpnHevLwipAdmissionStatus::StaleGeneration,
             VpnFlowStackAdmissionStatus::StaleGeneration},
        Case{VpnHevLwipAdmissionStatus::TransportUnavailable,
             VpnFlowStackAdmissionStatus::TransportUnavailable},
        Case{VpnHevLwipAdmissionStatus::TransportFailed,
             VpnFlowStackAdmissionStatus::TransportFailed},
    };

    for (const auto &testCase : cases) {
        RecordingHevLwipDriver driver;
        driver.nextAdmission.status = testCase.driverStatus;
        VpnHevLwipFlowStackBoundary boundary{
            VpnHevLwipFlowStackConfig{.ownerCount = 2, .generation = 9},
            driver};

        const auto result = boundary.admitPacket(requestFor(1, 9), packet());

        EXPECT_EQ(result.status, testCase.expectedStatus);
        EXPECT_EQ(result.canonicalOwner, 1U);
        EXPECT_EQ(driver.admitCalls, 1U);
    }
}

TEST(VpnHevLwipFlowStackTest,
     FacadeReceivesReturnPacketsFromDriver) {
    RecordingHevLwipDriver driver;
    driver.nextReturn = VpnFlowStackReturnResult{
        .status = VpnFlowStackReturnStatus::Packet,
        .bytes = 0,
    };
    driver.returnPacket = {
        std::byte{0x45}, std::byte{0x01}, std::byte{0x00}, std::byte{0x28}};
    VpnHevLwipFlowStackBoundary boundary{
        VpnHevLwipFlowStackConfig{.ownerCount = 2, .generation = 9},
        driver};

    std::array<std::byte, 64> buffer{};
    const auto result = boundary.receiveReturnPacket(buffer);

    ASSERT_TRUE(result.hasPacket());
    EXPECT_EQ(result.bytes, driver.returnPacket.size());
    EXPECT_TRUE(std::equal(
        driver.returnPacket.begin(), driver.returnPacket.end(), buffer.begin()));
    EXPECT_EQ(driver.returnCalls, 1U);

    const std::span<std::byte> emptyBuffer;
    EXPECT_EQ(boundary.receiveReturnPacket(emptyBuffer).status,
              VpnFlowStackReturnStatus::PacketTooLarge);
    EXPECT_EQ(driver.returnCalls, 1U);
}

TEST(VpnHevLwipFlowStackTest,
     FacadeDelegatesDriveFinishAndWakeAfterValidation) {
    RecordingHevLwipDriver driver;
    VpnHevLwipFlowStackBoundary boundary{
        VpnHevLwipFlowStackConfig{.ownerCount = 3, .generation = 20},
        driver};

    const auto sameOwner = serviceDeferredFlowStackWork(
        boundary,
        VpnFlowStackDeferredWork{
            .currentWorker = 1,
            .targetOwner = 1,
            .generation = 20,
            .reason = VpnFlowStackDeferredReason::SameOwnerRearm,
        },
        VpnFlowStackDriveBudget{
            .maxPackets = 7,
            .maxCallbacks = 3,
            .maxReturnPackets = 2,
        });

    EXPECT_EQ(sameOwner.action, VpnFlowStackServiceAction::LocalDrive);
    EXPECT_EQ(driver.driveCalls, 1U);
    EXPECT_EQ(driver.finishCalls, 1U);
    EXPECT_EQ(driver.wakeCalls, 0U);
    EXPECT_EQ(driver.lastDriveOwner, 1U);
    EXPECT_EQ(driver.lastDriveBudget.maxPackets, 7U);
    EXPECT_EQ(driver.lastDriveBudget.maxCallbacks, 3U);
    EXPECT_EQ(driver.lastDriveBudget.maxReturnPackets, 2U);
    EXPECT_EQ(driver.lastFinishOwner, 1U);

    const auto crossOwner = serviceDeferredFlowStackWork(
        boundary,
        VpnFlowStackDeferredWork{
            .currentWorker = 0,
            .targetOwner = 2,
            .generation = 20,
            .reason = VpnFlowStackDeferredReason::FdWake,
        },
        VpnFlowStackDriveBudget{.maxPackets = 1});
    EXPECT_EQ(crossOwner.action, VpnFlowStackServiceAction::CrossOwnerWake);
    EXPECT_EQ(driver.wakeCalls, 1U);
    ASSERT_TRUE(driver.lastWake.has_value());
    EXPECT_EQ(driver.lastWake->currentWorker, 0U);
    EXPECT_EQ(driver.lastWake->targetOwner, 2U);
    EXPECT_EQ(driver.lastWake->generation, 20U);

    EXPECT_EQ(boundary.driveOwner(3, VpnFlowStackDriveBudget{}),
              VpnFlowStackDriveStatus::Fault);
    EXPECT_EQ(boundary.finishOwnerIfReady(3), VpnFlowStackDriveStatus::Fault);
    EXPECT_EQ(boundary.enqueueOwnerWake(
                  VpnFlowStackDeferredWork{
                      .currentWorker = 0,
                      .targetOwner = 2,
                      .generation = 19,
                      .reason = VpnFlowStackDeferredReason::FdWake,
                  }),
              VpnFlowStackWakeStatus::StaleGeneration);
    EXPECT_EQ(driver.wakeCalls, 1U);
}

TEST(VpnHevLwipFlowStackTest,
     FacadeGenerationResetNotifiesDriverAndRejectsOldWork) {
    RecordingHevLwipDriver driver;
    VpnHevLwipFlowStackBoundary boundary{
        VpnHevLwipFlowStackConfig{.ownerCount = 2, .generation = 30},
        driver};

    boundary.setGeneration(31);

    EXPECT_EQ(boundary.generation(), 31U);
    EXPECT_EQ(driver.resetCalls, 1U);
    EXPECT_EQ(driver.lastResetGeneration, 31U);
    EXPECT_EQ(boundary.admitPacket(requestFor(1, 30), packet()).status,
              VpnFlowStackAdmissionStatus::StaleGeneration);

    const auto fresh = boundary.admitPacket(requestFor(1, 31), packet());
    EXPECT_TRUE(fresh.accepted());
    EXPECT_EQ(driver.admitCalls, 1U);
    ASSERT_TRUE(driver.lastContext.has_value());
    EXPECT_EQ(driver.lastContext->generation, 31U);
}

} // namespace
