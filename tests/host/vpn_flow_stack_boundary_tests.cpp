/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <VpnFlowStackBoundary.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <poll.h>
#include <span>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

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
    VpnFlowStackReturnResult nextReturn{
        .status = VpnFlowStackReturnStatus::NoPacket,
        .bytes = 0,
    };

    std::uint32_t admitCalls = 0;
    std::uint32_t returnCalls = 0;
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

    [[nodiscard]] VpnFlowStackReturnResult receiveReturnPacket(
        const std::span<std::byte>) noexcept override {
        ++returnCalls;
        return nextReturn;
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

void closeIfOpen(int &fd) noexcept {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

std::vector<std::byte> readPacketFromFd(const int fd) {
    std::array<std::byte, 2048> buffer{};
    const ssize_t bytes = ::read(fd, buffer.data(), buffer.size());
    if (bytes <= 0) {
        return {};
    }
    return std::vector<std::byte>(
        buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(bytes));
}

bool packetReadable(const int fd) noexcept {
    pollfd target{
        .fd = fd,
        .events = POLLIN | POLLERR | POLLHUP,
        .revents = 0,
    };
    return ::poll(&target, 1, 0) > 0 && (target.revents & POLLIN) != 0;
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

TEST(VpnFlowStackBoundaryTest,
     OwnerLocalAdapterAdmitsTunOriginToCanonicalOwnerShard) {
    VpnOwnerLocalFlowStackBoundary boundary{
        VpnOwnerLocalFlowStackConfig{
            .ownerCount = 4,
            .generation = 7,
            .maxPacketsPerOwner = 2,
            .maxPacketBytes = 64,
            .maxReturnPackets = 4,
        }};
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};

    const auto result = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 2,
            .generation = 7,
            .policyRevision = 3,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);

    ASSERT_TRUE(result.accepted());
    EXPECT_EQ(result.canonicalOwner, 2U);
    EXPECT_EQ(boundary.pendingPackets(0), 0U);
    EXPECT_EQ(boundary.pendingPackets(1), 0U);
    EXPECT_EQ(boundary.pendingPackets(2), 1U);
    EXPECT_EQ(boundary.pendingPackets(3), 0U);
    EXPECT_EQ(boundary.pendingReturnPackets(), 0U);
}

TEST(VpnFlowStackBoundaryTest,
     OwnerLocalAdapterRejectsStaleLoopAndUnsupportedIngress) {
    VpnOwnerLocalFlowStackBoundary boundary{
        VpnOwnerLocalFlowStackConfig{
            .ownerCount = 2,
            .generation = 9,
            .maxPacketsPerOwner = 2,
        }};
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};

    const auto stale = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 1,
            .generation = 8,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    EXPECT_EQ(stale.status, VpnFlowStackAdmissionStatus::StaleGeneration);

    const auto loop = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 1,
            .generation = 9,
            .provenance = VpnFlowStackPacketProvenance::FlowStackOrigin,
        },
        packet);
    EXPECT_EQ(loop.status, VpnFlowStackAdmissionStatus::LoopRejected);

    auto unsupportedFacts = packetFacts();
    unsupportedFacts.ipProtocol = 1;
    const auto unsupported = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = unsupportedFacts,
            .canonicalOwner = 1,
            .generation = 9,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    EXPECT_EQ(unsupported.status,
              VpnFlowStackAdmissionStatus::UnsupportedProtocol);

    auto missingPortFacts = packetFacts();
    missingPortFacts.portsAvailable = false;
    const auto missingPorts = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = missingPortFacts,
            .canonicalOwner = 1,
            .generation = 9,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    EXPECT_EQ(missingPorts.status,
              VpnFlowStackAdmissionStatus::UnsupportedProtocol);
    EXPECT_EQ(boundary.pendingPackets(1), 0U);
}

TEST(VpnFlowStackBoundaryTest,
     OwnerLocalAdapterDropsOwnerCapacityWithoutCrossOwnerSpill) {
    VpnOwnerLocalFlowStackBoundary boundary{
        VpnOwnerLocalFlowStackConfig{
            .ownerCount = 3,
            .generation = 11,
            .maxPacketsPerOwner = 1,
        }};
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};

    const auto first = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 1,
            .generation = 11,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    const auto overflow = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 1,
            .generation = 11,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    const auto otherOwner = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 2,
            .generation = 11,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);

    EXPECT_TRUE(first.accepted());
    EXPECT_EQ(overflow.status, VpnFlowStackAdmissionStatus::DroppedCapacity);
    EXPECT_TRUE(otherOwner.accepted());
    EXPECT_EQ(boundary.pendingPackets(0), 0U);
    EXPECT_EQ(boundary.pendingPackets(1), 1U);
    EXPECT_EQ(boundary.pendingPackets(2), 1U);
}

TEST(VpnFlowStackBoundaryTest,
     OwnerLocalDriveProducesReturnPacketsWithinBudget) {
    VpnOwnerLocalFlowStackBoundary boundary{
        VpnOwnerLocalFlowStackConfig{
            .ownerCount = 2,
            .generation = 13,
            .maxPacketsPerOwner = 4,
            .maxReturnPackets = 4,
        }};
    const std::array<std::byte, 4> firstPacket{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};
    const std::array<std::byte, 4> secondPacket{
        std::byte{0x45}, std::byte{0x01}, std::byte{0x00}, std::byte{0x28}};

    ASSERT_TRUE(boundary
                    .admitPacket(
                        VpnFlowStackAdmissionRequest{
                            .facts = packetFacts(),
                            .canonicalOwner = 1,
                            .generation = 13,
                            .provenance =
                                VpnFlowStackPacketProvenance::TunOrigin,
                        },
                        firstPacket)
                    .accepted());
    ASSERT_TRUE(boundary
                    .admitPacket(
                        VpnFlowStackAdmissionRequest{
                            .facts = packetFacts(),
                            .canonicalOwner = 1,
                            .generation = 13,
                            .provenance =
                                VpnFlowStackPacketProvenance::TunOrigin,
                        },
                        secondPacket)
                    .accepted());

    const auto firstDrive = boundary.driveOwner(
        1, VpnFlowStackDriveBudget{.maxPackets = 1, .maxReturnPackets = 1});

    EXPECT_EQ(firstDrive, VpnFlowStackDriveStatus::MadeProgress);
    EXPECT_EQ(boundary.pendingPackets(1), 1U);
    EXPECT_EQ(boundary.pendingReturnPackets(), 1U);
    EXPECT_EQ(boundary.finishOwnerIfReady(1),
              VpnFlowStackDriveStatus::MadeProgress);

    std::array<std::byte, 64> buffer{};
    auto received = boundary.receiveReturnPacket(buffer);
    ASSERT_TRUE(received.hasPacket());
    EXPECT_EQ(received.bytes, firstPacket.size());
    EXPECT_TRUE(std::equal(
        firstPacket.begin(), firstPacket.end(), buffer.begin()));

    const auto secondDrive = boundary.driveOwner(
        1, VpnFlowStackDriveBudget{.maxPackets = 4, .maxReturnPackets = 4});
    EXPECT_EQ(secondDrive, VpnFlowStackDriveStatus::MadeProgress);
    EXPECT_EQ(boundary.finishOwnerIfReady(1),
              VpnFlowStackDriveStatus::Completed);

    buffer.fill(std::byte{0x00});
    received = boundary.receiveReturnPacket(buffer);
    ASSERT_TRUE(received.hasPacket());
    EXPECT_EQ(received.bytes, secondPacket.size());
    EXPECT_TRUE(std::equal(
        secondPacket.begin(), secondPacket.end(), buffer.begin()));
    EXPECT_EQ(boundary.receiveReturnPacket(buffer).status,
              VpnFlowStackReturnStatus::NoPacket);
}

TEST(VpnFlowStackBoundaryTest,
     OwnerLocalAdapterQueuesOnlyGenerationTaggedCrossOwnerWakes) {
    VpnOwnerLocalFlowStackBoundary boundary{
        VpnOwnerLocalFlowStackConfig{
            .ownerCount = 4,
            .generation = 42,
            .maxWakeDepthPerOwner = 1,
        }};

    const auto sameOwner = serviceDeferredFlowStackWork(
        boundary,
        VpnFlowStackDeferredWork{
            .currentWorker = 2,
            .targetOwner = 2,
            .generation = 42,
            .reason = VpnFlowStackDeferredReason::SameOwnerRearm,
        },
        VpnFlowStackDriveBudget{.maxPackets = 1});
    EXPECT_EQ(sameOwner.action, VpnFlowStackServiceAction::LocalDrive);
    EXPECT_EQ(boundary.queuedWakes(2), 0U);

    const auto crossOwner = serviceDeferredFlowStackWork(
        boundary,
        VpnFlowStackDeferredWork{
            .currentWorker = 1,
            .targetOwner = 2,
            .generation = 42,
            .reason = VpnFlowStackDeferredReason::FdWake,
        },
        VpnFlowStackDriveBudget{.maxPackets = 1});
    EXPECT_EQ(crossOwner.action, VpnFlowStackServiceAction::CrossOwnerWake);
    EXPECT_EQ(crossOwner.wakeStatus, VpnFlowStackWakeStatus::Enqueued);
    EXPECT_EQ(boundary.queuedWakes(2), 1U);

    const auto capacity = serviceDeferredFlowStackWork(
        boundary,
        VpnFlowStackDeferredWork{
            .currentWorker = 1,
            .targetOwner = 2,
            .generation = 42,
            .reason = VpnFlowStackDeferredReason::TimerWake,
        },
        VpnFlowStackDriveBudget{.maxPackets = 1});
    EXPECT_EQ(capacity.wakeStatus, VpnFlowStackWakeStatus::CapacityDrop);
    EXPECT_EQ(boundary.queuedWakes(2), 1U);

    const auto stale = serviceDeferredFlowStackWork(
        boundary,
        VpnFlowStackDeferredWork{
            .currentWorker = 1,
            .targetOwner = 3,
            .generation = 41,
            .reason = VpnFlowStackDeferredReason::FdWake,
        },
        VpnFlowStackDriveBudget{.maxPackets = 1});
    EXPECT_EQ(stale.wakeStatus, VpnFlowStackWakeStatus::StaleGeneration);
    EXPECT_EQ(boundary.queuedWakes(3), 0U);
}

TEST(VpnFlowStackBoundaryTest,
     OwnerLocalGenerationChangeClearsQueuedPacketsReturnsAndWakes) {
    VpnOwnerLocalFlowStackBoundary boundary{
        VpnOwnerLocalFlowStackConfig{
            .ownerCount = 3,
            .generation = 50,
            .maxPacketsPerOwner = 4,
            .maxReturnPackets = 4,
            .maxWakeDepthPerOwner = 4,
        }};
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};

    ASSERT_TRUE(boundary
                    .admitPacket(
                        VpnFlowStackAdmissionRequest{
                            .facts = packetFacts(),
                            .canonicalOwner = 1,
                            .generation = 50,
                            .provenance =
                                VpnFlowStackPacketProvenance::TunOrigin,
                        },
                        packet)
                    .accepted());
    EXPECT_EQ(boundary.driveOwner(
                  1, VpnFlowStackDriveBudget{.maxPackets = 1,
                                             .maxReturnPackets = 1}),
              VpnFlowStackDriveStatus::MadeProgress);
    EXPECT_EQ(boundary.enqueueOwnerWake(
                  VpnFlowStackDeferredWork{
                      .currentWorker = 0,
                      .targetOwner = 2,
                      .generation = 50,
                      .reason = VpnFlowStackDeferredReason::FdWake,
                  }),
              VpnFlowStackWakeStatus::Enqueued);
    EXPECT_EQ(boundary.pendingReturnPackets(), 1U);
    EXPECT_EQ(boundary.queuedWakes(2), 1U);

    boundary.setGeneration(51);

    EXPECT_EQ(boundary.generation(), 51U);
    EXPECT_EQ(boundary.pendingPackets(1), 0U);
    EXPECT_EQ(boundary.pendingReturnPackets(), 0U);
    EXPECT_EQ(boundary.queuedWakes(2), 0U);

    const auto stale = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 1,
            .generation = 50,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    EXPECT_EQ(stale.status, VpnFlowStackAdmissionStatus::StaleGeneration);

    const auto fresh = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 1,
            .generation = 51,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);
    EXPECT_TRUE(fresh.accepted());
}

TEST(VpnFlowStackBoundaryTest,
     FdBackedAdmissionWritesTunOriginPacketToTransportFd) {
    int transportFds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                           transportFds),
              0);
    VpnFdFlowStackBoundary boundary{transportFds[0]};
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};

    const auto result = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 3,
            .generation = 42,
            .policyRevision = 7,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);

    EXPECT_TRUE(result.accepted());
    EXPECT_EQ(result.canonicalOwner, 3U);
    const auto transported = readPacketFromFd(transportFds[1]);
    ASSERT_EQ(transported.size(), packet.size());
    EXPECT_TRUE(std::equal(packet.begin(), packet.end(), transported.begin()));

    closeIfOpen(transportFds[0]);
    closeIfOpen(transportFds[1]);
}

TEST(VpnFlowStackBoundaryTest,
     FdBackedAdmissionReportsUnavailableWithoutTransportFd) {
    int transportFd = -1;
    VpnFdFlowStackBoundary boundary{transportFd};
    const std::array<std::byte, 4> packet{};

    const auto result = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 3,
            .provenance = VpnFlowStackPacketProvenance::TunOrigin,
        },
        packet);

    EXPECT_EQ(result.status,
              VpnFlowStackAdmissionStatus::TransportUnavailable);
    EXPECT_FALSE(result.accepted());
    EXPECT_EQ(result.canonicalOwner, 3U);
}

TEST(VpnFlowStackBoundaryTest,
     FdBackedAdmissionRejectsFlowStackOriginToAvoidLoop) {
    int transportFds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                           transportFds),
              0);
    VpnFdFlowStackBoundary boundary{transportFds[0]};
    const std::array<std::byte, 4> packet{};

    const auto result = boundary.admitPacket(
        VpnFlowStackAdmissionRequest{
            .facts = packetFacts(),
            .canonicalOwner = 3,
            .provenance = VpnFlowStackPacketProvenance::FlowStackOrigin,
        },
        packet);

    EXPECT_EQ(result.status, VpnFlowStackAdmissionStatus::LoopRejected);
    EXPECT_FALSE(result.accepted());
    EXPECT_FALSE(packetReadable(transportFds[1]));

    closeIfOpen(transportFds[0]);
    closeIfOpen(transportFds[1]);
}

TEST(VpnFlowStackBoundaryTest,
     FdBackedReceiveReadsFlowStackReturnPacket) {
    int transportFds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                           transportFds),
              0);
    VpnFdFlowStackBoundary boundary{transportFds[0]};
    const std::array<std::byte, 4> packet{
        std::byte{0x45}, std::byte{0x00}, std::byte{0x00}, std::byte{0x28}};
    ASSERT_EQ(::write(transportFds[1], packet.data(), packet.size()),
              static_cast<ssize_t>(packet.size()));

    std::array<std::byte, 64> buffer{};
    const auto result = boundary.receiveReturnPacket(buffer);

    ASSERT_TRUE(result.hasPacket());
    EXPECT_EQ(result.bytes, packet.size());
    EXPECT_TRUE(std::equal(
        packet.begin(), packet.end(), buffer.begin()));

    closeIfOpen(transportFds[0]);
    closeIfOpen(transportFds[1]);
}

TEST(VpnFlowStackBoundaryTest,
     FdBackedReceiveReportsNoPacketWithoutBlocking) {
    int transportFds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                           transportFds),
              0);
    VpnFdFlowStackBoundary boundary{transportFds[0]};

    std::array<std::byte, 64> buffer{};
    const auto result = boundary.receiveReturnPacket(buffer);

    EXPECT_EQ(result.status, VpnFlowStackReturnStatus::NoPacket);
    EXPECT_FALSE(result.hasPacket());
    EXPECT_EQ(result.bytes, 0U);

    closeIfOpen(transportFds[0]);
    closeIfOpen(transportFds[1]);
}

TEST(VpnFlowStackBoundaryTest,
     FdBackedReceiveReportsUnavailableWithoutTransportFd) {
    int transportFd = -1;
    VpnFdFlowStackBoundary boundary{transportFd};

    std::array<std::byte, 64> buffer{};
    const auto result = boundary.receiveReturnPacket(buffer);

    EXPECT_EQ(result.status,
              VpnFlowStackReturnStatus::TransportUnavailable);
    EXPECT_FALSE(result.hasPacket());
    EXPECT_EQ(result.bytes, 0U);
}

} // namespace
