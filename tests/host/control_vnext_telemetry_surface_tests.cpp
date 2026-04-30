/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>
#include <ControlVNextSessionCommands.hpp>
#include <FlowTelemetry.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
FlowTelemetry flowTelemetry;
std::shared_mutex mutexListeners;
std::mutex mutexControlMutations;

namespace ControlVNextSessionCommands {

// Provide minimal stubs for non-telemetry command handlers.
std::optional<ResponsePlan> handleDaemonCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)limits;
    if (request.cmd == "RESETALL") {
        const std::lock_guard<std::mutex> controlLock(mutexControlMutations);
        const std::lock_guard listenersLock(mutexListeners);
        flowTelemetry.resetAll();
        rapidjson::Document response = ControlVNext::makeOkResponse(request.id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    return std::nullopt;
}

std::optional<ResponsePlan> handleDomainCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

std::optional<ResponsePlan> handleIpRulesCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

std::optional<ResponsePlan> handleMetricsCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

} // namespace ControlVNextSessionCommands

namespace {

bool writeAll(const int fd, const std::string_view data) {
    size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
        if (n > 0) {
            offset += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

struct RecvFrameWithFd {
    std::string json;
    int receivedFd = -1;
};

RecvFrameWithFd recvOneResponseFrameWithOptionalFd(const int fd, const size_t maxFrameBytes,
                                                   const std::chrono::milliseconds timeout) {
    ControlVNext::NetstringDecoder decoder(maxFrameBytes);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int receivedFd = -1;

    std::array<std::byte, 4096> buf{};
    for (;;) {
        if (const auto payload = decoder.pop(); payload.has_value()) {
            return RecvFrameWithFd{.json = *payload, .receivedFd = receivedFd};
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("timed out waiting for response frame");
        }
        const int pollTimeoutMs = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());

        pollfd pfd{.fd = fd, .events = POLLIN | POLLHUP, .revents = 0};
        const int rc = ::poll(&pfd, 1, pollTimeoutMs);
        if (rc == 0) {
            continue;
        }
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("poll failed: ") + std::strerror(errno));
        }
        if (pfd.revents & POLLHUP) {
            throw std::runtime_error("socket closed");
        }

        // recvmsg() so we can capture SCM_RIGHTS if present.
        iovec iov{};
        iov.iov_base = buf.data();
        iov.iov_len = buf.size();

        union {
            char buf[CMSG_SPACE(sizeof(int))];
            struct cmsghdr align;
        } control;

        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.buf;
        msg.msg_controllen = sizeof(control.buf);

        const ssize_t n = ::recvmsg(fd, &msg, 0);
        if (n == 0) {
            throw std::runtime_error("socket closed");
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("recvmsg failed: ") + std::strerror(errno));
        }
        if ((msg.msg_flags & MSG_CTRUNC) != 0) {
            throw std::runtime_error("ancillary data truncated");
        }

        for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                int newFd = -1;
                std::memcpy(&newFd, CMSG_DATA(cmsg), sizeof(int));
                if (newFd >= 0 && receivedFd < 0) {
                    receivedFd = newFd;
                } else if (newFd >= 0) {
                    ::close(newFd); // keep only the first fd if multiple were received
                }
            }
        }

        if (const auto framingErr = decoder.feed(std::span<const std::byte>(
                buf.data(), static_cast<size_t>(n)));
            framingErr.has_value()) {
            throw std::runtime_error("framing error while reading response");
        }
    }
}

struct UniqueFd {
    int fd = -1;
    ~UniqueFd() {
        if (fd >= 0) {
            ::close(fd);
        }
    }
};

} // namespace

TEST(ControlVNextTelemetrySurface, OpenResponsePlanOwnsDuplicatedFdAcrossSessionReset) {
    {
        const std::lock_guard<std::mutex> controlLock(mutexControlMutations);
        const std::lock_guard listenersLock(mutexListeners);
        flowTelemetry.resetAll();
    }

    rapidjson::Document req;
    ControlVNext::JsonError parseErr;
    ASSERT_TRUE(ControlVNext::parseStrictJsonObject(
        R"({"id":90,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})", req, parseErr))
        << parseErr.message;

    ControlVNext::RequestView request;
    ASSERT_FALSE(ControlVNext::parseRequestEnvelope(req, request).has_value());

    int owner = 0;
    auto maybePlan = [&] {
        const std::lock_guard<std::mutex> controlLock(mutexControlMutations);
        return ControlVNextSessionCommands::handleTelemetryCommand(
            request, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                                 .maxResponseBytes = 16 * 1024 * 1024},
            &owner, /*canPassFd=*/true);
    }();
    ASSERT_TRUE(maybePlan.has_value());
    auto &plan = *maybePlan;
    ASSERT_TRUE(plan.fdToSend.valid());

    // Simulate a preemption/reset before ControlVNextSession gets to send SCM_RIGHTS.
    {
        const std::lock_guard<std::mutex> controlLock(mutexControlMutations);
        const std::lock_guard listenersLock(mutexListeners);
        flowTelemetry.resetAll();
    }

    std::array<std::byte, FlowTelemetryAbi::kSlotBytes> slot{};
    const ssize_t n = ::pread(plan.fdToSend.get(), slot.data(), slot.size(), 0);
    ASSERT_EQ(n, static_cast<ssize_t>(slot.size())) << std::strerror(errno);
}

TEST(ControlVNextTelemetrySurface, OpenFlowOverUnixSendsFdAndRingReceivesSyntheticRecord) {
    int fds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds), 0) << std::strerror(errno);
    UniqueFd serverFd{.fd = fds[0]};
    UniqueFd clientFd{.fd = fds[1]};

    std::thread server([fd = serverFd.fd] {
        ControlVNextSession session(
            fd, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                            .maxResponseBytes = 16 * 1024 * 1024},
            /*canPassFdOverride=*/true);
        session.run();
    });
    serverFd.fd = -1; // ownership moved to server thread

    const std::string frame =
        ControlVNext::encodeNetstring(R"({"id":1,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})");
    ASSERT_TRUE(writeAll(clientFd.fd, frame));

    const auto r = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    ASSERT_GE(r.receivedFd, 0);

    rapidjson::Document resp;
    ControlVNext::JsonError parseErr;
    ASSERT_TRUE(ControlVNext::parseStrictJsonObject(r.json, resp, parseErr)) << parseErr.message;
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);
    const auto &result = *view.result;
    ASSERT_TRUE(result.IsObject());
    EXPECT_STREQ(result["actualLevel"].GetString(), "flow");
    EXPECT_EQ(result["slotBytes"].GetUint(), FlowTelemetryAbi::kSlotBytes);
    EXPECT_EQ(result["slotCount"].GetUint(), FlowTelemetryAbi::kSlotCount);
    EXPECT_EQ(result["ringDataBytes"].GetUint64(), FlowTelemetryAbi::kRingDataBytes);

    // Emit one synthetic record from the same process.
    ASSERT_TRUE(flowTelemetry.exportSyntheticTestRecord());

    void *addr = ::mmap(nullptr, FlowTelemetryAbi::kRingDataBytes, PROT_READ | PROT_WRITE,
                        MAP_SHARED, r.receivedFd, 0);
    ASSERT_NE(addr, MAP_FAILED) << std::strerror(errno);

    const auto unmapGuard = std::unique_ptr<void, void (*)(void *)>(addr, [](void *p) {
        ::munmap(p, FlowTelemetryAbi::kRingDataBytes);
    });

    // ticket=0 => slotIndex=0. Wait briefly for commit.
    const std::byte *slot0 = reinterpret_cast<const std::byte *>(addr);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    for (;;) {
        std::uint32_t state = 0;
        std::memcpy(&state, slot0 + FlowTelemetryAbi::kSlotOffsetState, sizeof(state));
        if (state == static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed)) {
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            FAIL() << "synthetic record was not committed in time";
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    const std::span<const std::byte> slotSpan(slot0, FlowTelemetryAbi::kSlotBytes);
    const std::uint16_t recordType =
        FlowTelemetryAbi::readU16Le(slotSpan, FlowTelemetryAbi::kSlotOffsetRecordType);
    EXPECT_EQ(recordType, static_cast<std::uint16_t>(FlowTelemetryAbi::RecordType::Flow));

    const std::uint32_t payloadSize =
        FlowTelemetryAbi::readU32Le(slotSpan, FlowTelemetryAbi::kSlotOffsetPayloadSize);
    EXPECT_EQ(payloadSize, 8u);

    EXPECT_EQ(slot0[FlowTelemetryAbi::kSlotHeaderBytes + 0], std::byte{'S'});
    EXPECT_EQ(slot0[FlowTelemetryAbi::kSlotHeaderBytes + 1], std::byte{'N'});
    EXPECT_EQ(slot0[FlowTelemetryAbi::kSlotHeaderBytes + 2], std::byte{'O'});
    EXPECT_EQ(slot0[FlowTelemetryAbi::kSlotHeaderBytes + 3], std::byte{'R'});

    // Close.
    const std::string closeFrame =
        ControlVNext::encodeNetstring(R"({"id":2,"cmd":"TELEMETRY.CLOSE","args":{}})");
    ASSERT_TRUE(writeAll(clientFd.fd, closeFrame));
    const auto r2 = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    EXPECT_LT(r2.receivedFd, 0);

    rapidjson::Document resp2;
    ASSERT_TRUE(ControlVNext::parseStrictJsonObject(r2.json, resp2, parseErr));
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp2, view).has_value());
    EXPECT_TRUE(view.ok);

    // Close client socket to let the server session exit before joining.
    ::close(clientFd.fd);
    clientFd.fd = -1;

    if (server.joinable()) {
        server.join();
    }
}

TEST(ControlVNextTelemetrySurface, OpenFlowWithoutFdPassingIsRejectedWithHint) {
    // Some host sandboxes deny AF_INET sockets. We still need to validate the behavior for
    // non-fd-capable sessions, so we simulate that by forcing canPassFdOverride=false.
    int fds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds), 0) << std::strerror(errno);
    UniqueFd serverFd{.fd = fds[0]};
    UniqueFd clientFd{.fd = fds[1]};

    std::thread server([fd = serverFd.fd] {
        ControlVNextSession session(
            fd, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                            .maxResponseBytes = 16 * 1024 * 1024},
            /*canPassFdOverride=*/false);
        session.run();
    });
    serverFd.fd = -1;

    const std::string frame =
        ControlVNext::encodeNetstring(R"({"id":10,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})");
    ASSERT_TRUE(writeAll(clientFd.fd, frame));

    const auto r = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    EXPECT_LT(r.receivedFd, 0);

    rapidjson::Document resp;
    ControlVNext::JsonError parseErr;
    ASSERT_TRUE(ControlVNext::parseStrictJsonObject(r.json, resp, parseErr)) << parseErr.message;
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    ASSERT_TRUE(view.error->HasMember("code"));
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
    ASSERT_TRUE(view.error->HasMember("hint"));
    const std::string_view hint((*view.error)["hint"].GetString(),
                               (*view.error)["hint"].GetStringLength());
    EXPECT_NE(hint.find("Unix"), std::string_view::npos);

    // Close client socket to let the server session exit before joining.
    ::close(clientFd.fd);
    clientFd.fd = -1;

    if (server.joinable()) {
        server.join();
    }
}

TEST(ControlVNextTelemetrySurface, OpenRejectsUnknownArgsKey) {
    int fds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds), 0) << std::strerror(errno);
    UniqueFd serverFd{.fd = fds[0]};
    UniqueFd clientFd{.fd = fds[1]};

    std::thread server([fd = serverFd.fd] {
        ControlVNextSession session(
            fd, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                            .maxResponseBytes = 16 * 1024 * 1024},
            /*canPassFdOverride=*/true);
        session.run();
    });
    serverFd.fd = -1;

    const std::string frame = ControlVNext::encodeNetstring(
        R"({"id":20,"cmd":"TELEMETRY.OPEN","args":{"level":"flow","x":1}})");
    ASSERT_TRUE(writeAll(clientFd.fd, frame));

    const auto r = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    EXPECT_LT(r.receivedFd, 0);

    rapidjson::Document resp;
    ControlVNext::JsonError parseErr;
    ASSERT_TRUE(ControlVNext::parseStrictJsonObject(r.json, resp, parseErr)) << parseErr.message;
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");

    ::close(clientFd.fd);
    clientFd.fd = -1;
    if (server.joinable()) {
        server.join();
    }
}

TEST(ControlVNextTelemetrySurface, SecondOpenPreemptsFirstSession) {
    int fdsA[2]{-1, -1};
    int fdsB[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fdsA), 0) << std::strerror(errno);
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fdsB), 0) << std::strerror(errno);

    UniqueFd serverA{.fd = fdsA[0]};
    UniqueFd clientA{.fd = fdsA[1]};
    UniqueFd serverB{.fd = fdsB[0]};
    UniqueFd clientB{.fd = fdsB[1]};

    std::thread tA([fd = serverA.fd] {
        ControlVNextSession session(
            fd, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                            .maxResponseBytes = 16 * 1024 * 1024},
            /*canPassFdOverride=*/true);
        session.run();
    });
    serverA.fd = -1;

    std::thread tB([fd = serverB.fd] {
        ControlVNextSession session(
            fd, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                            .maxResponseBytes = 16 * 1024 * 1024},
            /*canPassFdOverride=*/true);
        session.run();
    });
    serverB.fd = -1;

    // OPEN A
    ASSERT_TRUE(writeAll(clientA.fd, ControlVNext::encodeNetstring(
                                        R"({"id":30,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})")));
    const auto rA = recvOneResponseFrameWithOptionalFd(
        clientA.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    ASSERT_GE(rA.receivedFd, 0);

    void *addrA = ::mmap(nullptr, FlowTelemetryAbi::kRingDataBytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED, rA.receivedFd, 0);
    ASSERT_NE(addrA, MAP_FAILED) << std::strerror(errno);
    const auto unmapA = std::unique_ptr<void, void (*)(void *)>(addrA, [](void *p) {
        ::munmap(p, FlowTelemetryAbi::kRingDataBytes);
    });
    const std::byte *slotA0 = reinterpret_cast<const std::byte *>(addrA);

    ASSERT_TRUE(flowTelemetry.exportSyntheticTestRecord());

    const auto waitCommitted = [&](const std::byte *slot0) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        for (;;) {
            std::uint32_t state = 0;
            std::memcpy(&state, slot0 + FlowTelemetryAbi::kSlotOffsetState, sizeof(state));
            if (state == static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed)) {
                return;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                FAIL() << "record was not committed in time";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    waitCommitted(slotA0);
    const std::uint64_t ticketA0 = FlowTelemetryAbi::readU64Le(
        std::span<const std::byte>(slotA0, FlowTelemetryAbi::kSlotBytes), FlowTelemetryAbi::kSlotOffsetTicket);
    EXPECT_EQ(ticketA0, 0u);

    // OPEN B (preempts)
    ASSERT_TRUE(writeAll(clientB.fd, ControlVNext::encodeNetstring(
                                        R"({"id":31,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})")));
    const auto rB = recvOneResponseFrameWithOptionalFd(
        clientB.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    ASSERT_GE(rB.receivedFd, 0);

    void *addrB = ::mmap(nullptr, FlowTelemetryAbi::kRingDataBytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED, rB.receivedFd, 0);
    ASSERT_NE(addrB, MAP_FAILED) << std::strerror(errno);
    const auto unmapB = std::unique_ptr<void, void (*)(void *)>(addrB, [](void *p) {
        ::munmap(p, FlowTelemetryAbi::kRingDataBytes);
    });
    const std::byte *slotB0 = reinterpret_cast<const std::byte *>(addrB);

    ASSERT_TRUE(flowTelemetry.exportSyntheticTestRecord());
    waitCommitted(slotB0);

    // Old ring A must not observe new tickets.
    const std::uint64_t ticketA0After = FlowTelemetryAbi::readU64Le(
        std::span<const std::byte>(slotA0, FlowTelemetryAbi::kSlotBytes), FlowTelemetryAbi::kSlotOffsetTicket);
    EXPECT_EQ(ticketA0After, ticketA0);

    // Cleanup: close clients so server threads exit.
    ::close(clientA.fd);
    clientA.fd = -1;
    ::close(clientB.fd);
    clientB.fd = -1;

    if (tA.joinable()) {
        tA.join();
    }
    if (tB.joinable()) {
        tB.join();
    }

    // Ensure we don't leak an active session across tests.
    flowTelemetry.resetAll();
}

TEST(ControlVNextTelemetrySurface, ResetAllInvalidatesOldRingAndReopenRebuilds) {
    int fds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds), 0) << std::strerror(errno);
    UniqueFd serverFd{.fd = fds[0]};
    UniqueFd clientFd{.fd = fds[1]};

    std::thread server([fd = serverFd.fd] {
        ControlVNextSession session(
            fd, ControlVNextSession::Limits{.maxRequestBytes = 16 * 1024 * 1024,
                                            .maxResponseBytes = 16 * 1024 * 1024},
            /*canPassFdOverride=*/true);
        session.run();
    });
    serverFd.fd = -1;

    // OPEN 1
    ASSERT_TRUE(writeAll(clientFd.fd, ControlVNext::encodeNetstring(
                                        R"({"id":40,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})")));
    const auto r1 = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    ASSERT_GE(r1.receivedFd, 0);

    void *addr1 = ::mmap(nullptr, FlowTelemetryAbi::kRingDataBytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED, r1.receivedFd, 0);
    ASSERT_NE(addr1, MAP_FAILED) << std::strerror(errno);
    const auto unmap1 = std::unique_ptr<void, void (*)(void *)>(addr1, [](void *p) {
        ::munmap(p, FlowTelemetryAbi::kRingDataBytes);
    });
    const std::byte *slot10 = reinterpret_cast<const std::byte *>(addr1);

    ASSERT_TRUE(flowTelemetry.exportSyntheticTestRecord());

    const auto waitCommitted = [&](const std::byte *slot0) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        for (;;) {
            std::uint32_t state = 0;
            std::memcpy(&state, slot0 + FlowTelemetryAbi::kSlotOffsetState, sizeof(state));
            if (state == static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed)) {
                return;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                FAIL() << "record was not committed in time";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    waitCommitted(slot10);
    const std::uint64_t ticket1 = FlowTelemetryAbi::readU64Le(
        std::span<const std::byte>(slot10, FlowTelemetryAbi::kSlotBytes), FlowTelemetryAbi::kSlotOffsetTicket);

    // RESETALL
    ASSERT_TRUE(writeAll(clientFd.fd,
                         ControlVNext::encodeNetstring(R"({"id":41,"cmd":"RESETALL","args":{}})")));
    const auto rReset = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    EXPECT_LT(rReset.receivedFd, 0);

    // No consumer after reset.
    EXPECT_FALSE(flowTelemetry.exportSyntheticTestRecord());

    // OPEN 2
    ASSERT_TRUE(writeAll(clientFd.fd, ControlVNext::encodeNetstring(
                                        R"({"id":42,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}})")));
    const auto r2 = recvOneResponseFrameWithOptionalFd(
        clientFd.fd, /*maxFrameBytes=*/16 * 1024 * 1024, std::chrono::milliseconds(2000));
    ASSERT_GE(r2.receivedFd, 0);

    void *addr2 = ::mmap(nullptr, FlowTelemetryAbi::kRingDataBytes, PROT_READ | PROT_WRITE,
                         MAP_SHARED, r2.receivedFd, 0);
    ASSERT_NE(addr2, MAP_FAILED) << std::strerror(errno);
    const auto unmap2 = std::unique_ptr<void, void (*)(void *)>(addr2, [](void *p) {
        ::munmap(p, FlowTelemetryAbi::kRingDataBytes);
    });
    const std::byte *slot20 = reinterpret_cast<const std::byte *>(addr2);

    ASSERT_TRUE(flowTelemetry.exportSyntheticTestRecord());
    waitCommitted(slot20);

    // Old ring must not observe new tickets.
    const std::uint64_t ticket1After = FlowTelemetryAbi::readU64Le(
        std::span<const std::byte>(slot10, FlowTelemetryAbi::kSlotBytes), FlowTelemetryAbi::kSlotOffsetTicket);
    EXPECT_EQ(ticket1After, ticket1);

    ::close(clientFd.fd);
    clientFd.fd = -1;
    if (server.joinable()) {
        server.join();
    }

    // Ensure we don't leak an active session across tests.
    flowTelemetry.resetAll();
}
