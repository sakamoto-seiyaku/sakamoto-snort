/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <thread>

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
std::shared_mutex mutexListeners;
std::mutex mutexControlMutations;

namespace ControlVNextSessionCommands::TestHooks {
void reset();
void blockCommandUntilReleased(std::string_view cmd);
void releaseBlockedCommand();
bool waitForBlockedCommand(std::chrono::milliseconds timeout);
void markResetEntered();
int resetCountSnapshot();
int checkpointRestoreCountSnapshot();
} // namespace ControlVNextSessionCommands::TestHooks

void snortResetAll() {
    const std::lock_guard<std::mutex> controlLock(mutexControlMutations);
    const std::lock_guard listenersLock(mutexListeners);
    ControlVNextSessionCommands::TestHooks::markResetEntered();
}

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

struct Harness {
    int clientFd = -1;
    std::thread serverThread;
    ControlVNext::NetstringDecoder decoder{16 * 1024 * 1024};

    explicit Harness(const size_t maxRequestBytes, const size_t maxResponseBytes) {
        int fds[2]{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
            throw std::runtime_error("socketpair failed");
        }

        clientFd = fds[1];
        serverThread = std::thread([serverFd = fds[0], maxRequestBytes, maxResponseBytes] {
            ControlVNextSession session(
                serverFd, ControlVNextSession::Limits{.maxRequestBytes = maxRequestBytes,
                                                     .maxResponseBytes = maxResponseBytes},
                /*canPassFdOverride=*/true);
            session.run();
        });
    }

    ~Harness() {
        if (clientFd >= 0) {
            ::close(clientFd);
        }
        if (serverThread.joinable()) {
            serverThread.join();
        }
    }

    rapidjson::Document readOneResponse() {
        if (auto doc = tryReadOneResponse(std::chrono::milliseconds::max())) {
            return std::move(*doc);
        }
        throw std::runtime_error("timed out waiting for response");
    }

    std::optional<rapidjson::Document> tryReadOneResponse(const std::chrono::milliseconds timeout) {
        const auto deadline = timeout == std::chrono::milliseconds::max()
                                  ? std::chrono::steady_clock::time_point::max()
                                  : std::chrono::steady_clock::now() + timeout;
        std::array<std::byte, 4096> buf{};
        for (;;) {
            if (const auto payload = decoder.pop(); payload.has_value()) {
                rapidjson::Document doc;
                ControlVNext::JsonError error;
                if (!ControlVNext::parseStrictJsonObject(*payload, doc, error)) {
                    throw std::runtime_error("response JSON parse failed");
                }
                return doc;
            }

            int pollTimeout = -1;
            if (deadline != std::chrono::steady_clock::time_point::max()) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline) {
                    return std::nullopt;
                }
                pollTimeout = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            }

            pollfd pfd{.fd = clientFd, .events = POLLIN | POLLHUP, .revents = 0};
            const int pollRc = ::poll(&pfd, 1, pollTimeout);
            if (pollRc == 0) {
                return std::nullopt;
            }
            if (pollRc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("poll failed: ") + std::strerror(errno));
            }

            const ssize_t n = ::read(clientFd, buf.data(), buf.size());
            if (n == 0) {
                throw std::runtime_error("connection closed without response");
            }
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("read failed: ") + std::strerror(errno));
            }
            if (const auto framingErr = decoder.feed(std::span<const std::byte>(
                    buf.data(), static_cast<size_t>(n)));
                framingErr.has_value()) {
                throw std::runtime_error("framing error while reading response");
            }
        }
    }

    void sendFrame(const std::string_view frame) {
        if (!writeAll(clientFd, frame)) {
            throw std::runtime_error("write failed");
        }
    }

    void sendJsonFrame(const std::string_view json) {
        sendFrame(ControlVNext::encodeNetstring(json));
    }

    bool waitForClose(const int timeoutMs = 1000) const {
        pollfd pfd{.fd = clientFd, .events = POLLIN | POLLHUP, .revents = 0};
        const int rc = ::poll(&pfd, 1, timeoutMs);
        if (rc <= 0) {
            return false;
        }
        return (pfd.revents & POLLHUP) != 0;
    }
};

} // namespace

static void expectOkResponse(const rapidjson::Document &resp, const uint32_t expectedId) {
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(resp, view).has_value());
    EXPECT_EQ(view.id, expectedId);
    EXPECT_TRUE(view.ok);
}

TEST(ControlVNextDaemonSession, RejectsUnknownRequestKeys) {
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"HELLO","args":{},"extra":1})");
    const rapidjson::Document resp = h.readOneResponse();

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    EXPECT_EQ(view.id, 1u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    ASSERT_TRUE(view.error->HasMember("code"));
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");
}

TEST(ControlVNextDaemonSession, RejectsUnknownCmd) {
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":2,"cmd":"NOPE","args":{}})");
    const rapidjson::Document resp = h.readOneResponse();

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    EXPECT_EQ(view.id, 2u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "UNSUPPORTED_COMMAND");
}

TEST(ControlVNextDaemonSession, RejectsUnknownArgsKeys) {
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":3,"cmd":"HELLO","args":{"x":1}})");
    const rapidjson::Document resp = h.readOneResponse();

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    EXPECT_EQ(view.id, 3u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");
}

TEST(ControlVNextDaemonSession, HelloHasRequiredFieldsAndEchoesId) {
    Harness h(/*maxRequestBytes=*/1024, /*maxResponseBytes=*/2048);

    h.sendJsonFrame(R"({"id":10,"cmd":"HELLO","args":{}})");
    const rapidjson::Document resp = h.readOneResponse();

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    EXPECT_EQ(view.id, 10u);
    EXPECT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);

    const auto &result = *view.result;
    ASSERT_TRUE(result.IsObject());
    ASSERT_TRUE(result.HasMember("protocol"));
    ASSERT_TRUE(result.HasMember("protocolVersion"));
    ASSERT_TRUE(result.HasMember("framing"));
    ASSERT_TRUE(result.HasMember("maxRequestBytes"));
    ASSERT_TRUE(result.HasMember("maxResponseBytes"));
    ASSERT_TRUE(result.HasMember("daemonBuildId"));
    ASSERT_TRUE(result.HasMember("artifactAbi"));
    ASSERT_TRUE(result.HasMember("capabilities"));
    EXPECT_STREQ(result["protocol"].GetString(), "control-vnext");
    EXPECT_EQ(result["protocolVersion"].GetUint(), 1u);
    EXPECT_STREQ(result["framing"].GetString(), "netstring");
    EXPECT_EQ(result["maxRequestBytes"].GetUint64(), 1024u);
    EXPECT_EQ(result["maxResponseBytes"].GetUint64(), 2048u);
    ASSERT_TRUE(result["daemonBuildId"].IsString());
    EXPECT_NE(std::string_view(result["daemonBuildId"].GetString(),
                               result["daemonBuildId"].GetStringLength()),
              std::string_view());
    ASSERT_TRUE(result["artifactAbi"].IsString());
    ASSERT_TRUE(result["capabilities"].IsArray());
    EXPECT_GT(result["capabilities"].Size(), 0u);
    for (const auto &capability : result["capabilities"].GetArray()) {
        EXPECT_TRUE(capability.IsString());
        EXPECT_GT(capability.GetStringLength(), 0u);
    }
}

TEST(ControlVNextDaemonSession, HelloRemainsCompatibleForExistingFieldReaders) {
    Harness h(/*maxRequestBytes=*/3072, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":12,"cmd":"HELLO","args":{}})");
    const rapidjson::Document resp = h.readOneResponse();

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    EXPECT_EQ(view.id, 12u);
    EXPECT_TRUE(view.ok);
    ASSERT_NE(view.result, nullptr);

    const auto &result = *view.result;
    EXPECT_STREQ(result["protocol"].GetString(), "control-vnext");
    EXPECT_EQ(result["protocolVersion"].GetUint(), 1u);
    EXPECT_STREQ(result["framing"].GetString(), "netstring");
    EXPECT_EQ(result["maxRequestBytes"].GetUint64(), 3072u);
    EXPECT_EQ(result["maxResponseBytes"].GetUint64(), 4096u);
}

TEST(ControlVNextDaemonSession, QuitClosesAfterResponse) {
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":11,"cmd":"QUIT","args":{}})");
    const rapidjson::Document resp = h.readOneResponse();

    ControlVNext::ResponseView view;
    const auto envErr = ControlVNext::parseResponseEnvelope(resp, view);
    ASSERT_FALSE(envErr.has_value());
    EXPECT_EQ(view.id, 11u);
    EXPECT_TRUE(view.ok);

    ASSERT_TRUE(h.waitForClose()) << "expected server close after QUIT";
    std::array<std::byte, 16> buf{};
    const ssize_t n = ::read(h.clientFd, buf.data(), buf.size());
    EXPECT_EQ(n, 0) << "expected EOF after QUIT";
}

TEST(ControlVNextDaemonSession, MutationRespondsWhileDatapathLockIsHeld) {
    ControlVNextSessionCommands::TestHooks::reset();
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);
    std::unique_lock<std::shared_mutex> datapathLock(mutexListeners);

    h.sendJsonFrame(R"({"id":20,"cmd":"CONFIG.SET","args":{}})");
    auto resp = h.tryReadOneResponse(std::chrono::milliseconds(250));

    datapathLock.unlock();
    ASSERT_TRUE(resp.has_value()) << "CONFIG.SET should not wait for mutexListeners";
    expectOkResponse(*resp, 20u);
}

TEST(ControlVNextDaemonSession, LargeMutationDispatchDoesNotRequireDatapathLock) {
    ControlVNextSessionCommands::TestHooks::reset();
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);
    std::unique_lock<std::shared_mutex> datapathLock(mutexListeners);

    h.sendJsonFrame(R"({"id":21,"cmd":"DOMAINLISTS.IMPORT","args":{}})");
    auto resp = h.tryReadOneResponse(std::chrono::milliseconds(250));

    datapathLock.unlock();
    ASSERT_TRUE(resp.has_value()) << "DOMAINLISTS.IMPORT dispatch should not wait for mutexListeners";
    expectOkResponse(*resp, 21u);
}

TEST(ControlVNextDaemonSession, CheckpointSaveDispatchDoesNotRequireDatapathLock) {
    ControlVNextSessionCommands::TestHooks::reset();
    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);
    std::unique_lock<std::shared_mutex> datapathLock(mutexListeners);

    h.sendJsonFrame(R"({"id":22,"cmd":"CHECKPOINT.SAVE","args":{"slot":0}})");
    auto resp = h.tryReadOneResponse(std::chrono::milliseconds(250));

    datapathLock.unlock();
    ASSERT_TRUE(resp.has_value()) << "CHECKPOINT.SAVE should not wait for mutexListeners";
    expectOkResponse(*resp, 22u);
}

TEST(ControlVNextDaemonSession, ResetAllWaitsForInFlightControlMutation) {
    ControlVNextSessionCommands::TestHooks::reset();
    ControlVNextSessionCommands::TestHooks::blockCommandUntilReleased("CONFIG.SET");
    Harness mutationClient(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);
    Harness resetClient(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    mutationClient.sendJsonFrame(R"({"id":30,"cmd":"CONFIG.SET","args":{}})");
    if (!ControlVNextSessionCommands::TestHooks::waitForBlockedCommand(
            std::chrono::milliseconds(1000))) {
        ControlVNextSessionCommands::TestHooks::releaseBlockedCommand();
        FAIL() << "CONFIG.SET did not enter the test mutation boundary";
    }

    resetClient.sendJsonFrame(R"({"id":31,"cmd":"RESETALL","args":{}})");
    EXPECT_FALSE(resetClient.tryReadOneResponse(std::chrono::milliseconds(150)).has_value())
        << "RESETALL responded before the in-flight mutation left the control boundary";
    EXPECT_EQ(ControlVNextSessionCommands::TestHooks::resetCountSnapshot(), 0);

    ControlVNextSessionCommands::TestHooks::releaseBlockedCommand();
    const rapidjson::Document mutationResp = mutationClient.readOneResponse();
    const rapidjson::Document resetResp = resetClient.readOneResponse();

    expectOkResponse(mutationResp, 30u);
    expectOkResponse(resetResp, 31u);
    EXPECT_EQ(ControlVNextSessionCommands::TestHooks::resetCountSnapshot(), 1);
}

TEST(ControlVNextDaemonSession, CheckpointRestoreWaitsForInFlightControlMutation) {
    ControlVNextSessionCommands::TestHooks::reset();
    ControlVNextSessionCommands::TestHooks::blockCommandUntilReleased("DOMAINLISTS.IMPORT");
    Harness mutationClient(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);
    Harness restoreClient(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    mutationClient.sendJsonFrame(R"({"id":40,"cmd":"DOMAINLISTS.IMPORT","args":{}})");
    if (!ControlVNextSessionCommands::TestHooks::waitForBlockedCommand(
            std::chrono::milliseconds(1000))) {
        ControlVNextSessionCommands::TestHooks::releaseBlockedCommand();
        FAIL() << "DOMAINLISTS.IMPORT did not enter the test mutation boundary";
    }

    restoreClient.sendJsonFrame(R"({"id":41,"cmd":"CHECKPOINT.RESTORE","args":{"slot":0}})");
    EXPECT_FALSE(restoreClient.tryReadOneResponse(std::chrono::milliseconds(150)).has_value())
        << "CHECKPOINT.RESTORE responded before the in-flight mutation left the control boundary";
    EXPECT_EQ(ControlVNextSessionCommands::TestHooks::checkpointRestoreCountSnapshot(), 0);

    ControlVNextSessionCommands::TestHooks::releaseBlockedCommand();
    const rapidjson::Document mutationResp = mutationClient.readOneResponse();
    const rapidjson::Document restoreResp = restoreClient.readOneResponse();

    expectOkResponse(mutationResp, 40u);
    expectOkResponse(restoreResp, 41u);
    EXPECT_EQ(ControlVNextSessionCommands::TestHooks::checkpointRestoreCountSnapshot(), 1);
}

TEST(ControlVNextDaemonSession, OversizedRequestDisconnectsWithoutResponse) {
    Harness h(/*maxRequestBytes=*/2, /*maxResponseBytes=*/4096);

    h.sendFrame("3:abc,");

    ASSERT_TRUE(h.waitForClose()) << "expected disconnect for oversized frame";

    std::array<std::byte, 16> buf{};
    const ssize_t n = ::read(h.clientFd, buf.data(), buf.size());
    ASSERT_EQ(n, 0) << "expected EOF";

    // Ensure no response frame was queued.
    EXPECT_FALSE(h.decoder.pop().has_value());
}
