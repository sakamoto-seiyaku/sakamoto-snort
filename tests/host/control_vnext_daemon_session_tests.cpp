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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <thread>

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
std::shared_mutex mutexListeners;

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
                                                     .maxResponseBytes = maxResponseBytes});
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
    EXPECT_STREQ(result["protocol"].GetString(), "control-vnext");
    EXPECT_EQ(result["protocolVersion"].GetUint(), 1u);
    EXPECT_STREQ(result["framing"].GetString(), "netstring");
    EXPECT_EQ(result["maxRequestBytes"].GetUint64(), 1024u);
    EXPECT_EQ(result["maxResponseBytes"].GetUint64(), 2048u);
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
