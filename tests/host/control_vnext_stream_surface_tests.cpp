/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>
#include <ControlVNextStreamManager.hpp>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
std::shared_mutex mutexListeners;
std::mutex mutexControlMutations;

void snortResetAll() {
    const std::lock_guard<std::mutex> controlLock(mutexControlMutations);
    const std::lock_guard listenersLock(mutexListeners);
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

    void sendFrame(const std::string_view frame) {
        if (!writeAll(clientFd, frame)) {
            throw std::runtime_error("write failed");
        }
    }

    void sendJsonFrame(const std::string_view json) {
        sendFrame(ControlVNext::encodeNetstring(json));
    }

    std::optional<rapidjson::Document> readFrame(const int timeoutMs) {
        std::array<std::byte, 4096> buf{};
        for (;;) {
            if (const auto payload = decoder.pop(); payload.has_value()) {
                rapidjson::Document doc;
                ControlVNext::JsonError error;
                if (!ControlVNext::parseStrictJsonObject(*payload, doc, error)) {
                    throw std::runtime_error("frame JSON parse failed");
                }
                return doc;
            }

            pollfd pfd{.fd = clientFd, .events = POLLIN | POLLHUP, .revents = 0};
            const int rc = ::poll(&pfd, 1, timeoutMs);
            if (rc == 0) {
                return std::nullopt;
            }
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("poll failed: ") + std::strerror(errno));
            }
            if (pfd.revents & POLLHUP) {
                throw std::runtime_error("connection closed while waiting for frame");
            }

            const ssize_t n = ::read(clientFd, buf.data(), buf.size());
            if (n == 0) {
                throw std::runtime_error("connection closed while reading frame");
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
                throw std::runtime_error("framing error while reading frame");
            }
        }
    }
};

} // namespace

TEST(ControlVNextStreamSurface, StartEmitsStartedNotice) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns","horizonSec":0,"minSize":0}})");

    const auto respDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(respDoc.has_value());
    ControlVNext::ResponseView resp;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*respDoc, resp).has_value());
    EXPECT_EQ(resp.id, 1u);
    EXPECT_TRUE(resp.ok);

    const auto noticeDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(noticeDoc.has_value());
    ControlVNext::EventView event;
    ASSERT_FALSE(ControlVNext::parseEventEnvelope(*noticeDoc, event).has_value());
    EXPECT_EQ(event.type, "notice");
    ASSERT_TRUE(noticeDoc->HasMember("notice"));
    EXPECT_STREQ((*noticeDoc)["notice"].GetString(), "started");
    ASSERT_TRUE(noticeDoc->HasMember("stream"));
    EXPECT_STREQ((*noticeDoc)["stream"].GetString(), "dns");

    h.sendJsonFrame(R"({"id":2,"cmd":"STREAM.STOP","args":{}})");
    const auto stopDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(stopDoc.has_value());
    ControlVNext::ResponseView stopResp;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*stopDoc, stopResp).has_value());
    EXPECT_EQ(stopResp.id, 2u);
    EXPECT_TRUE(stopResp.ok);
}

TEST(ControlVNextStreamSurface, StartRejectsUnknownArgsKey) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns","x":1}})");

    const auto respDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(respDoc.has_value());
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*respDoc, view).has_value());
    EXPECT_EQ(view.id, 1u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");
}

TEST(ControlVNextStreamSurface, StartRejectsUnknownType) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"nope"}})");

    const auto respDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(respDoc.has_value());
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*respDoc, view).has_value());
    EXPECT_EQ(view.id, 1u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "INVALID_ARGUMENT");
}

TEST(ControlVNextStreamSurface, ActivityStartRejectsReplayArgs) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"activity","horizonSec":1}})");

    const auto respDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(respDoc.has_value());
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*respDoc, view).has_value());
    EXPECT_EQ(view.id, 1u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "SYNTAX_ERROR");
}

TEST(ControlVNextStreamSurface, StopIsIdempotentWhenNotStarted) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.STOP","args":{}})");
    const auto respDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(respDoc.has_value());
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*respDoc, view).has_value());
    EXPECT_EQ(view.id, 1u);
    EXPECT_TRUE(view.ok);

    EXPECT_FALSE(h.readFrame(/*timeoutMs=*/200).has_value());
}

TEST(ControlVNextStreamSurface, RejectsNonStreamCommandInStreamMode) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns"}})");
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // response
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // started notice

    h.sendJsonFrame(R"({"id":2,"cmd":"METRICS.GET","args":{"name":"traffic"}})");
    const auto conflictDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(conflictDoc.has_value());

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*conflictDoc, view).has_value());
    EXPECT_EQ(view.id, 2u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "STATE_CONFLICT");
}

TEST(ControlVNextStreamSurface, StopIsAckBarrier) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns"}})");
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // response
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // started notice

    h.sendJsonFrame(R"({"id":2,"cmd":"STREAM.STOP","args":{}})");
    const auto stopDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(stopDoc.has_value());
    ControlVNext::ResponseView stopResp;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*stopDoc, stopResp).has_value());
    EXPECT_EQ(stopResp.id, 2u);
    EXPECT_TRUE(stopResp.ok);

    // Ack barrier: no further events/notices until next START.
    EXPECT_FALSE(h.readFrame(/*timeoutMs=*/200).has_value());
}

TEST(ControlVNextStreamSurface, SecondSubscriberIsStateConflict) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness a(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);
    Harness b(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    a.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns"}})");
    ASSERT_TRUE(a.readFrame(/*timeoutMs=*/1000).has_value()); // response
    ASSERT_TRUE(a.readFrame(/*timeoutMs=*/1000).has_value()); // started notice

    b.sendJsonFrame(R"({"id":2,"cmd":"STREAM.START","args":{"type":"dns"}})");
    const auto doc = b.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(doc.has_value());
    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*doc, view).has_value());
    EXPECT_EQ(view.id, 2u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "STATE_CONFLICT");

    a.sendJsonFrame(R"({"id":3,"cmd":"STREAM.STOP","args":{}})");
    ASSERT_TRUE(a.readFrame(/*timeoutMs=*/1000).has_value());
}

TEST(ControlVNextStreamSurface, SameConnectionCannotStartAnotherType) {
    for (const int fd : controlVNextStream.resetAll()) {
        (void)::shutdown(fd, SHUT_RDWR);
    }

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns"}})");
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // response
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // started notice

    h.sendJsonFrame(R"({"id":2,"cmd":"STREAM.START","args":{"type":"pkt"}})");
    const auto conflictDoc = h.readFrame(/*timeoutMs=*/1000);
    ASSERT_TRUE(conflictDoc.has_value());

    ControlVNext::ResponseView view;
    ASSERT_FALSE(ControlVNext::parseResponseEnvelope(*conflictDoc, view).has_value());
    EXPECT_EQ(view.id, 2u);
    EXPECT_FALSE(view.ok);
    ASSERT_NE(view.error, nullptr);
    EXPECT_STREQ((*view.error)["code"].GetString(), "STATE_CONFLICT");

    h.sendJsonFrame(R"({"id":3,"cmd":"STREAM.STOP","args":{}})");
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value());
}
