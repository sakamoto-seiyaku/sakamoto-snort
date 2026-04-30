/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>
#include <ControlVNextStreamJson.hpp>
#include <ControlVNextStreamManager.hpp>
#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
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

    bool waitForClose(const int timeoutMs) {
        pollfd pfd{.fd = clientFd, .events = POLLIN | POLLHUP, .revents = 0};
        const int rc = ::poll(&pfd, 1, timeoutMs);
        if (rc <= 0) {
            return false;
        }
        if (pfd.revents & POLLHUP) {
            return true;
        }
        char byte = '\0';
        return ::read(clientFd, &byte, 1) == 0;
    }
};

std::uint64_t totalTraffic(const TrafficSnapshot &snapshot) {
    std::uint64_t total = 0;
    for (const auto &dim : snapshot.dims) {
        total += dim.allow;
        total += dim.block;
    }
    return total;
}

void resetStreamState() { controlVNextStream.resetAll(); }

ControlVNextStreamManager::DnsEvent makeReplayDnsEvent(const std::uint32_t uid) {
    return ControlVNextStreamManager::DnsEvent{
        .timestamp = timespec{.tv_sec = static_cast<std::time_t>(uid), .tv_nsec = 0},
        .uid = uid,
        .app = std::make_shared<const std::string>("replay.app"),
    };
}

} // namespace

TEST(ControlVNextStreamSurface, StartEmitsStartedNotice) {
    resetStreamState();

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

TEST(ControlVNextStreamSurface, ReplayUsesOnlyBoundedDebugPrebuffer) {
    ControlVNextStreamManager manager(ControlVNextStreamManager::Caps{
        .maxHorizonSec = 60,
        .maxRingEvents = 2,
        .maxPendingEvents = 8,
    });

    manager.observeDnsTracked(makeReplayDnsEvent(1001));
    manager.observeDnsTracked(makeReplayDnsEvent(1002));
    manager.observeDnsTracked(makeReplayDnsEvent(1003));

    int sessionKey = 0;
    ControlVNextStreamManager::StartResult startResult{};
    ASSERT_TRUE(manager.start(&sessionKey,
                              ControlVNextStreamManager::StartParams{
                                  .type = ControlVNextStreamManager::Type::Dns,
                                  .horizonSec = 0,
                                  .minSize = 100,
                              },
                              startResult));
    EXPECT_EQ(startResult.effectiveHorizonSec, 0u);
    EXPECT_EQ(startResult.effectiveMinSize, 2u);

    const auto first = manager.popDnsPending(&sessionKey);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->uid, 1002u);

    const auto second = manager.popDnsPending(&sessionKey);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->uid, 1003u);

    EXPECT_FALSE(manager.popDnsPending(&sessionKey).has_value());

    auto started = ControlVNextStreamJson::makeStartedNotice(ControlVNextStreamManager::Type::Dns,
                                                            startResult.effectiveHorizonSec,
                                                            startResult.effectiveMinSize);
    EXPECT_TRUE(started.HasMember("horizonSec"));
    EXPECT_TRUE(started.HasMember("minSize"));
    EXPECT_FALSE(started.HasMember("history"));
    EXPECT_FALSE(started.HasMember("timeline"));
}

TEST(ControlVNextStreamSurface, StartRejectsUnknownArgsKey) {
    resetStreamState();

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
    resetStreamState();

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
    resetStreamState();

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
    resetStreamState();

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
    resetStreamState();

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
    resetStreamState();

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

TEST(ControlVNextStreamSurface, ResetAllCancelsStreamThroughOwningSession) {
    resetStreamState();

    Harness h(/*maxRequestBytes=*/4096, /*maxResponseBytes=*/4096);

    h.sendJsonFrame(R"({"id":1,"cmd":"STREAM.START","args":{"type":"dns"}})");
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // response
    ASSERT_TRUE(h.readFrame(/*timeoutMs=*/1000).has_value()); // started notice

    controlVNextStream.resetAll();

    EXPECT_TRUE(h.waitForClose(/*timeoutMs=*/1000));
}

TEST(ControlVNextStreamSurface, SecondSubscriberIsStateConflict) {
    resetStreamState();

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
    resetStreamState();

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

TEST(ControlVNextStreamSurface, SuppressedDnsTakeAndResetDoesNotLoseConcurrentIncrements) {
    ControlVNextStreamManager manager(ControlVNextStreamManager::Caps{
        .maxHorizonSec = 0,
        .maxRingEvents = 0,
        .maxPendingEvents = 8,
    });
    int sessionKey = 0;
    ControlVNextStreamManager::StartResult startResult{};
    ASSERT_TRUE(manager.start(&sessionKey,
                              ControlVNextStreamManager::StartParams{
                                  .type = ControlVNextStreamManager::Type::Dns,
                              },
                              startResult));

    constexpr int kProducerCount = 4;
    constexpr int kIterations = 25000;
    std::atomic_bool start{false};
    std::atomic_int activeProducers{kProducerCount};
    std::atomic<std::uint64_t> expected{0};
    std::uint64_t observed = 0;

    std::thread consumer([&] {
        while (!start.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        while (activeProducers.load(std::memory_order_acquire) > 0) {
            observed += totalTraffic(manager.takeSuppressedTraffic(ControlVNextStreamManager::Type::Dns));
            std::this_thread::yield();
        }
    });

    std::array<std::thread, kProducerCount> producers;
    for (int producer = 0; producer < kProducerCount; ++producer) {
        producers[producer] = std::thread([&, producer] {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < kIterations; ++i) {
                manager.observeDnsSuppressed(((i + producer) % 2) == 0);
                expected.fetch_add(1, std::memory_order_relaxed);
                if ((i % 64) == 0) {
                    std::this_thread::yield();
                }
            }
            activeProducers.fetch_sub(1, std::memory_order_release);
        });
    }

    start.store(true, std::memory_order_release);
    for (auto &producer : producers) {
        producer.join();
    }
    consumer.join();
    observed += totalTraffic(manager.takeSuppressedTraffic(ControlVNextStreamManager::Type::Dns));

    EXPECT_EQ(observed, expected.load(std::memory_order_relaxed));
}

TEST(ControlVNextStreamSurface, SuppressedPktTakeAndResetClearsPacketAndByteCounters) {
    ControlVNextStreamManager manager(ControlVNextStreamManager::Caps{
        .maxHorizonSec = 0,
        .maxRingEvents = 0,
        .maxPendingEvents = 8,
    });
    int sessionKey = 0;
    ControlVNextStreamManager::StartResult startResult{};
    ASSERT_TRUE(manager.start(&sessionKey,
                              ControlVNextStreamManager::StartParams{
                                  .type = ControlVNextStreamManager::Type::Pkt,
                              },
                              startResult));

    manager.observePktSuppressed(/*input=*/true, /*accepted=*/true, /*bytes=*/7);
    manager.observePktSuppressed(/*input=*/false, /*accepted=*/false, /*bytes=*/11);

    const auto snapshot = manager.takeSuppressedTraffic(ControlVNextStreamManager::Type::Pkt);
    EXPECT_EQ(snapshot.dims[1].allow, 1U);
    EXPECT_EQ(snapshot.dims[2].allow, 7U);
    EXPECT_EQ(snapshot.dims[3].block, 1U);
    EXPECT_EQ(snapshot.dims[4].block, 11U);
    EXPECT_EQ(totalTraffic(manager.takeSuppressedTraffic(ControlVNextStreamManager::Type::Pkt)), 0U);
}

TEST(ControlVNextStreamSurface, SuppressedCountersStartFromCleanSubscriptionBoundary) {
    ControlVNextStreamManager manager(ControlVNextStreamManager::Caps{
        .maxHorizonSec = 0,
        .maxRingEvents = 0,
        .maxPendingEvents = 8,
    });
    manager.observeDnsSuppressed(/*blocked=*/true);
    EXPECT_EQ(totalTraffic(manager.takeSuppressedTraffic(ControlVNextStreamManager::Type::Dns)), 0U);

    int sessionKey = 0;
    ControlVNextStreamManager::StartResult startResult{};
    ASSERT_TRUE(manager.start(&sessionKey,
                              ControlVNextStreamManager::StartParams{
                                  .type = ControlVNextStreamManager::Type::Dns,
                              },
                              startResult));

    manager.observeDnsSuppressed(/*blocked=*/false);
    EXPECT_EQ(totalTraffic(manager.takeSuppressedTraffic(ControlVNextStreamManager::Type::Dns)), 1U);
}
