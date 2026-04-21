/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre_snort_ctl_session.hpp>

#include <ControlVNextCodec.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(const int fd) : _fd(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept : _fd(std::exchange(other._fd, -1)) {}
    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) {
            reset(std::exchange(other._fd, -1));
        }
        return *this;
    }

    [[nodiscard]] int get() const { return _fd; }
    [[nodiscard]] explicit operator bool() const { return _fd >= 0; }

    void reset(const int fd = -1) {
        if (_fd >= 0) {
            ::close(_fd);
        }
        _fd = fd;
    }

private:
    int _fd = -1;
};

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

std::vector<std::string_view> splitLines(const std::string &s) {
    std::vector<std::string_view> out;
    size_t start = 0;
    while (start < s.size()) {
        const size_t end = s.find('\n', start);
        if (end == std::string::npos) {
            out.emplace_back(s.data() + start, s.size() - start);
            break;
        }
        out.emplace_back(s.data() + start, end - start);
        start = end + 1;
    }
    while (!out.empty() && out.back().empty()) {
        out.pop_back();
    }
    return out;
}

} // namespace

TEST(ControlVNextCtl, HelloRoundtripOverSocketpair) {
    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds), 0)
        << std::strerror(errno);
    UniqueFd serverFd(fds[0]);
    UniqueFd clientFd(fds[1]);

    std::thread server([fd = std::move(serverFd)]() mutable {
        ControlVNext::NetstringDecoder decoder(/*maxFrameBytes=*/1024 * 1024);
        std::array<std::byte, 4096> buf{};

        std::optional<std::string> payload;
        while (!payload.has_value()) {
            const ssize_t n = ::read(fd.get(), buf.data(), buf.size());
            if (n <= 0) {
                return;
            }
            if (const auto framingErr =
                    decoder.feed(std::span<const std::byte>(buf.data(), static_cast<size_t>(n)));
                framingErr.has_value()) {
                return;
            }
            payload = decoder.pop();
        }

        rapidjson::Document requestDoc;
        ControlVNext::JsonError jsonError;
        if (!ControlVNext::parseStrictJsonObject(*payload, requestDoc, jsonError)) {
            return;
        }
        ControlVNext::RequestView requestView;
        if (ControlVNext::parseRequestEnvelope(requestDoc, requestView).has_value()) {
            return;
        }
        if (requestView.cmd != "HELLO") {
            return;
        }

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        result.AddMember("protocol", "control-vnext", alloc);
        result.AddMember("protocolVersion", 1, alloc);
        result.AddMember("framing", "netstring", alloc);
        result.AddMember("maxRequestBytes", 123456, alloc);
        result.AddMember("maxResponseBytes", 123456, alloc);

        const rapidjson::Document responseDoc =
            ControlVNext::makeOkResponse(requestView.id, &result);
        const std::string responseJson =
            ControlVNext::encodeJson(responseDoc, ControlVNext::JsonFormat::Compact);
        const std::string responseFrame = ControlVNext::encodeNetstring(responseJson);
        if (!writeAll(fd.get(), responseFrame)) {
            return;
        }

        rapidjson::Document event(rapidjson::kObjectType);
        event.AddMember("type", "notice", event.GetAllocator());
        event.AddMember("notice", "started", event.GetAllocator());
        const std::string eventJson =
            ControlVNext::encodeJson(event, ControlVNext::JsonFormat::Compact);
        const std::string eventFrame = ControlVNext::encodeNetstring(eventJson);
        (void)writeAll(fd.get(), eventFrame);
    });

    SucreSnortCtl::RequestOptions request;
    request.id = 1;
    request.cmd = "HELLO";
    request.argsJson = "{}";

    SucreSnortCtl::SessionOptions options;
    options.pretty = false;
    options.follow = true;
    options.maxFrames = 2;
    options.maxFrameBytes = 1024 * 1024;

    std::ostringstream out;
    std::ostringstream err;
    const int rc = SucreSnortCtl::runSession(clientFd.get(), request, options, out, err);
    EXPECT_EQ(rc, 0) << "stderr:\n" << err.str() << "\nstdout:\n" << out.str();

    if (server.joinable()) {
        server.join();
    }

    const std::string output = out.str();
    const auto lines = splitLines(output);
    ASSERT_GE(lines.size(), 2u) << output;

    {
        rapidjson::Document doc;
        ControlVNext::JsonError parseErr;
        ASSERT_TRUE(ControlVNext::parseStrictJsonObject(lines[0], doc, parseErr)) << parseErr.message;
        ControlVNext::ResponseView resp;
        ASSERT_FALSE(ControlVNext::parseResponseEnvelope(doc, resp).has_value());
        EXPECT_TRUE(resp.ok);
        EXPECT_EQ(resp.id, 1u);
    }

    {
        rapidjson::Document doc;
        ControlVNext::JsonError parseErr;
        ASSERT_TRUE(ControlVNext::parseStrictJsonObject(lines[1], doc, parseErr)) << parseErr.message;
        ControlVNext::EventView ev;
        ASSERT_FALSE(ControlVNext::parseEventEnvelope(doc, ev).has_value());
        EXPECT_EQ(ev.type, "notice");
    }
}
