/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <ControlVNextCodec.hpp>
#include <RuntimeControl.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <algorithm>
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
#include <vector>

namespace {

class FakeRuntimeControl final : public SnortRuntime::BaseRuntimeControl {
public:
    bool nfqueuePassThroughReady() const noexcept override { return ready; }
    bool resetBaseRuntime() noexcept override {
        ++resetCount;
        return resetResult;
    }

    bool ready = true;
    bool resetResult = true;
    int resetCount = 0;
};

bool writeAll(const int fd, const std::string_view data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

class ControlServerHarness {
public:
    explicit ControlServerHarness(FakeRuntimeControl &runtime) {
        int fds[2]{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
            throw std::runtime_error(std::string("socketpair failed: ") + std::strerror(errno));
        }

        clientFd_ = fds[1];
        serverThread_ = std::thread([serverFd = fds[0], &runtime] {
            SnortControlVNext::ControlServer server(runtime);
            server.serveClient(serverFd);
            ::close(serverFd);
        });
    }

    ~ControlServerHarness() {
        if (clientFd_ >= 0) {
            ::close(clientFd_);
        }
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
    }

    rapidjson::Document call(const std::uint32_t id, const std::string_view cmd) {
        const std::string frame = ControlVNext::encodeNetstring(
            std::string("{\"id\":") + std::to_string(id) + ",\"cmd\":\"" + std::string(cmd) +
            "\",\"args\":{}}");
        if (!writeAll(clientFd_, frame)) {
            throw std::runtime_error("write failed");
        }
        return readOneResponse();
    }

private:
    rapidjson::Document readOneResponse() {
        std::array<std::byte, 4096> buffer{};
        for (;;) {
            if (const auto payload = decoder_.pop(); payload.has_value()) {
                rapidjson::Document doc;
                ControlVNext::JsonError error;
                if (!ControlVNext::parseStrictJsonObject(*payload, doc, error)) {
                    throw std::runtime_error(error.message);
                }
                return doc;
            }

            const ssize_t n = ::read(clientFd_, buffer.data(), buffer.size());
            if (n == 0) {
                throw std::runtime_error("connection closed");
            }
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("read failed: ") + std::strerror(errno));
            }
            const auto bytes = std::span<const std::byte>(buffer.data(), static_cast<size_t>(n));
            if (const auto err = decoder_.feed(bytes); err.has_value()) {
                throw std::runtime_error(err->message);
            }
        }
    }

    int clientFd_ = -1;
    std::thread serverThread_;
    ControlVNext::NetstringDecoder decoder_{16 * 1024 * 1024};
};

std::vector<std::string_view> capabilityStrings(const rapidjson::Value &capabilities) {
    std::vector<std::string_view> out;
    for (const auto &capability : capabilities.GetArray()) {
        out.emplace_back(capability.GetString(), capability.GetStringLength());
    }
    return out;
}

} // namespace

TEST(ControlServerContract, HelloAdvertisesPassThroughCapabilityWhenRuntimeReady) {
    FakeRuntimeControl runtime;
    runtime.ready = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(1, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto &result = response["result"];
    const auto capabilities = capabilityStrings(result["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "snort10-base"),
              capabilities.end());
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "nfqueue-pass-through"),
              capabilities.end());
}

TEST(ControlServerContract, HelloOmitsPassThroughCapabilityBeforeRuntimeReady) {
    FakeRuntimeControl runtime;
    runtime.ready = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(4, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "snort10-base"),
              capabilities.end());
    EXPECT_EQ(std::find(capabilities.begin(), capabilities.end(), "nfqueue-pass-through"),
              capabilities.end());
}

TEST(ControlServerContract, ResetAllReinstallsOnlyBaseRuntimeState) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(2, "RESETALL");

    ASSERT_TRUE(response["ok"].GetBool());
    EXPECT_EQ(runtime.resetCount, 1);
}

TEST(ControlServerContract, LegacyControlCommandsRemainUnsupported) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(3, "APPS.LIST");

    ASSERT_FALSE(response["ok"].GetBool());
    ASSERT_TRUE(response.HasMember("error"));
    ASSERT_TRUE(response["error"].HasMember("code"));
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
    EXPECT_EQ(runtime.resetCount, 0);
}
