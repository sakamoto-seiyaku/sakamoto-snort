/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <ControlVNextCodec.hpp>
#include <RuntimeConfig.hpp>
#include <RuntimeControl.hpp>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace {

class FakeRuntimeControl final : public SnortRuntime::BaseRuntimeControl {
public:
    bool nfqueuePassThroughReady() const noexcept override { return true; }
    bool resetBaseRuntime() noexcept override { return true; }
};

class ScopedEnv {
public:
    ScopedEnv(std::string name, std::string value) : name_(std::move(name)) {
        setenv(name_.c_str(), value.c_str(), 1);
    }

    ~ScopedEnv() { unsetenv(name_.c_str()); }

private:
    std::string name_;
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

rapidjson::Document rpc(const int fd, const std::uint32_t id, const std::string_view cmd) {
    const std::string frame = ControlVNext::encodeNetstring(
        std::string("{\"id\":") + std::to_string(id) + ",\"cmd\":\"" + std::string(cmd) +
        "\",\"args\":{}}");
    if (!writeAll(fd, frame)) {
        throw std::runtime_error("write failed");
    }

    ControlVNext::NetstringDecoder decoder(16 * 1024 * 1024);
    std::array<std::byte, 4096> buffer{};
    for (;;) {
        if (const auto payload = decoder.pop(); payload.has_value()) {
            rapidjson::Document doc;
            ControlVNext::JsonError error;
            if (!ControlVNext::parseStrictJsonObject(*payload, doc, error)) {
                throw std::runtime_error(error.message);
            }
            return doc;
        }

        const ssize_t n = ::read(fd, buffer.data(), buffer.size());
        if (n == 0) {
            throw std::runtime_error("connection closed");
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("read failed: ") + std::strerror(errno));
        }
        if (const auto err = decoder.feed(std::span<const std::byte>(
                buffer.data(), static_cast<std::size_t>(n)));
            err.has_value()) {
            throw std::runtime_error(err->message);
        }
    }
}

int createBoundFilesystemSocket(const std::string_view path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        throw std::runtime_error(std::string("socket failed: ") + std::strerror(errno));
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, std::string(path).c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0) {
        const std::string message = std::string("bind failed: ") + std::strerror(errno);
        ::close(fd);
        throw std::runtime_error(message);
    }
    return fd;
}

int connectFilesystemSocket(const std::string_view path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, std::string(path).c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int connectAbstractSocket() {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    std::strncpy(addr.sun_path + 1, SnortConfig::kControlVNextSocketName,
                 sizeof(addr.sun_path) - 2);
    const auto nameLen = strnlen(SnortConfig::kControlVNextSocketName,
                                 sizeof(addr.sun_path) - 1);
    const auto addrLen =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);
    if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), addrLen) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int waitForConnectFilesystem(const std::string_view path) {
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (const int fd = connectFilesystemSocket(path); fd >= 0) {
            return fd;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return -1;
}

void requestShutdownThroughAbstractFallback() {
    if (const int fd = connectAbstractSocket(); fd >= 0) {
        (void)rpc(fd, 99, "QUIT");
        ::close(fd);
    }
}

} // namespace

TEST(ControlServerInitSocket, AcceptsInheritedAndroidInitSocket) {
    char dirTemplate[] = "/tmp/snort-init-socket-XXXXXX";
    char *dir = ::mkdtemp(dirTemplate);
    ASSERT_NE(dir, nullptr);
    const std::string socketPath = std::string(dir) + "/control";
    const int inheritedFd = createBoundFilesystemSocket(socketPath);
    ScopedEnv env(std::string("ANDROID_SOCKET_") + SnortConfig::kControlVNextSocketName,
                  std::to_string(inheritedFd));

    FakeRuntimeControl runtime;
    SnortControlVNext::ControlServer server(runtime);
    std::thread serverThread([&server] { EXPECT_EQ(server.run(), 0); });

    const int clientFd = waitForConnectFilesystem(socketPath);
    if (clientFd < 0) {
        requestShutdownThroughAbstractFallback();
        serverThread.join();
        ::close(inheritedFd);
        ::unlink(socketPath.c_str());
        ::rmdir(dir);
        FAIL() << "server did not accept inherited init socket";
    }

    const rapidjson::Document hello = rpc(clientFd, 1, "HELLO");
    EXPECT_TRUE(hello["ok"].GetBool());
    EXPECT_STREQ(hello["result"]["protocol"].GetString(), "control-vnext");

    const rapidjson::Document quit = rpc(clientFd, 2, "QUIT");
    EXPECT_TRUE(quit["ok"].GetBool());
    ::close(clientFd);

    serverThread.join();
    ::close(inheritedFd);
    ::unlink(socketPath.c_str());
    ::rmdir(dir);
}
