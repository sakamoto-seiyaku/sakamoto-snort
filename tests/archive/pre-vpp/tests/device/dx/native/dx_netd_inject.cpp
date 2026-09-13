/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr const char *kDefaultSocketPath = "/dev/socket/sucre-snort-netd";
constexpr const char *kDefaultAbstractName = "sucre-snort-netd";

[[nodiscard]] bool writeExact(const int fd, const void *buf, const size_t len) {
    const ssize_t n = ::write(fd, buf, len);
    return n == static_cast<ssize_t>(len);
}

[[nodiscard]] bool readExact(const int fd, void *buf, const size_t len) {
    const ssize_t n = ::read(fd, buf, len);
    return n == static_cast<ssize_t>(len);
}

[[nodiscard]] std::optional<int> connectFilesystemSeqpacket(const std::string_view path) {
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return std::nullopt;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return std::nullopt;
    }
    std::memcpy(addr.sun_path, path.data(), path.size());
    addr.sun_path[path.size()] = '\0';

    if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return std::nullopt;
    }
    return fd;
}

[[nodiscard]] std::optional<int> connectAbstractSeqpacket(const std::string_view name) {
    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return std::nullopt;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    if (name.size() >= sizeof(addr.sun_path) - 1) {
        ::close(fd);
        return std::nullopt;
    }
    std::memcpy(addr.sun_path + 1, name.data(), name.size());
    const socklen_t addrLen =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());

    if (::connect(fd, reinterpret_cast<const sockaddr *>(&addr), addrLen) != 0) {
        ::close(fd);
        return std::nullopt;
    }
    return fd;
}

[[nodiscard]] std::optional<uint32_t> parseU32(const char *s) {
    if (!s || !*s) {
        return std::nullopt;
    }
    errno = 0;
    char *end = nullptr;
    const unsigned long v = std::strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return std::nullopt;
    }
    if (v > 0xFFFFFFFFul) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(v);
}

[[nodiscard]] std::string argValue(int &i, const int argc, char **argv) {
    if (i + 1 >= argc) {
        return {};
    }
    ++i;
    return std::string(argv[i]);
}

void printUsage(const char *argv0) {
    std::fprintf(stderr,
                 "Usage: %s --uid <uid> --domain <domain> [--socket <path>] [--abstract <name>]\n",
                 argv0);
}

} // namespace

int main(int argc, char **argv) {
    uint32_t uid = 0;
    std::string domain;
    std::string socketPath = kDefaultSocketPath;
    std::string abstractName = kDefaultAbstractName;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        if (arg == "--uid") {
            const std::string v = argValue(i, argc, argv);
            const auto parsed = parseU32(v.c_str());
            if (!parsed.has_value()) {
                std::fprintf(stderr, "invalid --uid: %s\n", v.c_str());
                return 2;
            }
            uid = *parsed;
            continue;
        }
        if (arg == "--domain") {
            domain = argValue(i, argc, argv);
            continue;
        }
        if (arg == "--socket") {
            socketPath = argValue(i, argc, argv);
            continue;
        }
        if (arg == "--abstract") {
            abstractName = argValue(i, argc, argv);
            continue;
        }

        std::fprintf(stderr, "unknown arg: %s\n", argv[i]);
        printUsage(argv[0]);
        return 2;
    }

    if (uid == 0 || domain.empty()) {
        printUsage(argv[0]);
        return 2;
    }

    auto fd = connectFilesystemSeqpacket(socketPath);
    if (!fd.has_value()) {
        fd = connectAbstractSeqpacket(abstractName);
    }
    if (!fd.has_value()) {
        std::fprintf(stderr, "failed to connect to %s or @%s: %s\n", socketPath.c_str(),
                     abstractName.c_str(), std::strerror(errno));
        return 3;
    }

    std::string host = domain;
    host.push_back('\0');
    const uint32_t hostLen = static_cast<uint32_t>(host.size());

    if (!writeExact(*fd, &hostLen, sizeof(hostLen)) ||
        !writeExact(*fd, host.data(), host.size()) ||
        !writeExact(*fd, &uid, sizeof(uid))) {
        std::fprintf(stderr, "failed to write request: %s\n", std::strerror(errno));
        ::close(*fd);
        return 4;
    }

    bool verdict = false;
    bool getips = false;
    if (!readExact(*fd, &verdict, sizeof(verdict)) || !readExact(*fd, &getips, sizeof(getips))) {
        std::fprintf(stderr, "failed to read response: %s\n", std::strerror(errno));
        ::close(*fd);
        return 5;
    }

    if (getips) {
        const int family = -1;
        if (!writeExact(*fd, &family, sizeof(family))) {
            std::fprintf(stderr, "failed to write ip terminator: %s\n", std::strerror(errno));
            ::close(*fd);
            return 6;
        }
    }

    std::printf("verdict=%d getips=%d\n", verdict ? 1 : 0, getips ? 1 : 0);
    ::close(*fd);
    return 0;
}

