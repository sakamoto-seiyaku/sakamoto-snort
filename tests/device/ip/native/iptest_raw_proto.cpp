/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Args {
    int family = 4;
    std::string dst;
    int proto = 136;
    int count = 1;
    int payloadBytes = 32;
    int delayMs = 0;
};

[[nodiscard]] bool parseInt(const char *s, int &out) {
    if (!s || !*s) {
        return false;
    }
    char *end = nullptr;
    errno = 0;
    const long v = std::strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

[[nodiscard]] const char *argValue(int &i, const int argc, char **argv) {
    if (i + 1 >= argc) {
        return nullptr;
    }
    return argv[++i];
}

void usage(const char *argv0) {
    std::fprintf(stderr,
                 "Usage: %s --family 4|6 --dst ADDR [--proto N] [--count N] "
                 "[--payloadBytes N] [--delayMs N]\n",
                 argv0);
}

[[nodiscard]] bool parseArgs(int argc, char **argv, Args &args) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return false;
        }
        if (arg == "--family") {
            const char *v = argValue(i, argc, argv);
            if (!parseInt(v, args.family)) {
                return false;
            }
            continue;
        }
        if (arg == "--dst") {
            const char *v = argValue(i, argc, argv);
            if (!v) {
                return false;
            }
            args.dst = v;
            continue;
        }
        if (arg == "--proto") {
            const char *v = argValue(i, argc, argv);
            if (!parseInt(v, args.proto)) {
                return false;
            }
            continue;
        }
        if (arg == "--count") {
            const char *v = argValue(i, argc, argv);
            if (!parseInt(v, args.count)) {
                return false;
            }
            continue;
        }
        if (arg == "--payloadBytes") {
            const char *v = argValue(i, argc, argv);
            if (!parseInt(v, args.payloadBytes)) {
                return false;
            }
            continue;
        }
        if (arg == "--delayMs") {
            const char *v = argValue(i, argc, argv);
            if (!parseInt(v, args.delayMs)) {
                return false;
            }
            continue;
        }

        std::fprintf(stderr, "unknown arg: %s\n", argv[i]);
        return false;
    }

    if ((args.family != 4 && args.family != 6) || args.dst.empty() ||
        args.proto <= 0 || args.proto > 255 || args.count <= 0 ||
        args.payloadBytes < 0 || args.payloadBytes > 1400 || args.delayMs < 0) {
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv) {
    Args args{};
    if (!parseArgs(argc, argv, args)) {
        usage(argv[0]);
        return 2;
    }

    const int family = (args.family == 6) ? AF_INET6 : AF_INET;
    constexpr int kUdpLiteProto = 136;
    const bool useDatagram = (args.proto == kUdpLiteProto);
    const int sockType = useDatagram ? SOCK_DGRAM : SOCK_RAW;
    const int fd = ::socket(family, sockType | SOCK_CLOEXEC, args.proto);
    if (fd < 0) {
        std::fprintf(stderr, "socket(proto=%d family=%d type=%s) failed: %s\n",
                     args.proto, args.family, useDatagram ? "dgram" : "raw", std::strerror(errno));
        return 3;
    }

    std::vector<std::uint8_t> payload(static_cast<std::size_t>(args.payloadBytes), 0xA5u);
    for (int i = 0; i < args.count; ++i) {
        ssize_t n = -1;
        if (args.family == 6) {
            sockaddr_in6 addr{};
            addr.sin6_family = AF_INET6;
            addr.sin6_port = htons(9);
            if (::inet_pton(AF_INET6, args.dst.c_str(), &addr.sin6_addr) != 1) {
                std::fprintf(stderr, "invalid IPv6 dst: %s\n", args.dst.c_str());
                ::close(fd);
                return 2;
            }
            n = ::sendto(fd, payload.data(), payload.size(), 0,
                         reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
        } else {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(9);
            if (::inet_pton(AF_INET, args.dst.c_str(), &addr.sin_addr) != 1) {
                std::fprintf(stderr, "invalid IPv4 dst: %s\n", args.dst.c_str());
                ::close(fd);
                return 2;
            }
            n = ::sendto(fd, payload.data(), payload.size(), 0,
                         reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
        }

        if (n < 0) {
            std::fprintf(stderr, "sendto failed: %s\n", std::strerror(errno));
            ::close(fd);
            return 4;
        }
        if (args.delayMs > 0 && i + 1 < args.count) {
            ::usleep(static_cast<useconds_t>(args.delayMs * 1000));
        }
    }

    ::close(fd);
    return 0;
}
