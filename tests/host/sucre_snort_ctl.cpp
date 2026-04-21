/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre_snort_ctl_session.hpp>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <charconv>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
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

struct Target {
    enum class Kind {
        Tcp,
        UnixPath,
        UnixAbstract,
    };

    Kind kind = Kind::Tcp;
    std::string host = "127.0.0.1";
    uint16_t port = 60607;
    std::string unixPath;
    std::string abstractName;
};

struct Options {
    Target target;
    bool pretty = true;
    bool follow = false;
    size_t maxFrames = 0; // 0 = unlimited
    uint32_t id = 1;

    std::string cmd;
    std::string argsJson = "{}";
};

[[noreturn]] void die(const std::string_view message, const int exitCode = 2) {
    std::cerr << "sucre-snort-ctl: " << message << "\n";
    std::exit(exitCode);
}

void printHelp(std::ostream &out) {
    out << "Usage:\n"
           "  sucre-snort-ctl [--tcp host:port | --unix path | --abstract name] [options] <cmd> "
           "[argsJson]\n"
           "  sucre-snort-ctl help\n"
           "  sucre-snort-ctl hello\n"
           "\n"
           "Targets:\n"
           "  --tcp <host:port>   Connect to TCP endpoint (default: 127.0.0.1:60607)\n"
           "  --unix <path>       Connect to unix socket (filesystem path)\n"
           "  --abstract <name>   Connect to unix socket (abstract namespace)\n"
           "\n"
           "Options:\n"
           "  --id <u32>          Request id (default: 1)\n"
           "  --pretty            Pretty-print JSON output (default)\n"
           "  --compact           Compact JSON output\n"
           "  --follow            Continue printing frames after the response (events)\n"
           "  --max-frames <N>    Stop after printing N frames (response+events)\n"
           "  -h, --help          Show help\n"
           "\n"
           "Command directory (vNext v1):\n"
           "  Meta: HELLO, QUIT, RESETALL\n"
           "  Inventory: APPS.LIST, IFACES.LIST\n"
           "  Config: CONFIG.GET, CONFIG.SET\n"
	           "  Domain: DOMAINRULES.GET/APPLY, DOMAINPOLICY.GET/APPLY, DOMAINLISTS.GET/APPLY/IMPORT\n"
	           "  IP: IPRULES.PREFLIGHT/PRINT/APPLY\n"
	           "  Observability: METRICS.GET, METRICS.RESET, STREAM.START, STREAM.STOP\n"
	           "\n"
	           "Examples:\n"
	           "  sucre-snort-ctl --tcp 127.0.0.1:60607 hello\n"
	           "  sucre-snort-ctl HELLO\n"
           "  sucre-snort-ctl APPS.LIST '{\"query\":\"com.\",\"userId\":0,\"limit\":50}'\n"
           "  sucre-snort-ctl --follow STREAM.START '{\"type\":\"dns\",\"horizonSec\":0,\"minSize\":0}'\n";
}

std::optional<uint16_t> parseU16(const std::string_view token) {
    uint32_t value = 0;
    const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), value);
    if (ec != std::errc{} || ptr != token.data() + token.size()) {
        return std::nullopt;
    }
    if (value > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint16_t>(value);
}

Target parseTcpTarget(const std::string_view hostPort) {
    const auto colonPos = hostPort.rfind(':');
    if (colonPos == std::string_view::npos || colonPos == 0 || colonPos + 1 >= hostPort.size()) {
        die("invalid --tcp target (expected host:port)");
    }
    const std::string host(hostPort.substr(0, colonPos));
    const std::string_view portStr = hostPort.substr(colonPos + 1);
    const auto port = parseU16(portStr);
    if (!port.has_value()) {
        die("invalid --tcp port");
    }
    Target target;
    target.kind = Target::Kind::Tcp;
    target.host = host;
    target.port = *port;
    return target;
}

UniqueFd connectTcp(const std::string &host, const uint16_t port) {
    addrinfo hints {};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    std::string service = std::to_string(port);
    addrinfo *result = nullptr;
    if (const int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &result); rc != 0) {
        die(std::string("getaddrinfo failed: ") + gai_strerror(rc));
    }

    UniqueFd sock;
    for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
        const int fd = ::socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            sock.reset(fd);
            break;
        }
        ::close(fd);
    }
    ::freeaddrinfo(result);

    if (!sock) {
        die("tcp connect failed");
    }
    return sock;
}

UniqueFd connectUnixPath(const std::string &path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        die(std::string("socket(AF_UNIX) failed: ") + std::strerror(errno));
    }
    UniqueFd sock(fd);

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        die("unix path too long");
    }
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

    if (::connect(sock.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        die(std::string("unix connect failed: ") + std::strerror(errno));
    }
    return sock;
}

UniqueFd connectUnixAbstract(const std::string &name) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        die(std::string("socket(AF_UNIX) failed: ") + std::strerror(errno));
    }
    UniqueFd sock(fd);

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (name.size() + 1 >= sizeof(addr.sun_path)) {
        die("abstract unix name too long");
    }
    addr.sun_path[0] = '\0';
    std::memcpy(addr.sun_path + 1, name.data(), name.size());

    // Length is up to the last byte written.
    const socklen_t len =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
    if (::connect(sock.get(), reinterpret_cast<sockaddr *>(&addr), len) != 0) {
        die(std::string("abstract unix connect failed: ") + std::strerror(errno));
    }
    return sock;
}

Options parseArgs(const int argc, char **argv) {
    Options opts;

    std::vector<std::string_view> positionals;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "-h" || arg == "--help") {
            printHelp(std::cout);
            std::exit(0);
        }
        if (arg == "--tcp") {
            if (i + 1 >= argc) {
                die("missing value for --tcp");
            }
            opts.target = parseTcpTarget(argv[++i]);
            continue;
        }
        if (arg == "--unix") {
            if (i + 1 >= argc) {
                die("missing value for --unix");
            }
            opts.target.kind = Target::Kind::UnixPath;
            opts.target.unixPath = argv[++i];
            continue;
        }
        if (arg == "--abstract") {
            if (i + 1 >= argc) {
                die("missing value for --abstract");
            }
            opts.target.kind = Target::Kind::UnixAbstract;
            opts.target.abstractName = argv[++i];
            continue;
        }
        if (arg == "--id") {
            if (i + 1 >= argc) {
                die("missing value for --id");
            }
            uint32_t value = 0;
            const std::string_view token(argv[++i]);
            const auto [ptr, ec] =
                std::from_chars(token.data(), token.data() + token.size(), value);
            if (ec != std::errc{} || ptr != token.data() + token.size()) {
                die("invalid --id (expected u32)");
            }
            opts.id = value;
            continue;
        }
        if (arg == "--pretty") {
            opts.pretty = true;
            continue;
        }
        if (arg == "--compact") {
            opts.pretty = false;
            continue;
        }
        if (arg == "--follow") {
            opts.follow = true;
            continue;
        }
        if (arg == "--max-frames") {
            if (i + 1 >= argc) {
                die("missing value for --max-frames");
            }
            size_t value = 0;
            const std::string_view token(argv[++i]);
            const auto [ptr, ec] =
                std::from_chars(token.data(), token.data() + token.size(), value);
            if (ec != std::errc{} || ptr != token.data() + token.size()) {
                die("invalid --max-frames (expected integer)");
            }
            opts.maxFrames = value;
            continue;
        }

        if (!arg.empty() && arg.front() == '-') {
            die("unknown option: " + std::string(arg));
        }

        positionals.push_back(arg);
    }

    if (positionals.empty()) {
        printHelp(std::cout);
        std::exit(2);
    }

    if (positionals[0] == "help") {
        printHelp(std::cout);
        std::exit(0);
    }

    if (positionals[0] == "hello") {
        opts.cmd = "HELLO";
        opts.argsJson = "{}";
        return opts;
    }

    opts.cmd = std::string(positionals[0]);
    if (positionals.size() >= 2) {
        opts.argsJson = std::string(positionals[1]);
    }
    return opts;
}

} // namespace

int main(const int argc, char **argv) {
#if defined(SIGPIPE)
    std::signal(SIGPIPE, SIG_IGN);
#endif
    const Options opts = parseArgs(argc, argv);

    UniqueFd sock;
    switch (opts.target.kind) {
    case Target::Kind::Tcp:
        sock = connectTcp(opts.target.host, opts.target.port);
        break;
    case Target::Kind::UnixPath:
        sock = connectUnixPath(opts.target.unixPath);
        break;
    case Target::Kind::UnixAbstract:
        sock = connectUnixAbstract(opts.target.abstractName);
        break;
    }

    SucreSnortCtl::RequestOptions request;
    request.id = opts.id;
    request.cmd = opts.cmd;
    request.argsJson = opts.argsJson;

    SucreSnortCtl::SessionOptions session;
    session.pretty = opts.pretty;
    session.follow = opts.follow;
    session.maxFrames = opts.maxFrames;

    return SucreSnortCtl::runSession(sock.get(), request, session, std::cout, std::cerr);
}
