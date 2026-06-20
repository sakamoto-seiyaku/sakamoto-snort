/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>

#include <ControlVNextCodec.hpp>
#include <DaemonRuntime.hpp>
#include <RuntimeConfig.hpp>
#include <RuntimeControl.hpp>

#include <rapidjson/document.h>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr int kSendFlags =
#ifdef MSG_NOSIGNAL
    MSG_NOSIGNAL;
#else
    0;
#endif

bool writeAll(const int fd, const std::string_view bytes) {
    const char *data = bytes.data();
    std::size_t remaining = bytes.size();
    while (remaining > 0) {
        const ssize_t n = ::send(fd, data, remaining, kSendFlags);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        data += n;
        remaining -= static_cast<std::size_t>(n);
    }
    return true;
}

int androidInitSocketFd(const char *const name) noexcept {
    if (name == nullptr || *name == '\0') {
        return -1;
    }

    const std::string envName = std::string("ANDROID_SOCKET_") + name;
    const char *const value = std::getenv(envName.c_str());
    if (value == nullptr || *value == '\0') {
        return -1;
    }

    errno = 0;
    char *end = nullptr;
    const long fd = std::strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || fd < 0 || fd > INT_MAX) {
        return -1;
    }
    return static_cast<int>(fd);
}

rapidjson::Document makeHelloResult(const SnortRuntime::BaseRuntimeControl &runtime) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();

    result.AddMember("protocol", "control-vnext", alloc);
    result.AddMember("protocolVersion", SnortConfig::kControlProtocolVersion, alloc);
    result.AddMember("framing", "netstring", alloc);
    result.AddMember("maxRequestBytes",
                     static_cast<std::uint64_t>(SnortConfig::kControlMaxRequestBytes), alloc);
    result.AddMember("maxResponseBytes",
                     static_cast<std::uint64_t>(SnortConfig::kControlMaxResponseBytes), alloc);

#ifdef SUCRE_SNORT_DAEMON_BUILD_ID
    result.AddMember("daemonBuildId", SUCRE_SNORT_DAEMON_BUILD_ID, alloc);
#else
    result.AddMember("daemonBuildId", "snort10-base-unknown", alloc);
#endif

#ifdef SUCRE_SNORT_ARTIFACT_ABI
    result.AddMember("artifactAbi", SUCRE_SNORT_ARTIFACT_ABI, alloc);
#else
    result.AddMember("artifactAbi", "host", alloc);
#endif

    rapidjson::Value capabilities(rapidjson::kArrayType);
    capabilities.PushBack("snort10-base", alloc);
    if (runtime.nfqueuePassThroughReady()) {
        capabilities.PushBack("nfqueue-pass-through", alloc);
    }
    result.AddMember("capabilities", capabilities, alloc);

    return result;
}

rapidjson::Document dispatchRequest(const ControlVNext::RequestView &request,
                                    SnortRuntime::BaseRuntimeControl &runtime) {
    if (request.cmd == "HELLO") {
        rapidjson::Document result = makeHelloResult(runtime);
        return ControlVNext::makeOkResponse(request.id, &result);
    }

    if (request.cmd == "RESETALL") {
        if (!runtime.resetBaseRuntime()) {
            return ControlVNext::makeErrorResponse(request.id, "RUNTIME_RESET_FAILED",
                                                   "base runtime reset failed");
        }
        return ControlVNext::makeOkResponse(request.id, nullptr);
    }

    if (request.cmd == "QUIT") {
        SnortRuntime::requestShutdown();
        return ControlVNext::makeOkResponse(request.id, nullptr);
    }

    return ControlVNext::makeErrorResponse(request.id, "UNSUPPORTED_COMMAND",
                                           "unsupported command in SNORT-10 base");
}

bool sendDocument(const int fd, const rapidjson::Document &doc) {
    const std::string json = ControlVNext::encodeJson(doc, ControlVNext::JsonFormat::Compact);
    if (json.size() > SnortConfig::kControlMaxResponseBytes) {
        const auto err = ControlVNext::makeErrorResponse(0, "RESPONSE_TOO_LARGE",
                                                         "response exceeds maxResponseBytes");
        const std::string errJson = ControlVNext::encodeJson(err, ControlVNext::JsonFormat::Compact);
        return writeAll(fd, ControlVNext::encodeNetstring(errJson));
    }
    return writeAll(fd, ControlVNext::encodeNetstring(json));
}

} // namespace

namespace SnortControlVNext {

ControlServer::ControlServer(SnortRuntime::BaseRuntimeControl &runtime) : runtime_(runtime) {}

int ControlServer::createAbstractListener() {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        std::cerr << "control socket create failed: " << std::strerror(errno) << "\n";
        return -1;
    }

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    std::strncpy(addr.sun_path + 1, SnortConfig::kControlVNextSocketName,
                 sizeof(addr.sun_path) - 2);

    const std::size_t nameLen =
        strnlen(SnortConfig::kControlVNextSocketName, sizeof(addr.sun_path) - 1);
    const auto addrLen =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);

    if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), addrLen) < 0) {
        std::cerr << "control socket bind failed: " << std::strerror(errno) << "\n";
        ::close(fd);
        return -1;
    }

    if (::listen(fd, SnortConfig::kControlListenBacklog) < 0) {
        std::cerr << "control socket listen failed: " << std::strerror(errno) << "\n";
        ::close(fd);
        return -1;
    }

    return fd;
}

void ControlServer::serveClient(const int clientFd) {
    ControlVNext::NetstringDecoder decoder(SnortConfig::kControlMaxRequestBytes);
    char buffer[4096];

    while (!SnortRuntime::shutdownRequested()) {
        const ssize_t n = ::recv(clientFd, buffer, sizeof(buffer), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }

        const auto bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(buffer), static_cast<std::size_t>(n));
        if (const auto netErr = decoder.feed(bytes); netErr.has_value()) {
            const auto response = ControlVNext::makeErrorResponse(
                0, "SYNTAX_ERROR", netErr->message);
            (void)sendDocument(clientFd, response);
            return;
        }

        while (auto payload = decoder.pop()) {
            rapidjson::Document requestDoc;
            ControlVNext::JsonError jsonError;
            if (!ControlVNext::parseStrictJsonObject(*payload, requestDoc, jsonError)) {
                const auto response =
                    ControlVNext::makeErrorResponse(0, "SYNTAX_ERROR", jsonError.message);
                (void)sendDocument(clientFd, response);
                return;
            }

            ControlVNext::RequestView request;
            if (const auto envErr = ControlVNext::parseRequestEnvelope(requestDoc, request);
                envErr.has_value()) {
                const auto response =
                    ControlVNext::makeErrorResponse(0, envErr->code, envErr->message);
                (void)sendDocument(clientFd, response);
                return;
            }

            const auto response = dispatchRequest(request, runtime_);
            if (!sendDocument(clientFd, response)) {
                return;
            }
            if (request.cmd == "QUIT") {
                return;
            }
        }
    }
}

int ControlServer::run() {
    std::vector<int> serverFds;

    const int initFd = androidInitSocketFd(SnortConfig::kControlVNextSocketName);
    if (initFd >= 0) {
        if (::listen(initFd, SnortConfig::kControlListenBacklog) < 0) {
            std::cerr << "control init socket listen failed: " << std::strerror(errno) << "\n";
            ::close(initFd);
            return 1;
        }
        serverFds.push_back(initFd);
        std::cerr << "SNORT-10 base control listening on init socket "
                  << SnortConfig::kControlVNextSocketName << "\n";
    }

    const int abstractFd = createAbstractListener();
    if (abstractFd >= 0) {
        serverFds.push_back(abstractFd);
        std::cerr << "SNORT-10 base control listening on @"
                  << SnortConfig::kControlVNextSocketName << "\n";
    } else if (serverFds.empty()) {
        return 1;
    }

    std::vector<pollfd> pollFds;
    pollFds.reserve(serverFds.size());
    for (const int fd : serverFds) {
        pollFds.push_back(pollfd{.fd = fd, .events = POLLIN, .revents = 0});
    }

    while (!SnortRuntime::shutdownRequested()) {
        for (auto &pollFd : pollFds) {
            pollFd.revents = 0;
        }

        const int ready = ::poll(pollFds.data(), pollFds.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "control poll failed: " << std::strerror(errno) << "\n";
            break;
        }

        for (const auto &pollFd : pollFds) {
            if ((pollFd.revents & POLLIN) == 0) {
                continue;
            }

            const int clientFd = ::accept(pollFd.fd, nullptr, nullptr);
            if (clientFd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::cerr << "control accept failed: " << std::strerror(errno) << "\n";
                continue;
            }
            serveClient(clientFd);
            ::close(clientFd);
            if (SnortRuntime::shutdownRequested()) {
                break;
            }
        }
    }

    for (const int fd : serverFds) {
        ::close(fd);
    }
    return 0;
}

} // namespace SnortControlVNext
