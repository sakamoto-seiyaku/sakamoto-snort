/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNext.hpp>

#include <ControlVNextSession.hpp>

#include <Settings.hpp>
#include <sucre-snort.hpp>

#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstddef>
#include <stdexcept>
#include <thread>

namespace {

void serveClient(const int sockClient) {
    int fd = sockClient;
    try {
        ControlVNextSession session(
            fd,
            ControlVNextSession::Limits{.maxRequestBytes = settings.controlVNextMaxRequestBytes,
                                       .maxResponseBytes = settings.controlVNextMaxResponseBytes});
        fd = -1;
        session.run();
    } catch (const std::exception &e) {
        LOG(ERROR) << __FUNCTION__ << " - vNext control client exception: " << e.what();
    } catch (...) {
        LOG(ERROR) << __FUNCTION__ << " - vNext control client exception: unknown";
    }
    if (fd >= 0) {
        ::close(fd);
    }
}

[[noreturn]] void acceptLoop(const int serverFd, const char *const kind) {
    for (;;) {
        if (const int sockClient = accept(serverFd, nullptr, nullptr); sockClient < 0) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - " << kind << " accept error: " << std::strerror(err);
        } else {
            std::thread([sockClient] { serveClient(sockClient); }).detach();
        }
    }
}

[[nodiscard]] int createAbstractListener(const char *const name, const int backlog) {
    int abstractSocket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (abstractSocket < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - failed to create abstract socket: " << std::strerror(err);
        throw std::runtime_error("control vnext unix socket error: failed to create abstract listener");
    }

    sockaddr_un addrAbstract;
    memset(&addrAbstract, 0, sizeof(addrAbstract));
    addrAbstract.sun_family = AF_UNIX;
    addrAbstract.sun_path[0] = '\0';
    strncpy(addrAbstract.sun_path + 1, name, sizeof(addrAbstract.sun_path) - 1);

    const size_t nameLen = strnlen(name, sizeof(addrAbstract.sun_path) - 1);
    const socklen_t addrLen = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + nameLen);

    if (bind(abstractSocket, reinterpret_cast<const sockaddr *>(&addrAbstract), addrLen) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - failed to bind abstract socket: " << std::strerror(err);
        close(abstractSocket);
        throw std::runtime_error("control vnext unix socket error: failed to bind abstract listener");
    }

    if (listen(abstractSocket, backlog) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - abstract socket listen failed: " << std::strerror(err);
        close(abstractSocket);
        throw std::runtime_error("control vnext unix socket listen error");
    }

    return abstractSocket;
}

} // namespace

void ControlVNext::start() {
    std::thread([this] {
        try {
            unixServer();
        } catch (const std::exception &e) {
            LOG(FATAL) << "Control vNext unix server failed: " << e.what();
        } catch (...) {
            LOG(FATAL) << "Control vNext unix server failed: unknown exception";
        }
    }).detach();
    if (settings.inetControl()) {
        std::thread([this] {
            try {
                inetServer();
            } catch (const std::exception &e) {
                LOG(FATAL) << "Control vNext inet server failed: " << e.what();
            } catch (...) {
                LOG(FATAL) << "Control vNext inet server failed: unknown exception";
            }
        }).detach();
    }
}

void ControlVNext::unixServer() {
    int unixSocket = android_get_control_socket(settings.controlVNextSocketPath);

    if (unixSocket >= 1) {
        if (listen(unixSocket, settings.controlClients) == -1) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - socket listen failed: " << std::strerror(err);
            throw std::runtime_error("control vnext unix socket listen error");
        }

        const int abstractSocket =
            createAbstractListener(settings.controlVNextSocketPath, settings.controlClients);
        LOG(INFO) << __FUNCTION__ << " - Control vNext init socket inherited, exposing @"
                  << settings.controlVNextSocketPath;
        std::thread([abstractSocket] { acceptLoop(abstractSocket, "unix abstract"); }).detach();

        acceptLoop(unixSocket, "unix init");
    }

    const std::string socketPath = std::string("/dev/socket/") + settings.controlVNextSocketPath;
    LOG(INFO) << __FUNCTION__
              << " - Control vNext socket not inherited from init, creating fallback at "
              << socketPath << " and @" << settings.controlVNextSocketPath;

    unlink(socketPath.c_str());

    int devSocket = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (devSocket < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__
                   << " - failed to create fallback /dev socket: " << std::strerror(err);
        throw std::runtime_error("control vnext unix socket error: failed to create /dev fallback");
    }

    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(devSocket, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - failed to bind fallback /dev socket: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error("control vnext unix socket error: failed to bind /dev fallback");
    }

    if (chmod(socketPath.c_str(), 0666) < 0) {
        const int err = errno;
        LOG(WARNING) << __FUNCTION__
                     << " - failed to set /dev socket permissions: " << std::strerror(err);
    }

    if (listen(devSocket, settings.controlClients) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - /dev socket listen failed: " << std::strerror(err);
        close(devSocket);
        throw std::runtime_error("control vnext unix socket listen error");
    }

    const int abstractSocket =
        createAbstractListener(settings.controlVNextSocketPath, settings.controlClients);
    std::thread([abstractSocket] { acceptLoop(abstractSocket, "unix abstract"); }).detach();
    acceptLoop(devSocket, "unix /dev");
}

void ControlVNext::inetServer() {
    int inetSocket = -1;
    sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(settings.controlVNextPort);
    addr.sin_family = AF_INET;

    try {
        if ((inetSocket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)) == -1) {
            throw "inet socket create error";
        }
        if (int reuse = 1;
            setsockopt(inetSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            throw "inet socket setsockopt failed";
        }
        for (uint32_t i = 0; i < settings.controlBindTrials; ++i) {
            if (bind(inetSocket, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            } else {
                goto binded;
            }
        }
        throw "inet socket bind error";
    binded:
        if (listen(inetSocket, settings.controlClients) != 0) {
            throw "inet socket listen error";
        }
        for (;;) {
            if (const int sockClient = accept(inetSocket, nullptr, nullptr); sockClient < 0) {
                throw "inet socket accept error";
            } else {
                std::thread([sockClient] { serveClient(sockClient); }).detach();
            }
        }
    } catch (const char *error) {
        LOG(ERROR) << __FUNCTION__ << " - " << error;
        if (inetSocket >= 0) {
            close(inetSocket);
        }
    }
}
