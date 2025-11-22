/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <thread>
#include <cstring>
#include <cerrno>

#include <DnsListener.hpp>

DnsListener::DnsListener()
    : Streamable<DnsRequest>(settings.saveDnsStream) {}

DnsListener::~DnsListener() {}

void DnsListener::start() {
    std::thread([&] { server(); }).detach();
}

void DnsListener::server() {
    int sockServer = android_get_control_socket(settings.netdSocketPath);

    if (sockServer < 1) {
        // Fallback: manually create socket in /dev/socket/ for debugging
        // This allows the daemon to run when started directly via adb
        const std::string socketPath = "/dev/socket/sucre-snort-netd";
        LOG(INFO) << __FUNCTION__ << " - Netd socket not inherited from init, creating fallback at " << socketPath;

        // Clean up any existing socket file
        unlink(socketPath.c_str());

        // Create UNIX domain socket with SOCK_SEQPACKET (important for DnsResolver compatibility!)
        sockServer = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (sockServer < 0) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - Failed to create fallback socket: " << std::strerror(err);
            throw std::runtime_error("netd socket control error: failed to create fallback socket");
        }

        // Bind to /dev/socket/ path
        sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

        if (bind(sockServer, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
            const int err = errno;
            LOG(ERROR) << __FUNCTION__ << " - Failed to bind fallback socket: " << std::strerror(err);
            close(sockServer);
            throw std::runtime_error("netd socket control error: failed to bind fallback socket");
        }

        // Match init.rc: socket sucre-snort-netd seqpacket 0600 root root
        if (chmod(socketPath.c_str(), 0600) < 0) {
            const int err = errno;
            LOG(WARNING) << __FUNCTION__ << " - Failed to set socket permissions: " << std::strerror(err);
            // Continue anyway, permissions might still work
        }

        LOG(INFO) << __FUNCTION__ << " - Fallback socket created successfully on FD " << sockServer;
    }

    if (const int one = 1;
        setsockopt(sockServer, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - Socket setsockopt failed: " << std::strerror(err);
        throw std::runtime_error("netd socket setsockopt error");
    }

    if (listen(sockServer, settings.controlClients) == -1) {
        const int err = errno;
        LOG(ERROR) << __FUNCTION__ << " - Socket listen failed: " << std::strerror(err);
        throw std::runtime_error("netd socket listen error");
    }

    for (;;) {
        if (const int sockClient = accept(sockServer, nullptr, nullptr); sockClient == -1) {
            LOG(ERROR) << __FUNCTION__ << " - dnslistener accept error";
        } else {
            // Explicitly capture this for C++20 compatibility (no implicit this with [=]).
            std::thread([this, sockClient] { clientRun(sockClient); }).detach();
        }
    }
}

void DnsListener::clientRun(const int socket) {
    // Never hold the global listeners lock across blocking I/O. We only take it briefly
    // around critical sections that must quiesce during resetall.
    // Soften stuck clients: set a small read timeout to avoid indefinitely hanging threads.
    {
        const timeval tv{.tv_sec = 0, .tv_usec = 250000}; // 250 ms
        (void)setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    try {
        uint32_t len;
        clientRead(socket, &len, sizeof(len), "len read error");
        if (len < 3 || len > HOST_NAME_MAX) {
            throw "domain name invalid";
        }
        // Avoid VLA; read into std::string buffer and trim optional NUL terminator
        std::string host;
        host.resize(len);
        clientRead(socket, host.data(), len, "domain read error");
        if (!host.empty() && host.back() == '\0') {
            host.pop_back();
        }
        App::Uid uid;
        clientRead(socket, &uid, sizeof(uid), "uid read error");
        const auto app = appManager.make(uid);
        const auto domain = domManager.make(std::move(host));

        // Decision must observe a consistent snapshot vs resetall. Keep the lock window tiny.
        bool blocked = false;
        Stats::Color cs = Stats::GREY;
        bool verdict = true;
        bool getips = false;
        {
            const std::shared_lock<std::shared_mutex> g(mutexListeners);
            const auto bc = app->blocked(domain);
            blocked = bc.first;
            cs = bc.second;
            verdict = !blocked;
            getips = verdict || settings.getBlackIPs();
        }
        clientWrite(socket, &verdict, sizeof(verdict), "verdict write error");
        clientWrite(socket, &getips, sizeof(getips), "getips write error");
        if (getips) {
            // Clear existing mappings under the global lock (short window) to quiesce vs resetall.
            {
                const std::shared_lock<std::shared_mutex> g(mutexListeners);
                domManager.removeIPs(domain);
            }
            int family = -1;
            do {
                clientRead(socket, &family, sizeof(family), "family read error");
                if (family == AF_INET) {
                    // Read IP without holding the global lock, then publish under a tiny lock.
                    Address<IPv4> ip([=](uint8_t *address, const uint32_t l) {
                        clientRead(socket, address, l, "ip read error");
                    });
                    const std::shared_lock<std::shared_mutex> g(mutexListeners);
                    domManager.addIPBoth(domain, ip);
                } else if (family == AF_INET6) {
                    Address<IPv6> ip([=](uint8_t *address, const uint32_t l) {
                        clientRead(socket, address, l, "ip read error");
                    });
                    const std::shared_lock<std::shared_mutex> g(mutexListeners);
                    domManager.addIPBoth(domain, ip);
                }
            } while (family != -1);
        }
        if (settings.blockEnabled() && app->tracked()) {
            // Keep stats and streaming within a tiny lock window to align with resetall freeze.
            const std::shared_lock<std::shared_mutex> g(mutexListeners);
            appManager.updateStats(domain, app, blocked, cs, Stats::DNS, 1);
            stream(std::make_shared<DnsRequest>(app, domain, cs, blocked));
        }
    } catch (const char *error) {
        LOG(ERROR) << __FUNCTION__ << " - " << error;
    }
    close(socket);
}

template <class IP> void DnsListener::readIP(const int socket, const Domain::Ptr &domain) {
    // Unused after refactor; kept for ABI compatibility if needed. The new code reads the IP
    // without holding the global lock, then publishes under a tiny lock in clientRun.
    Address<IP> ip([=](uint8_t *address, const uint32_t len) {
        clientRead(socket, address, len, "ip read error");
    });
    const std::shared_lock<std::shared_mutex> g(mutexListeners);
    domManager.addIPBoth(domain, ip);
}

void DnsListener::clientRead(const int socket, void *data, const uint32_t len, const char *error) {
    if (read(socket, data, len) != static_cast<ssize_t>(len)) {
        throw error;
    }
}

void DnsListener::clientWrite(const int socket, const void *data, const uint32_t len,
                              const char *error) {
    if (write(socket, data, len) != static_cast<ssize_t>(len)) {
        throw error;
    }
}

void DnsListener::save() { Streamable<DnsRequest>::save(); }

void DnsListener::restore() { Streamable<DnsRequest>::restore(); }
