/*
 * Copyright 2019 - 2022, iodé Technologies
 *
 * This file is part of the iode-snort project.
 *
 * iode-snort is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * iode-snort is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with iode-snort. If not, see <https://www.gnu.org/licenses/>.
 */

#include <cutils/sockets.h>
#include <sys/un.h>
#include <thread>

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
        throw std::runtime_error("netd socket control error");
    }

    if (const int one = 1;
        setsockopt(sockServer, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        throw std::runtime_error("netd socket setsockopt error");
    }

    if (listen(sockServer, settings.controlClients) == -1) {
        throw std::runtime_error("netd socket listen error");
    }

    for (;;) {
        if (const int sockClient = accept(sockServer, nullptr, nullptr); sockClient == -1) {
            LOG(ERROR) << __FUNCTION__ << " - dnslistener accept error";
        } else {
            std::thread([=] { clientRun(sockClient); }).detach();
        }
    }
}

void DnsListener::clientRun(const int socket) {
    const std::shared_lock_guard lock(mutexListeners);
    try {
        uint32_t len;
        clientRead(socket, &len, sizeof(len), "len read error");
        if (len < 3 || len > HOST_NAME_MAX) {
            throw "domain name invalid";
        }
        char hostname[len];
        clientRead(socket, hostname, len, "domain read error");
        App::Uid uid;
        clientRead(socket, &uid, sizeof(uid), "uid read error");
        const auto app = appManager.make(uid);
        const auto domain = domManager.make(hostname);
        const auto [blocked, cs] = app->blocked(domain);
        const bool verdict = !blocked;
        clientWrite(socket, &verdict, sizeof(verdict), "verdict write error");
        const bool getips = verdict || settings.getBlackIPs();
        clientWrite(socket, &getips, sizeof(getips), "getips write error");
        if (getips) {
            domManager.removeIPs(domain);
            int family = -1;
            do {
                clientRead(socket, &family, sizeof(family), "family read error");
                if (family == AF_INET) {
                    readIP<IPv4>(socket, domain);
                } else if (family == AF_INET6) {
                    readIP<IPv6>(socket, domain);
                }
            } while (family != -1);
        }
        if (settings.blockEnabled() && app->tracked()) {
            appManager.updateStats(domain, app, blocked, cs, Stats::DNS, 1);
            stream(std::make_shared<DnsRequest>(app, domain, cs, blocked));
        }
    } catch (const char *error) {
        LOG(ERROR) << __FUNCTION__ << " - " << error;
    }
    close(socket);
}

template <class IP> void DnsListener::readIP(const int socket, const Domain::Ptr &domain) {
    const auto &ip = domain->addIP<IP>(Address<IP>([=](uint8_t *address, const uint32_t len) {
        clientRead(socket, address, len, "ip read error");
    }));
    domManager.addIP<IP>(domain, ip);
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
