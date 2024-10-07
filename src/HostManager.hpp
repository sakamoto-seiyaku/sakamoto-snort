/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <netdb.h>

#include <DomainManager.hpp>
#include <Host.hpp>

class HostManager {
private:
    using NamesMap = std::unordered_map<std::string, std::vector<const Host::Ptr>>;
    using IPv4Map = std::unordered_map<Address<IPv4>, const Host::Ptr>;
    using IPv6Map = std::unordered_map<Address<IPv6>, const Host::Ptr>;

    std::vector<const Host::Ptr> _hosts;
    NamesMap _byName;
    IPv4Map _byIPv4;
    IPv6Map _byIPv6;
    std::shared_mutex _mutexHosts;
    std::shared_mutex _mutexName;
    std::shared_mutex _mutexIP;

public:
    HostManager();

    ~HostManager();

    HostManager(const HostManager &) = delete;

    template <class IP> const Host::Ptr find(const Address<IP> &ip, const bool locked);

    template <class IP> const Host::Ptr make(const Address<IP> &ip);

    template <class IP> void domain(const Host::Ptr host, const Address<IP> &ip) {
        host->domain(domManager.find(ip));
    }

    void reset();

    void printHosts(std::stringstream &out, const std::string &subname);

    void printHostsByName(std::stringstream &out, const std::string &subname);

private:
    template <class IP> auto &byIP();

    template <class IP> const Host::Ptr create(const Address<IP> &ip);
};

template <class IP> auto &HostManager::byIP() {
    if constexpr (std::is_same_v<IP, IPv4>) {
        return _byIPv4;
    } else {
        return _byIPv6;
    }
}

template <class IP> const Host::Ptr HostManager::find(const Address<IP> &ip, const bool locked) {
    if (!locked) {
        _mutexIP.lock_shared();
    }
    const auto it = byIP<IP>().find(ip);
    if (!locked) {
        _mutexIP.unlock_shared();
    }
    return it != byIP<IP>().end() ? it->second : nullptr;
}

template <class IP> const Host::Ptr HostManager::make(const Address<IP> &ip) {
    if (const auto host = find<IP>(ip, false)) {
        return host;
    } else {
        return create(ip);
    }
}

template <class IP> const Host::Ptr HostManager::create(const Address<IP> &ip) {
    const std::lock_guard lockIP(_mutexIP);
    Host::Ptr host = nullptr;
    if (!(host = find<IP>(ip, true))) {
        const std::lock_guard lock(_mutexHosts);
        host = _hosts.emplace_back(std::make_shared<Host>());
        byIP<IP>().emplace(ip, host);
        host->template addIP<IP>(ip);
        host->domain(domManager.find(ip));
    }
    if (settings.reverseDns() && !host->resolved()) {
        sockaddr_storage sa;
        // IP::fillSockAddr(&sa, ip.raw());
        ip.fillSockAddr(sa);
        char buffer[NI_MAXHOST];
        if (getnameinfo(reinterpret_cast<sockaddr *>(&sa), sizeof(sa), buffer, sizeof(buffer),
                        nullptr, 0, NI_NAMEREQD) == 0) {
            host->name(buffer);
            const std::lock_guard lock(_mutexName);
            _byName.try_emplace(buffer).first->second.push_back(host);
        }
        host->setResolved();
    }
    return host;
}

extern HostManager hostManager;
