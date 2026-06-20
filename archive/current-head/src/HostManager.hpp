/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <netdb.h>
#include <sys/socket.h>

#include <DomainManager.hpp>
#include <Host.hpp>

class HostManager {
private:
    using NamesMap = std::unordered_map<std::string, std::vector<Host::Ptr>>;
    using IPv4Map = std::unordered_map<Address<IPv4>, const Host::Ptr>;
    using IPv6Map = std::unordered_map<Address<IPv6>, const Host::Ptr>;

    // Singleton Host used for hot-path early-drop reasons where we must not materialize
    // per-remote host state (and thus must not touch host caches or DomainManager).
    Host::Ptr _anonymousHost;

    std::vector<Host::Ptr> _hosts;
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

    template <class IP> const Host::Ptr prepare(const Address<IP> &ip);

    template <class IP>
    const Host::Ptr publishPrepared(const Address<IP> &ip, const Host::Ptr &prepared);

    // Create/find a Host without attempting reverse DNS resolution, regardless of settings.
    // Intended for hot-path early-drop reasons (e.g., IFACE_BLOCK) where hostname is irrelevant.
    template <class IP> const Host::Ptr makeNoReverseDns(const Address<IP> &ip);

    template <class IP> void domain(const Host::Ptr host, const Address<IP> &ip) {
        host->domain(domManager.find(ip));
    }

    const Host::Ptr &anonymousHost() const { return _anonymousHost; }

    void reset();

    void printHosts(std::stringstream &out, const std::string &subname);

    void printHostsByName(std::stringstream &out, const std::string &subname);

private:
    template <class IP> auto &byIP();

    template <class IP> const Host::Ptr create(const Address<IP> &ip, const bool allowReverseDns);
};

template <class IP> auto &HostManager::byIP() {
    if constexpr (std::is_same_v<IP, IPv4>) {
        return _byIPv4;
    } else {
        return _byIPv6;
    }
}

template <class IP> const Host::Ptr HostManager::find(const Address<IP> &ip, const bool locked) {
    // Fix #15: keep the shared lock while evaluating iterator and copying the pointer
    if (!locked) {
        _mutexIP.lock_shared();
    }
    auto &map = byIP<IP>();
    const auto it = map.find(ip);
    const Host::Ptr result = (it != map.end()) ? it->second : nullptr;
    if (!locked) {
        _mutexIP.unlock_shared();
    }
    return result;
}

template <class IP> const Host::Ptr HostManager::make(const Address<IP> &ip) {
    if (const auto host = find<IP>(ip, false)) {
        return host;
    } else {
        return publishPrepared(ip, prepare(ip));
    }
}

template <class IP> const Host::Ptr HostManager::makeNoReverseDns(const Address<IP> &ip) {
    if (const auto host = find<IP>(ip, false)) {
        return host;
    } else {
        return create(ip, false);
    }
}

template <class IP> const Host::Ptr HostManager::prepare(const Address<IP> &ip) {
    auto host = std::make_shared<Host>();
    host->template addIP<IP>(ip);
    host->domain(domManager.find(ip));

    if (settings.reverseDns()) {
        sockaddr_storage sa{};
        ip.fillSockAddr(sa);
        char buffer[NI_MAXHOST];
        if (getnameinfo(reinterpret_cast<sockaddr *>(&sa), sizeof(sa), buffer, sizeof(buffer),
                        nullptr, 0, NI_NAMEREQD) == 0) {
            host->name(buffer);
        }
        host->setResolved();
    }
    return host;
}

template <class IP>
const Host::Ptr HostManager::publishPrepared(const Address<IP> &ip, const Host::Ptr &prepared) {
    {
        const std::lock_guard lockIP(_mutexIP);
        if (const auto host = find<IP>(ip, true)) {
            return host;
        }
        if (!prepared) {
            return nullptr;
        }
        {
            const std::lock_guard lockHosts(_mutexHosts);
            _hosts.emplace_back(prepared);
            byIP<IP>().emplace(ip, prepared);
        }
    }

    if (prepared->hasName()) {
        const std::lock_guard lockName(_mutexName);
        _byName.try_emplace(prepared->name()).first->second.push_back(prepared);
    }
    return prepared;
}

template <class IP>
const Host::Ptr HostManager::create(const Address<IP> &ip, const bool allowReverseDns) {
    Host::Ptr host = nullptr;
    // Phase 1: ensure host exists and mappings are in place under Manager locks only
    {
        const std::lock_guard lockIP(_mutexIP);
        if (!(host = find<IP>(ip, true))) {
            const std::lock_guard lockHosts(_mutexHosts);
            host = _hosts.emplace_back(std::make_shared<Host>());
            byIP<IP>().emplace(ip, host);
            host->template addIP<IP>(ip);
            host->domain(domManager.find(ip));
        }
    }
    // Phase 2: reverse DNS outside of Manager locks; update Host then name index, no nested locks
    if (allowReverseDns && settings.reverseDns() && !host->resolved()) {
        sockaddr_storage sa{};
        ip.fillSockAddr(sa);
        char buffer[NI_MAXHOST];
        if (getnameinfo(reinterpret_cast<sockaddr *>(&sa), sizeof(sa), buffer, sizeof(buffer),
                        nullptr, 0, NI_NAMEREQD) == 0) {
            host->name(buffer); // Host-internal lock
            const std::lock_guard lockName(_mutexName);
            _byName.try_emplace(buffer).first->second.push_back(host);
        }
        host->setResolved();
    }
    return host;
}

extern HostManager hostManager;
