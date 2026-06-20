/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <sstream>
#include <vector>
#include <shared_mutex>
#include <atomic>

#include <Domain.hpp>

class Host {
public:
    using Ptr = std::shared_ptr<Host>;

private:
    std::string _name;
    std::atomic_bool _resolved{false};
    std::vector<Address<IPv4>> _ipv4;
    std::vector<Address<IPv6>> _ipv6;
    Domain::Ptr _domain = nullptr;
    mutable std::shared_mutex _mutex;

public:
    Host();

    Host(const Host &) = delete;

    // Read name under shared lock; return by value to avoid exposing references to internal state
    std::string name() const {
        const std::shared_lock<std::shared_mutex> lock(_mutex);
        return _name;
    }

    // Write name under exclusive lock; pass-by-value to enable move from temporaries
    void name(std::string name) {
        const std::lock_guard lock(_mutex);
        _name = std::move(name);
    }

    bool resolved() const { return _resolved.load(std::memory_order_acquire); }

    void setResolved() { _resolved.store(true, std::memory_order_release); }

    bool hasName() const {
        const std::shared_lock<std::shared_mutex> lock(_mutex);
        return !_name.empty();
    }

    const Domain::Ptr domain();

    void domain(const Domain::Ptr &domain);

    template <class IP> void addIP(const Address<IP> &ip);

    void print(std::stringstream &out);

private:
    template <class IP> std::vector<Address<IP>> &addr();
};

template <class IP> void Host::addIP(const Address<IP> &ip) {
    std::lock_guard lock(_mutex);
    addr<IP>().push_back(ip);
}

template <class IP> std::vector<Address<IP>> &Host::addr() {
    if constexpr (std::is_same_v<IP, IPv4>) {
        return _ipv4;
    } else {
        return _ipv6;
    }
}
