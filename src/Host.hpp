/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <sstream>
#include <vector>

#include <Domain.hpp>

class Host {
public:
    using Ptr = std::shared_ptr<Host>;

private:
    std::string _name;
    bool _resolved = false;
    std::vector<const Address<IPv4>> _ipv4;
    std::vector<const Address<IPv6>> _ipv6;
    Domain::Ptr _domain = nullptr;
    std::shared_mutex _mutex;

public:
    Host();

    Host(const Host &) = delete;

    const std::string &name() { return _name; }

    void name(const std::string &&name) { _name = name; }

    bool resolved() { return _resolved; }

    void setResolved() { _resolved = true; }

    bool hasName() const { return _name.size() != 0; }

    const Domain::Ptr domain();

    void domain(const Domain::Ptr &domain);

    template <class IP> void addIP(const Address<IP> &ip);

    void print(std::stringstream &out);

private:
    template <class IP> std::vector<const Address<IP>> &addr();
};

template <class IP> void Host::addIP(const Address<IP> &ip) {
    std::lock_guard lock(_mutex);
    addr<IP>().push_back(ip);
}

template <class IP> std::vector<const Address<IP>> &Host::addr() {
    if constexpr (std::is_same_v<IP, IPv4>) {
        return _ipv4;
    } else {
        return _ipv6;
    }
}
