/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <unordered_set>
#include <atomic>

#include <Address.hpp>
#include <DomainStats.hpp>
#include <IP.hpp>

class Domain {
public:
    using Ptr = std::shared_ptr<Domain>;

private:
    using IPv4Set = std::unordered_set<Address<IPv4>>;
    using IPv6Set = std::unordered_set<Address<IPv6>>;

    const std::string _name;
    std::atomic<uint8_t> _blockMask{0};
    std::atomic<uint8_t> _color{static_cast<uint8_t>(Stats::GREY)};

    DomainStats _stats;
    IPv4Set _ipv4;
    IPv6Set _ipv6;
    std::time_t _timestampIP = 0;
    std::shared_mutex _mutexIP;

public:
    Domain(const std::string &&name);

    ~Domain();

    Domain(const Domain &) = delete;

    const std::string &name() const { return _name; }

    uint8_t blockMask() const { return _blockMask.load(std::memory_order_relaxed); }

    void blockMask(const uint8_t blockMask) { _blockMask.store(blockMask, std::memory_order_relaxed); }

    Stats::Color color() const { return static_cast<Stats::Color>(_color.load(std::memory_order_relaxed)); }

    void color(const Stats::Color color) { _color.store(static_cast<uint8_t>(color), std::memory_order_relaxed); }

    DomainStats &stats() { return _stats; }

    bool validIP();

    template <class IP> auto &ips() {
        if constexpr (std::is_same_v<IP, IPv4>) {
            return _ipv4;
        } else {
            return _ipv6;
        }
    }

    template <class IP> auto &addIP(const Address<IP> &&ip);

    void updateStats(const Stats::Type ts, const Stats::Block bs, const uint64_t val);

    void clearIPs();

    void save(Saver &saver);

    void restore(Saver &saver);

    template <class... Args> void print(std::ostream &out, DomainStats &stats, const Args... args);

private:
    template <class IP> void saveIP(Saver &saver);

    template <class IP> void restoreIP(Saver &saver);

    template <class IP> void printIP(std::ostream &out);
};

template <class IP> auto &Domain::addIP(const Address<IP> &&ip) {
    const std::lock_guard lock(_mutexIP);
    _timestampIP = std::time(nullptr);
    return *(ips<IP>().emplace(std::move(ip)).first);
}

template <class... Args>
void Domain::print(std::ostream &out, DomainStats &stats, const Args... args) {
    const std::shared_lock<std::shared_mutex> lock(_mutexIP);
    out << "{" << JSF("domain") << JSS(_name) << "," << JSF("blockMask")
        << static_cast<uint32_t>(_blockMask.load(std::memory_order_relaxed)) << "," << JSF("ipv4");
    printIP<IPv4>(out);
    out << "," << JSF("ipv6");
    printIP<IPv6>(out);
    out << "," << JSF("stats");
    stats.print(out, args...);
    out << "}";
}

template <class IP> void Domain::printIP(std::ostream &out) {
    out << "[";
    bool first = true;
    for (const auto ip : ips<IP>()) {
        when(first, out << ",");
        out << "\"";
        ip.print(out);
        out << "\"";
    }
    out << "]";
}
