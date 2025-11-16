/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <Saver.hpp>
#include <Domain.hpp>

Domain::Domain(const std::string &&name)
    : _name(name) {}

Domain::~Domain() {}

void Domain::updateStats(const Stats::Type ts, const Stats::Block bs, const uint64_t val) {
    _stats.update(ts, bs, val);
}

bool Domain::validIP() { return std::time(nullptr) - _timestampIP <= settings.maxAgeIP(); }

void Domain::save(Saver &saver) {
    const std::shared_lock_guard lock(_mutexIP);
    saver.write(_name);
    saver.write<Stats::Color>(static_cast<Stats::Color>(_color.load(std::memory_order_relaxed)));
    saveIP<IPv4>(saver);
    saveIP<IPv6>(saver);
    saver.write(_timestampIP);
    _stats.save(saver);
}

template <class IP> void Domain::saveIP(Saver &saver) {
    saver.write<uint32_t>(ips<IP>().size());
    for (const auto &ip : ips<IP>()) {
        ip.save(saver);
    }
}

void Domain::restore(Saver &saver) {
    Stats::Color cs = saver.read<Stats::Color>();
    restoreIP<IPv4>(saver);
    restoreIP<IPv6>(saver);
    if (settings.savedVersion() >= 4) {
        _timestampIP = saver.read<std::time_t>();
    }
    _stats.restore(saver);
    if (settings.savedVersion() == 1 && cs != Stats::BLACK) {
        _stats.migrateV1V2();
    }
}

template <class IP> void Domain::restoreIP(Saver &saver) {
    uint32_t nb = saver.read<uint32_t>();
    for (uint32_t i = 0; i < nb; ++i) {
        addIP<IP>(Address<IP>(saver));
    }
}

void Domain::clearIPs() {
    _ipv4.clear();
    _ipv6.clear();
}
