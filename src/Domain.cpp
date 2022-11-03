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
    saver.write<Stats::Color>(_color);
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
