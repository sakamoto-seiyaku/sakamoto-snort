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

#include <sys/socket.h>

#include <Settings.hpp>
#include <HostManager.hpp>

HostManager::HostManager() {}

HostManager::~HostManager() {}

void HostManager::reset() {
    _hosts.clear();
    _byName.clear();
    _byIPv4.clear();
    _byIPv6.clear();
}

void HostManager::printHosts(std::stringstream &out, const std::string &subname) {
    const std::shared_lock_guard lock(_mutexHosts);
    out << "[";
    bool first = true;
    for (const auto &host : _hosts) {
        if (subname.size() == 0 || host->name().find(subname) != std::string::npos) {
            when(first, out << ",");
            host->print(out);
        }
    }
    out << "]";
}

void HostManager::printHostsByName(std::stringstream &out, const std::string &subname) {
    const std::shared_lock_guard lock(_mutexName);
    out << "[";
    bool first = true;
    for (const auto &[name, hosts] : _byName) {
        if (subname.size() == 0 || name.find(subname) != std::string::npos) {
            for (const auto &host : hosts) {
                when(first, out << ",");
                host->print(out);
            }
        }
    }
    out << "]";
}
