/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
