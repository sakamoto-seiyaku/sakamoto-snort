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
    {
        const std::lock_guard lock(_mutexHosts);
        _hosts.clear();
    }
    {
        const std::lock_guard lock(_mutexName);
        _byName.clear();
    }
    {
        const std::lock_guard lock(_mutexIP);
        _byIPv4.clear();
        _byIPv6.clear();
    }
}

void HostManager::printHosts(std::stringstream &out, const std::string &subname) {
    // Snapshot vector of hosts under lock, then print outside to avoid nested Manager→Host locks
    std::vector<Host::Ptr> snap;
    {
        const std::shared_lock<std::shared_mutex> lock(_mutexHosts);
        snap = _hosts; // copy shared_ptrs
    }
    out << "[";
    bool first = true;
    for (const auto &host : snap) {
        const std::string name = host->name();
        if (subname.empty() || name.find(subname) != std::string::npos) {
            when(first, out << ",");
            host->print(out);
        }
    }
    out << "]";
}

void HostManager::printHostsByName(std::stringstream &out, const std::string &subname) {
    // Snapshot matching hosts under _mutexName, then print outside to avoid _mutexName→Host locks
    std::vector<Host::Ptr> snap;
    {
        const std::shared_lock<std::shared_mutex> lock(_mutexName);
        for (const auto &[name, hosts] : _byName) {
            if (subname.empty() || name.find(subname) != std::string::npos) {
                snap.insert(snap.end(), hosts.begin(), hosts.end());
            }
        }
    }
    // Deduplicate hosts by pointer to avoid repeated entries when a host appears in multiple
    // name buckets or with multiple IPs; order is preserved based on first occurrence.
    std::vector<Host::Ptr> unique;
    {
        std::unordered_set<Host::Ptr> seen;
        seen.reserve(snap.size());
        for (const auto &host : snap) {
            if (seen.insert(host).second) {
                unique.push_back(host);
            }
        }
    }
    out << "[";
    bool first = true;
    for (const auto &host : unique) {
        when(first, out << ",");
        host->print(out);
    }
    out << "]";
}
