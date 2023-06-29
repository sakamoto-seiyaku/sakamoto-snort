/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#include <Host.hpp>

Host::Host() {}

const Domain::Ptr Host::domain() {
    const std::shared_lock_guard lock(_mutex);
    return _domain;
}

void Host::domain(const Domain::Ptr &domain) {
    const std::lock_guard lock(_mutex);
    _domain = domain;
}

void Host::print(std::stringstream &out) {
    const std::shared_lock_guard lock(_mutex);
    out << "{" << JSF("name") << JSS(_name) << ",";
    if (_domain) {
        out << JSF("domain") << JSS(_domain->name()) << "," << JSF("color")
            << JSS(Stats::colorNames[_domain->color()]) << ",";
    }
    out << JSF("ipv4") << "[";
    bool first = true;
    for (const auto &ip : _ipv4) {
        when(first, out << ",");
        ip.print(out);
    }
    out << "]," << JSF("ipv6") << "[";
    first = true;
    for (const auto &ip : _ipv6) {
        when(first, out << ",");
        out << "\"";
        ip.print(out);
        out << "\"";
    }
    out << "]}";
}
