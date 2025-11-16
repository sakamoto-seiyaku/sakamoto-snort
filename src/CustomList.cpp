/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <Saver.hpp>
#include <DomainManager.hpp>
#include <CustomList.hpp>

CustomList::CustomList() {}

CustomList::~CustomList() {}

bool CustomList::exists(const Domain::Ptr &domain) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    return _domains.find(domain) != _domains.end();
}

void CustomList::add(const Domain::Ptr &domain) {
    const std::lock_guard lock(_mutex);
    _domains.insert(domain);
}

void CustomList::remove(const Domain::Ptr &domain) {
    const std::lock_guard lock(_mutex);
    _domains.erase(domain);
}

void CustomList::reset() {
    const std::lock_guard lock(_mutex);
    _domains.clear();
}

void CustomList::save(Saver &saver) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    saver.write<uint32_t>(_domains.size());
    for (const auto &domain : _domains) {
        saver.write(domain->name());
    }
}

void CustomList::restore(Saver &saver) {
    const std::lock_guard lock(_mutex);
    uint32_t nb = saver.read<uint32_t>();
    for (uint32_t i = 0; i < nb; ++i) {
        std::string name;
        saver.readDomName(name);
        if (auto domain = domManager.find(name)) {
            _domains.insert(domain);
        }
    }
}

void CustomList::print(std::ostream &out) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &domain : _domains) {
        when(first, out << ",");
        out << JSS(domain->name());
    }
    out << "]";
}
