/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <iode-snort.hpp>

#include <Saver.hpp>
#include <CustomList.hpp>

CustomList::CustomList(const FindDomainFun &&findDomain)
    : _findDomain(findDomain) {}

CustomList::~CustomList() {}

bool CustomList::exists(const Domain::Ptr &domain) {
    const std::shared_lock_guard lock(_mutex);
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
    const std::shared_lock_guard lock(_mutex);
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
        if (auto domain = _findDomain(name)) {
            _domains.insert(domain);
        }
    }
}

void CustomList::print(std::ostream &out) {
    const std::shared_lock_guard lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &domain : _domains) {
        when(first, out << ",");
        out << JSS(domain->name());
    }
    out << "]";
}
