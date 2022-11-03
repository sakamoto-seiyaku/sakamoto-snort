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

void CustomList::add(const std::string &name) {
    const std::lock_guard lock(_mutex);
    if (auto domain = _findDomain(name)) {
        _domains.insert(domain);
    }
}

void CustomList::remove(const std::string &name) {
    const std::lock_guard lock(_mutex);
    if (auto domain = _findDomain(name)) {
        _domains.erase(domain);
    }
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
    const std::lock_guard lock(_mutex);
    bool first = true;
    out << "[";
    for (const auto &domain : _domains) {
        when(first, out << ",");
        out << JSS(domain->name());
    }
    out << "]";
}
