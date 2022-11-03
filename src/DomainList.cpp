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

#include <fstream>

#include <DomainList.hpp>

DomainList::DomainList() {}

DomainList::~DomainList() {}

uint8_t DomainList::blockMask(const std::string &domain) {
    const std::shared_lock_guard lock(_mutex);
    auto it = _domains.find(domain);
    if (it == _domains.end()) {
        return 0;
    }
    return it->second;
}

bool DomainList::set(const std::string filename) { return add(filename, true); }

bool DomainList::add(const std::string filename) { return add(filename, false); }

bool DomainList::add(const std::string filename, const bool clear) {
    //    const std::lock_guard lock(_mutex);
    if (clear) {
        _domains.clear();
    }
    return read(filename);
}

bool DomainList::read(const std::string filename) {
    if (auto in = std::ifstream(filename); in.is_open()) {
        std::string hostname;
        uint32_t mask;
        while (in >> hostname >> mask) {
            auto [it, inserted] = _domains.emplace(std::move(hostname), mask);
            if (!inserted) {
                it->second |= mask;
            }
        }
        return true;
    } else {
        throw std::runtime_error("Cannot open hosts file");
    }
}
