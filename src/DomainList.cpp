/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#include <fstream>

#include <DomainList.hpp>

DomainList::DomainList() {}

DomainList::~DomainList() {}

uint8_t DomainList::blockMask(const std::string &domain) {
    const std::shared_lock_guard lock(_mutex);
    auto it = _domains.find(domain);
    if (it != _domains.end()) {
        return it->second;
    }
    auto first = domain.find_first_of('.');
    auto last = domain.find_last_of('.');
    while (first != last) {
	auto it = _domains.find(domain.substr(first + 1));
	if (it != _domains.end()) {
            return it->second;
	}
	first = domain.find_first_of('.', first + 1);
    }
    return 0;
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
