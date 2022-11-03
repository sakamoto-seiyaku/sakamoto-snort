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

#pragma once

#include <unordered_map>

#include <iode-snort.hpp>

class DomainList {
private:
    using DomsSet = std::unordered_map<std::string, uint8_t>;

    DomsSet _domains;
    std::shared_mutex _mutex;

public:
    DomainList();

    ~DomainList();

    DomainList(const DomainList &) = delete;

    uint32_t size() const { return _domains.size(); }

    uint8_t blockMask(const std::string &domain);

    bool set(const std::string filename);

    bool add(const std::string filename);

private:
    bool add(const std::string filename, const bool clear);

    bool read(const std::string filename);
};
