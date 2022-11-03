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

#include <set>

#include <Domain.hpp>

class CustomList {
private:
    using DomSet = std::set<const Domain::Ptr>;
    using FindDomainFun = std::function<const Domain::Ptr(const std::string &)>;

    DomSet _domains;
    std::shared_mutex _mutex;
    FindDomainFun _findDomain;

public:
    CustomList(const FindDomainFun &&findDomain);

    ~CustomList();

    CustomList(const CustomList &) = delete;

    bool exists(const Domain::Ptr &domain);

    void add(const std::string &name);

    void remove(const std::string &name);

    void reset();

    void print(std::ostream &out);

    void save(Saver &saver);

    void restore(Saver &saver);
};
