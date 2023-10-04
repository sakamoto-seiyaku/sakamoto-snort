/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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

    void add(const Domain::Ptr &domain);

    void remove(const Domain::Ptr &domain);

    void reset();

    void print(std::ostream &out);

    void save(Saver &saver);

    void restore(Saver &saver);
};
