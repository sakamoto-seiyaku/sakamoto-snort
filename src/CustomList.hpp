/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <set>
#include <string>
#include <vector>

#include <Domain.hpp>

class CustomList {
private:
    using DomSet = std::set<Domain::Ptr>;

    DomSet _domains;
    mutable std::shared_mutex _mutex;

public:
    CustomList();

    ~CustomList();

    CustomList(const CustomList &) = delete;

    bool exists(const Domain::Ptr &domain);

    void add(const Domain::Ptr &domain);

    void remove(const Domain::Ptr &domain);

    void reset();

    // Snapshot custom domain names. Order is unspecified (caller may sort if needed).
    std::vector<std::string> snapshotNames() const;

    void print(std::ostream &out);

    void save(Saver &saver);

    void restore(Saver &saver);
};
