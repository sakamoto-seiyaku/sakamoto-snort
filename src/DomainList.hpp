/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
