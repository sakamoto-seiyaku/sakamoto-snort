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
#include <string>

#include <iode-snort.hpp>

class DefaultAppsManager {
private:
    enum Status { INSTALLED, REMOVED, TOBEINSTALLED, TOBEREMOVED };

    struct DefApp {
        const std::string dir;
        Status status;
        const bool removable;
        const uint32_t category;
        DefApp(const std::string _dir, const Status _status, const bool _removable,
               const uint32_t _category)
            : dir(_dir)
            , status(_status)
            , removable(_removable)
            , category(_category) {}
    };

    std::unordered_map<std::string, DefApp> _apps;
    std::shared_mutex _mutex;

public:
    DefaultAppsManager();

    ~DefaultAppsManager();

    DefaultAppsManager(const DefaultAppsManager &) = delete;

    void start();

    void install(const std::string &appName);

    void remove(const std::string &appName);

    void print(std::ostream &out);

private:
    void save();
};

extern DefaultAppsManager defAppManager;
