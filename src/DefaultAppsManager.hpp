/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <unordered_map>
#include <string>

#include <sucre-snort.hpp>

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
