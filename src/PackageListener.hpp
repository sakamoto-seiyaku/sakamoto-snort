/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <AppManager.hpp>

#include <mutex>

class PackageListener {
private:
    using NamesMap = std::map<App::Uid, std::vector<std::string>>;

    std::mutex _mutexNames;
    NamesMap _names;

public:
    PackageListener();

    ~PackageListener();

    PackageListener(const PackageListener &) = delete;

    void start();

    void reset();

private:
    void listen();

    void updatePackages();
};

extern PackageListener pkgListener;
