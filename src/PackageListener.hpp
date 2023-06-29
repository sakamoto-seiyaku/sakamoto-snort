/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#pragma once

#include <AppManager.hpp>

class PackageListener {
private:
    using NamesMap = std::map<App::Uid, std::vector<const std::string>>;

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
