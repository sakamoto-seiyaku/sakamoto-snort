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

    // Variant used during init and RESETALL when `mutexListeners` is held exclusively by the
    // orchestrating thread. The regular update path takes a shared lock on `mutexListeners`
    // to avoid racing with RESETALL, but doing so while an exclusive lock is held would deadlock.
    void updatePackagesNoListenersLock();

    void updatePackagesImpl(bool takeListenersLock);
};

extern PackageListener pkgListener;
