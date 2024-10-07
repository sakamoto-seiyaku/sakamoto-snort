/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <Activity.hpp>
#include <Streamable.hpp>

class ActivityManager : public Streamable<Activity> {
private:
    App::Ptr _topApp = nullptr;
    std::chrono::time_point<std::chrono::steady_clock> _timestamp =
        std::chrono::steady_clock::now();
    std::shared_mutex _mutex;

public:
    ActivityManager();

    ~ActivityManager();

    ActivityManager(const ActivityManager &) = delete;

    void make(const App::Ptr app);

    void update(const App::Ptr app, const bool force);

    void startStream(const SocketIO::Ptr sockio, const bool pretty, const std::time_t horizon,
                     const std::uint32_t minSize);

private:
    void create(const App::Ptr app);
};

extern ActivityManager activityManager;
