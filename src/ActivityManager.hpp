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

private:
    void create(const App::Ptr app);
};

extern ActivityManager activityManager;
