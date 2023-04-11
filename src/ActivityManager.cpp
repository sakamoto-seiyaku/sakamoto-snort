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

#include <ratio>
#include <ActivityManager.hpp>

ActivityManager::ActivityManager() {}

ActivityManager::~ActivityManager() {}

void ActivityManager::make(const App::Ptr app) {
    const std::lock_guard lock(_mutex);
    _topApp = app;
    create(app);
}

void ActivityManager::update(const App::Ptr app, const bool force) {
    const std::lock_guard lock(_mutex);
    if (app == _topApp) {
        const auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::milli> elapsed = now - _timestamp;
        if (force || elapsed.count() > Settings::activityNotificationIntervalMs) {
            _timestamp = now;
            create(app);
        }
    }
}

void ActivityManager::create(const App::Ptr app) {
    const Activity::Ptr activity = std::make_shared<Activity>(app);
    stream(activity);
    activity->streamed(true);
}
