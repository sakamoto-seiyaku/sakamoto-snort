/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
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
    if (app == nullptr) {
        create(nullptr);
    } else if (app == _topApp) {
        const auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::milli> elapsed = now - _timestamp;
        if (force || elapsed.count() >= Settings::activityNotificationIntervalMs) {
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

void ActivityManager::startStream(const SocketIO::Ptr sockio, const bool pretty,
                                  const std::time_t horizon, const std::uint32_t minSize) {
    Streamable<Activity>::startStream(sockio, pretty, horizon, minSize);
    const std::lock_guard lock(_mutex);
    create(_topApp);
}
