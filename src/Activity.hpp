/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <AppManager.hpp>

class Activity {
public:
    using Ptr = std::shared_ptr<Activity>;

private:
    const App::Ptr _app;
    bool _streamed = false;

public:
    Activity(const App::Ptr app);

    ~Activity();

    Activity(const Activity &) = delete;

    void streamed(bool streamed) { _streamed = streamed; }

    void print(std::ostream &out) const;

    bool inHorizon(const uint32_t horizon, const timespec timeRef) const;

    bool expired(const Activity::Ptr activity) const;

    void save(Saver &saver);

    static Activity::Ptr restore(Saver &saver);
};
