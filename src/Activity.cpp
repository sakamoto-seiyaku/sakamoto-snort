/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later 
 */

#include <Activity.hpp>

Activity::Activity(App::Ptr app)
    : _app(app) {}

Activity::~Activity() {}

void Activity::print(std::ostream &out) const {
    out << "{" << JSF("blockEnabled") << settings.blockEnabled();
    if (_app != nullptr) {
        out << "," << JSF("app");
        _app->printAppNotif(out);
    }
    out << "}";
}

bool Activity::inHorizon(const uint32_t horizon, const timespec timeRef) const { return true; }

bool Activity::expired(const Activity::Ptr activity) const { return _streamed; }

void Activity::save(Saver &saver) {}

Activity::Ptr restore(Saver &saver) { return nullptr; }
