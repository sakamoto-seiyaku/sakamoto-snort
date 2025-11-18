/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <iomanip>

#include <sucre-snort.hpp>
#include <Timer.hpp>

void Timer::set(std::string &&name, std::string &&message) {
    const std::lock_guard lock(_mutex);
    _timers[name] = {message, std::chrono::steady_clock::now()};
}

void Timer::set(std::string &&name) { set(std::move(name), ""); }

void Timer::get(std::string &&name, std::string &&message) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    if (auto it = _timers.find(name); it != _timers.end()) {
        get(it->second, message);
    } else {
        LOG(WARNING) << __FUNCTION__ << " - timer not set for: " << name;
    }
}

void Timer::get(std::string &&name) {
    const std::shared_lock<std::shared_mutex> lock(_mutex);
    if (auto it = _timers.find(name); it != _timers.end()) {
        get(it->second, it->second.message);
    } else {
        LOG(WARNING) << __FUNCTION__ << " - timer not set for: " << name;
    }
}

void Timer::get(TimerData &t, std::string &message) {
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(now - t.start);
    LOG(INFO) << message << ": " << elapsed.count();
}
