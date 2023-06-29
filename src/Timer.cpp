/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#include <iomanip>

#include <iode-snort.hpp>
#include <Timer.hpp>

void Timer::set(std::string &&name, std::string &&message) {
    _timers[name] = {name, message, std::chrono::steady_clock::now()};
}

void Timer::set(std::string &&name) { set(std::move(name), ""); }

void Timer::get(std::string &&name, std::string &&message) {
    auto &t = _timers[name];
    get(t, message);
}

void Timer::get(std::string &&name) {
    auto &t = _timers[name];
    get(t, t.message);
}

void Timer::get(timer &t, std::string &message) {
    auto now = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(now - t.start);
    LOG(INFO) << message << ": " << elapsed.count();
}
