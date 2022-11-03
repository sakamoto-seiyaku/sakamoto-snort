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
