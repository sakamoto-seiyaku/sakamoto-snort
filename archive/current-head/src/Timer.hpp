/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <chrono>
#include <map>
#include <shared_mutex>
#include <string>

class Timer {
private:
    struct TimerData {
        std::string message;
        std::chrono::steady_clock::time_point start;
    };

    static inline std::map<std::string, TimerData> _timers;
    static inline std::shared_mutex _mutex;

public:
    static void set(std::string &&name, std::string &&message);

    static void set(std::string &&name);

    static void get(std::string &&name, std::string &&message);

    static void get(std::string &&name);

private:
    static void get(TimerData &t, std::string &message);
};
