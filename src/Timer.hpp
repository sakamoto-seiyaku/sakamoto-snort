/*
 * SPDX-FileCopyrightText: 2019-2023 iodé Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
 
#pragma once

#include <chrono>
#include <map>
#include <string>

class Timer {
private:
    struct timer {
        std::string name;
        std::string message;
        std::chrono::steady_clock::time_point start;
    };

    static inline std::map<std::string, struct timer> _timers;

public:
    static void set(std::string &&name, std::string &&message);

    static void set(std::string &&name);

    static void get(std::string &&name, std::string &&message);

    static void get(std::string &&name);

private:
    static void get(timer &t, std::string &message);
};
