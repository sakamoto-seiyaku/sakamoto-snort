/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstddef>

class ControlVNextSession {
public:
    struct Limits {
        size_t maxRequestBytes = 0;
        size_t maxResponseBytes = 0;
    };

    ControlVNextSession(int fd, Limits limits);

    ~ControlVNextSession();

    ControlVNextSession(const ControlVNextSession &) = delete;
    ControlVNextSession &operator=(const ControlVNextSession &) = delete;

    void run();

private:
    int _fd = -1;
    Limits _limits;
};

