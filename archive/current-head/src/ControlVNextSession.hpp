/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstddef>
#include <optional>

class ControlVNextSession {
public:
    struct Limits {
        size_t maxRequestBytes = 0;
        size_t maxResponseBytes = 0;
    };

    // canPassFdOverride:
    // - std::nullopt: attempt to detect (best-effort).
    // - true/false: force the session capability (used by listeners that know transport).
    ControlVNextSession(int fd, Limits limits, std::optional<bool> canPassFdOverride = std::nullopt);

    ~ControlVNextSession();

    ControlVNextSession(const ControlVNextSession &) = delete;
    ControlVNextSession &operator=(const ControlVNextSession &) = delete;

    void run();

private:
    int _fd = -1;
    Limits _limits;
    std::optional<bool> _canPassFdOverride;
};
