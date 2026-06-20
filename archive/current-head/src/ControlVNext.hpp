/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

class ControlVNext {
public:
    ControlVNext() = default;

    ~ControlVNext() = default;

    ControlVNext(const ControlVNext &) = delete;
    ControlVNext &operator=(const ControlVNext &) = delete;

    void start();

private:
    void unixServer();

    void inetServer();
};

