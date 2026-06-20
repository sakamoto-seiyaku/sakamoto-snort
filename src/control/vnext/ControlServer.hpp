/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

namespace SnortControlVNext {

class ControlServer {
public:
    ControlServer() = default;
    ControlServer(const ControlServer &) = delete;
    ControlServer &operator=(const ControlServer &) = delete;

    int run();

private:
    static int createAbstractListener();
    static void serveClient(int clientFd);
};

} // namespace SnortControlVNext
