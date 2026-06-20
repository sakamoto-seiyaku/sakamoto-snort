/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <RuntimeControl.hpp>

namespace SnortControlVNext {

class ControlServer {
public:
    explicit ControlServer(SnortRuntime::BaseRuntimeControl &runtime);
    ControlServer(const ControlServer &) = delete;
    ControlServer &operator=(const ControlServer &) = delete;

    int run();
    void serveClient(int clientFd);

private:
    static int createAbstractListener();

    SnortRuntime::BaseRuntimeControl &runtime_;
};

} // namespace SnortControlVNext
