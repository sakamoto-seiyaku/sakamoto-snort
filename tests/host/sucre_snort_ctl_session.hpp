/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>

namespace SucreSnortCtl {

struct RequestOptions {
    uint32_t id = 1;
    std::string cmd;
    std::string argsJson = "{}";
};

struct SessionOptions {
    bool pretty = true;
    bool follow = false;
    size_t maxFrames = 0;     // 0 = unlimited
    size_t maxFrameBytes = 0; // 0 = default
};

[[nodiscard]] int runSession(int fd, const RequestOptions &request, const SessionOptions &options,
                             std::ostream &out, std::ostream &err);

} // namespace SucreSnortCtl

