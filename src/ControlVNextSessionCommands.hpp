/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>

#include <optional>

namespace ControlVNextSessionCommands {

struct ResponsePlan {
    rapidjson::Document response;
    bool closeAfterWrite = false;
};

// Handles daemon-specific vNext commands (inventory/config/reset). Returns std::nullopt when cmd is
// not recognized by this handler.
std::optional<ResponsePlan> handleDaemonCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits);

} // namespace ControlVNextSessionCommands

