/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

namespace ControlVNextSessionCommands {

std::optional<ResponsePlan> handleDaemonCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

std::optional<ResponsePlan> handleDomainCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

std::optional<ResponsePlan> handleIpRulesCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

std::optional<ResponsePlan> handleMetricsCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)request;
    (void)limits;
    return std::nullopt;
}

} // namespace ControlVNextSessionCommands
