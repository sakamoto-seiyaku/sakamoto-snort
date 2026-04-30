/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <ControlVNextCodec.hpp>
#include <ControlVNextSession.hpp>

#include <optional>
#include <unistd.h>
#include <utility>

namespace ControlVNextSessionCommands {

class OwnedFd {
public:
    OwnedFd() = default;
    explicit OwnedFd(const int fd) : _fd(fd) {}
    ~OwnedFd() { reset(); }

    OwnedFd(const OwnedFd &) = delete;
    OwnedFd &operator=(const OwnedFd &) = delete;

    OwnedFd(OwnedFd &&other) noexcept : _fd(std::exchange(other._fd, -1)) {}
    OwnedFd &operator=(OwnedFd &&other) noexcept {
        if (this != &other) {
            reset(std::exchange(other._fd, -1));
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return _fd; }
    [[nodiscard]] bool valid() const noexcept { return _fd >= 0; }

    void reset(const int fd = -1) noexcept {
        if (_fd >= 0) {
            (void)::close(_fd);
        }
        _fd = fd;
    }

private:
    int _fd = -1;
};

struct ResponsePlan {
    rapidjson::Document response;
    // If valid, response must be sent via sendmsg(SCM_RIGHTS) on Unix sockets.
    OwnedFd fdToSend;
    bool closeAfterWrite = false;
};

// Handles daemon-specific vNext commands (inventory/config/reset). Returns std::nullopt when cmd is
// not recognized by this handler.
std::optional<ResponsePlan> handleDaemonCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits);

// Handles domain vNext commands (DOMAINRULES/DOMAINPOLICY/DOMAINLISTS). Returns std::nullopt when cmd
// is not recognized by this handler.
std::optional<ResponsePlan> handleDomainCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits);

// Handles iprules vNext commands (IPRULES.PREFLIGHT/PRINT/APPLY). Returns std::nullopt when cmd is
// not recognized by this handler.
std::optional<ResponsePlan> handleIpRulesCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits);

// Handles checkpoint vNext commands (CHECKPOINT.LIST/SAVE/RESTORE/CLEAR). Returns std::nullopt
// when cmd is not recognized by this handler.
std::optional<ResponsePlan> handleCheckpointCommand(const ControlVNext::RequestView &request,
                                                    const ControlVNextSession::Limits &limits);

// Handles vNext metrics commands (METRICS.GET/METRICS.RESET). Returns std::nullopt when cmd is not
// recognized by this handler.
std::optional<ResponsePlan> handleMetricsCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits);

// Handles vNext telemetry commands (TELEMETRY.OPEN/TELEMETRY.CLOSE). Returns std::nullopt when cmd
// is not recognized by this handler.
std::optional<ResponsePlan> handleTelemetryCommand(const ControlVNext::RequestView &request,
                                                   const ControlVNextSession::Limits &limits,
                                                   void *sessionKey, bool canPassFd);

} // namespace ControlVNextSessionCommands
