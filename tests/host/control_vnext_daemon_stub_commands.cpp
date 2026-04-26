/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>
#include <sucre-snort.hpp>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace ControlVNextSessionCommands {

namespace TestHooks {

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::string g_blockCommand;
bool g_blockCommandEntered = false;
bool g_releaseBlockedCommand = true;
int g_resetCount = 0;

void maybeBlockCommand(const std::string_view cmd) {
    std::unique_lock<std::mutex> lock(g_mutex);
    if (cmd != g_blockCommand) {
        return;
    }

    g_blockCommandEntered = true;
    g_cv.notify_all();
    g_cv.wait(lock, [] { return g_releaseBlockedCommand; });
}

} // namespace

void reset() {
    const std::lock_guard<std::mutex> lock(g_mutex);
    g_blockCommand.clear();
    g_blockCommandEntered = false;
    g_releaseBlockedCommand = true;
    g_resetCount = 0;
}

void blockCommandUntilReleased(const std::string_view cmd) {
    const std::lock_guard<std::mutex> lock(g_mutex);
    g_blockCommand.assign(cmd);
    g_blockCommandEntered = false;
    g_releaseBlockedCommand = false;
}

void releaseBlockedCommand() {
    {
        const std::lock_guard<std::mutex> lock(g_mutex);
        g_releaseBlockedCommand = true;
    }
    g_cv.notify_all();
}

bool waitForBlockedCommand(const std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, timeout, [] { return g_blockCommandEntered; });
}

void markResetEntered() {
    {
        const std::lock_guard<std::mutex> lock(g_mutex);
        ++g_resetCount;
    }
    g_cv.notify_all();
}

int resetCountSnapshot() {
    const std::lock_guard<std::mutex> lock(g_mutex);
    return g_resetCount;
}

} // namespace TestHooks

namespace {

ResponsePlan okResponse(const ControlVNext::RequestView &request) {
    TestHooks::maybeBlockCommand(request.cmd);
    rapidjson::Document response = ControlVNext::makeOkResponse(request.id, nullptr);
    return ResponsePlan{.response = std::move(response)};
}

} // namespace

std::optional<ResponsePlan> handleDaemonCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)limits;
    if (request.cmd == "RESETALL") {
        snortResetAll();
        rapidjson::Document response = ControlVNext::makeOkResponse(request.id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    if (request.cmd == "CONFIG.SET") {
        return okResponse(request);
    }
    return std::nullopt;
}

std::optional<ResponsePlan> handleDomainCommand(const ControlVNext::RequestView &request,
                                                const ControlVNextSession::Limits &limits) {
    (void)limits;
    if (request.cmd == "DOMAINRULES.APPLY" || request.cmd == "DOMAINPOLICY.APPLY" ||
        request.cmd == "DOMAINLISTS.APPLY" || request.cmd == "DOMAINLISTS.IMPORT") {
        return okResponse(request);
    }
    return std::nullopt;
}

std::optional<ResponsePlan> handleIpRulesCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)limits;
    if (request.cmd == "IPRULES.APPLY") {
        return okResponse(request);
    }
    return std::nullopt;
}

std::optional<ResponsePlan> handleMetricsCommand(const ControlVNext::RequestView &request,
                                                 const ControlVNextSession::Limits &limits) {
    (void)limits;
    if (request.cmd == "METRICS.RESET") {
        return okResponse(request);
    }
    return std::nullopt;
}

} // namespace ControlVNextSessionCommands
