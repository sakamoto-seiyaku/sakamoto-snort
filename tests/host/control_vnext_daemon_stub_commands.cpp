/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>
#include <sucre-snort.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace ControlVNextSessionCommands {

namespace TestHooks {

namespace {

enum class BlockedCommand {
    None,
    ConfigSet,
    DomainListsImport,
    CheckpointRestore,
};

std::atomic<BlockedCommand> g_blockCommand{BlockedCommand::None};
std::atomic<bool> g_blockCommandEntered{false};
std::atomic<bool> g_releaseBlockedCommand{true};
std::atomic<int> g_resetCount{0};
std::atomic<int> g_checkpointRestoreCount{0};

BlockedCommand parseBlockedCommand(const std::string_view cmd) {
    if (cmd == "CONFIG.SET") {
        return BlockedCommand::ConfigSet;
    }
    if (cmd == "DOMAINLISTS.IMPORT") {
        return BlockedCommand::DomainListsImport;
    }
    if (cmd == "CHECKPOINT.RESTORE") {
        return BlockedCommand::CheckpointRestore;
    }
    return BlockedCommand::None;
}

void maybeBlockCommand(const std::string_view cmd) {
    const auto blockedCommand = parseBlockedCommand(cmd);
    if (blockedCommand == BlockedCommand::None ||
        blockedCommand != g_blockCommand.load(std::memory_order_acquire)) {
        return;
    }

    g_blockCommandEntered.store(true, std::memory_order_release);
    while (!g_releaseBlockedCommand.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

} // namespace

void reset() {
    g_blockCommand.store(BlockedCommand::None, std::memory_order_release);
    g_blockCommandEntered.store(false, std::memory_order_release);
    g_releaseBlockedCommand.store(true, std::memory_order_release);
    g_resetCount.store(0, std::memory_order_release);
    g_checkpointRestoreCount.store(0, std::memory_order_release);
}

void blockCommandUntilReleased(const std::string_view cmd) {
    g_blockCommand.store(parseBlockedCommand(cmd), std::memory_order_release);
    g_blockCommandEntered.store(false, std::memory_order_release);
    g_releaseBlockedCommand.store(false, std::memory_order_release);
}

void releaseBlockedCommand() {
    g_releaseBlockedCommand.store(true, std::memory_order_release);
}

bool waitForBlockedCommand(const std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (g_blockCommandEntered.load(std::memory_order_acquire)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return g_blockCommandEntered.load(std::memory_order_acquire);
}

void markResetEntered() {
    g_resetCount.fetch_add(1, std::memory_order_acq_rel);
}

int resetCountSnapshot() {
    return g_resetCount.load(std::memory_order_acquire);
}

void markCheckpointRestoreEntered() {
    g_checkpointRestoreCount.fetch_add(1, std::memory_order_acq_rel);
}

int checkpointRestoreCountSnapshot() {
    return g_checkpointRestoreCount.load(std::memory_order_acquire);
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

std::optional<ResponsePlan> handleCheckpointCommand(const ControlVNext::RequestView &request,
                                                    const ControlVNextSession::Limits &limits) {
    (void)limits;
    if (request.cmd == "CHECKPOINT.SAVE" || request.cmd == "CHECKPOINT.CLEAR") {
        const std::lock_guard<std::mutex> lock(mutexControlMutations);
        return okResponse(request);
    }
    if (request.cmd == "CHECKPOINT.RESTORE") {
        const std::lock_guard<std::mutex> lock(mutexControlMutations);
        TestHooks::maybeBlockCommand(request.cmd);
        TestHooks::markCheckpointRestoreEntered();
        rapidjson::Document response = ControlVNext::makeOkResponse(request.id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }
    if (request.cmd == "CHECKPOINT.LIST") {
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

std::optional<ResponsePlan> handleTelemetryCommand(const ControlVNext::RequestView &request,
                                                   const ControlVNextSession::Limits &limits,
                                                   void *sessionKey, const bool canPassFd) {
    (void)request;
    (void)limits;
    (void)sessionKey;
    (void)canPassFd;
    return std::nullopt;
}

} // namespace ControlVNextSessionCommands
