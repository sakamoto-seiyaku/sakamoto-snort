/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

#include <FlowTelemetry.hpp>
#include <sucre-snort.hpp>

#include <cerrno>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <utility>

namespace ControlVNextSessionCommands {

namespace {

[[nodiscard]] rapidjson::Value makeString(const std::string_view value,
                                         rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out;
    out.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), alloc);
    return out;
}

[[nodiscard]] std::optional<std::string_view>
unknownArgsKey(const rapidjson::Value &args, const std::initializer_list<std::string_view> allowed) {
    return ControlVNext::findUnknownKey(args, allowed);
}

[[nodiscard]] std::optional<std::string_view>
unknownConfigKey(const rapidjson::Value &cfg, const std::initializer_list<std::string_view> allowed) {
    return ControlVNext::findUnknownKey(cfg, allowed);
}

[[nodiscard]] bool parseLevel(const rapidjson::Value &v, FlowTelemetry::Level &out) noexcept {
    if (!v.IsString()) {
        return false;
    }
    const std::string_view s(v.GetString(), v.GetStringLength());
    if (s == "off") {
        out = FlowTelemetry::Level::Off;
        return true;
    }
    if (s == "flow") {
        out = FlowTelemetry::Level::Flow;
        return true;
    }
    return false;
}

} // namespace

std::optional<ResponsePlan> handleTelemetryCommand(const ControlVNext::RequestView &request,
                                                   const ControlVNextSession::Limits &limits,
                                                   void *sessionKey, const bool canPassFd) {
    (void)limits;
    const uint32_t id = request.id;
    const rapidjson::Value &args = *request.args;

    if (request.cmd != "TELEMETRY.OPEN" && request.cmd != "TELEMETRY.CLOSE") {
        return std::nullopt;
    }

    const auto requireEmptyArgs = [&](const std::string_view cmd) -> std::optional<rapidjson::Document> {
        if (const auto unknown = unknownArgsKey(args, {}); unknown.has_value()) {
            return ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
        }
        (void)cmd;
        return std::nullopt;
    };

    if (request.cmd == "TELEMETRY.CLOSE") {
        if (auto err = requireEmptyArgs("TELEMETRY.CLOSE"); err.has_value()) {
            return ResponsePlan{.response = std::move(*err)};
        }

        const std::unique_lock<std::shared_mutex> lock(mutexListeners);
        if (flowTelemetry.isOwner(sessionKey)) {
            (void)snortExportTelemetryDisabledEnds();
        }
        flowTelemetry.close(sessionKey);
        rapidjson::Document response = ControlVNext::makeOkResponse(id, nullptr);
        return ResponsePlan{.response = std::move(response)};
    }

    // TELEMETRY.OPEN
    if (const auto unknown = unknownArgsKey(args, {"level", "config"}); unknown.has_value()) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
        return ResponsePlan{.response = std::move(response)};
    }

    const auto levelIt = args.FindMember("level");
    if (levelIt == args.MemberEnd()) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.level");
        return ResponsePlan{.response = std::move(response)};
    }

    FlowTelemetry::Level level = FlowTelemetry::Level::Off;
    if (!parseLevel(levelIt->value, level)) {
        rapidjson::Document response =
            ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.level must be \"off\" or \"flow\"");
        return ResponsePlan{.response = std::move(response)};
    }

    std::optional<FlowTelemetry::Config> overrideCfg = std::nullopt;
    if (const auto cfgIt = args.FindMember("config"); cfgIt != args.MemberEnd()) {
        if (!cfgIt->value.IsObject()) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.config must be an object");
            return ResponsePlan{.response = std::move(response)};
        }
        const rapidjson::Value &cfg = cfgIt->value;
        if (const auto unknown = unknownConfigKey(
                cfg, {"slotBytes", "ringDataBytes", "pollIntervalMs", "bytesThreshold", "packetsThreshold",
                      "maxExportIntervalMs", "blockTtlMs", "pickupTtlMs", "invalidTtlMs", "maxFlowEntries",
                      "maxEntriesPerUid"});
            unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args.config key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        FlowTelemetry::Config parsed{};

        if (const auto it = cfg.FindMember("slotBytes"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.config.slotBytes must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.slotBytes = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("ringDataBytes"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint64()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.ringDataBytes must be u64");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.ringDataBytes = it->value.GetUint64();
        }
        if (const auto it = cfg.FindMember("pollIntervalMs"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.pollIntervalMs must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.pollIntervalMs = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("bytesThreshold"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint64()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.bytesThreshold must be u64");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.bytesThreshold = it->value.GetUint64();
        }
        if (const auto it = cfg.FindMember("packetsThreshold"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint64()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.packetsThreshold must be u64");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.packetsThreshold = it->value.GetUint64();
        }
        if (const auto it = cfg.FindMember("maxExportIntervalMs"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.maxExportIntervalMs must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.maxExportIntervalMs = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("blockTtlMs"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.blockTtlMs must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.blockTtlMs = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("pickupTtlMs"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.pickupTtlMs must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.pickupTtlMs = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("invalidTtlMs"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.invalidTtlMs must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.invalidTtlMs = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("maxFlowEntries"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.maxFlowEntries must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.maxFlowEntries = it->value.GetUint();
        }
        if (const auto it = cfg.FindMember("maxEntriesPerUid"); it != cfg.MemberEnd()) {
            if (!it->value.IsUint()) {
                rapidjson::Document response = ControlVNext::makeErrorResponse(
                    id, "INVALID_ARGUMENT", "args.config.maxEntriesPerUid must be u32");
                return ResponsePlan{.response = std::move(response)};
            }
            parsed.maxEntriesPerUid = it->value.GetUint();
        }

        overrideCfg = parsed;
    }

    FlowTelemetry::OpenResult openRes{};
    OwnedFd fdToSend;
    std::string openErr;
    {
        const std::unique_lock<std::shared_mutex> lock(mutexListeners);
        if (level == FlowTelemetry::Level::Off && flowTelemetry.isOwner(sessionKey)) {
            (void)snortExportTelemetryDisabledEnds();
        }
        if (!flowTelemetry.open(sessionKey, canPassFd, level, overrideCfg, openRes, openErr)) {
            rapidjson::Document response =
                ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT",
                                                openErr.empty() ? "telemetry open failed" : openErr);
            if (level == FlowTelemetry::Level::Flow && !canPassFd) {
                if (response.HasMember("error") && response["error"].IsObject()) {
                    response["error"].AddMember(
                        "hint",
                        makeString("use vNext Unix domain socket (fd passing required)",
                                   response.GetAllocator()),
                        response.GetAllocator());
                }
            }
            return ResponsePlan{.response = std::move(response)};
        }
        if (openRes.actualLevel == FlowTelemetry::Level::Flow) {
            const int dupFd = ::fcntl(openRes.sharedMemoryFd, F_DUPFD_CLOEXEC, 0);
            if (dupFd < 0) {
                const std::string err = std::string("shared memory fd duplicate failed: ") +
                    std::strerror(errno);
                flowTelemetry.close(sessionKey);
                rapidjson::Document response =
                    ControlVNext::makeErrorResponse(id, "INTERNAL_ERROR", err);
                return ResponsePlan{.response = std::move(response)};
            }
            fdToSend.reset(dupFd);
        }
    }

    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("actualLevel", makeString(flowTelemetryLevelStr(openRes.actualLevel), alloc), alloc);
    result.AddMember("sessionId", openRes.sessionId, alloc);
    result.AddMember("abiVersion", openRes.abiVersion, alloc);
    result.AddMember("slotBytes", openRes.slotBytes, alloc);
    result.AddMember("slotCount", openRes.slotCount, alloc);
    result.AddMember("ringDataBytes", openRes.ringDataBytes, alloc);
    result.AddMember("maxPayloadBytes", openRes.maxPayloadBytes, alloc);
    result.AddMember("writeTicketSnapshot", openRes.writeTicketSnapshot, alloc);

    rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);

    ResponsePlan plan{.response = std::move(response)};
    plan.fdToSend = std::move(fdToSend);
    return plan;
}

} // namespace ControlVNextSessionCommands
