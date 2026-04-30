/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextSessionCommands.hpp>

#include <PolicyCheckpoint.hpp>
#include <sucre-snort.hpp>

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace ControlVNextSessionCommands {

namespace {

[[nodiscard]] std::optional<std::string_view>
unknownArgsKey(const rapidjson::Value &args, std::initializer_list<std::string_view> allowed) {
    return ControlVNext::findUnknownKey(args, allowed);
}

[[nodiscard]] rapidjson::Value makeSlotMetadataValue(const PolicyCheckpoint::SlotMetadata &meta,
                                                     rapidjson::Document::AllocatorType &alloc) {
    rapidjson::Value out(rapidjson::kObjectType);
    out.AddMember("slot", meta.slot, alloc);
    out.AddMember("present", meta.present, alloc);
    if (meta.present) {
        out.AddMember("formatVersion", meta.formatVersion, alloc);
        out.AddMember("sizeBytes", meta.sizeBytes, alloc);
        out.AddMember("createdAt", meta.createdAt, alloc);
    }
    return out;
}

[[nodiscard]] rapidjson::Document makeCheckpointError(const std::uint32_t id,
                                                      const PolicyCheckpoint::Status &status) {
    const char *code = status.code.empty() ? "INTERNAL_ERROR" : status.code.c_str();
    const std::string message =
        status.message.empty() ? std::string("checkpoint operation failed") : status.message;
    return ControlVNext::makeErrorResponse(id, code, message);
}

[[nodiscard]] std::optional<rapidjson::Document> parseSlotArg(const std::uint32_t id,
                                                              const rapidjson::Value &args,
                                                              std::uint32_t &slot) {
    const auto slotIt = args.FindMember("slot");
    if (slotIt == args.MemberEnd()) {
        return ControlVNext::makeErrorResponse(id, "MISSING_ARGUMENT", "missing args.slot");
    }
    if (!slotIt->value.IsUint()) {
        return ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.slot must be u32");
    }
    slot = slotIt->value.GetUint();
    if (!PolicyCheckpoint::isValidSlot(slot)) {
        return ControlVNext::makeErrorResponse(id, "INVALID_ARGUMENT", "args.slot must be 0, 1, or 2");
    }
    return std::nullopt;
}

[[nodiscard]] ResponsePlan makeMetadataResponse(const std::uint32_t id,
                                                const PolicyCheckpoint::SlotMetadata &metadata) {
    rapidjson::Document result(rapidjson::kObjectType);
    auto &alloc = result.GetAllocator();
    result.AddMember("slot", makeSlotMetadataValue(metadata, alloc), alloc);
    result.AddMember("maxSlotBytes", PolicyCheckpoint::kMaxSlotBytes, alloc);
    rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
    return ResponsePlan{.response = std::move(response)};
}

} // namespace

std::optional<ResponsePlan> handleCheckpointCommand(const ControlVNext::RequestView &request,
                                                    const ControlVNextSession::Limits &limits) {
    (void)limits;
    const std::uint32_t id = request.id;
    const rapidjson::Value &args = *request.args;

    if (request.cmd == "CHECKPOINT.LIST") {
        if (const auto unknown = unknownArgsKey(args, {}); unknown.has_value()) {
            rapidjson::Document response = ControlVNext::makeErrorResponse(
                id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
            return ResponsePlan{.response = std::move(response)};
        }

        const auto slots = PolicyCheckpoint::listSlots();

        rapidjson::Document result(rapidjson::kObjectType);
        auto &alloc = result.GetAllocator();
        rapidjson::Value slotsValue(rapidjson::kArrayType);
        for (const auto &slot : slots) {
            slotsValue.PushBack(makeSlotMetadataValue(slot, alloc), alloc);
        }
        result.AddMember("slots", slotsValue, alloc);
        result.AddMember("slotCount", PolicyCheckpoint::kSlotCount, alloc);
        result.AddMember("maxSlotBytes", PolicyCheckpoint::kMaxSlotBytes, alloc);

        rapidjson::Document response = ControlVNext::makeOkResponse(id, &result);
        return ResponsePlan{.response = std::move(response)};
    }

    if (request.cmd != "CHECKPOINT.SAVE" && request.cmd != "CHECKPOINT.RESTORE" &&
        request.cmd != "CHECKPOINT.CLEAR") {
        return std::nullopt;
    }

    if (const auto unknown = unknownArgsKey(args, {"slot"}); unknown.has_value()) {
        rapidjson::Document response = ControlVNext::makeErrorResponse(
            id, "SYNTAX_ERROR", "unknown args key: " + std::string(*unknown));
        return ResponsePlan{.response = std::move(response)};
    }

    std::uint32_t slot = 0;
    if (auto err = parseSlotArg(id, args, slot); err.has_value()) {
        return ResponsePlan{.response = std::move(*err)};
    }

    PolicyCheckpoint::SlotMetadata metadata;
    PolicyCheckpoint::Status status;
    if (request.cmd == "CHECKPOINT.SAVE") {
        status = snortCheckpointSave(slot, metadata);
    } else if (request.cmd == "CHECKPOINT.RESTORE") {
        status = snortCheckpointRestore(slot, metadata);
    } else {
        status = snortCheckpointClear(slot, metadata);
    }

    if (!status.ok) {
        rapidjson::Document response = makeCheckpointError(id, status);
        return ResponsePlan{.response = std::move(response)};
    }
    return makeMetadataResponse(id, metadata);
}

} // namespace ControlVNextSessionCommands
